/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Socket networking code.
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "soup-address.h"
#include "soup-socket.h"
#include "soup-marshal.h"
#include "soup-misc.h"
#include "soup-ssl.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	CONNECT_RESULT,
	READABLE,
	WRITABLE,
	DISCONNECTED,
	NEW_CONNECTION,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_NON_BLOCKING,
	PROP_NODELAY,
	PROP_REUSEADDR,
	PROP_IS_SERVER,
	PROP_SSL_CREDENTIALS,

	LAST_PROP
};

struct SoupSocketPrivate {
	int sockfd;
	SoupAddress *local_addr, *remote_addr;
	GIOChannel *iochannel;

	guint non_blocking:1;
	guint nodelay:1;
	guint reuseaddr:1;
	guint is_server:1;
	gpointer ssl_creds;

	guint           watch;
	guint           read_tag, write_tag, error_tag;
	GByteArray     *read_buf;

	GMutex *iolock, *addrlock;
};

#ifdef HAVE_IPV6
#define soup_sockaddr_max sockaddr_in6
#else
#define soup_sockaddr_max sockaddr_in
#endif

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
init (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	sock->priv = g_new0 (SoupSocketPrivate, 1);
	sock->priv->sockfd = -1;
	sock->priv->non_blocking = sock->priv->nodelay = TRUE;
	sock->priv->reuseaddr = TRUE;
	sock->priv->addrlock = g_mutex_new ();
	sock->priv->iolock = g_mutex_new ();
}

static void
disconnect_internal (SoupSocket *sock)
{
	g_io_channel_unref (sock->priv->iochannel);
	sock->priv->iochannel = NULL;
	sock->priv->sockfd = -1;

	if (sock->priv->read_tag) {
		g_source_remove (sock->priv->read_tag);
		sock->priv->read_tag = 0;
	}
	if (sock->priv->write_tag) {
		g_source_remove (sock->priv->write_tag);
		sock->priv->write_tag = 0;
	}
	if (sock->priv->error_tag) {
		g_source_remove (sock->priv->error_tag);
		sock->priv->error_tag = 0;
	}
}

static void
finalize (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	if (sock->priv->iochannel)
		disconnect_internal (sock);

	if (sock->priv->local_addr)
		g_object_unref (sock->priv->local_addr);
	if (sock->priv->remote_addr)
		g_object_unref (sock->priv->remote_addr);

	if (sock->priv->watch)
		g_source_remove (sock->priv->watch);

	g_mutex_free (sock->priv->addrlock);
	g_mutex_free (sock->priv->iolock);

	g_free (sock->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */
	signals[CONNECT_RESULT] =
		g_signal_new ("connect_result",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSocketClass, connect_result),
			      NULL, NULL,
			      soup_marshal_NONE__INT,
			      G_TYPE_NONE, 1,
			      G_TYPE_INT);
	signals[READABLE] =
		g_signal_new ("readable",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, readable),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[WRITABLE] =
		g_signal_new ("writable",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, writable),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (SoupSocketClass, disconnected),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
	signals[NEW_CONNECTION] =
		g_signal_new ("new_connection",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSocketClass, new_connection),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SOCKET);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_NON_BLOCKING,
		g_param_spec_boolean (SOUP_SOCKET_FLAG_NONBLOCKING,
				      "Non-blocking",
				      "Whether or not the socket uses non-blocking I/O",
				      TRUE,
				      G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_NODELAY,
		g_param_spec_boolean (SOUP_SOCKET_FLAG_NODELAY,
				      "NODELAY",
				      "Whether or not the socket uses TCP NODELAY",
				      TRUE,
				      G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_REUSEADDR,
		g_param_spec_boolean (SOUP_SOCKET_FLAG_REUSEADDR,
				      "REUSEADDR",
				      "Whether or not the socket uses the TCP REUSEADDR flag",
				      TRUE,
				      G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_IS_SERVER,
		g_param_spec_boolean (SOUP_SOCKET_IS_SERVER,
				      "Server",
				      "Whether or not the socket is a server socket",
				      FALSE,
				      G_PARAM_READABLE));
	g_object_class_install_property (
		object_class, PROP_SSL_CREDENTIALS,
		g_param_spec_pointer (SOUP_SOCKET_SSL_CREDENTIALS,
				      "SSL credentials",
				      "SSL credential information, passed from the session to the SSL implementation",
				      G_PARAM_READWRITE));
}

SOUP_MAKE_TYPE (soup_socket, SoupSocket, class_init, init, PARENT_TYPE)


static void
update_fdflags (SoupSocket *sock)
{
	int flags, opt;

	if (sock->priv->sockfd == -1)
		return;

	flags = fcntl (sock->priv->sockfd, F_GETFL, 0);
	if (flags != -1) {
		if (sock->priv->non_blocking)
			flags |= O_NONBLOCK;
		else
			flags &= ~O_NONBLOCK;
		fcntl (sock->priv->sockfd, F_SETFL, flags);
	}

	opt = (sock->priv->nodelay != 0);
	setsockopt (sock->priv->sockfd, IPPROTO_TCP,
		    TCP_NODELAY, &opt, sizeof (opt));

	opt = (sock->priv->reuseaddr != 0);
	setsockopt (sock->priv->sockfd, SOL_SOCKET,
		    SO_REUSEADDR, &opt, sizeof (opt));
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	switch (prop_id) {
	case PROP_NON_BLOCKING:
		sock->priv->non_blocking = g_value_get_boolean (value);
		update_fdflags (sock);
		break;
	case PROP_NODELAY:
		sock->priv->nodelay = g_value_get_boolean (value);
		update_fdflags (sock);
		break;
	case PROP_REUSEADDR:
		sock->priv->reuseaddr = g_value_get_boolean (value);
		update_fdflags (sock);
		break;
	case PROP_SSL_CREDENTIALS:
		sock->priv->ssl_creds = g_value_get_pointer (value);
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	switch (prop_id) {
	case PROP_NON_BLOCKING:
		g_value_set_boolean (value, sock->priv->non_blocking);
		break;
	case PROP_NODELAY:
		g_value_set_boolean (value, sock->priv->nodelay);
		break;
	case PROP_REUSEADDR:
		g_value_set_boolean (value, sock->priv->reuseaddr);
		break;
	case PROP_IS_SERVER:
		g_value_set_boolean (value, sock->priv->is_server);
		break;
	case PROP_SSL_CREDENTIALS:
		g_value_set_pointer (value, sock->priv->ssl_creds);
		break;
	default:
		break;
	}
}


/**
 * soup_socket_new:
 * @optname1: name of first property to set (or %NULL)
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Return value: a new (disconnected) socket
 **/
SoupSocket *
soup_socket_new (const char *optname1, ...)
{
	SoupSocket *sock;
	va_list ap;

	va_start (ap, optname1);
	sock = (SoupSocket *)g_object_new_valist (SOUP_TYPE_SOCKET,
						  optname1, ap);
	va_end (ap);

	return sock;
}

static GIOChannel *
get_iochannel (SoupSocket *sock)
{
	g_mutex_lock (sock->priv->iolock);
	if (!sock->priv->iochannel) {
		sock->priv->iochannel =
			g_io_channel_unix_new (sock->priv->sockfd);
		g_io_channel_set_close_on_unref (sock->priv->iochannel, TRUE);
		g_io_channel_set_encoding (sock->priv->iochannel, NULL, NULL);
		g_io_channel_set_buffered (sock->priv->iochannel, FALSE);
	}
	g_mutex_unlock (sock->priv->iolock);
	return sock->priv->iochannel;
}

static gboolean
idle_connect_result (gpointer user_data)
{
	SoupSocket *sock = user_data;

	sock->priv->watch = 0;

	g_signal_emit (sock, signals[CONNECT_RESULT], 0,
		       sock->priv->sockfd != -1 ? SOUP_STATUS_OK : SOUP_STATUS_CANT_CONNECT);
	return FALSE;
}

static gboolean
connect_watch (GIOChannel* iochannel, GIOCondition condition, gpointer data)
{
	SoupSocket *sock = data;
	int error = 0;
	int len = sizeof (error);

	/* Remove the watch now in case we don't return immediately */
	g_source_remove (sock->priv->watch);
	sock->priv->watch = 0;

	if (condition & ~(G_IO_IN | G_IO_OUT))
		goto cant_connect;

	if (getsockopt (sock->priv->sockfd, SOL_SOCKET, SO_ERROR,
			&error, &len) != 0)
		goto cant_connect;
	if (error)
		goto cant_connect;

	return idle_connect_result (sock);

 cant_connect:
	g_signal_emit (sock, signals[CONNECT_RESULT], 0, SOUP_STATUS_CANT_CONNECT);
	return FALSE;
}

static void
got_address (SoupAddress *addr, guint status, gpointer user_data)
{
	SoupSocket *sock = user_data;

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		g_signal_emit (sock, signals[CONNECT_RESULT], 0, status);
		g_object_unref (sock);
		return;
	}

	soup_socket_connect (sock, sock->priv->remote_addr);
	/* soup_socket_connect re-reffed addr */
	g_object_unref (addr);

	g_object_unref (sock);
}

/**
 * soup_socket_connect:
 * @sock: a client #SoupSocket (which must not already be connected)
 * @remote_addr: address to connect to
 *
 * If %SOUP_SOCKET_FLAG_NONBLOCKING has been set on the socket, this
 * begins asynchronously connecting to the given address. The socket
 * will emit %connect_result when it succeeds or fails (but not before
 * returning from this function).
 *
 * If %SOUP_SOCKET_FLAG_NONBLOCKING has not been set, this will
 * attempt to synchronously connect.
 *
 * Return value: %SOUP_STATUS_CONTINUE if connecting asynchronously,
 * otherwise a success or failure code.
 **/
guint
soup_socket_connect (SoupSocket *sock, SoupAddress *remote_addr)
{
	struct sockaddr *sa;
	int len, status;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (!sock->priv->is_server, SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (sock->priv->sockfd == -1, SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (SOUP_IS_ADDRESS (remote_addr), SOUP_STATUS_MALFORMED);

	sock->priv->remote_addr = g_object_ref (remote_addr);
	if (!sock->priv->non_blocking) {
		status = soup_address_resolve_sync (remote_addr);
		if (!SOUP_STATUS_IS_SUCCESSFUL (status))
			return status;
	}

	sa = soup_address_get_sockaddr (sock->priv->remote_addr, &len);
	if (!sa) {
		if (!sock->priv->non_blocking)
			return SOUP_STATUS_CANT_RESOLVE;

		g_object_ref (sock);
		soup_address_resolve_async (remote_addr, got_address, sock);
		return SOUP_STATUS_CONTINUE;
	}

	sock->priv->sockfd = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sock->priv->sockfd == -1) {
		goto done;
	}
	update_fdflags (sock);

	status = connect (sock->priv->sockfd, sa, len);

	if (status == -1) {
		if (errno == EINPROGRESS) {
			/* Wait for connect to succeed or fail */
			sock->priv->watch =
				g_io_add_watch (get_iochannel (sock),
						G_IO_IN | G_IO_OUT |
						G_IO_PRI | G_IO_ERR |
						G_IO_HUP | G_IO_NVAL,
						connect_watch, sock);
			return SOUP_STATUS_CONTINUE;
		} else {
			close (sock->priv->sockfd);
			sock->priv->sockfd = -1;
		}
	}

 done:
	if (sock->priv->non_blocking) {
		sock->priv->watch = g_idle_add (idle_connect_result, sock);
		return SOUP_STATUS_CONTINUE;
	} else if (sock->priv->sockfd == -1)
		return SOUP_STATUS_CANT_CONNECT;
	else {
		get_iochannel (sock);
		return SOUP_STATUS_OK;
	}
}

static gboolean
listen_watch (GIOChannel* iochannel, GIOCondition condition, gpointer data)
{
	SoupSocket *sock = data, *new;
	struct soup_sockaddr_max sa;
	int sa_len, sockfd;

	if (condition & (G_IO_HUP | G_IO_ERR)) {
		g_source_remove (sock->priv->watch);
		sock->priv->watch = 0;
		return FALSE;
	}

	sa_len = sizeof (sa);
	sockfd = accept (sock->priv->sockfd, (struct sockaddr *)&sa, &sa_len);
	if (sockfd == -1)
		return TRUE;

	new = g_object_new (SOUP_TYPE_SOCKET, NULL);
	new->priv->sockfd = sockfd;
	new->priv->non_blocking = sock->priv->non_blocking;
	new->priv->nodelay = sock->priv->nodelay;
	new->priv->is_server = TRUE;
	new->priv->ssl_creds = sock->priv->ssl_creds;
	update_fdflags (new);

	new->priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&sa, sa_len);

	if (new->priv->ssl_creds) {
		if (!soup_socket_start_ssl (new)) {
			g_object_unref (new);
			return TRUE;
		}
	} else
		get_iochannel (new);

	g_signal_emit (sock, signals[NEW_CONNECTION], 0, new);
	g_object_unref (new);

	return TRUE;
}

/**
 * soup_socket_listen:
 * @sock: a server #SoupSocket (which must not already be connected or
 * listening)
 * @local_addr: Local address to bind to.
 *
 * Makes @sock start listening on the given interface and port. When
 * connections come in, @sock will emit %new_connection.
 *
 * Return value: whether or not @sock is now listening.
 **/
gboolean
soup_socket_listen (SoupSocket *sock, SoupAddress *local_addr)
{
	struct sockaddr *sa;
	int sa_len;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);
	g_return_val_if_fail (sock->priv->is_server, FALSE);
	g_return_val_if_fail (sock->priv->sockfd == -1, FALSE);
	g_return_val_if_fail (SOUP_IS_ADDRESS (local_addr), FALSE);

	/* @local_addr may have its port set to 0. So we intentionally
	 * don't store it in sock->priv->local_addr, so that if the
	 * caller calls soup_socket_get_local_address() later, we'll
	 * have to make a new addr by calling getsockname(), which
	 * will have the right port number.
	 */
	sa = soup_address_get_sockaddr (local_addr, &sa_len);
	g_return_val_if_fail (sa != NULL, FALSE);

	sock->priv->sockfd = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sock->priv->sockfd < 0)
		goto cant_listen;
	update_fdflags (sock);

	/* Bind */
	if (bind (sock->priv->sockfd, sa, sa_len) != 0)
		goto cant_listen;

	/* Listen */
	if (listen (sock->priv->sockfd, 10) != 0)
		goto cant_listen;

	sock->priv->watch = g_io_add_watch (get_iochannel (sock),
					    G_IO_IN | G_IO_ERR | G_IO_HUP,
					    listen_watch, sock);
	return TRUE;

 cant_listen:
	if (sock->priv->sockfd != -1) {
		close (sock->priv->sockfd);
		sock->priv->sockfd = -1;
	}

	return FALSE;
}

/**
 * soup_socket_start_ssl:
 * @sock: the socket
 *
 * Starts using SSL on @socket.
 *
 * Return value: success or failure
 **/
gboolean
soup_socket_start_ssl (SoupSocket *sock)
{
	GIOChannel *ssl_chan;

	get_iochannel (sock);
	ssl_chan = soup_ssl_wrap_iochannel (
		sock->priv->iochannel, sock->priv->is_server ?
		SOUP_SSL_TYPE_SERVER : SOUP_SSL_TYPE_CLIENT,
		soup_address_get_name (sock->priv->remote_addr),
		sock->priv->ssl_creds);

	if (!ssl_chan)
		return FALSE;

	sock->priv->iochannel = ssl_chan;
	return TRUE;
}
	

/**
 * soup_socket_client_new_async:
 * @hostname: remote machine to connect to
 * @port: remote port to connect to
 * @ssl_creds: SSL credentials structure, or %NULL if not SSL
 * @callback: callback to call when the socket is connected
 * @user_data: data for @callback
 *
 * Creates a connection to @hostname and @port. @callback will be
 * called when the connection completes (or fails).
 *
 * Return value: the new socket (not yet ready for use).
 **/
SoupSocket *
soup_socket_client_new_async (const char *hostname, guint port,
			      gpointer ssl_creds,
			      SoupSocketCallback callback, gpointer user_data)
{
	SoupSocket *sock;

	g_return_val_if_fail (hostname != NULL, NULL);

	sock = g_object_new (SOUP_TYPE_SOCKET,
			     SOUP_SOCKET_SSL_CREDENTIALS, ssl_creds,
			     NULL);
	soup_socket_connect (sock, soup_address_new (hostname, port));

	if (callback) {
		soup_signal_connect_once (sock, "connect_result",
					  G_CALLBACK (callback), user_data);
	}
	return sock;
}

/**
 * soup_socket_client_new_sync:
 * @hostname: remote machine to connect to
 * @port: remote port to connect to
 * @ssl_creds: SSL credentials structure, or %NULL if not SSL
 * @status_ret: pointer to return the soup status in
 *
 * Creates a connection to @hostname and @port. If @status_ret is not
 * %NULL, it will contain a status code on return.
 *
 * Return value: the new socket, or %NULL if it could not connect.
 **/
SoupSocket *
soup_socket_client_new_sync (const char *hostname, guint port,
			     gpointer ssl_creds, guint *status_ret)
{
	SoupSocket *sock;
	guint status;

	g_return_val_if_fail (hostname != NULL, NULL);

	sock = g_object_new (SOUP_TYPE_SOCKET,
			     SOUP_SOCKET_SSL_CREDENTIALS, ssl_creds,
			     NULL);
	sock->priv->non_blocking = FALSE;
	status = soup_socket_connect (sock, soup_address_new (hostname, port));

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		g_object_unref (sock);
		sock = NULL;
	}

	if (status_ret)
		*status_ret = status;
	return sock;
}

/**
 * soup_socket_server_new:
 * @local_addr: Local address to bind to. (Use soup_address_any_new() to
 * accept connections on any local address)
 * @ssl_creds: SSL credentials, or %NULL if this is not an SSL server
 * @callback: Callback to call when a client connects
 * @user_data: data to pass to @callback.
 *
 * Create and open a new #SoupSocket listening on the specified
 * address. @callback will be called each time a client connects,
 * with a new #SoupSocket.
 *
 * Returns: a new #SoupSocket, or NULL if there was a failure.
 **/
SoupSocket *
soup_socket_server_new (SoupAddress *local_addr, gpointer ssl_creds,
			SoupSocketListenerCallback callback,
			gpointer user_data)
{
	SoupSocket *sock;

	g_return_val_if_fail (SOUP_IS_ADDRESS (local_addr), NULL);

	sock = g_object_new (SOUP_TYPE_SOCKET,
			     SOUP_SOCKET_SSL_CREDENTIALS, ssl_creds,
			     NULL);
	sock->priv->is_server = TRUE;
	if (!soup_socket_listen (sock, local_addr)) {
		g_object_unref (sock);
		return NULL;
	}

	if (callback) {
		g_signal_connect (sock, "new_connection",
				  G_CALLBACK (callback), user_data);
	}

	return sock;
}


void
soup_socket_disconnect (SoupSocket *sock)
{
	gboolean already_disconnected = FALSE;

	g_return_if_fail (SOUP_IS_SOCKET (sock));

	if (g_mutex_trylock (sock->priv->iolock)) {
		if (sock->priv->iochannel)
			disconnect_internal (sock);
		else
			already_disconnected = TRUE;
		g_mutex_unlock (sock->priv->iolock);
	} else {
		int sockfd;

		/* Another thread is currently doing IO, so
		 * we can't close the iochannel. So just kick
		 * the file descriptor out from under it.
		 */

		sockfd = sock->priv->sockfd;
		sock->priv->sockfd = -1;
		if (sockfd == -1)
			already_disconnected = TRUE;
		else {
			g_io_channel_set_close_on_unref (sock->priv->iochannel,
							 FALSE);
			close (sockfd);
		}
	}

	if (already_disconnected)
		return;

	/* Give all readers a chance to notice the connection close */
	g_signal_emit (sock, signals[READABLE], 0);

	/* FIXME: can't disconnect until all data is read */

	/* Then let everyone know we're disconnected */
	g_signal_emit (sock, signals[DISCONNECTED], 0);
}

gboolean
soup_socket_is_connected (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);

	return sock->priv->iochannel != NULL;
}


SoupAddress *
soup_socket_get_local_address (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	g_mutex_lock (sock->priv->addrlock);
	if (!sock->priv->local_addr) {
		struct soup_sockaddr_max bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getsockname (sock->priv->sockfd, (struct sockaddr *)&bound_sa, &sa_len);
		sock->priv->local_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}
	g_mutex_unlock (sock->priv->addrlock);

	return sock->priv->local_addr;
}

SoupAddress *
soup_socket_get_remote_address (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	g_mutex_lock (sock->priv->addrlock);
	if (!sock->priv->remote_addr) {
		struct soup_sockaddr_max bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getpeername (sock->priv->sockfd, (struct sockaddr *)&bound_sa, &sa_len);
		sock->priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}
	g_mutex_unlock (sock->priv->addrlock);

	return sock->priv->remote_addr;
}




static gboolean
socket_read_watch (GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	SoupSocket *sock = user_data;

	sock->priv->read_tag = 0;
	g_signal_emit (sock, signals[READABLE], 0);

	return FALSE;
}

static SoupSocketIOStatus
read_from_network (SoupSocket *sock, gpointer buffer, gsize len, gsize *nread)
{
	GIOStatus status;
	GIOCondition cond = G_IO_IN;
	GError *err = NULL;

	if (!sock->priv->iochannel) 
		return SOUP_SOCKET_EOF;

	status = g_io_channel_read_chars (sock->priv->iochannel,
					  buffer, len, nread, &err);
	if (err) {
		if (err->domain == SOUP_SSL_ERROR &&
		    err->code == SOUP_SSL_ERROR_HANDSHAKE_NEEDS_WRITE)
			cond = G_IO_OUT;
		g_error_free (err);
	}

	switch (status) {
	case G_IO_STATUS_NORMAL:
	case G_IO_STATUS_AGAIN:
		if (*nread > 0)
			return SOUP_SOCKET_OK;

		if (!sock->priv->read_tag) {
			sock->priv->read_tag =
				g_io_add_watch (sock->priv->iochannel, cond,
						socket_read_watch, sock);
		}
		return SOUP_SOCKET_WOULD_BLOCK;

	case G_IO_STATUS_EOF:
		return SOUP_SOCKET_EOF;

	default:
		return SOUP_SOCKET_ERROR;
	}
}

static SoupSocketIOStatus
read_from_buf (SoupSocket *sock, gpointer buffer, gsize len, gsize *nread)
{
	GByteArray *read_buf = sock->priv->read_buf;

	*nread = MIN (read_buf->len, len);
	memcpy (buffer, read_buf->data, *nread);

	if (*nread == read_buf->len) {
		g_byte_array_free (read_buf, TRUE);
		sock->priv->read_buf = NULL;
	} else {
		memmove (read_buf->data, read_buf->data + *nread, 
			 read_buf->len - *nread);
		g_byte_array_set_size (read_buf, read_buf->len - *nread);
	}

	return SOUP_SOCKET_OK;
}

/**
 * soup_socket_read:
 * @sock: the socket
 * @buffer: buffer to read into
 * @len: size of @buffer in bytes
 * @nread: on return, the number of bytes read into @buffer
 *
 * Attempts to read up to @len bytes from @sock into @buffer. If some
 * data is successfully read, soup_socket_read() will return
 * %SOUP_SOCKET_OK, and *@nread will contain the number of bytes
 * actually read.
 *
 * If @sock is non-blocking, and no data is available, the return
 * value will be %SOUP_SOCKET_WOULD_BLOCK. In this case, the caller
 * can connect to the %readable signal to know when there is more data
 * to read. (NB: You MUST read all available data off the socket
 * first. The %readable signal will only be emitted after
 * soup_socket_read() has returned %SOUP_SOCKET_WOULD_BLOCK.)
 *
 * Return value: a #SoupSocketIOStatus, as described above (or
 * %SOUP_SOCKET_EOF if the socket is no longer connected, or
 * %SOUP_SOCKET_ERROR on any other error).
 **/
SoupSocketIOStatus
soup_socket_read (SoupSocket *sock, gpointer buffer, gsize len, gsize *nread)
{
	SoupSocketIOStatus status;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);

	g_mutex_lock (sock->priv->iolock);
	if (sock->priv->read_buf)
		status = read_from_buf (sock, buffer, len, nread);
	else
		status = read_from_network (sock, buffer, len, nread);
	g_mutex_unlock (sock->priv->iolock);

	return status;
}

/**
 * soup_socket_read_until:
 * @sock: the socket
 * @buffer: buffer to read into
 * @len: size of @buffer in bytes
 * @boundary: boundary to read until
 * @boundary_len: length of @boundary in bytes
 * @nread: on return, the number of bytes read into @buffer
 * @got_boundary: on return, whether or not the data in @buffer
 * ends with the boundary string
 *
 * Like soup_socket_read(), but reads no further than the first
 * occurrence of @boundary. (If the boundary is found, it will be
 * included in the returned data, and *@got_boundary will be set to
 * %TRUE.) Any data after the boundary will returned in future reads.
 *
 * Return value: as for soup_socket_read()
 **/
SoupSocketIOStatus
soup_socket_read_until (SoupSocket *sock, gpointer buffer, gsize len,
			gconstpointer boundary, gsize boundary_len,
			gsize *nread, gboolean *got_boundary)
{
	SoupSocketIOStatus status;
	GByteArray *read_buf;
	guint match_len, prev_len;
	guint8 *p, *end;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);
	g_return_val_if_fail (len >= boundary_len, SOUP_SOCKET_ERROR);

	g_mutex_lock (sock->priv->iolock);

	*got_boundary = FALSE;

	if (!sock->priv->read_buf)
		sock->priv->read_buf = g_byte_array_new ();
	read_buf = sock->priv->read_buf;

	if (read_buf->len < boundary_len) {
		prev_len = read_buf->len;
		g_byte_array_set_size (read_buf, len);
		status = read_from_network (sock,
					    read_buf->data + prev_len,
					    len - prev_len, nread);
		read_buf->len = prev_len + *nread;

		if (status != SOUP_SOCKET_OK) {
			g_mutex_unlock (sock->priv->iolock);
			return status;
		}
	}

	/* Scan for the boundary */
	end = read_buf->data + read_buf->len;
	for (p = read_buf->data; p <= end - boundary_len; p++) {
		if (!memcmp (p, boundary, boundary_len)) {
			p += boundary_len;
			*got_boundary = TRUE;
			break;
		}
	}

	/* Return everything up to 'p' (which is either just after the
	 * boundary, or @boundary_len - 1 bytes before the end of the
	 * buffer).
	 */
	match_len = p - read_buf->data;
	status = read_from_buf (sock, buffer, MIN (len, match_len), nread);

	g_mutex_unlock (sock->priv->iolock);
	return status;
}

static gboolean
socket_write_watch (GIOChannel *chan, GIOCondition condition, gpointer user_data)
{
	SoupSocket *sock = user_data;

	sock->priv->write_tag = 0;
	g_signal_emit (sock, signals[WRITABLE], 0);

	return FALSE;
}

/**
 * soup_socket_write:
 * @sock: the socket
 * @buffer: data to write
 * @len: size of @buffer, in bytes
 * @nwrote: on return, number of bytes written
 *
 * Attempts to write @len bytes from @buffer to @sock. If some data is
 * successfully written, the resturn status will be
 * %SOUP_SOCKET_SUCCESS, and *@nwrote will contain the number of bytes
 * actually written.
 *
 * If @sock is non-blocking, and no data could be written right away,
 * the return value will be %SOUP_SOCKET_WOULD_BLOCK. In this case,
 * the caller can connect to the %writable signal to know when more
 * data can be written. (NB: %writable is only emitted after a
 * %SOUP_SOCKET_WOULD_BLOCK.)
 *
 * Return value: a #SoupSocketIOStatus, as described above (or
 * %SOUP_SOCKET_EOF or %SOUP_SOCKET_ERROR).
 **/
SoupSocketIOStatus
soup_socket_write (SoupSocket *sock, gconstpointer buffer,
		   gsize len, gsize *nwrote)
{
	GIOStatus status;
	gpointer pipe_handler;
	GIOCondition cond = G_IO_OUT;
	GError *err = NULL;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);

	g_mutex_lock (sock->priv->iolock);

	if (!sock->priv->iochannel) {
		g_mutex_unlock (sock->priv->iolock);
		return SOUP_SOCKET_EOF;
	}
	if (sock->priv->write_tag) {
		g_mutex_unlock (sock->priv->iolock);
		return SOUP_SOCKET_WOULD_BLOCK;
	}

	pipe_handler = signal (SIGPIPE, SIG_IGN);
	status = g_io_channel_write_chars (sock->priv->iochannel,
					   buffer, len, nwrote, &err);
	signal (SIGPIPE, pipe_handler);
	if (err) {
		if (err->domain == SOUP_SSL_ERROR &&
		    err->code == SOUP_SSL_ERROR_HANDSHAKE_NEEDS_READ)
			cond = G_IO_IN;
		g_error_free (err);
	}

	if (status != G_IO_STATUS_NORMAL && status != G_IO_STATUS_AGAIN) {
		g_mutex_unlock (sock->priv->iolock);
		return SOUP_SOCKET_ERROR;
	}

	if (*nwrote) {
		g_mutex_unlock (sock->priv->iolock);
		return SOUP_SOCKET_OK;
	}

	sock->priv->write_tag =
		g_io_add_watch (sock->priv->iochannel, cond, 
				socket_write_watch, sock);
	g_mutex_unlock (sock->priv->iolock);
	return SOUP_SOCKET_WOULD_BLOCK;
}
