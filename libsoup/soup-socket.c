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
#include "soup-private.h"
#include "soup-socket.h"
#include "soup-marshal.h"
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

struct SoupSocketPrivate {
	int sockfd;
	SoupAddress *local_addr, *remote_addr;
	GIOChannel *iochannel;

	guint watch;
	guint flags;

	guint           read_tag, write_tag, error_tag;
	GByteArray     *read_buf;
};

#define SOUP_SOCKET_FLAG_SSL    (1<<8)

#define SOUP_SOCKET_SET_FLAG(sock, flag) (sock)->priv->flags |= (flag)
#define SOUP_SOCKET_CLEAR_FLAG(sock, flag) (sock)->priv->flags &= ~(flag)
#define SOUP_SOCKET_CHECK_FLAG(sock, flag) ((sock)->priv->flags & (flag))

static void
init (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	sock->priv = g_new0 (SoupSocketPrivate, 1);
	sock->priv->sockfd = -1;
}

static void
disconnect_internal (SoupSocket *sock)
{
	g_io_channel_unref (sock->priv->iochannel);
	sock->priv->iochannel = NULL;

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

	g_free (sock->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;

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
}

SOUP_MAKE_TYPE (soup_socket, SoupSocket, class_init, init, PARENT_TYPE)


/**
 * soup_socket_new:
 *
 * Return value: a new (disconnected) socket
 **/
SoupSocket *
soup_socket_new (void)
{
	return g_object_new (SOUP_TYPE_SOCKET, NULL);
}

static void
update_fdflags (SoupSocket *sock, guint mask)
{
	int flags, opt;

	if (mask & SOUP_SOCKET_FLAG_NONBLOCKING) {
		flags = fcntl (sock->priv->sockfd, F_GETFL, 0);
		g_return_if_fail (flags != -1);

		if (sock->priv->flags & SOUP_SOCKET_FLAG_NONBLOCKING)
			flags |= O_NONBLOCK;
		else
			flags &= ~O_NONBLOCK;
		fcntl (sock->priv->sockfd, F_SETFL, flags);
	}
	if (mask & SOUP_SOCKET_FLAG_NODELAY) {
		opt = (sock->priv->flags & SOUP_SOCKET_FLAG_NODELAY) != 0;
		setsockopt (sock->priv->sockfd, IPPROTO_TCP,
			    TCP_NODELAY, &opt, sizeof (opt));
	}
	if (mask & SOUP_SOCKET_FLAG_REUSEADDR) {
		opt = (sock->priv->flags & SOUP_SOCKET_FLAG_REUSEADDR) != 0;
		setsockopt (sock->priv->sockfd, SOL_SOCKET,
			    SO_REUSEADDR, &opt, sizeof (opt));
	}
}

void
soup_socket_set_flags (SoupSocket *sock, guint mask, guint flags)
{
	g_return_if_fail (SOUP_IS_SOCKET (sock));

	sock->priv->flags |= mask & flags;
	sock->priv->flags &= ~(mask & ~flags);

	if (sock->priv->sockfd)
		update_fdflags (sock, mask);
}

static GIOChannel *
get_iochannel (SoupSocket *sock)
{
	if (!sock->priv->iochannel) {
		sock->priv->iochannel =
			g_io_channel_unix_new (sock->priv->sockfd);
		g_io_channel_set_close_on_unref (sock->priv->iochannel, TRUE);
		g_io_channel_set_encoding (sock->priv->iochannel, NULL, NULL);
		g_io_channel_set_buffered (sock->priv->iochannel, FALSE);
	}
	return sock->priv->iochannel;
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

	if (SOUP_SOCKET_CHECK_FLAG (sock, SOUP_SOCKET_FLAG_SSL))
		soup_socket_start_ssl (sock);

	g_signal_emit (sock, signals[CONNECT_RESULT], 0, SOUP_STATUS_OK);
	return FALSE;

 cant_connect:
	g_signal_emit (sock, signals[CONNECT_RESULT], 0, SOUP_STATUS_CANT_CONNECT);
	return FALSE;
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

static void
got_address (SoupAddress *addr, guint status, gpointer user_data)
{
	SoupSocket *sock = user_data;

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		g_signal_emit (sock, signals[CONNECT_RESULT], 0, status);
		return;
	}

	soup_socket_connect (sock, sock->priv->remote_addr);
	/* soup_socket_connect re-reffed addr */
	g_object_unref (addr);
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
	gboolean sync;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (!SOUP_SOCKET_CHECK_FLAG (sock, SOUP_SOCKET_FLAG_SERVER), FALSE);
	g_return_val_if_fail (sock->priv->sockfd == -1, SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (SOUP_IS_ADDRESS (remote_addr), SOUP_STATUS_MALFORMED);

	sync = !(sock->priv->flags & SOUP_SOCKET_FLAG_NONBLOCKING);

	sock->priv->remote_addr = g_object_ref (remote_addr);
	if (sync) {
		status = soup_address_resolve_sync (remote_addr);
		if (!SOUP_STATUS_IS_SUCCESSFUL (status))
			return status;
	}

	sa = soup_address_get_sockaddr (sock->priv->remote_addr, &len);
	if (!sa) {
		if (sync)
			return SOUP_STATUS_CANT_RESOLVE;

		soup_address_resolve_async (remote_addr, got_address, sock);
		return SOUP_STATUS_CONTINUE;
	}

	sock->priv->sockfd = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sock->priv->sockfd == -1) {
		g_free (sa);
		goto done;
	}
	update_fdflags (sock, SOUP_SOCKET_FLAG_ALL);

	status = connect (sock->priv->sockfd, sa, len);
	g_free (sa);

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
	if (sync) {
		return sock->priv->sockfd != -1 ?
			SOUP_STATUS_OK : SOUP_STATUS_CANT_CONNECT;
	} else {
		sock->priv->watch = g_idle_add (idle_connect_result, sock);
		return SOUP_STATUS_CONTINUE;
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

	new = soup_socket_new ();
	new->priv->sockfd = sockfd;
	new->priv->flags = (SOUP_SOCKET_FLAG_NONBLOCKING |
			    SOUP_SOCKET_FLAG_NODELAY |
			    SOUP_SOCKET_FLAG_SERVER |
			    (sock->priv->flags & SOUP_SOCKET_FLAG_SSL));
	update_fdflags (new, SOUP_SOCKET_FLAG_ALL);

	new->priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&sa, sa_len);

	if (SOUP_SOCKET_CHECK_FLAG (new, SOUP_SOCKET_FLAG_SSL))
		soup_socket_start_ssl (new);
	else
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
	g_return_val_if_fail (SOUP_SOCKET_CHECK_FLAG (sock, SOUP_SOCKET_FLAG_SERVER), FALSE);
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
	update_fdflags (sock, SOUP_SOCKET_FLAG_ALL);

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
	if (sa)
		g_free (sa);
	return FALSE;
}

/**
 * soup_socket_start_ssl:
 * @socket: the socket
 *
 * Starts using SSL on @socket.
 **/
void
soup_socket_start_ssl (SoupSocket *sock)
{
	GIOChannel *chan;

	chan = get_iochannel (sock);
	sock->priv->iochannel =
		SOUP_SOCKET_CHECK_FLAG (sock, SOUP_SOCKET_FLAG_SERVER) ?
		soup_ssl_get_server_iochannel (chan) :
		soup_ssl_get_iochannel (chan);
	SOUP_SOCKET_SET_FLAG (sock, SOUP_SOCKET_FLAG_SSL);
}
	

/**
 * soup_socket_client_new_async:
 * @hostname: remote machine to connect to
 * @port: remote port to connect to
 * @ssl: whether or not to use SSL
 * @callback: callback to call when the socket is connected
 * @user_data: data for @callback
 *
 * Creates a connection to @hostname and @port. @callback will be
 * called when the connection completes (or fails).
 *
 * Return value: the new socket (not yet ready for use).
 **/
SoupSocket *
soup_socket_client_new_async (const char *hostname, guint port, gboolean ssl, 
			      SoupSocketCallback callback, gpointer user_data)
{
	SoupSocket *sock;

	g_return_val_if_fail (hostname != NULL, NULL);

	sock = soup_socket_new ();
	sock->priv->flags = (SOUP_SOCKET_FLAG_NONBLOCKING |
			     (ssl ? SOUP_SOCKET_FLAG_SSL : 0));
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
 * @ssl: whether or not to use SSL
 * @status_ret: pointer to return the soup status in
 *
 * Creates a connection to @hostname and @port. If @status_ret is not
 * %NULL, it will contain a status code on return.
 *
 * Return value: the new socket, or %NULL if it could not connect.
 **/
SoupSocket *
soup_socket_client_new_sync (const char *hostname, guint port, gboolean ssl,
			     guint *status_ret)
{
	SoupSocket *sock;
	guint status;

	g_return_val_if_fail (hostname != NULL, NULL);

	sock = soup_socket_new ();
	sock->priv->flags = ssl ? SOUP_SOCKET_FLAG_SSL : 0;
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
 * @ssl: Whether or not this is an SSL server.
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
soup_socket_server_new (SoupAddress *local_addr, gboolean ssl,
			SoupSocketListenerCallback callback,
			gpointer user_data)
{
	SoupSocket *sock;

	g_return_val_if_fail (SOUP_IS_ADDRESS (local_addr), NULL);

	sock = soup_socket_new ();
	sock->priv->flags = (SOUP_SOCKET_FLAG_SERVER |
			     SOUP_SOCKET_FLAG_NONBLOCKING |
			     (ssl ? SOUP_SOCKET_FLAG_SSL : 0));
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
	g_return_if_fail (SOUP_IS_SOCKET (sock));

	if (!sock->priv->iochannel)
		return;

	disconnect_internal (sock);

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

	if (!sock->priv->local_addr) {
		struct soup_sockaddr_max bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getsockname (sock->priv->sockfd, (struct sockaddr *)&bound_sa, &sa_len);
		sock->priv->local_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}

	return sock->priv->local_addr;
}

SoupAddress *
soup_socket_get_remote_address (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	if (!sock->priv->local_addr) {
		struct soup_sockaddr_max bound_sa;
		int sa_len;

		sa_len = sizeof (bound_sa);
		getpeername (sock->priv->sockfd, (struct sockaddr *)&bound_sa, &sa_len);
		sock->priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa, sa_len);
	}

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

	if (!sock->priv->iochannel)
		return SOUP_SOCKET_EOF;

	status = g_io_channel_read_chars (sock->priv->iochannel,
					  buffer, len, nread, NULL);
	switch (status) {
	case G_IO_STATUS_NORMAL:
	case G_IO_STATUS_AGAIN:
		if (*nread > 0)
			return SOUP_SOCKET_OK;

		if (!sock->priv->read_tag) {
			sock->priv->read_tag =
				g_io_add_watch (sock->priv->iochannel, G_IO_IN,
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
		memcpy (read_buf->data, read_buf->data + *nread, 
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
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);

	if (sock->priv->read_buf)
		return read_from_buf (sock, buffer, len, nread);
	else
		return read_from_network (sock, buffer, len, nread);
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

		if (status != SOUP_SOCKET_OK)
			return status;
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
	return read_from_buf (sock, buffer, MIN (len, match_len), nread);
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
 * @nwrite: on return, number of bytes written
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

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), SOUP_SOCKET_ERROR);

	if (!sock->priv->iochannel)
		return SOUP_SOCKET_EOF;
	if (sock->priv->write_tag)
		return SOUP_SOCKET_WOULD_BLOCK;

	pipe_handler = signal (SIGPIPE, SIG_IGN);
	status = g_io_channel_write_chars (sock->priv->iochannel,
					   buffer, len, nwrote, NULL);
	signal (SIGPIPE, pipe_handler);
	if (status != G_IO_STATUS_NORMAL && status != G_IO_STATUS_AGAIN)
		return SOUP_SOCKET_ERROR;

	if (*nwrote)
		return SOUP_SOCKET_OK;

	sock->priv->write_tag =
		g_io_add_watch (sock->priv->iochannel, G_IO_OUT,
				socket_write_watch, sock);
	return SOUP_SOCKET_WOULD_BLOCK;
}
