/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Socket networking code.
 *
 * Based on code in David Helder's GNET Networking Library,
 * Copyright (C) 2000  David Helder & Andrew Lanoix.
 *
 * All else Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "soup-private.h"
#include "soup-socket.h"
#include "soup-marshal.h"
#include "soup-ssl.h"

#include <sys/socket.h>
#include <netinet/tcp.h>

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	CONNECT_RESULT,
	NEW_CONNECTION,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct SoupSocketPrivate {
	int sockfd;
	SoupAddress *local_addr, *remote_addr;
	GIOChannel *iochannel;

	guint watch;
	gboolean server, ssl;
};

static void
init (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	sock->priv = g_new0 (SoupSocketPrivate, 1);
	sock->priv->sockfd = -1;
}

static void
finalize (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);

	if (sock->priv->local_addr)
		g_object_unref (sock->priv->local_addr);
	if (sock->priv->remote_addr)
		g_object_unref (sock->priv->remote_addr);

	if (sock->priv->iochannel)
		g_io_channel_unref (sock->priv->iochannel);

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

#define SOUP_SOCKET_NONBLOCKING (1<<0)
#define SOUP_SOCKET_NONBUFFERED (1<<1)
#define SOUP_SOCKET_REUSEADDR   (1<<2)

static void
soup_set_sockopts (int sockfd, int opts)
{
	int flags;

	if (opts & SOUP_SOCKET_NONBLOCKING) {
		flags = fcntl (sockfd, F_GETFL, 0);
		if (flags != -1)
			fcntl (sockfd, F_SETFL, flags | O_NONBLOCK);
	}

	if (opts & SOUP_SOCKET_NONBUFFERED) {
		flags = 1;
		setsockopt (sockfd, IPPROTO_TCP, TCP_NODELAY,
			    &flags, sizeof (flags));
	}

	if (opts & SOUP_SOCKET_REUSEADDR) {
		flags = 1;
		setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR,
			    &flags, sizeof (flags));
	}
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

	if (sock->priv->ssl)
		soup_socket_start_ssl (sock);

	g_signal_emit (sock, signals[CONNECT_RESULT], 0, SOUP_ERROR_OK);
	return FALSE;

 cant_connect:
	g_signal_emit (sock, signals[CONNECT_RESULT], 0, SOUP_ERROR_CANT_CONNECT);
	return FALSE;
}

static gboolean
idle_connect_result (gpointer user_data)
{
	SoupSocket *sock = user_data;

	sock->priv->watch = 0;

	g_signal_emit (sock, signals[CONNECT_RESULT], 0,
		       sock->priv->sockfd != -1 ? SOUP_ERROR_OK : SOUP_ERROR_CANT_CONNECT);
	return FALSE;
}

static void
got_address (SoupAddress *addr, SoupKnownErrorCode status, gpointer user_data)
{
	SoupSocket *sock = user_data;

	if (!SOUP_ERROR_IS_SUCCESSFUL (status)) {
		g_signal_emit (sock, signals[CONNECT_RESULT], 0, status);
		return;
	}

	soup_socket_connect (sock, addr);
	/* soup_socket_connect re-reffed addr */
	g_object_unref (addr);
}

/**
 * soup_socket_connect:
 * @sock: a #SoupSocket (which must not be connected or listening)
 * @remote_addr: address to connect to
 *
 * Starts connecting to the indicated remote address and port. The
 * socket will emit %connect_result when it succeeds or fails (but
 * not before returning from this function).
 **/
void
soup_socket_connect (SoupSocket *sock, SoupAddress *remote_addr)
{
	struct sockaddr *sa = NULL;
	int len, status;

	g_return_if_fail (SOUP_IS_SOCKET (sock));
	g_return_if_fail (SOUP_IS_ADDRESS (remote_addr));
	g_return_if_fail (sock->priv->sockfd == -1);

	sock->priv->remote_addr = g_object_ref (remote_addr);
	sa = soup_address_get_sockaddr (sock->priv->remote_addr, &len);
	if (!sa) {
		soup_address_resolve (sock->priv->remote_addr,
				      got_address, sock);
		return;
	}

	sock->priv->sockfd = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sock->priv->sockfd < 0)
		goto cant_connect;
	soup_set_sockopts (sock->priv->sockfd,
			   SOUP_SOCKET_NONBLOCKING | SOUP_SOCKET_NONBUFFERED);

	/* Connect (non-blocking) */
	status = connect (sock->priv->sockfd, sa, len);
	g_free (sa);
	sa = NULL;

	if (status == 0) {
		/* Connect already succeeded */
		sock->priv->watch = g_idle_add (idle_connect_result, sock);
		return;
	}
	if (errno != EINPROGRESS)
		goto cant_connect;

	soup_socket_get_iochannel (sock);
	sock->priv->watch = g_io_add_watch (sock->priv->iochannel,
					    (G_IO_IN | G_IO_OUT | G_IO_PRI |
					     G_IO_ERR | G_IO_HUP | G_IO_NVAL),
					    connect_watch, sock);
	return;

 cant_connect: 
	if (sa)
		g_free (sa);
	if (sock->priv->sockfd != -1) {
		close (sock->priv->sockfd);
		sock->priv->sockfd = -1;
	}
	sock->priv->watch = g_idle_add (idle_connect_result, sock);
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

	soup_set_sockopts (sockfd,
			   SOUP_SOCKET_NONBLOCKING | SOUP_SOCKET_NONBUFFERED);

	new = soup_socket_new ();
	new->priv->sockfd = sockfd;
	new->priv->remote_addr = soup_address_new_from_sockaddr ((struct sockaddr *)&sa, sa_len);

	new->priv->server = TRUE;
	if (sock->priv->ssl) {
		new->priv->ssl = TRUE;
		soup_socket_start_ssl (new);
	}

	g_signal_emit (sock, signals[NEW_CONNECTION], 0, new);
	g_object_unref (new);

	return TRUE;
}

/**
 * soup_socket_listen:
 * @sock: a #SoupSocket (which must not be connected or listening)
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
	g_return_val_if_fail (SOUP_IS_ADDRESS (local_addr), FALSE);
	g_return_val_if_fail (sock->priv->sockfd == -1, FALSE);

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
	soup_set_sockopts (sock->priv->sockfd,
			   SOUP_SOCKET_NONBLOCKING | SOUP_SOCKET_REUSEADDR);

	/* Bind */
	if (bind (sock->priv->sockfd, sa, sa_len) != 0)
		goto cant_listen;

	/* Listen */
	if (listen (sock->priv->sockfd, 10) != 0)
		goto cant_listen;

	sock->priv->server = TRUE;

	soup_socket_get_iochannel (sock);
	sock->priv->watch = g_io_add_watch (sock->priv->iochannel,
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

	chan = soup_socket_get_iochannel (sock);
	sock->priv->iochannel = sock->priv->server ?
		soup_ssl_get_server_iochannel (chan) :
		soup_ssl_get_iochannel (chan);
	sock->priv->ssl = TRUE;
}
	

/**
 * soup_socket_client_new:
 * @hostname: remote machine to connect to
 * @port: remote port to connect to
 * @ssl: whether or not to use SSL
 * @callback: callback to call when the socket is connected
 * @user_data: data for @callback
 *
 * Creates a connection to @uri. @callback will be called when the
 * connection completes (or fails).
 *
 * Return value: the new socket (not yet ready for use).
 **/
SoupSocket *
soup_socket_client_new (const char *hostname, guint port, gboolean ssl,
			SoupSocketCallback callback, gpointer user_data)
{
	SoupSocket *sock;

	g_return_val_if_fail (hostname != NULL, NULL);

	sock = soup_socket_new ();
	sock->priv->ssl = ssl;
	soup_socket_connect (sock, soup_address_new (hostname, port));

	if (callback) {
		soup_signal_connect_once (sock, "connect_result",
					  G_CALLBACK (callback), user_data);
	}
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
	sock->priv->ssl = ssl;

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


/**
 * soup_socket_get_iochannel:
 * @sock: #SoupSocket to get #GIOChannel from.
 *
 * Get the #GIOChannel for the #SoupSocket.
 *
 * If you ref the iochannel, it will remain valid after @sock is
 * destroyed.
 *
 * Returns: A #GIOChannel; %NULL on failure.
 **/
GIOChannel *
soup_socket_get_iochannel (SoupSocket *sock)
{
	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	if (!sock->priv->iochannel) {
		sock->priv->iochannel =
			g_io_channel_unix_new (sock->priv->sockfd);
		g_io_channel_set_close_on_unref (sock->priv->iochannel, TRUE);
	}
	return sock->priv->iochannel;
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
