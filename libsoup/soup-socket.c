/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Platform neutral socket networking code.
 *
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@ximian.com)
 *
 * Original code compliments of David Helder's GNET Networking Library, and is
 * Copyright (C) 2000  David Helder & Andrew Lanoix.
 *
 * All else Copyright (C) 2000, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>

#include "soup-private.h"
#include "soup-socket.h"

#include <unistd.h>
#ifndef socklen_t
#  define socklen_t size_t
#endif

typedef struct {
	SoupSocketConnectFn  func;
	gpointer             data;
	guint                port;

	gpointer             inetaddr_id;
	gpointer             tcp_id;
} SoupSocketConnectState;

static void
soup_socket_connect_tcp_cb (SoupSocket* socket,
			    SoupSocketConnectStatus status,
			    gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;
	SoupSocketConnectFn func = state->func;
	gpointer user_data = state->data;

	if (status == SOUP_SOCKET_NEW_STATUS_OK)
		(*func) (socket,
			 SOUP_SOCKET_CONNECT_ERROR_NONE,
			 user_data);
	else
		(*func) (NULL,
			 SOUP_SOCKET_CONNECT_ERROR_NETWORK,
			 user_data);

	if (state->tcp_id)
		g_free (state);
}

static void
soup_socket_connect_inetaddr_cb (SoupAddress* inetaddr,
				 SoupAddressStatus status,
				 gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;

	if (status == SOUP_ADDRESS_STATUS_OK) {
		state->tcp_id = soup_socket_new (inetaddr, state->port,
						 soup_socket_connect_tcp_cb,
						 state);
		soup_address_unref (inetaddr);
	} else {
		SoupSocketConnectFn func = state->func;
		gpointer user_data = state->data;

		(*func) (NULL, 
			 SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE, 
			 user_data);
	}

	if (state->inetaddr_id && !state->tcp_id)
		g_free (state);
	else
		state->inetaddr_id = NULL;
}

/**
 * soup_socket_connect:
 * @hostname: Name of host to connect to
 * @port: Port to connect to
 * @func: Callback function
 * @data: User data passed when callback function is called.
 *
 * A quick and easy non-blocking #SoupSocket constructor.  This
 * connects to the specified address and port and then calls the
 * callback with the data.  Use this function when you're a client
 * connecting to a server and you don't want to block or mess with
 * #SoupAddress's.  It may call the callback before the function
 * returns.  It will call the callback if there is a failure.
 *
 * Returns: ID of the connection which can be used with
 * soup_socket_connect_cancel() to cancel it; NULL if it succeeds
 * or fails immediately.
 **/
SoupSocketConnectId
soup_socket_connect (const gchar*        hostname,
		     const gint          port,
		     SoupSocketConnectFn func,
		     gpointer            data)
{
	SoupSocketConnectState* state;
	SoupAddress *cached_addr;

	g_return_val_if_fail (hostname != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	state = g_new0 (SoupSocketConnectState, 1);
	state->func = func;
	state->data = data;
	state->port = port;

	state->inetaddr_id = soup_address_new (hostname,
					       soup_socket_connect_inetaddr_cb,
					       state);
	/* NOTE: soup_address_new could succeed immediately
	 * and call our callback, in which case state->inetaddr_id
	 * will be NULL but state->tcp_id may be set.
	 */

	if (state->tcp_id || state->inetaddr_id)
		return state;
	else {
		g_free (state);
		return NULL;
	}
}

/**
 * soup_socket_connect_cancel:
 * @id: Id of the connection.
 *
 * Cancel an asynchronous connection that was started with
 * soup_socket_connect().
 */
void
soup_socket_connect_cancel (SoupSocketConnectId id)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) id;

	g_return_if_fail (state != NULL);

	if (state->inetaddr_id)
		soup_address_new_cancel (state->inetaddr_id);
	else if (state->tcp_id)
		soup_socket_new_cancel (state->tcp_id);

	g_free (state);
}

static void
soup_socket_connect_sync_cb (SoupSocket              *socket,
			     SoupSocketConnectStatus  status,
			     gpointer                 data)
{
	SoupSocket **ret = data;
	*ret = socket;
}

SoupSocket *
soup_socket_connect_sync (const gchar *name,
			  const gint   port)
{
	SoupSocket *ret = (SoupSocket *) 0xdeadbeef;

	soup_socket_connect (name, port, soup_socket_connect_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupSocket *) 0xdeadbeef) return ret;
	}

	return ret;
}

static void
soup_socket_new_sync_cb (SoupSocket*         socket,
			 SoupSocketNewStatus status,
			 gpointer            data)
{
	SoupSocket **ret = data;
	*ret = socket;
}

SoupSocket *
soup_socket_new_sync (SoupAddress *addr, guint port)
{
	SoupSocket *ret = (SoupSocket *) 0xdeadbeef;

	soup_socket_new (addr, port, soup_socket_new_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupSocket *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_socket_ref
 * @s: SoupSocket to reference
 *
 * Increment the reference counter of the SoupSocket.
 **/
void
soup_socket_ref (SoupSocket* s)
{
	g_return_if_fail (s != NULL);

	++s->ref_count;
}

/**
 * soup_socket_unref
 * @s: #SoupSocket to unreference
 *
 * Remove a reference from the #SoupSocket.  When reference count
 * reaches 0, the socket is deleted.
 **/
void
soup_socket_unref (SoupSocket* s)
{
	g_return_if_fail(s != NULL);

	--s->ref_count;

	if (s->ref_count == 0) {
		close (s->sockfd);
		if (s->addr) soup_address_unref (s->addr);
		if (s->iochannel) g_io_channel_unref (s->iochannel);

		g_free(s);
	}
}

/**
 * soup_socket_get_iochannel:
 * @socket: SoupSocket to get GIOChannel from.
 *
 * Get the #GIOChannel for the #SoupSocket.
 *
 * For a client socket, the #GIOChannel represents the data stream.
 * Use it like you would any other #GIOChannel.
 *
 * For a server socket however, the #GIOChannel represents incoming
 * connections.  If you can read from it, there's a connection
 * waiting.
 *
 * There is one channel for every socket.  This function refs the
 * channel before returning it.  You should unref the channel when
 * you are done with it.  However, you should not close the channel -
 * this is done when you delete the socket.
 *
 * Returns: A #GIOChannel; NULL on failure.
 *
 **/
GIOChannel*
soup_socket_get_iochannel (SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, NULL);

	if (socket->iochannel == NULL)
		socket->iochannel = g_io_channel_unix_new (socket->sockfd);

	g_io_channel_ref (socket->iochannel);

	return socket->iochannel;
}

/**
 * soup_socket_get_address:
 * @socket: #SoupSocket to get address of.
 *
 * Get the address of the socket.  If the socket is connected to a
 * remote machine (as a client or server), the address will be the
 * address of that machine. If it is a listening socket, the address
 * will be %NULL.
 *
 * Returns: #SoupAddress of socket; NULL on failure.
 **/
SoupAddress *
soup_socket_get_address (const SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, NULL);
	g_return_val_if_fail (socket->addr != NULL, NULL);

	soup_address_ref (socket->addr);

	return socket->addr;
}

/**
 * soup_socket_get_port:
 * @socket: SoupSocket to get the port number of.
 *
 * Get the port number the socket is bound to.
 *
 * Returns: Port number of the socket.
 **/
gint
soup_socket_get_port(const SoupSocket* socket)
{
	g_return_val_if_fail (socket != NULL, 0);

	return socket->port;
}

/**
 * soup_socket_server_new:
 * @local_addr: Local address to bind to. (soup_address_ipv4_any() to
 * accept connections on any local IPv4 address)
 * @local_port: Port number for the socket (SOUP_SERVER_ANY_PORT if you
 * don't care).
 *
 * Create and open a new #SoupSocket listening on the specified
 * address and port. Use this sort of socket when your are a server
 * and you know what the port number should be (or pass 0 if you don't
 * care what the port is).
 *
 * Returns: a new #SoupSocket, or NULL if there was a failure.
 **/
SoupSocket *
soup_socket_server_new (SoupAddress *local_addr, guint local_port)
{
	SoupSocket* s;
	struct sockaddr *sa = NULL;
	struct soup_sockaddr_max bound_sa;
	int sa_len;
	const int on = 1;
	gint flags;

	g_return_val_if_fail (local_addr != NULL, NULL);

	/* Create an appropriate sockaddr */
	soup_address_make_sockaddr (local_addr, local_port, &sa, &sa_len);

	/* Create socket */
	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;

	if ((s->sockfd = socket (sa->sa_family, SOCK_STREAM, 0)) < 0) {
		g_free (s);
		g_free (sa);
		return NULL;
	}

	/* Set REUSEADDR so we can reuse the port */
	if (setsockopt (s->sockfd,
			SOL_SOCKET,
			SO_REUSEADDR,
			&on,
			sizeof (on)) != 0)
		g_warning("Can't set reuse on tcp socket\n");

	/* Get the flags (should all be 0?) */
	flags = fcntl (s->sockfd, F_GETFL, 0);
	if (flags == -1) goto SETUP_ERROR;

	/* Make the socket non-blocking */
	if (fcntl (s->sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
		goto SETUP_ERROR;

	/* Bind */
	if (bind (s->sockfd, sa, sa_len) != 0)
		goto SETUP_ERROR;
	g_free (sa);

	sa_len = sizeof (bound_sa);
	getsockname (s->sockfd, (struct sockaddr *)&bound_sa, &sa_len); 
	s->addr = soup_address_new_from_sockaddr ((struct sockaddr *)&bound_sa,
						  &s->port);

	/* Listen */
	if (listen (s->sockfd, 10) != 0) goto SETUP_ERROR;

	return s;

 SETUP_ERROR:
	close (s->sockfd);
	g_free (s);
	g_free (sa);
	return NULL;
}


#define SOUP_ANY_IO_CONDITION  (G_IO_IN | G_IO_OUT | G_IO_PRI | \
                                G_IO_ERR | G_IO_HUP | G_IO_NVAL)

typedef struct {
	gint             sockfd;
	SoupAddress     *addr;
	guint            port;
	SoupSocketNewFn  func;
	gpointer         data;
	gint             flags;
	guint            connect_watch;
} SoupSocketState;

static gboolean
soup_socket_new_cb (GIOChannel* iochannel,
		    GIOCondition condition,
		    gpointer data)
{
	SoupSocketState* state = (SoupSocketState*) data;
	SoupSocket* s;
	gint error = 0;
	gint len = sizeof (gint);

	/* Remove the watch now in case we don't return immediately */
	g_source_remove (state->connect_watch);

	if (condition & ~(G_IO_IN | G_IO_OUT)) goto ERROR;

	errno = 0;
	if (getsockopt (state->sockfd,
			SOL_SOCKET,
			SO_ERROR,
			&error,
			&len) != 0) goto ERROR;

	if (error) goto ERROR;

	if (fcntl (state->sockfd, F_SETFL, state->flags) != 0)
		goto ERROR;

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = state->sockfd;
	s->addr = state->addr;
	s->port = state->port;

	(*state->func) (s, SOUP_SOCKET_NEW_STATUS_OK, state->data);

	g_free (state);

	return FALSE;

 ERROR:
	soup_address_unref (state->addr);
	(*state->func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, state->data);
	g_free (state);

	return FALSE;
}

/**
 * soup_socket_new:
 * @addr: Address to connect to.
 * @port: Port to connect to
 * @func: Callback function.
 * @data: User data passed when callback function is called.
 *
 * Connect to a specifed address asynchronously.  When the connection
 * is complete or there is an error, it will call the callback.  It
 * may call the callback before the function returns.  It will call
 * the callback if there is a failure.
 *
 * Returns: ID of the connection which can be used with
 * soup_socket_connect_cancel() to cancel it; NULL on
 * failure.
 **/
SoupSocketNewId
soup_socket_new (SoupAddress      *addr,
		 guint             port,
		 SoupSocketNewFn   func,
		 gpointer          data)
{
	gint sockfd;
	gint flags;
	SoupSocketState* state;
	GIOChannel *chan;
	struct sockaddr *sa;
	int len;

	g_return_val_if_fail(addr != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	/* Create socket */
	soup_address_make_sockaddr (addr, port, &sa, &len);
	sockfd = socket (sa->sa_family, SOCK_STREAM, 0);
	if (sockfd < 0) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		g_free (sa);
		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		g_free (sa);
		return NULL;
	}

	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		g_free (sa);
		return NULL;
	}

	errno = 0;

	/* Connect (but non-blocking!) */
	if (connect (sockfd, sa, len) < 0 && errno != EINPROGRESS) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		g_free (sa);
		return NULL;
	}
	g_free (sa);

	/* Unref in soup_socket_new_cb if failure */
	soup_address_ref (addr);

	/* Connect succeeded, return immediately */
	if (!errno) {
		SoupSocket *s = g_new0 (SoupSocket, 1);
		s->ref_count = 1;
		s->sockfd = sockfd;
		s->addr = addr;

		(*func) (s, SOUP_SOCKET_NEW_STATUS_OK, data);
		return NULL;
	}

	chan = g_io_channel_unix_new (sockfd);

	/* Wait for the connection */
	state = g_new0 (SoupSocketState, 1);
	state->sockfd = sockfd;
	state->addr = addr;
	state->port = port;
	state->func = func;
	state->data = data;
	state->flags = flags;
	state->connect_watch = g_io_add_watch (chan,
					       SOUP_ANY_IO_CONDITION,
					       soup_socket_new_cb,
					       state);

	g_io_channel_unref (chan);

	return state;
}

/**
 * soup_socket_new_cancel:
 * @id: ID of the connection.
 *
 * Cancel an asynchronous connection that was started with
 * soup_socket_new().
 **/
void
soup_socket_new_cancel (SoupSocketNewId id)
{
	SoupSocketState* state = (SoupSocketState*) id;

	g_source_remove (state->connect_watch);
	soup_address_unref (state->addr);
	g_free (state);
}

static SoupSocket *
server_accept_internal (SoupSocket *socket, gboolean block)
{
	int sockfd;
	int flags;
	struct soup_sockaddr_max sa;
	socklen_t n;
	fd_set fdset;
	SoupSocket* s;

	g_return_val_if_fail (socket != NULL, NULL);

 try_again:
	FD_ZERO (&fdset);
	FD_SET (socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, NULL) == -1) {
		if (errno == EINTR) goto try_again;
		return NULL;
	}

	n = sizeof(sa);

	if ((sockfd = accept (socket->sockfd, (struct sockaddr *)&sa, &n)) == -1) {
		if (!block)
			return NULL;
		if (errno == EWOULDBLOCK ||
		    errno == ECONNABORTED ||
#ifdef EPROTO		/* OpenBSD does not have EPROTO */
		    errno == EPROTO ||
#endif
		    errno == EINTR)
			goto try_again;

		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) return NULL;

	/* Make the socket non-blocking */
	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
		return NULL;

	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;
	s->sockfd = sockfd;
	s->addr = soup_address_new_from_sockaddr ((struct sockaddr *)&sa,
						  &s->port);

	return s;
}

/**
 * soup_socket_server_accept:
 * @socket: #SoupSocket to accept connections from.
 *
 * Accept a connection from the socket.  The socket must have been
 * created using soup_socket_server_new().  This function will
 * block (use soup_socket_server_try_accept() if you don't
 * want to block).  If the socket's #GIOChannel is readable, it DOES
 * NOT mean that this function will not block.
 *
 * Returns: a new #SoupSocket if there is another connect, or NULL if
 * there's an error.
 **/
SoupSocket *
soup_socket_server_accept (SoupSocket *socket)
{
	return server_accept_internal (socket, TRUE);
}

/**
 * soup_socket_server_try_accept:
 * @socket: SoupSocket to accept connections from.
 *
 * Accept a connection from the socket without blocking.  The socket
 * must have been created using soup_socket_server_new().  This
 * function is best used with the sockets #GIOChannel.  If the
 * channel is readable, then you PROBABLY have a connection.  It is
 * possible for the connection to close by the time you call this, so
 * it may return NULL even if the channel was readable.
 *
 * Returns a new SoupSocket if there is another connect, or NULL
 * otherwise.
 **/
SoupSocket *
soup_socket_server_try_accept (SoupSocket *socket)
{
	return server_accept_internal (socket, FALSE);
}
