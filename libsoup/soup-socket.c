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

#define SOUP_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))

typedef struct {
	SoupSocketConnectFn  func;
	gpointer             data;

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
		state->tcp_id = soup_socket_new (inetaddr,
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

	/* Check if a cached version of the address already exists */
	cached_addr = soup_address_lookup_in_cache (hostname, port);
	if (cached_addr) {
		state->tcp_id = soup_socket_new (cached_addr,
						 soup_socket_connect_tcp_cb,
						 state);
		soup_address_unref (cached_addr);
	} else {
		state->inetaddr_id = soup_address_new (hostname,
						       port,
						       soup_socket_connect_inetaddr_cb,
						       state);
		/* NOTE: soup_address_new could succeed immediately
		 * and call our callback, in which case state->inetaddr_id
		 * will be NULL but state->tcp_id may be set.
		 */
	}

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
soup_socket_new_sync (SoupAddress *addr)
{
	SoupSocket *ret = (SoupSocket *) 0xdeadbeef;

	soup_socket_new (addr, soup_socket_new_sync_cb, &ret);

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
 * Get the address of the socket.  If the socket is client socket,
 * the address is the address of the remote host it is connected to.
 * If the socket is a server socket, the address is the address of
 * the local host.  (Though you should use
 * soup_address_gethostaddr() to get the #SoupAddress of the local
 * host.)
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

	return g_ntohs (SOUP_SOCKADDR_IN (socket->addr->sa).sin_port);
}

/**
 * soup_socket_server_new:
 * @port: Port number for the socket (SOUP_SERVER_ANY_PORT if you don't care).
 *
 * Create and open a new #SoupSocket with the specified port number.
 * Use this sort of socket when your are a server and you know what
 * the port number should be (or pass 0 if you don't care what the
 * port is).
 *
 * Returns: a new #SoupSocket, or NULL if there was a failure.
 **/
SoupSocket *
soup_socket_server_new (const gint port)
{
	SoupSocket* s;
	struct sockaddr_in* sa_in;
	socklen_t socklen;
	const int on = 1;
	gint flags;

	/* Create socket */
	s = g_new0 (SoupSocket, 1);
	s->ref_count = 1;

	if ((s->sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0) {
		g_free (s);
		return NULL;
	}

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;

	/* Set up address and port for connection */
	sa_in = (struct sockaddr_in*) &s->addr->sa;
	sa_in->sin_family = AF_INET;
	sa_in->sin_addr.s_addr = g_htonl (INADDR_ANY);
	sa_in->sin_port = g_htons (port);

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
	if (bind (s->sockfd, &s->addr->sa, sizeof (s->addr->sa)) != 0)
		goto SETUP_ERROR;

	/* Get the socket name - don't care if it fails */
	socklen = sizeof (s->addr->sa);
	getsockname (s->sockfd, &s->addr->sa, &socklen);

	/* Listen */
	if (listen (s->sockfd, 10) != 0) goto SETUP_ERROR;

	return s;

 SETUP_ERROR:
	close (s->sockfd);
	g_free (s->addr);
	g_free (s);
	return NULL;
}


#define SOUP_ANY_IO_CONDITION  (G_IO_IN | G_IO_OUT | G_IO_PRI | \
                                G_IO_ERR | G_IO_HUP | G_IO_NVAL)

typedef struct {
	gint             sockfd;
	SoupAddress     *addr;
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
		 SoupSocketNewFn   func,
		 gpointer          data)
{
	gint sockfd;
	gint flags;
	SoupSocketState* state;
	GIOChannel *chan;

	g_return_val_if_fail(addr != NULL, NULL);
	g_return_val_if_fail(func != NULL, NULL);

	/* Create socket */
	sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	/* Get the flags (should all be 0?) */
	flags = fcntl (sockfd, F_GETFL, 0);
	if (flags == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	if (fcntl (sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

	errno = 0;

	/* Connect (but non-blocking!) */
	if (connect (sockfd, &addr->sa, sizeof (addr->sa)) < 0 &&
	    errno != EINPROGRESS) {
		(func) (NULL, SOUP_SOCKET_NEW_STATUS_ERROR, data);
		return NULL;
	}

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
	gint sockfd;
	gint flags;
	struct sockaddr sa;
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

	n = sizeof(s->addr->sa);

	if ((sockfd = accept (socket->sockfd, &sa, &n)) == -1) {
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

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
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
	gint sockfd;
	gint flags;
	struct sockaddr sa;
	socklen_t n;
	fd_set fdset;
	SoupSocket* s;
	struct timeval tv = {0, 0};

	g_return_val_if_fail (socket != NULL, NULL);

 try_again:
	FD_ZERO (&fdset);
	FD_SET (socket->sockfd, &fdset);

	if (select (socket->sockfd + 1, &fdset, NULL, NULL, &tv) == -1) {
		if (errno == EINTR) goto try_again;
		return NULL;
	}

	n = sizeof(sa);

	if ((sockfd = accept (socket->sockfd, &sa, &n)) == -1) {
		/* If we get an error, return.  We don't want to try again as we
		   do in soup_socket_server_accept() - it might cause a
		   block. */
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

	s->addr = g_new0 (SoupAddress, 1);
	s->addr->ref_count = 1;
	memcpy (&s->addr->sa, &sa, sizeof (s->addr->sa));

	return s;
}
