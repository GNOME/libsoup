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

#include <fcntl.h>
#include <glib.h>
#include <string.h>

#include "soup-private.h"
#include "soup-socket.h"

#ifdef SOUP_WIN32
#  define socklen_t gint32
#  define SOUP_CLOSE_SOCKET(fd) closesocket(fd)
#  define SOUP_SOCKET_IOCHANNEL_NEW(fd) g_io_channel_win32_new_stream_socket(fd)
#  ifndef INET_ADDRSTRLEN
#    define INET_ADDRSTRLEN 16
#    define INET6_ADDRSTRLEN 46
#  endif
#else
#  include <unistd.h>
#  ifndef socklen_t
#    define socklen_t size_t
#  endif
#  define SOUP_CLOSE_SOCKET(fd) close(fd)
#  define SOUP_SOCKET_IOCHANNEL_NEW(fd) g_io_channel_unix_new(fd)
#endif

#define SOUP_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))

typedef struct {
	SoupSocketConnectFn  func;
	gpointer             data;

	gpointer             inetaddr_id;
	gpointer             tcp_id;
} SoupSocketConnectState;

static void
soup_address_new_sync_cb (SoupAddress *addr,
			  SoupAddressStatus  status,
			  gpointer           user_data)
{
	SoupAddress **ret = user_data;
	*ret = addr;
}

SoupAddress *
soup_address_new_sync (const gchar *name, const gint port)
{
	SoupAddress *ret = (SoupAddress *) 0xdeadbeef;

	soup_address_new (name, port, soup_address_new_sync_cb, &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (SoupAddress *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_address_ref
 * @ia: SoupAddress to reference
 *
 * Increment the reference counter of the SoupAddress.
 **/
void
soup_address_ref (SoupAddress* ia)
{
	g_return_if_fail (ia != NULL);

	++ia->ref_count;
}

/**
 * soup_address_copy
 * @ia: SoupAddress to copy
 *
 * Creates a copy of the given SoupAddress
 **/
SoupAddress *
soup_address_copy (SoupAddress* ia)
{
	SoupAddress* new_ia;
	g_return_val_if_fail (ia != NULL, NULL);

	new_ia = g_new0(SoupAddress, 1);
	new_ia->ref_count = 1;

	new_ia->name = g_strdup (ia->name);
	memcpy (&new_ia->sa, &ia->sa, sizeof(struct sockaddr));

	return new_ia;
}

static void
soup_address_get_name_sync_cb (SoupAddress       *addr,
			       SoupAddressStatus  status,
			       const char        *name,
			       gpointer           user_data)
{
	const char **ret = user_data;
	*ret = name;
}

const gchar *
soup_address_get_name_sync (SoupAddress *addr)
{
	const char *ret = (const char *) 0xdeadbeef;

	soup_address_get_name (addr, 
			       soup_address_get_name_sync_cb, 
			       (gpointer) &ret);

	while (1) {
		g_main_iteration (TRUE);
		if (ret != (const char *) 0xdeadbeef) return ret;
	}

	return ret;
}

/**
 * soup_address_get_canonical_name:
 * @ia: Address to get the canonical name of.
 *
 * Get the "canonical" name of an address (eg, for IP4 the dotted
 * decimal name 141.213.8.59).
 *
 * Returns: NULL if there was an error.  The caller is responsible
 * for deleting the returned string.
 **/
gchar*
soup_address_get_canonical_name (SoupAddress* ia)
{
	gchar buffer [INET_ADDRSTRLEN];	/* defined in netinet/in.h */
	guchar* p = (guchar*) &(SOUP_SOCKADDR_IN(ia->sa).sin_addr);

	g_return_val_if_fail (ia != NULL, NULL);

	g_snprintf(buffer,
		   sizeof (buffer),
		   "%d.%d.%d.%d",
		   p [0],
		   p [1],
		   p [2],
		   p [3]);

	return g_strdup (buffer);
}

/**
 * soup_address_get_port:
 * @ia: Address to get the port number of.
 *
 * Get the port number.
 * Returns: the port number.
 */
gint
soup_address_get_port (const SoupAddress* ia)
{
	g_return_val_if_fail(ia != NULL, -1);

	return (gint) g_ntohs (((struct sockaddr_in*) &ia->sa)->sin_port);
}

/**
 * soup_address_set_port:
 * @ia: The %SoupAddress.
 * @addrlen: Pointer to socklen_t the returned sockaddr's length is to be 
 * placed in.
 *
 * Return value: const pointer to @ia's sockaddr buffer.
 **/
const struct sockaddr *
soup_address_get_sockaddr (SoupAddress *ia, guint *addrlen)
{
	g_return_val_if_fail (ia != NULL, NULL);

	if (addrlen)
		*addrlen = sizeof (struct sockaddr_in);

	return &ia->sa;
}

/**
 * soup_address_hash:
 * @p: Pointer to an #SoupAddress.
 *
 * Hash the address.  This is useful for glib containers.
 *
 * Returns: hash value.
 **/
guint
soup_address_hash (const gpointer p)
{
	const SoupAddress* ia;
	guint32 port;
	guint32 addr;

	g_assert(p != NULL);

	ia = (const SoupAddress*) p;
	/* We do pay attention to network byte order just in case the hash
	   result is saved or sent to a different host.  */
	port = (guint32) g_ntohs (((struct sockaddr_in*) &ia->sa)->sin_port);
	addr = g_ntohl (((struct sockaddr_in*) &ia->sa)->sin_addr.s_addr);

	return (port ^ addr);
}

/**
 * soup_address_equal:
 * @p1: Pointer to first #SoupAddress.
 * @p2: Pointer to second #SoupAddress.
 *
 * Compare two #SoupAddress's.
 *
 * Returns: 1 if they are the same; 0 otherwise.
 **/
gint
soup_address_equal (const gpointer p1, const gpointer p2)
{
	const SoupAddress* ia1 = (const SoupAddress*) p1;
	const SoupAddress* ia2 = (const SoupAddress*) p2;

	g_assert(p1 != NULL && p2 != NULL);

	/* Note network byte order doesn't matter */
	return ((SOUP_SOCKADDR_IN(ia1->sa).sin_addr.s_addr ==
		 SOUP_SOCKADDR_IN(ia2->sa).sin_addr.s_addr) &&
		(SOUP_SOCKADDR_IN(ia1->sa).sin_port ==
		 SOUP_SOCKADDR_IN(ia2->sa).sin_port));
}

/**
 * soup_address_noport_equal:
 * @p1: Pointer to first SoupAddress.
 * @p2: Pointer to second SoupAddress.
 *
 * Compare two #SoupAddress's, but does not compare the port numbers.
 *
 * Returns: 1 if they are the same; 0 otherwise.
 **/
gint
soup_address_noport_equal (const gpointer p1, const gpointer p2)
{
	const SoupAddress* ia1 = (const SoupAddress*) p1;
	const SoupAddress* ia2 = (const SoupAddress*) p2;

	g_assert (p1 != NULL && p2 != NULL);

	/* Note network byte order doesn't matter */
	return (SOUP_SOCKADDR_IN(ia1->sa).sin_addr.s_addr ==
		SOUP_SOCKADDR_IN(ia2->sa).sin_addr.s_addr);
}

/**
 * soup_address_gethostaddr:
 *
 * Get the primary host's #SoupAddress.
 *
 * Returns: the #SoupAddress of the host; NULL if there was an error.
 * The caller is responsible for deleting the returned #SoupAddress.
 **/
SoupAddress *
soup_address_gethostaddr (void)
{
	gchar* name;
	struct sockaddr_in* sa_in, sa;
	SoupAddress* ia = NULL;

	name = soup_address_gethostname ();

	if (name && soup_gethostbyname (name, &sa, NULL)) {
		ia = g_new0 (SoupAddress, 1);
		ia->name = g_strdup (name);
		ia->ref_count = 1;

		sa_in = (struct sockaddr_in*) &ia->sa;
		sa_in->sin_family = AF_INET;
		sa_in->sin_port = 0;
		memcpy (&sa_in->sin_addr, &sa.sin_addr, 4);
        }

	return ia;
}


static void
soup_socket_connect_tcp_cb (SoupSocket* socket,
			    SoupSocketConnectStatus status,
			    gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;

	if (status == SOUP_SOCKET_NEW_STATUS_OK)
		(*state->func) (socket,
				SOUP_SOCKET_CONNECT_ERROR_NONE,
				state->data);
	else
		(*state->func) (NULL,
				SOUP_SOCKET_CONNECT_ERROR_NETWORK,
				state->data);

	g_free (state);
}

static void
soup_socket_connect_inetaddr_cb (SoupAddress* inetaddr,
				 SoupAddressStatus status,
				 gpointer data)
{
	SoupSocketConnectState* state = (SoupSocketConnectState*) data;

	if (status == SOUP_ADDRESS_STATUS_OK) {
		state->inetaddr_id = NULL;
		state->tcp_id = soup_socket_new (inetaddr,
						 soup_socket_connect_tcp_cb,
						 state);
		soup_address_unref (inetaddr);
	} else {
		(*state->func) (NULL,
				SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE,
				state->data);
		g_free (state);
	}
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
 * soup_socket_connect_cancel() to cancel it; NULL on
 * failure.
 **/
SoupSocketConnectId
soup_socket_connect (const gchar*        hostname,
		     const gint          port,
		     SoupSocketConnectFn func,
		     gpointer            data)
{
	SoupSocketConnectState* state;
	gpointer id;

	g_return_val_if_fail (hostname != NULL, NULL);
	g_return_val_if_fail (func != NULL, NULL);

	state = g_new0 (SoupSocketConnectState, 1);
	state->func = func;
	state->data = data;

	id = soup_address_new (hostname,
			       port,
			       soup_socket_connect_inetaddr_cb,
			       state);

	/* Note that soup_address_new can fail immediately and call
	   our callback which will delete the state.  The users callback
	   would be called in the process. */

	if (id == NULL) return NULL;

	state->inetaddr_id = id;

	return state;
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
		SOUP_CLOSE_SOCKET (s->sockfd);
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
		socket->iochannel = SOUP_SOCKET_IOCHANNEL_NEW (socket->sockfd);

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

	/* The socket is set to non-blocking mode later in the Windows
	   version.*/
#ifndef SOUP_WIN32
	{
		const int on = 1;
		gint flags;

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
	}
#endif

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
	SOUP_CLOSE_SOCKET (s->sockfd);
	g_free (s->addr);
	g_free (s);
	return NULL;
}
