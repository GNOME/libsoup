/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection.c: A single HTTP/HTTPS connection
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include <fcntl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "soup-connection.h"
#include "soup-private.h"
#include "soup-marshal.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"

struct SoupConnectionPrivate {
	SoupSocket  *socket;
	SoupUri     *dest_uri;
	gboolean     is_proxy;
	time_t       last_used;

	SoupMessage *cur_req;
};

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	CONNECT_RESULT,
	DISCONNECTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void request_done (SoupMessage *req, gpointer user_data);

static void
init (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	conn->priv = g_new0 (SoupConnectionPrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	if (conn->priv->dest_uri)
		soup_uri_free (conn->priv->dest_uri);

	g_free (conn->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	if (conn->priv->cur_req)
		request_done (conn->priv->cur_req, conn);
	soup_connection_disconnect (conn);

	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* signals */
	signals[CONNECT_RESULT] =
		g_signal_new ("connect_result",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, connect_result),
			      NULL, NULL,
			      soup_marshal_NONE__INT,
			      G_TYPE_NONE, 1,
			      G_TYPE_INT);
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, disconnected),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
}

SOUP_MAKE_TYPE (soup_connection, SoupConnection, class_init, init, PARENT_TYPE)


static void
socket_disconnected (SoupSocket *sock, gpointer conn)
{
	soup_connection_disconnect (conn);
}

static SoupConnection *
connection_new (const SoupUri *uri, gboolean is_proxy,
		SoupSocketCallback connect_callback,
		SoupConnectionCallback user_callback,
		gpointer user_data)
{
	SoupConnection *conn;

	conn = g_object_new (SOUP_TYPE_CONNECTION, NULL);
	conn->priv->is_proxy = is_proxy;

	soup_signal_connect_once (conn, "connect_result",
				  G_CALLBACK (user_callback), user_data);

	conn->priv->socket = soup_socket_client_new (uri->host, uri->port,
						     uri->protocol == SOUP_PROTOCOL_HTTPS,
						     connect_callback, conn);
	g_signal_connect (conn->priv->socket, "disconnected",
			  G_CALLBACK (socket_disconnected), conn);
	return conn;
}

static void
socket_connected (SoupSocket *sock, guint status, gpointer conn)
{
	g_signal_emit (conn, signals[CONNECT_RESULT], 0, status);
}

/**
 * soup_connection_new:
 * @uri: remote machine to connect to
 * @callback: callback to call after connecting
 * @user_data: data for @callback
 *
 * Creates a connection to @uri. @callback will be called when the
 * connection completes (or fails).
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new (const SoupUri *uri,
		     SoupConnectionCallback callback, gpointer user_data)
{
	return connection_new (uri, FALSE, socket_connected,
			       callback, user_data);
}

static void
proxy_socket_connected (SoupSocket *sock, guint status, gpointer conn)
{
	if (status == SOUP_STATUS_CANT_RESOLVE)
		status = SOUP_STATUS_CANT_RESOLVE_PROXY;
	else if (status == SOUP_STATUS_CANT_CONNECT)
		status = SOUP_STATUS_CANT_CONNECT_PROXY;

	g_signal_emit (conn, signals[CONNECT_RESULT], 0, status);
}

/**
 * soup_connection_new_proxy:
 * @proxy_uri: proxy to connect to
 * @callback: callback to call after connecting
 * @user_data: data for @callback
 *
 * Creates a connection to @proxy_uri. @callback will be called when
 * the connection completes (or fails).
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new_proxy (const SoupUri *proxy_uri,
			   SoupConnectionCallback callback,
			   gpointer user_data)
{
	return connection_new (proxy_uri, TRUE, proxy_socket_connected,
			       callback, user_data);
}

static void
tunnel_connected (SoupMessage *msg, gpointer user_data)
{
	SoupConnection *conn = user_data;

	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		soup_socket_start_ssl (conn->priv->socket);

	proxy_socket_connected (NULL, msg->status_code, conn);
	g_object_unref (msg);
}

static void
tunnel_failed (SoupMessage *msg, gpointer conn)
{
	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       SOUP_STATUS_CANT_CONNECT);
	g_object_unref (msg);
}

static void
tunnel_socket_connected (SoupSocket *sock, guint status, gpointer user_data)
{
	SoupConnection *conn = user_data;
	SoupMessage *connect_msg;

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		socket_connected (sock, status, conn);
		return;
	}

	connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
						 conn->priv->dest_uri);
	g_signal_connect (connect_msg, "read_body",
			  G_CALLBACK (tunnel_connected), conn);
	g_signal_connect (connect_msg, "write_error",
			  G_CALLBACK (tunnel_failed), conn);
	g_signal_connect (connect_msg, "read_error",
			  G_CALLBACK (tunnel_failed), conn);

	soup_connection_send_request (conn, connect_msg);
}

/**
 * soup_connection_new_tunnel:
 * @proxy_uri: proxy to connect to
 * @dest_uri: remote machine to ask the proxy to connect to
 * @callback: callback to call after connecting
 * @user_data: data for @callback
 *
 * Creates a connection to @uri via @proxy_uri. @callback will be
 * called when the connection completes (or fails).
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new_tunnel (const SoupUri *proxy_uri, const SoupUri *dest_uri,
			    SoupConnectionCallback callback,
			    gpointer user_data)
{
	SoupConnection *conn;

	conn = connection_new (proxy_uri, TRUE, tunnel_socket_connected,
			       callback, user_data);
	conn->priv->dest_uri = soup_uri_copy (dest_uri);
	return conn;
}

/**
 * soup_connection_disconnect:
 * @conn: a connection
 *
 * Disconnects @conn's socket and emits a %disconnected signal.
 * After calling this, @conn will be essentially useless.
 **/
void
soup_connection_disconnect (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	if (!conn->priv->socket)
		return;

	g_signal_handlers_disconnect_by_func (conn->priv->socket,
					      socket_disconnected, conn);
	g_object_unref (conn->priv->socket);
	conn->priv->socket = NULL;
	g_signal_emit (conn, signals[DISCONNECTED], 0);
}

gboolean
soup_connection_is_connected (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->socket != NULL;
}

/**
 * soup_connection_get_socket:
 * @conn: a #SoupConnection.
 *
 * Return value: @conn's socket
 */
SoupSocket *
soup_connection_get_socket (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return conn->priv->socket;
}


/**
 * soup_connection_is_in_use:
 * @conn: a connection
 *
 * Return value: whether or not @conn is being used.
 **/
gboolean
soup_connection_is_in_use (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->cur_req != NULL;
}

/**
 * soup_connection_last_used:
 * @conn: a #SoupConnection.
 *
 * Return value: the last time a response was received on @conn, or 0
 * if @conn has not been used yet.
 */
time_t
soup_connection_last_used (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->last_used;
}

/**
 * soup_connection_is_new:
 * @conn: a connection
 *
 * Return value: whether or not @conn is "new". (That is, it has not
 * yet completed a whole HTTP transaction.)
 **/
gboolean
soup_connection_is_new (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->last_used == 0;
}


static void
request_done (SoupMessage *req, gpointer user_data)
{
	SoupConnection *conn = user_data;

	g_object_remove_weak_pointer (G_OBJECT (conn->priv->cur_req),
				      (gpointer *)conn->priv->cur_req);
	conn->priv->cur_req = NULL;
	conn->priv->last_used = time (NULL);

	g_signal_handlers_disconnect_by_func (req, request_done, conn);

	if (!soup_message_is_keepalive (req))
		soup_connection_disconnect (conn);
}

void
soup_connection_send_request (SoupConnection *conn, SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (SOUP_IS_MESSAGE (req));
	g_return_if_fail (conn->priv->socket != NULL);
	g_return_if_fail (conn->priv->cur_req == NULL);

	conn->priv->cur_req = req;
	g_object_add_weak_pointer (G_OBJECT (req),
				   (gpointer *)conn->priv->cur_req);

	g_signal_connect (req, "finished", G_CALLBACK (request_done), conn);

	soup_message_send_request (req, conn->priv->socket,
				   conn->priv->is_proxy);
}
