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
	SoupUri     *proxy_uri, *dest_uri;
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

	if (conn->priv->proxy_uri)
		soup_uri_free (conn->priv->proxy_uri);
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


/**
 * soup_connection_new:
 * @uri: remote machine to connect to
 *
 * Creates a connection to @uri. You must call
 * soup_connection_connect_async() or soup_connection_connect_sync()
 * to connect it after creating it.
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new (const SoupUri *uri)
{
	SoupConnection *conn;

	conn = g_object_new (SOUP_TYPE_CONNECTION, NULL);
	conn->priv->dest_uri = soup_uri_copy_root (uri);

	return conn;
}

/**
 * soup_connection_new_proxy:
 * @proxy_uri: proxy to connect to
 *
 * Creates a connection to @proxy_uri. As with soup_connection_new(),
 * the returned object is not yet connected.
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new_proxy (const SoupUri *proxy_uri)
{
	SoupConnection *conn;

	conn = g_object_new (SOUP_TYPE_CONNECTION, NULL);
	conn->priv->proxy_uri = soup_uri_copy_root (proxy_uri);

	return conn;
}

/**
 * soup_connection_new_tunnel:
 * @proxy_uri: proxy to connect to
 * @dest_uri: remote machine to ask the proxy to connect to
 *
 * Creates a connection to @uri via @proxy_uri. As with
 * soup_connection_new(), the returned object is not yet connected.
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new_tunnel (const SoupUri *proxy_uri, const SoupUri *dest_uri)
{
	SoupConnection *conn;

	conn = g_object_new (SOUP_TYPE_CONNECTION, NULL);
	conn->priv->dest_uri = soup_uri_copy_root (dest_uri);
	conn->priv->proxy_uri = soup_uri_copy_root (proxy_uri);

	return conn;
}


static void
socket_disconnected (SoupSocket *sock, gpointer conn)
{
	soup_connection_disconnect (conn);
}

static inline guint
proxified_status (SoupConnection *conn, guint status)
{
	if (!conn->priv->proxy_uri)
		return status;

	if (status == SOUP_STATUS_CANT_RESOLVE)
		return SOUP_STATUS_CANT_RESOLVE_PROXY;
	else if (status == SOUP_STATUS_CANT_CONNECT)
		return SOUP_STATUS_CANT_CONNECT_PROXY;
	else
		return status;
}

static void
tunnel_connect_finished (SoupMessage *msg, gpointer user_data)
{
	SoupConnection *conn = user_data;

	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		soup_socket_start_ssl (conn->priv->socket);

	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (conn, msg->status_code));
	g_object_unref (msg);
}

static void
socket_connect_result (SoupSocket *sock, guint status, gpointer user_data)
{
	SoupConnection *conn = user_data;

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		g_signal_emit (conn, signals[CONNECT_RESULT], 0,
			       proxified_status (conn, status));
		return;
	}

	/* See if we need to tunnel */
	if (conn->priv->proxy_uri && conn->priv->dest_uri) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 conn->priv->dest_uri);
		g_signal_connect (connect_msg, "finished",
				  G_CALLBACK (tunnel_connect_finished), conn);

		soup_connection_send_request (conn, connect_msg);
		return;
	}

	g_signal_emit (conn, signals[CONNECT_RESULT], 0, status);
}

/**
 * soup_connection_connect_async:
 * @conn: the connection
 * @ac: the async context to use
 * @callback: callback to call when the connection succeeds or fails
 * @user_data: data for @callback
 *
 * Asynchronously connects @conn.
 **/
void
soup_connection_connect_async (SoupConnection *conn,
			       SoupConnectionCallback callback,
			       gpointer user_data)
{
	const SoupUri *uri;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (conn->priv->socket == NULL);

	if (callback) {
		soup_signal_connect_once (conn, "connect_result",
					  G_CALLBACK (callback), user_data);
	}

	if (conn->priv->proxy_uri)
		uri = conn->priv->proxy_uri;
	else
		uri = conn->priv->dest_uri;

	conn->priv->socket =
		soup_socket_client_new_async (uri->host, uri->port,
					      uri->protocol == SOUP_PROTOCOL_HTTPS,
					      socket_connect_result, conn);
	g_signal_connect (conn->priv->socket, "disconnected",
			  G_CALLBACK (socket_disconnected), conn);
}

/**
 * soup_connection_connect_sync:
 * @conn: the connection
 *
 * Synchronously connects @conn.
 *
 * Return value: the soup status
 **/
guint
soup_connection_connect_sync (SoupConnection *conn)
{
	const SoupUri *uri;
	guint status;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (conn->priv->socket == NULL, SOUP_STATUS_MALFORMED);

	if (conn->priv->proxy_uri)
		uri = conn->priv->proxy_uri;
	else
		uri = conn->priv->dest_uri;

	conn->priv->socket =
		soup_socket_client_new_sync (uri->host, uri->port,
					     uri->protocol == SOUP_PROTOCOL_HTTPS,
					     &status);

	if (SOUP_STATUS_IS_SUCCESSFUL (status) &&
	    conn->priv->proxy_uri && conn->priv->dest_uri) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 conn->priv->dest_uri);
		soup_connection_send_request (conn, connect_msg);
		status = connect_msg->status_code;
		g_object_unref (connect_msg);
	}

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		if (conn->priv->socket)
			g_object_unref (conn->priv->socket);
		conn->priv->socket = NULL;
	}

	return proxified_status (conn, status);
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
				   conn->priv->proxy_uri != NULL);
}
