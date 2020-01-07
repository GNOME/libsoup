/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection.c: A single HTTP/HTTPS connection
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-connection.h"
#include "soup.h"
#include "soup-message-queue.h"
#include "soup-socket-private.h"
#include "soup-misc-private.h"

typedef struct {
	SoupSocket  *socket;
	SoupSocketProperties *socket_props;

	SoupURI *remote_uri, *proxy_uri;
	gboolean ssl;

	SoupMessage *current_msg;
	SoupConnectionState state;
	time_t       unused_timeout;
	GSource     *idle_timeout_src;
	gboolean     reusable;
} SoupConnectionPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (SoupConnection, soup_connection, G_TYPE_OBJECT)

enum {
	EVENT,
	DISCONNECTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_REMOTE_URI,
	PROP_SOCKET_PROPERTIES,
	PROP_STATE,
	PROP_SSL,

	LAST_PROP
};

static void stop_idle_timer (SoupConnectionPrivate *priv);

/* Number of seconds after which we close a connection that hasn't yet
 * been used.
 */
#define SOUP_CONNECTION_UNUSED_TIMEOUT 3

static void
soup_connection_init (SoupConnection *conn)
{
}

static void
soup_connection_finalize (GObject *object)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (SOUP_CONNECTION (object));

	g_clear_pointer (&priv->remote_uri, soup_uri_free);
	g_clear_pointer (&priv->proxy_uri, soup_uri_free);
	g_clear_pointer (&priv->socket_props, soup_socket_properties_unref);
	g_clear_object (&priv->current_msg);

	if (priv->socket) {
		g_signal_handlers_disconnect_by_data (priv->socket, object);
		g_object_unref (priv->socket);
	}

	G_OBJECT_CLASS (soup_connection_parent_class)->finalize (object);
}

static void
soup_connection_dispose (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	stop_idle_timer (priv);

	G_OBJECT_CLASS (soup_connection_parent_class)->dispose (object);
}

static void
soup_connection_set_property (GObject *object, guint prop_id,
			      const GValue *value, GParamSpec *pspec)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (SOUP_CONNECTION (object));

	switch (prop_id) {
	case PROP_REMOTE_URI:
		priv->remote_uri = g_value_dup_boxed (value);
		break;
	case PROP_SOCKET_PROPERTIES:
		priv->socket_props = g_value_dup_boxed (value);
		break;
	case PROP_STATE:
		soup_connection_set_state (SOUP_CONNECTION (object), g_value_get_uint (value));
		break;
	case PROP_SSL:
		priv->ssl = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_connection_get_property (GObject *object, guint prop_id,
			      GValue *value, GParamSpec *pspec)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (SOUP_CONNECTION (object));

	switch (prop_id) {
	case PROP_REMOTE_URI:
		g_value_set_boxed (value, priv->remote_uri);
		break;
	case PROP_SOCKET_PROPERTIES:
		g_value_set_boxed (value, priv->socket_props);
		break;
	case PROP_STATE:
		g_value_set_enum (value, priv->state);
		break;
	case PROP_SSL:
		g_value_set_boolean (value, priv->ssl);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_connection_class_init (SoupConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	/* virtual method override */
	object_class->dispose = soup_connection_dispose;
	object_class->finalize = soup_connection_finalize;
	object_class->set_property = soup_connection_set_property;
	object_class->get_property = soup_connection_get_property;

	/* signals */
	signals[EVENT] =
		g_signal_new ("event",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      G_TYPE_SOCKET_CLIENT_EVENT,
			      G_TYPE_IO_STREAM);
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, disconnected),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_REMOTE_URI,
		g_param_spec_boxed (SOUP_CONNECTION_REMOTE_URI,
				    "Remote URI",
				    "The URI of the HTTP server",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_SOCKET_PROPERTIES,
		g_param_spec_boxed (SOUP_CONNECTION_SOCKET_PROPERTIES,
				    "Socket properties",
				    "Socket properties",
				    SOUP_TYPE_SOCKET_PROPERTIES,
				    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_STATE,
		g_param_spec_enum (SOUP_CONNECTION_STATE,
				   "Connection state",
				   "Current state of connection",
				   SOUP_TYPE_CONNECTION_STATE, SOUP_CONNECTION_NEW,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_SSL,
		g_param_spec_boolean (SOUP_CONNECTION_SSL,
				      "Connection uses TLS",
				      "Whether the connection should use TLS",
				      FALSE,G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));
}

static void
soup_connection_event (SoupConnection      *conn,
		       GSocketClientEvent   event,
		       GIOStream           *connection)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	if (!connection && priv->socket)
		connection = soup_socket_get_connection (priv->socket);

	g_signal_emit (conn, signals[EVENT], 0,
		       event, connection);
}

static gboolean
idle_timeout (gpointer conn)
{
	soup_connection_disconnect (conn);
	return FALSE;
}

static void
start_idle_timer (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	if (priv->socket_props->idle_timeout > 0 && !priv->idle_timeout_src) {
		priv->idle_timeout_src =
			soup_add_timeout (priv->socket_props->async_context,
					  priv->socket_props->idle_timeout * 1000,
					  idle_timeout, conn);
	}
}

static void
stop_idle_timer (SoupConnectionPrivate *priv)
{
	if (priv->idle_timeout_src) {
		g_source_destroy (priv->idle_timeout_src);
		priv->idle_timeout_src = NULL;
	}
}

static void
current_msg_got_body (SoupMessage *msg, gpointer user_data)
{
	SoupConnection *conn = user_data;
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	priv->unused_timeout = 0;

	if (priv->proxy_uri &&
	    msg->method == SOUP_METHOD_CONNECT &&
	    SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_PROXY_NEGOTIATED, NULL);

		/* We're now effectively no longer proxying */
		g_clear_pointer (&priv->proxy_uri, soup_uri_free);
	}

	priv->reusable = soup_message_is_keepalive (msg);
}

static void
clear_current_msg (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);
	SoupMessage *msg;

	msg = priv->current_msg;
	priv->current_msg = NULL;

	g_signal_handlers_disconnect_by_func (msg, G_CALLBACK (current_msg_got_body), conn);
	g_object_unref (msg);
}

static void
set_current_msg (SoupConnection *conn, SoupMessage *msg)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_if_fail (priv->state == SOUP_CONNECTION_IN_USE);

	g_object_freeze_notify (G_OBJECT (conn));

	if (priv->current_msg) {
		g_return_if_fail (priv->current_msg->method == SOUP_METHOD_CONNECT);
		clear_current_msg (conn);
	}

	stop_idle_timer (priv);

	priv->current_msg = g_object_ref (msg);
	priv->reusable = FALSE;

	g_signal_connect (msg, "got-body",
			  G_CALLBACK (current_msg_got_body), conn);

	if (priv->proxy_uri && msg->method == SOUP_METHOD_CONNECT)
		soup_connection_event (conn, G_SOCKET_CLIENT_PROXY_NEGOTIATING, NULL);

	g_object_thaw_notify (G_OBJECT (conn));
}

static void
re_emit_socket_event (SoupSocket          *socket,
		      GSocketClientEvent   event,
		      GIOStream           *connection,
		      gpointer             user_data)
{
	SoupConnection *conn = user_data;

	/* We handle COMPLETE ourselves */
	if (event != G_SOCKET_CLIENT_COMPLETE)
		soup_connection_event (conn, event, connection);
}

static void
socket_connect_finished (GTask *task, SoupSocket *sock, GError *error)
{
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	if (!error) {
		if (!priv->ssl || !priv->proxy_uri) {
			soup_connection_event (conn,
					       G_SOCKET_CLIENT_COMPLETE,
					       NULL);
		}

		soup_connection_set_state (conn, SOUP_CONNECTION_IN_USE);
		priv->unused_timeout = time (NULL) + SOUP_CONNECTION_UNUSED_TIMEOUT;
		start_idle_timer (conn);

		g_task_return_boolean (task, TRUE);
	} else
		g_task_return_error (task, error);
	g_object_unref (task);
}

static void
socket_handshake_complete (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	GTask *task = user_data;
	GError *error = NULL;

	soup_socket_handshake_finish (sock, result, &error);
	socket_connect_finished (task, sock, error);
}

static void
socket_connect_complete (GObject *object, GAsyncResult *result, gpointer user_data)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	GTask *task = user_data;
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);
	GError *error = NULL;

	if (!soup_socket_connect_finish_internal (sock, result, &error)) {
		socket_connect_finished (task, sock, error);
		return;
	}

	priv->proxy_uri = soup_socket_get_http_proxy_uri (sock);

	if (priv->ssl && !priv->proxy_uri) {
		soup_socket_handshake_async (sock, priv->remote_uri->host,
					     g_task_get_cancellable (task),
					     socket_handshake_complete, task);
		return;
	}

	socket_connect_finished (task, sock, NULL);
}

void
soup_connection_connect_async (SoupConnection      *conn,
			       GCancellable        *cancellable,
			       GAsyncReadyCallback  callback,
			       gpointer             user_data)
{
	SoupConnectionPrivate *priv;
	SoupAddress *remote_addr;
	GTask *task;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = soup_connection_get_instance_private (conn);
	g_return_if_fail (priv->socket == NULL);

	soup_connection_set_state (conn, SOUP_CONNECTION_CONNECTING);

	/* Set the protocol to ensure correct proxy resolution. */
	remote_addr =
		g_object_new (SOUP_TYPE_ADDRESS,
			      SOUP_ADDRESS_NAME, priv->remote_uri->host,
			      SOUP_ADDRESS_PORT, priv->remote_uri->port,
			      SOUP_ADDRESS_PROTOCOL, priv->remote_uri->scheme,
			      NULL);

	priv->socket =
		soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS, remote_addr,
				 SOUP_SOCKET_SOCKET_PROPERTIES, priv->socket_props,
				 NULL);
	g_object_unref (remote_addr);

	g_signal_connect (priv->socket, "event",
			  G_CALLBACK (re_emit_socket_event), conn);

	soup_socket_properties_push_async_context (priv->socket_props);
	task = g_task_new (conn, cancellable, callback, user_data);

	soup_socket_connect_async_internal (priv->socket, cancellable,
					    socket_connect_complete, task);
	soup_socket_properties_pop_async_context (priv->socket_props);
}

gboolean
soup_connection_connect_finish (SoupConnection  *conn,
				GAsyncResult    *result,
				GError         **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

gboolean
soup_connection_connect_sync (SoupConnection  *conn,
			      GCancellable    *cancellable,
			      GError         **error)
{
	SoupConnectionPrivate *priv;
	SoupAddress *remote_addr;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = soup_connection_get_instance_private (conn);
	g_return_val_if_fail (priv->socket == NULL, FALSE);

	soup_connection_set_state (conn, SOUP_CONNECTION_CONNECTING);

	/* Set the protocol to ensure correct proxy resolution. */
	remote_addr =
		g_object_new (SOUP_TYPE_ADDRESS,
			      SOUP_ADDRESS_NAME, priv->remote_uri->host,
			      SOUP_ADDRESS_PORT, priv->remote_uri->port,
			      SOUP_ADDRESS_PROTOCOL, priv->remote_uri->scheme,
			      NULL);

	priv->socket =
		soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS, remote_addr,
				 SOUP_SOCKET_SOCKET_PROPERTIES, priv->socket_props,
				 SOUP_SOCKET_FLAG_NONBLOCKING, FALSE,
				 NULL);
	g_object_unref (remote_addr);

	g_signal_connect (priv->socket, "event",
			  G_CALLBACK (re_emit_socket_event), conn);
	if (!soup_socket_connect_sync_internal (priv->socket, cancellable, error))
		return FALSE;

	priv->proxy_uri = soup_socket_get_http_proxy_uri (priv->socket);

	if (priv->ssl && !priv->proxy_uri) {
		if (!soup_socket_handshake_sync (priv->socket,
						 priv->remote_uri->host,
						 cancellable, error))
			return FALSE;
	}

	if (!priv->ssl || !priv->proxy_uri) {
		soup_connection_event (conn,
				       G_SOCKET_CLIENT_COMPLETE,
				       NULL);
	}
	soup_connection_set_state (conn, SOUP_CONNECTION_IN_USE);
	priv->unused_timeout = time (NULL) + SOUP_CONNECTION_UNUSED_TIMEOUT;
	start_idle_timer (conn);

	return TRUE;
}

gboolean
soup_connection_is_tunnelled (SoupConnection *conn)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = soup_connection_get_instance_private (conn);

	return priv->ssl && priv->proxy_uri != NULL;
}

gboolean
soup_connection_start_ssl_sync (SoupConnection  *conn,
				GCancellable    *cancellable,
				GError         **error)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);
	priv = soup_connection_get_instance_private (conn);

	if (soup_socket_handshake_sync (priv->socket, priv->remote_uri->host,
					cancellable, error)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_COMPLETE, NULL);
		return TRUE;
	} else
		return FALSE;
}

static void
start_ssl_completed (GObject *object, GAsyncResult *result, gpointer user_data)
{
	GTask *task = user_data;
	SoupConnection *conn = g_task_get_source_object (task);
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);
	GError *error = NULL;

	if (soup_socket_handshake_finish (priv->socket, result, &error)) {
		soup_connection_event (conn, G_SOCKET_CLIENT_COMPLETE, NULL);
		g_task_return_boolean (task, TRUE);
	} else
		g_task_return_error (task, error);
	g_object_unref (task);
}

void
soup_connection_start_ssl_async (SoupConnection      *conn,
				 GCancellable        *cancellable,
				 GAsyncReadyCallback  callback,
				 gpointer             user_data)
{
	SoupConnectionPrivate *priv;
	GTask *task;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = soup_connection_get_instance_private (conn);

	soup_socket_properties_push_async_context (priv->socket_props);
	task = g_task_new (conn, cancellable, callback, user_data);

	soup_socket_handshake_async (priv->socket, priv->remote_uri->host,
				     cancellable, start_ssl_completed, task);

	soup_socket_properties_pop_async_context (priv->socket_props);
}

gboolean
soup_connection_start_ssl_finish (SoupConnection  *conn,
				  GAsyncResult    *result,
				  GError         **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
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
	SoupConnectionPrivate *priv;
	SoupConnectionState old_state;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = soup_connection_get_instance_private (conn);

	old_state = priv->state;
	if (old_state != SOUP_CONNECTION_DISCONNECTED)
		soup_connection_set_state (conn, SOUP_CONNECTION_DISCONNECTED);

	if (priv->socket) {
		SoupSocket *socket = priv->socket;

		g_signal_handlers_disconnect_by_func (socket, G_CALLBACK (re_emit_socket_event), conn);

		priv->socket = NULL;
		soup_socket_disconnect (socket);
		g_object_unref (socket);
	}

	if (old_state != SOUP_CONNECTION_DISCONNECTED)
		g_signal_emit (conn, signals[DISCONNECTED], 0);
}

SoupSocket *
soup_connection_get_socket (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return priv->socket;
}

SoupURI *
soup_connection_get_remote_uri (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return priv->remote_uri;
}

SoupURI *
soup_connection_get_proxy_uri (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return priv->proxy_uri;
}

gboolean
soup_connection_is_via_proxy (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return priv->proxy_uri != NULL;
}

static gboolean
is_idle_connection_disconnected (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);
	GIOStream *iostream;
	GInputStream *istream;
	char buffer[1];
	GError *error = NULL;

	if (!soup_socket_is_connected (priv->socket))
		return TRUE;

	if (priv->unused_timeout && priv->unused_timeout < time (NULL))
		return TRUE;

	iostream = soup_socket_get_iostream (priv->socket);
	istream = g_io_stream_get_input_stream (iostream);

	/* This is tricky. The goal is to check if the socket is readable. If
	 * so, that means either the server has disconnected or it's broken (it
	 * should not send any data while the connection is in idle state). But
	 * we can't just check the readability of the SoupSocket because there
	 * could be non-application layer TLS data that is readable, but which
	 * we don't want to consider. So instead, just read and see if the read
	 * succeeds. This is OK to do here because if the read does succeed, we
	 * just disconnect and ignore the data anyway.
	 */
	g_pollable_input_stream_read_nonblocking (G_POLLABLE_INPUT_STREAM (istream),
						  &buffer, sizeof (buffer),
						  NULL, &error);
	if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_clear_error (&error);
		return TRUE;
	}

	g_error_free (error);

	return FALSE;
}

SoupConnectionState
soup_connection_get_state (SoupConnection *conn)
{
	SoupConnectionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn),
			      SOUP_CONNECTION_DISCONNECTED);
	priv = soup_connection_get_instance_private (conn);

	if (priv->state == SOUP_CONNECTION_IDLE &&
	    is_idle_connection_disconnected (conn))
		soup_connection_set_state (conn, SOUP_CONNECTION_REMOTE_DISCONNECTED);

	return priv->state;
}

void
soup_connection_set_state (SoupConnection *conn, SoupConnectionState state)
{
	SoupConnectionPrivate *priv;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (state >= SOUP_CONNECTION_NEW &&
			  state <= SOUP_CONNECTION_DISCONNECTED);

	g_object_freeze_notify (G_OBJECT (conn));

	priv = soup_connection_get_instance_private (conn);

	if (priv->current_msg) {
		g_warn_if_fail (state == SOUP_CONNECTION_IDLE ||
				state == SOUP_CONNECTION_DISCONNECTED);
		clear_current_msg (conn);
	}

	if (state == SOUP_CONNECTION_IDLE && !priv->reusable) {
		/* This will recursively call set_state() */
		soup_connection_disconnect (conn);
	} else {
		priv->state = state;

		if (priv->state == SOUP_CONNECTION_IDLE)
			start_idle_timer (conn);

		g_object_notify (G_OBJECT (conn), "state");
	}

	g_object_thaw_notify (G_OBJECT (conn));
}

gboolean
soup_connection_get_ever_used (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = soup_connection_get_instance_private (conn);

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return priv->unused_timeout == 0;
}

void
soup_connection_send_request (SoupConnection          *conn,
			      SoupMessageQueueItem    *item,
			      SoupMessageCompletionFn  completion_cb,
			      gpointer                 user_data)
{
	SoupConnectionPrivate *priv;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (item != NULL);
	priv = soup_connection_get_instance_private (conn);
	g_return_if_fail (priv->state != SOUP_CONNECTION_NEW &&
			  priv->state != SOUP_CONNECTION_DISCONNECTED);

	if (item->msg != priv->current_msg)
		set_current_msg (conn, item->msg);
	else
		priv->reusable = FALSE;

	soup_message_send_request (item, completion_cb, user_data);
}
