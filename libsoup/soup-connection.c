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

#include "soup-address.h"
#include "soup-connection.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-filter.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"
#include "soup-uri.h"

struct SoupConnectionPrivate {
	SoupSocket  *socket;

	/* proxy_uri is the URI of the proxy server we are connected
	 * to, if any. origin_uri is the URI of the origin server.
	 * conn_uri is the uri of the host we are actually directly
	 * connected to, which will be proxy_uri if there's a proxy
	 * and origin_uri if not.
	 */
	SoupUri     *proxy_uri, *origin_uri, *conn_uri;
	gpointer     ssl_creds;

	SoupMessageFilter *filter;

	SoupMessage *cur_req;
	time_t       last_used;
	gboolean     in_use;
};

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	CONNECT_RESULT,
	DISCONNECTED,
	AUTHENTICATE,
	REAUTHENTICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
  PROP_0,

  PROP_ORIGIN_URI,
  PROP_PROXY_URI,
  PROP_SSL_CREDS,
  PROP_MESSAGE_FILTER,

  LAST_PROP
};

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void request_done (SoupMessage *req, gpointer user_data);
static void send_request (SoupConnection *conn, SoupMessage *req);

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
	if (conn->priv->origin_uri)
		soup_uri_free (conn->priv->origin_uri);

	if (conn->priv->filter)
		g_object_unref (conn->priv->filter);

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
	SoupConnectionClass *connection_class =
		SOUP_CONNECTION_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method definition */
	connection_class->send_request = send_request;

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

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
	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, authenticate),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT_STRING_STRING_POINTER_POINTER,
			      G_TYPE_NONE, 5,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_STRING,
			      G_TYPE_POINTER,
			      G_TYPE_POINTER);
	signals[REAUTHENTICATE] =
		g_signal_new ("reauthenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, reauthenticate),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT_STRING_STRING_POINTER_POINTER,
			      G_TYPE_NONE, 5,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_STRING,
			      G_TYPE_POINTER,
			      G_TYPE_POINTER);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_ORIGIN_URI,
		g_param_spec_pointer (SOUP_CONNECTION_ORIGIN_URI,
				      "Origin URI",
				      "The HTTP origin server to use for this connection",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_PROXY_URI,
		g_param_spec_pointer (SOUP_CONNECTION_PROXY_URI,
				      "Proxy URI",
				      "The HTTP Proxy to use for this connection",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_CREDS,
		g_param_spec_pointer (SOUP_CONNECTION_SSL_CREDENTIALS,
				      "SSL credentials",
				      "Opaque SSL credentials for this connection",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_MESSAGE_FILTER,
		g_param_spec_pointer (SOUP_CONNECTION_MESSAGE_FILTER,
				      "Message filter",
				      "Message filter object for this connection",
				      G_PARAM_READWRITE));
}

SOUP_MAKE_TYPE (soup_connection, SoupConnection, class_init, init, PARENT_TYPE)


/**
 * soup_connection_new:
 * @propname1: name of first property to set
 * @...:
 *
 * Creates an HTTP connection. You must set at least one of
 * %SOUP_CONNECTION_ORIGIN_URI or %SOUP_CONNECTION_PROXY_URI. If you
 * set an origin server URI but no proxy URI, this will be a direct
 * connection. If you set a proxy URI and an https origin server URI,
 * this will be a tunnel. Otherwise it will be an http proxy
 * connection.
 *
 * You must call soup_connection_connect_async() or
 * soup_connection_connect_sync() to connect it after creating it.
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new (const char *propname1, ...)
{
	SoupConnection *conn;
	va_list ap;

	va_start (ap, propname1);
	conn = (SoupConnection *)g_object_new_valist (SOUP_TYPE_CONNECTION,
						      propname1, ap);
	va_end (ap);

	return conn;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupConnection *conn = SOUP_CONNECTION (object);
	gpointer pval;

	switch (prop_id) {
	case PROP_ORIGIN_URI:
		pval = g_value_get_pointer (value);
		conn->priv->origin_uri = pval ? soup_uri_copy (pval) : NULL;
		if (!conn->priv->proxy_uri)
			conn->priv->conn_uri = conn->priv->origin_uri;
		break;
	case PROP_PROXY_URI:
		pval = g_value_get_pointer (value);
		conn->priv->proxy_uri = pval ? soup_uri_copy (pval) : NULL;
		if (conn->priv->proxy_uri)
			conn->priv->conn_uri = conn->priv->proxy_uri;
		else
			conn->priv->conn_uri = conn->priv->origin_uri;
		break;
	case PROP_SSL_CREDS:
		conn->priv->ssl_creds = g_value_get_pointer (value);
		break;
	case PROP_MESSAGE_FILTER:
		conn->priv->filter = g_object_ref (g_value_get_pointer (value));
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	switch (prop_id) {
	case PROP_ORIGIN_URI:
		g_value_set_pointer (value, conn->priv->origin_uri ?
				     soup_uri_copy (conn->priv->origin_uri) :
				     NULL);
		break;
	case PROP_PROXY_URI:
		g_value_set_pointer (value, conn->priv->proxy_uri ?
				     soup_uri_copy (conn->priv->proxy_uri) :
				     NULL);
	case PROP_SSL_CREDS:
		g_value_set_pointer (value, conn->priv->ssl_creds);
		break;
	case PROP_MESSAGE_FILTER:
		g_value_set_pointer (value, g_object_ref (conn->priv->filter));
		break;
	default:
		break;
	}
}

static void
set_current_request (SoupConnection *conn, SoupMessage *req)
{
	g_return_if_fail (conn->priv->cur_req == NULL);

	req->status = SOUP_MESSAGE_STATUS_RUNNING;
	conn->priv->cur_req = req;
	conn->priv->in_use = TRUE;
	g_object_add_weak_pointer (G_OBJECT (req),
				   (gpointer *)conn->priv->cur_req);
}

static void
clear_current_request (SoupConnection *conn)
{
	if (conn->priv->cur_req) {
		g_object_remove_weak_pointer (G_OBJECT (conn->priv->cur_req),
					      (gpointer *)conn->priv->cur_req);
		conn->priv->cur_req = NULL;
	}
	conn->priv->in_use = FALSE;
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
	guint status = msg->status_code;

	clear_current_request (conn);

	if (SOUP_STATUS_IS_SUCCESSFUL (status)) {
		if (!soup_socket_start_ssl (conn->priv->socket))
			status = SOUP_STATUS_SSL_FAILED;
	}

	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (conn, status));
	g_object_unref (msg);
}

static void
tunnel_connect_restarted (SoupMessage *msg, gpointer user_data)
{
	SoupConnection *conn = user_data;
	guint status = msg->status_code;

	/* We only allow one restart: if another one happens, treat
	 * it as "finished".
	 */
	g_signal_handlers_disconnect_by_func (msg, tunnel_connect_restarted, conn);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (tunnel_connect_finished), conn);

	if (status == SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED) {
		/* Our parent session has handled the authentication
		 * and attempted to restart the message.
		 */
		if (soup_message_is_keepalive (msg)) {
			/* Connection is still open, so just send the
			 * message again.
			 */
			soup_connection_send_request (conn, msg);
		} else {
			/* Tell the session to try again. */
			soup_message_set_status (msg, SOUP_STATUS_TRY_AGAIN);
			soup_message_finished (msg);
		}
	} else
		soup_message_finished (msg);
}

static void
socket_connect_result (SoupSocket *sock, guint status, gpointer user_data)
{
	SoupConnection *conn = user_data;

	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		goto done;

	if (conn->priv->conn_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		if (!soup_socket_start_ssl (sock)) {
			status = SOUP_STATUS_SSL_FAILED;
			goto done;
		}
	}

	/* See if we need to tunnel */
	if (conn->priv->proxy_uri &&
	    conn->priv->origin_uri &&
	    conn->priv->origin_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 conn->priv->origin_uri);

		g_signal_connect (connect_msg, "restarted",
				  G_CALLBACK (tunnel_connect_restarted), conn);
		g_signal_connect (connect_msg, "finished",
				  G_CALLBACK (tunnel_connect_finished), conn);

		soup_connection_send_request (conn, connect_msg);
		return;
	}

 done:
	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (conn, status));
}

/**
 * soup_connection_connect_async:
 * @conn: the connection
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
	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (conn->priv->socket == NULL);

	if (callback) {
		soup_signal_connect_once (conn, "connect_result",
					  G_CALLBACK (callback), user_data);
	}

	conn->priv->socket =
		soup_socket_client_new_async (conn->priv->conn_uri->host,
					      conn->priv->conn_uri->port,
					      conn->priv->ssl_creds,
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
	guint status;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (conn->priv->socket == NULL, SOUP_STATUS_MALFORMED);

	conn->priv->socket =
		soup_socket_client_new_sync (conn->priv->conn_uri->host,
					     conn->priv->conn_uri->port,
					     conn->priv->ssl_creds,
					     &status);

	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		goto fail;

	if (conn->priv->conn_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		if (!soup_socket_start_ssl (conn->priv->socket)) {
			status = SOUP_STATUS_SSL_FAILED;
			goto fail;
		}
	}

	/* See if we need to tunnel */
	if (conn->priv->proxy_uri &&
	    conn->priv->origin_uri &&
	    conn->priv->origin_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 conn->priv->origin_uri);
		soup_connection_send_request (conn, connect_msg);
		status = connect_msg->status_code;

		if (status == SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED &&
		    SOUP_MESSAGE_IS_STARTING (connect_msg)) {
			if (soup_message_is_keepalive (connect_msg)) {
				/* Try once more */
				soup_connection_send_request (conn, connect_msg);
				status = connect_msg->status_code;
			} else
				status = SOUP_STATUS_TRY_AGAIN;
		}

		g_object_unref (connect_msg);
	}

	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
	fail:
		if (conn->priv->socket) {
			g_object_unref (conn->priv->socket);
			conn->priv->socket = NULL;
		}
	}

	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (conn, status));
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
	soup_socket_disconnect (conn->priv->socket);
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

	return conn->priv->in_use;
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
request_restarted (SoupMessage *req, gpointer conn)
{
	if (!soup_message_is_keepalive (req))
		soup_connection_disconnect (conn);
}

static void
request_done (SoupMessage *req, gpointer user_data)
{
	SoupConnection *conn = user_data;

	clear_current_request (conn);
	conn->priv->last_used = time (NULL);

	if (!soup_message_is_keepalive (req))
		soup_connection_disconnect (conn);

	g_signal_handlers_disconnect_by_func (req, request_done, conn);
	g_signal_handlers_disconnect_by_func (req, request_restarted, conn);
	g_object_unref (conn);
}

static void
send_request (SoupConnection *conn, SoupMessage *req)
{
	g_object_ref (conn);

	if (req != conn->priv->cur_req) {
		set_current_request (conn, req);

		g_signal_connect (req, "restarted",
				  G_CALLBACK (request_restarted), conn);
		g_signal_connect (req, "finished",
				  G_CALLBACK (request_done), conn);

		if (conn->priv->filter)
			soup_message_filter_setup_message (conn->priv->filter, req);
	}

	soup_message_send_request (req, conn->priv->socket,
				   conn->priv->proxy_uri != NULL);
}

void
soup_connection_send_request (SoupConnection *conn, SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (SOUP_IS_MESSAGE (req));
	g_return_if_fail (conn->priv->socket != NULL);

	SOUP_CONNECTION_GET_CLASS (conn)->send_request (conn, req);
}

void
soup_connection_reserve (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	conn->priv->in_use = TRUE;
}

void
soup_connection_authenticate (SoupConnection *conn, SoupMessage *msg,
			      const char *auth_type, const char *auth_realm,
			      char **username, char **password)
{
	g_signal_emit (conn, signals[AUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}

void
soup_connection_reauthenticate (SoupConnection *conn, SoupMessage *msg,
				const char *auth_type, const char *auth_realm,
				char **username, char **password)
{
	g_signal_emit (conn, signals[REAUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}
