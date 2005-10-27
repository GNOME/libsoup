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

#include "soup-address.h"
#include "soup-connection.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-message-filter.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"
#include "soup-uri.h"

typedef struct {
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
	gboolean     connected, in_use;
} SoupConnectionPrivate;
#define SOUP_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_CONNECTION, SoupConnectionPrivate))

G_DEFINE_TYPE (SoupConnection, soup_connection, G_TYPE_OBJECT)

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

static void send_request (SoupConnection *conn, SoupMessage *req);
static void clear_current_request (SoupConnection *conn);

static void
soup_connection_init (SoupConnection *conn)
{
}

static void
finalize (GObject *object)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);

	if (priv->proxy_uri)
		soup_uri_free (priv->proxy_uri);
	if (priv->origin_uri)
		soup_uri_free (priv->origin_uri);

	if (priv->filter)
		g_object_unref (priv->filter);

	G_OBJECT_CLASS (soup_connection_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	clear_current_request (conn);
	soup_connection_disconnect (conn);

	G_OBJECT_CLASS (soup_connection_parent_class)->dispose (object);
}

static void
soup_connection_class_init (SoupConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (SoupConnectionPrivate));

	/* virtual method definition */
	connection_class->send_request = send_request;

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */

	/**
	 * SoupConnection::connect-result:
	 * @conn: the connection
	 * @status: the status
	 *
	 * Emitted when a connection attempt succeeds or fails. This
	 * is used internally by soup_connection_connect_async().
	 **/
	signals[CONNECT_RESULT] =
		g_signal_new ("connect_result",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, connect_result),
			      NULL, NULL,
			      soup_marshal_NONE__INT,
			      G_TYPE_NONE, 1,
			      G_TYPE_INT);

	/**
	 * SoupConnection::disconnected:
	 * @conn: the connection
	 *
	 * Emitted when the connection's socket is disconnected, for
	 * whatever reason.
	 **/
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, disconnected),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupConnection::authenticate:
	 * @conn: the connection
	 * @msg: the #SoupMessage being sent
	 * @auth_type: the authentication type
	 * @auth_realm: the realm being authenticated to
	 * @username: the signal handler should set this to point to
	 * the provided username
	 * @password: the signal handler should set this to point to
	 * the provided password
	 *
	 * Emitted when the connection requires authentication.
	 * (#SoupConnectionNTLM makes use of this.)
	 **/
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

	/**
	 * SoupConnection::reauthenticate:
	 * @conn: the connection
	 * @msg: the #SoupMessage being sent
	 * @auth_type: the authentication type
	 * @auth_realm: the realm being authenticated to
	 * @username: the signal handler should set this to point to
	 * the provided username
	 * @password: the signal handler should set this to point to
	 * the provided password
	 *
	 * Emitted when the authentication data acquired by a previous
	 * %authenticate or %reauthenticate signal fails.
	 **/
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
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);
	gpointer pval;

	switch (prop_id) {
	case PROP_ORIGIN_URI:
		pval = g_value_get_pointer (value);
		priv->origin_uri = pval ? soup_uri_copy (pval) : NULL;
		if (!priv->proxy_uri)
			priv->conn_uri = priv->origin_uri;
		break;
	case PROP_PROXY_URI:
		pval = g_value_get_pointer (value);
		priv->proxy_uri = pval ? soup_uri_copy (pval) : NULL;
		if (priv->proxy_uri)
			priv->conn_uri = priv->proxy_uri;
		else
			priv->conn_uri = priv->origin_uri;
		break;
	case PROP_SSL_CREDS:
		priv->ssl_creds = g_value_get_pointer (value);
		break;
	case PROP_MESSAGE_FILTER:
		priv->filter = g_object_ref (g_value_get_pointer (value));
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ORIGIN_URI:
		g_value_set_pointer (value, priv->origin_uri ?
				     soup_uri_copy (priv->origin_uri) :
				     NULL);
		break;
	case PROP_PROXY_URI:
		g_value_set_pointer (value, priv->proxy_uri ?
				     soup_uri_copy (priv->proxy_uri) :
				     NULL);
	case PROP_SSL_CREDS:
		g_value_set_pointer (value, priv->ssl_creds);
		break;
	case PROP_MESSAGE_FILTER:
		g_value_set_pointer (value, g_object_ref (priv->filter));
		break;
	default:
		break;
	}
}

static void
set_current_request (SoupConnectionPrivate *priv, SoupMessage *req)
{
	g_return_if_fail (priv->cur_req == NULL);

	req->status = SOUP_MESSAGE_STATUS_RUNNING;
	priv->cur_req = req;
	priv->in_use = TRUE;
	g_object_add_weak_pointer (G_OBJECT (req), (gpointer *)&priv->cur_req);
}

static void
clear_current_request (SoupConnection *conn)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (priv->cur_req) {
		SoupMessage *cur_req = priv->cur_req;

		g_object_remove_weak_pointer (G_OBJECT (priv->cur_req),
					      (gpointer *)&priv->cur_req);
		priv->cur_req = NULL;

		if (!soup_message_is_keepalive (cur_req))
			soup_connection_disconnect (conn);
		else {
			priv->last_used = time (NULL);
			soup_message_io_stop (cur_req);
		}
	}
	priv->in_use = FALSE;
}

static void
socket_disconnected (SoupSocket *sock, gpointer conn)
{
	soup_connection_disconnect (conn);
}

static inline guint
proxified_status (SoupConnectionPrivate *priv, guint status)
{
	if (!priv->proxy_uri)
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
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	guint status = msg->status_code;

	clear_current_request (conn);

	if (SOUP_STATUS_IS_SUCCESSFUL (status)) {
		if (soup_socket_start_proxy_ssl (priv->socket,
						 priv->origin_uri->host))
			priv->connected = TRUE;
		else
			status = SOUP_STATUS_SSL_FAILED;
	} else if (SOUP_STATUS_IS_REDIRECTION (status)) {
		/* Oops, the proxy thinks we're a web browser. */
		status = SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED;
	}

	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (priv, status));
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
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		goto done;

	if (priv->conn_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		if (!soup_socket_start_ssl (sock)) {
			status = SOUP_STATUS_SSL_FAILED;
			goto done;
		}
	}

	/* See if we need to tunnel */
	if (priv->proxy_uri &&
	    priv->origin_uri &&
	    priv->origin_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 priv->origin_uri);

		g_signal_connect (connect_msg, "restarted",
				  G_CALLBACK (tunnel_connect_restarted), conn);
		g_signal_connect (connect_msg, "finished",
				  G_CALLBACK (tunnel_connect_finished), conn);

		soup_connection_send_request (conn, connect_msg);
		return;
	}

	priv->connected = TRUE;

 done:
	g_signal_emit (conn, signals[CONNECT_RESULT], 0,
		       proxified_status (priv, status));
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
	SoupConnectionPrivate *priv;

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	g_return_if_fail (priv->socket == NULL);

	if (callback) {
		soup_signal_connect_once (conn, "connect_result",
					  G_CALLBACK (callback), user_data);
	}

	priv->socket =
		soup_socket_client_new_async (priv->conn_uri->host,
					      priv->conn_uri->port,
					      priv->ssl_creds,
					      socket_connect_result, conn);
	g_signal_connect (priv->socket, "disconnected",
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
	SoupConnectionPrivate *priv;
	guint status;

	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), SOUP_STATUS_MALFORMED);
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);
	g_return_val_if_fail (priv->socket == NULL, SOUP_STATUS_MALFORMED);

	priv->socket =
		soup_socket_client_new_sync (priv->conn_uri->host,
					     priv->conn_uri->port,
					     priv->ssl_creds,
					     &status);

	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		goto fail;

	g_signal_connect (priv->socket, "disconnected",
			  G_CALLBACK (socket_disconnected), conn);

	if (priv->conn_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		if (!soup_socket_start_ssl (priv->socket)) {
			status = SOUP_STATUS_SSL_FAILED;
			goto fail;
		}
	}

	/* See if we need to tunnel */
	if (priv->proxy_uri &&
	    priv->origin_uri &&
	    priv->origin_uri->protocol == SOUP_PROTOCOL_HTTPS) {
		SoupMessage *connect_msg;

		connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
							 priv->origin_uri);
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

	if (SOUP_STATUS_IS_SUCCESSFUL (status))
		priv->connected = TRUE;
	else {
	fail:
		if (priv->socket) {
			g_object_unref (priv->socket);
			priv->socket = NULL;
		}
	}

	status = proxified_status (priv, status);
	g_signal_emit (conn, signals[CONNECT_RESULT], 0, status);
	return status;
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

	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (!priv->socket)
		return;

	g_signal_handlers_disconnect_by_func (priv->socket,
					      socket_disconnected, conn);
	soup_socket_disconnect (priv->socket);
	g_object_unref (priv->socket);
	priv->socket = NULL;

	/* Don't emit "disconnected" if we aren't yet connected */
	if (!priv->connected)
		return;

	priv->connected = FALSE;
	g_signal_emit (conn, signals[DISCONNECTED], 0);

	if (!priv->cur_req ||
	    priv->cur_req->status_code != SOUP_STATUS_IO_ERROR)
		return;

	/* There was a message queued on this connection, but the
	 * socket was closed while it was being sent.
	 */

	if (priv->last_used != 0) {
		/* If last_used is not 0, then that means at least one
		 * message was successfully sent on this connection
		 * before, and so the most likely cause of the
		 * IO_ERROR is that the connection was idle for too
		 * long and the server timed out and closed it (and we
		 * didn't notice until after we started sending the
		 * message). So we want the message to get tried again
		 * on a new connection. The only code path that could
		 * have gotten us to this point is through the call to
		 * io_cleanup() in soup_message_io_finished(), and so
		 * all we need to do to get the message requeued in
		 * this case is to change its status.
		 */
		priv->cur_req->status = SOUP_MESSAGE_STATUS_QUEUED;
		return;
	}

	/* If priv->last_used is 0, then that means this was the
	 * first message to be sent on this connection, so the error
	 * probably means that there's some network or server problem,
	 * so we let the IO_ERROR be returned to the caller.
	 *
	 * Of course, it's also possible that the error in the
	 * last_used != 0 case was because of a network/server problem
	 * too. It's even possible that the message crashed the
	 * server. In this case, requeuing it was the wrong thing to
	 * do, but presumably, the next attempt will also get an
	 * error, and eventually the message will be requeued onto a
	 * fresh connection and get an error, at which point the error
	 * will finally be returned to the caller.
	 */
}

/**
 * soup_connection_is_in_use:
 * @conn: a connection
 *
 * Tests whether or not @conn is in use.
 *
 * Return value: %TRUE if there is currently a request being processed
 * on @conn.
 **/
gboolean
soup_connection_is_in_use (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->in_use;
}

/**
 * soup_connection_last_used:
 * @conn: a #SoupConnection.
 *
 * Returns the last time a response was received on @conn.
 *
 * Return value: the last time a response was received on @conn, or 0
 * if @conn has not been used yet.
 */
time_t
soup_connection_last_used (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return SOUP_CONNECTION_GET_PRIVATE (conn)->last_used;
}

static void
send_request (SoupConnection *conn, SoupMessage *req)
{
	SoupConnectionPrivate *priv = SOUP_CONNECTION_GET_PRIVATE (conn);

	if (req != priv->cur_req) {
		set_current_request (priv, req);
		if (priv->filter)
			soup_message_filter_setup_message (priv->filter, req);
	}

	soup_message_send_request_internal (req, priv->socket, conn,
					    priv->proxy_uri != NULL);
}

/**
 * soup_connection_send_request:
 * @conn: a #SoupConnection
 * @req: a #SoupMessage
 *
 * Sends @req on @conn. This is a low-level function, intended for use
 * by #SoupSession.
 **/
void
soup_connection_send_request (SoupConnection *conn, SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));
	g_return_if_fail (SOUP_IS_MESSAGE (req));
	g_return_if_fail (SOUP_CONNECTION_GET_PRIVATE (conn)->socket != NULL);

	SOUP_CONNECTION_GET_CLASS (conn)->send_request (conn, req);
}

/**
 * soup_connection_reserve:
 * @conn: a #SoupConnection
 *
 * Marks @conn as "in use" despite not actually having a message on
 * it. This is used by #SoupSession to keep it from accidentally
 * trying to queue two messages on the same connection from different
 * threads at the same time.
 **/
void
soup_connection_reserve (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	SOUP_CONNECTION_GET_PRIVATE (conn)->in_use = TRUE;
}

/**
 * soup_connection_release:
 * @conn: a #SoupConnection
 *
 * Marks @conn as not "in use". This can be used to cancel the effect
 * of a soup_connection_reserve(). It is not necessary to call this
 * after soup_connection_send_request().
 **/
void
soup_connection_release (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	clear_current_request (conn);
}

/**
 * soup_connection_authenticate:
 * @conn: a #SoupConnection
 * @msg: the message to authenticate
 * @auth_type: type of authentication to use
 * @auth_realm: authentication realm
 * @username: on successful return, will contain the username to
 * authenticate with
 * @password: on successful return, will contain the password to
 * authenticate with
 *
 * Emits the %authenticate signal on @conn. For use by #SoupConnection
 * subclasses.
 **/
void
soup_connection_authenticate (SoupConnection *conn, SoupMessage *msg,
			      const char *auth_type, const char *auth_realm,
			      char **username, char **password)
{
	g_signal_emit (conn, signals[AUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}

/**
 * soup_connection_reauthenticate:
 * @conn: a #SoupConnection
 * @msg: the message to authenticate
 * @auth_type: type of authentication to use
 * @auth_realm: authentication realm
 * @username: on successful return, will contain the username to
 * authenticate with
 * @password: on successful return, will contain the password to
 * authenticate with
 *
 * Emits the %reauthenticate signal on @conn. For use by
 * #SoupConnection subclasses.
 **/
void
soup_connection_reauthenticate (SoupConnection *conn, SoupMessage *msg,
				const char *auth_type, const char *auth_realm,
				char **username, char **password)
{
	g_signal_emit (conn, signals[REAUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}
