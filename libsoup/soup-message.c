/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: HTTP request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <string.h>

#include "soup-auth.h"
#include "soup-error.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-context.h"
#include "soup-private.h"
#include "soup-queue.h"

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

static void cleanup_message (SoupMessage *req);

static void
init (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);

	msg->priv = g_new0 (SoupMessagePrivate, 1);

	msg->priv->status  = SOUP_MESSAGE_STATUS_IDLE;

	msg->request_headers = g_hash_table_new (soup_str_case_hash,
						 soup_str_case_equal);

	msg->response_headers = g_hash_table_new (soup_str_case_hash,
						  soup_str_case_equal);

	msg->priv->http_version = SOUP_HTTP_1_1;
}

static void
finalize (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);

	cleanup_message (msg);

	if (msg->priv->context)
		g_object_unref (msg->priv->context);

	if (msg->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->request.body);
	if (msg->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->response.body);

	soup_message_clear_headers (msg->request_headers);
	g_hash_table_destroy (msg->request_headers);

	soup_message_clear_headers (msg->response_headers);
	g_hash_table_destroy (msg->response_headers);

	g_slist_foreach (msg->priv->content_handlers, (GFunc) g_free, NULL);
	g_slist_free (msg->priv->content_handlers);

	g_free ((char *) msg->errorphrase);

	g_free (msg->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_message, SoupMessage, class_init, init, PARENT_TYPE)


/**
 * soup_message_new:
 * @method: the HTTP method for the created request
 * @uri: the destination endpoint (as a string)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage (or %NULL if @uri could not
 * be parsed).
 */
SoupMessage *
soup_message_new (const char *method, const char *uri)
{
	SoupMessage *msg;
	SoupContext *ctx;

	ctx = soup_context_get (uri);
	if (!ctx)
		return NULL;

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	msg->priv->context = ctx;

	return msg;
}

/**
 * soup_message_new_from_uri:
 * @method: the HTTP method for the created request
 * @uri: the destination endpoint (as a #SoupUri)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage (or %NULL if @uri is invalid)
 */
SoupMessage *
soup_message_new_from_uri (const char *method, const SoupUri *uri)
{
	SoupMessage *msg;
	SoupContext *ctx;

	ctx = soup_context_from_uri (uri);
	if (!ctx)
		return NULL;

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	msg->priv->context = ctx;

	return msg;
}

/**
 * soup_message_set_request:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_owner: the #SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message request.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the request body of a #SoupMessage
 */
void
soup_message_set_request (SoupMessage   *msg,
			  const char    *content_type,
			  SoupOwnership  req_owner,
			  char          *req_body,
			  gulong         req_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (req_body != NULL || req_length == 0);

	soup_message_add_header (msg->request_headers,
				 "Content-Type", content_type);
	msg->request.owner = req_owner;
	msg->request.body = req_body;
	msg->request.length = req_length;
}

/**
 * soup_message_set_response:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_owner: the #SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message response.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the response body of a #SoupMessage
 */
void
soup_message_set_response (SoupMessage   *msg,
			   const char    *content_type,
			   SoupOwnership  resp_owner,
			   char          *resp_body,
			   gulong         resp_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (resp_body != NULL || resp_length == 0);

	soup_message_add_header (msg->response_headers,
				 "Content-Type", content_type);
	msg->response.owner = resp_owner;
	msg->response.body = resp_body;
	msg->response.length = resp_length;
}

static void
cleanup_message (SoupMessage *req)
{
	if (req->priv->read_state)
		soup_message_read_cancel (req);

	if (req->priv->write_state)
		soup_message_write_cancel (req);

	if (req->priv->connect_tag) {
		soup_context_cancel_connect (req->priv->connect_tag);
		req->priv->connect_tag = NULL;
	}

	soup_message_set_connection (req, NULL);

	soup_queue_remove_request (req);
}

/**
 * soup_message_issue_callback:
 * @req: a #SoupMessage currently being processed.
 * @error: a #SoupErrorCode to be passed to @req's completion callback.
 * 
 * Finalizes the message request, by first freeing any temporary
 * resources, then issuing the callback function pointer passed in
 * soup_message_new() or soup_message_new_full(). If, after returning
 * from the callback, the message has not been requeued, @req will be
 * unreffed.
 */
void
soup_message_issue_callback (SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	/*
	 * Make sure we don't have some icky recursion if the callback
	 * runs the main loop, and the connection has some data or error
	 * which causes the callback to be run again.
	 */
	cleanup_message (req);

	if (req->priv->callback) {
		(*req->priv->callback) (req, req->priv->user_data);

		if (!SOUP_MESSAGE_IS_STARTING (req))
			g_object_unref (req);
	}
}

/**
 * soup_message_disconnect:
 * @msg: a #SoupMessage
 *
 * Utility function to close and unref the connection associated with
 * @msg if there was an error.
 **/
void
soup_message_disconnect (SoupMessage *msg)
{
	if (msg->priv->connection) {
		soup_connection_disconnect (msg->priv->connection);
		soup_message_set_connection (msg, NULL);
	}
}

/**
 * soup_message_cancel:
 * @msg: a #SoupMessage currently being processed.
 * 
 * Cancel a running message, and issue completion callback with an
 * error code of %SOUP_ERROR_CANCELLED. If not requeued by the
 * completion callback, the @msg will be destroyed.
 */
void
soup_message_cancel (SoupMessage *msg)
{
	soup_message_set_error (msg, SOUP_ERROR_CANCELLED);
	soup_message_disconnect (msg);
	soup_message_issue_callback (msg);
}

static gboolean
free_header_list (gpointer name, gpointer vals, gpointer user_data)
{
	g_free (name);
	g_slist_foreach (vals, (GFunc) g_free, NULL);
	g_slist_free (vals);

	return TRUE;
}

void
soup_message_clear_headers (GHashTable *hash)
{
	g_return_if_fail (hash != NULL);

	g_hash_table_foreach_remove (hash, free_header_list, NULL);
}

void
soup_message_remove_header (GHashTable *hash, const char *name)
{
	gpointer old_key, old_vals;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (name != NULL || name[0] != '\0');

	if (g_hash_table_lookup_extended (hash, name, &old_key, &old_vals)) {
		g_hash_table_remove (hash, name);
		free_header_list (old_key, old_vals, NULL);
	}
}

void
soup_message_add_header (GHashTable *hash, const char *name, const char *value)
{
	GSList *old_value;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (name != NULL || name [0] != '\0');
	g_return_if_fail (value != NULL);

	old_value = g_hash_table_lookup (hash, name);

	if (old_value)
		g_slist_append (old_value, g_strdup (value));
	else {
		g_hash_table_insert (hash, g_strdup (name),
				     g_slist_append (NULL, g_strdup (value)));
	}
}

/**
 * soup_message_get_header:
 * @hash: a header hash table
 * @name: header name.
 * 
 * Lookup the first transport header in @hash with a key equal to
 * @name.
 * 
 * Return value: the header's value or %NULL if not found.
 */
const char *
soup_message_get_header (GHashTable *hash, const char *name)
{
	GSList *vals;

	g_return_val_if_fail (hash != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	vals = g_hash_table_lookup (hash, name);
	if (vals)
		return vals->data;

	return NULL;
}

/**
 * soup_message_get_header_list:
 * @hash: a header hash table
 * @name: header name.
 * 
 * Lookup the all transport request headers in @hash with a key equal
 * to @name.
 * 
 * Return value: a const pointer to a #GSList of header values or
 * %NULL if not found.
 */
const GSList *
soup_message_get_header_list (GHashTable *hash, const char *name)
{
	g_return_val_if_fail (hash != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	return g_hash_table_lookup (hash, name);
}

typedef struct {
	GHFunc   func;
	gpointer user_data;
} SoupMessageForeachHeaderData;

static void
foreach_value_in_list (gpointer name, gpointer value, gpointer user_data)
{
	GSList *vals = value;
	SoupMessageForeachHeaderData *data = user_data;

	while (vals) {
		(*data->func) (name, vals->data, data->user_data);
		vals = vals->next;
	}
}

void
soup_message_foreach_header (GHashTable *hash, GHFunc func, gpointer user_data)
{
	SoupMessageForeachHeaderData data;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (func != NULL);

	data.func = func;
	data.user_data = user_data;
	g_hash_table_foreach (hash, foreach_value_in_list, &data);
}

static void
queue_message (SoupMessage *req)
{
	if (!req->priv->context) {
		soup_message_set_error_full (req, 
					     SOUP_ERROR_CANCELLED,
					     "Attempted to queue a message "
					     "with no destination context");
		soup_message_issue_callback (req);
		return;
	}

	if (req->priv->status != SOUP_MESSAGE_STATUS_IDLE)
		cleanup_message (req);

	switch (req->response.owner) {
	case SOUP_BUFFER_USER_OWNED:
		soup_message_set_error_full (req, 
					     SOUP_ERROR_CANCELLED,
					     "Attempted to queue a message "
					     "with a user owned response "
					     "buffer.");
		soup_message_issue_callback (req);
		return;
	case SOUP_BUFFER_SYSTEM_OWNED:
		g_free (req->response.body);
		break;
	case SOUP_BUFFER_STATIC:
		break;
	}

	req->response.owner = 0;
	req->response.body = NULL;
	req->response.length = 0;

	soup_message_clear_headers (req->response_headers);

	req->errorcode = 0;
	req->errorclass = 0;

	if (req->errorphrase) {
		g_free ((char *) req->errorphrase);
		req->errorphrase = NULL;
	}

	soup_queue_message (req);
}

/**
 * soup_message_queue:
 * @req: a #SoupMessage.
 * @callback: a #SoupCallbackFn which will be called after the message
 * completes or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message @req for sending. All messages are processed
 * while the glib main loop runs. If this #SoupMessage has been
 * processed before, any resources related to the time it was last
 * sent are freed.
 *
 * If the response #SoupDataBuffer has an owner of
 * %SOUP_BUFFER_USER_OWNED, the message will not be queued, and
 * @callback will be called with a #SoupErrorCode of
 * %SOUP_ERROR_CANCELLED.
 *
 * Upon message completetion, the callback specified in @callback will
 * be invoked. If after returning from this callback the message has
 * not been requeued using soup_message_queue(), @req will be unreffed.
 */
void
soup_message_queue (SoupMessage    *req,
		    SoupCallbackFn  callback,
		    gpointer        user_data)
{
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	req->priv->callback = callback;
	req->priv->user_data = user_data;

	queue_message (req);
}

static void
requeue_read_error (SoupMessage *msg, gpointer user_data)
{
	soup_message_disconnect (msg);
	queue_message (msg);
}

static void
requeue_read_finished (SoupMessage *msg, char *body, guint len,
		       gpointer user_data)
{
	SoupConnection *conn = msg->priv->connection;

	g_free (body);

	g_object_ref (conn);
	soup_message_set_connection (msg, NULL);

	if (soup_connection_is_connected (conn)) {
		soup_connection_mark_old (conn);
	} else {
		g_object_unref (conn);
		conn = NULL;
	}

	queue_message (msg);
	soup_message_set_connection (msg, conn);
}

/**
 * soup_message_requeue:
 * @req: a #SoupMessage
 *
 * This causes @req to be placed back on the queue to be attempted
 * again.
 **/
void
soup_message_requeue (SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	if (req->priv->connection && req->priv->read_state) {
		soup_message_read_set_callbacks (req, NULL, NULL,
						 requeue_read_finished,
						 requeue_read_error, NULL);

		if (req->priv->write_state)
			soup_message_write_cancel (req);
	} else
		queue_message (req);
}

/**
 * soup_message_send:
 * @msg: a #SoupMessage.
 * 
 * Synchronously send @msg. This call will not return until the
 * transfer is finished successfully or there is an unrecoverable
 * error.
 *
 * @msg is not freed upon return.
 *
 * Return value: the #SoupErrorClass of the error encountered while
 * sending or reading the response.
 */
SoupErrorClass
soup_message_send (SoupMessage *msg)
{
	soup_message_queue (msg, NULL, NULL);

	while (1) {
		g_main_iteration (TRUE);

		if (msg->priv->status == SOUP_MESSAGE_STATUS_FINISHED ||
		    SOUP_ERROR_IS_TRANSPORT (msg->errorcode))
			break;

		/* Quit if soup_shutdown has been called */
		if (!soup_initialized)
			return SOUP_ERROR_CANCELLED;
	}

	return msg->errorclass;
}

void
soup_message_set_flags (SoupMessage *msg, guint flags)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	msg->priv->msg_flags = flags;
}

guint
soup_message_get_flags (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);

	return msg->priv->msg_flags;
}

void
soup_message_set_http_version  (SoupMessage *msg, SoupHttpVersion version)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	msg->priv->http_version = version;
}

SoupHttpVersion
soup_message_get_http_version (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_HTTP_1_0);

	return msg->priv->http_version;
}

gboolean
soup_message_is_keepalive (SoupMessage *msg)
{
	const char *c_conn, *s_conn;

	c_conn = soup_message_get_header (msg->request_headers, "Connection");
	s_conn = soup_message_get_header (msg->response_headers, "Connection");

	if (msg->priv->http_version == SOUP_HTTP_1_0) {
		/* Only persistent if the client requested keepalive
		 * and the server agreed.
		 */

		if (!c_conn || !s_conn)
			return FALSE;
		if (g_strcasecmp (c_conn, "Keep-Alive") != 0 ||
		    g_strcasecmp (s_conn, "Keep-Alive") != 0)
			return FALSE;

		return TRUE;
	} else {
		/* Persistent unless either side requested otherwise */

		if (c_conn && g_strcasecmp (c_conn, "close") == 0)
			return FALSE;
		if (s_conn && g_strcasecmp (s_conn, "close") == 0)
			return FALSE;

		return TRUE;
	}
}

void
soup_message_set_context (SoupMessage *msg, SoupContext *new_ctx)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	if (msg->priv->context && new_ctx) {
		const SoupUri *old, *new;

		old = soup_context_get_uri (msg->priv->context);
		new = soup_context_get_uri (new_ctx);
		if (strcmp (old->host, new->host) != 0)
			cleanup_message (msg);
	} else if (!new_ctx)
		cleanup_message (msg);

	if (new_ctx)
		g_object_ref (new_ctx);
	if (msg->priv->context)
		g_object_unref (msg->priv->context);

	msg->priv->context = new_ctx;
}

const SoupUri *
soup_message_get_uri (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return soup_context_get_uri (msg->priv->context);
}

void
soup_message_set_connection (SoupMessage *msg, SoupConnection *conn)
{
	if (conn) {
		soup_connection_set_in_use (conn, TRUE);
		g_object_ref (conn);
	}
	if (msg->priv->connection) {
		soup_connection_set_in_use (msg->priv->connection, FALSE);
		g_object_unref (msg->priv->connection);
	}

	msg->priv->connection = conn;

	if (conn) {
		msg->priv->socket = soup_connection_get_socket (conn);
		g_object_ref (msg->priv->socket);
	} else if (msg->priv->socket) {
		g_object_unref (msg->priv->socket);
		msg->priv->socket = NULL;
	}
}

SoupConnection *
soup_message_get_connection (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return msg->priv->connection;
}

SoupSocket *
soup_message_get_socket (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return msg->priv->socket;
}

void
soup_message_set_error (SoupMessage *msg, SoupKnownErrorCode errcode)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (errcode != 0);

	g_free ((char *) msg->errorphrase);

	msg->errorcode = errcode;
	msg->errorclass = soup_error_get_class (errcode);
	msg->errorphrase = g_strdup (soup_error_get_phrase (errcode));
}

void
soup_message_set_error_full (SoupMessage *msg,
			     guint        errcode,
			     const char  *errphrase)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (errcode != 0);
	g_return_if_fail (errphrase != NULL);

	g_free ((char *) msg->errorphrase);

	msg->errorcode = errcode;
	msg->errorclass = soup_error_get_class (errcode);
	msg->errorphrase = g_strdup (errphrase);
}
