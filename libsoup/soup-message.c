/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include "soup-auth.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-context.h"
#include "soup-private.h"
#include "soup-queue.h"
#include "soup-transfer.h"

/**
 * soup_message_new:
 * @context: a %SoupContext for the destination endpoint.
 * @method: a string which will be used as the HTTP method for the created
 * request.
 * 
 * Creates a new empty %SoupMessage, which will connect to the URL represented
 * by @context. The new message has a status of @SOUP_STATUS_IDLE.
 *
 * Return value: the new %SoupMessage.
 */
SoupMessage *
soup_message_new (SoupContext *context, const gchar *method) 
{
	SoupMessage *ret;

	g_return_val_if_fail (context, NULL);

	ret          = g_new0 (SoupMessage, 1);
	ret->priv    = g_new0 (SoupMessagePrivate, 1);
	ret->status  = SOUP_STATUS_IDLE;
	ret->context = context;
	ret->method  = method ? method : SOUP_METHOD_POST;

	ret->priv->http_version = SOUP_HTTP_1_1;

	soup_context_ref (context);

	return ret;
}

/**
 * soup_message_new_full:
 * @context: a %SoupContext for the destination endpoint.
 * @method: a string which will be used as the HTTP method for the created
 * request.
 * @req_owner: the %SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message request.
 * @req_length: the byte length of @req_body.
 * 
 * Creates a new %SoupMessage, which will connect to the URL represented by
 * @context. The new message has a status of @SOUP_STATUS_IDLE. The request data
 * buffer will be filled from @req_owner, @req_body, and @req_length
 * respectively.
 *
 * Return value: the new %SoupMessage.
 */
SoupMessage *
soup_message_new_full (SoupContext   *context,
		       const gchar   *method,
		       SoupOwnership  req_owner,
		       gchar         *req_body,
		       gulong         req_length)
{
	SoupMessage *ret = soup_message_new (context, method);

	ret->request.owner = req_owner;
	ret->request.body = req_body;
	ret->request.length = req_length;

	return ret;
}

/**
 * soup_message_cleanup:
 * @req: a %SoupMessage.
 * 
 * Frees any temporary resources created in the processing of @req. Request and
 * response data buffers are left intact.
 */
void 
soup_message_cleanup (SoupMessage *req)
{
	g_return_if_fail (req != NULL);

	if (req->priv->read_tag) {
		soup_transfer_read_cancel (req->priv->read_tag);
		req->priv->read_tag = 0;
	}

	if (req->priv->write_tag) {
		soup_transfer_write_cancel (req->priv->write_tag);
		req->priv->write_tag = 0;
	}

	if (req->priv->connect_tag) {
		soup_context_cancel_connect (req->priv->connect_tag);
		req->priv->connect_tag = NULL;
	}
	if (req->connection) {
		soup_connection_release (req->connection);
		req->connection = NULL;
	}

	soup_active_requests = g_slist_remove (soup_active_requests, req);
}

static void
free_header (gchar *name, gchar *value, gpointer unused)
{
	g_free (name);
	g_free (value);
}

static void
finalize_message (SoupMessage *req)
{
	soup_context_unref (req->context);

	if (req->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->request.body);
	if (req->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->response.body);

	if (req->priv->req_header) 
		g_string_free (req->priv->req_header, TRUE);

	if (req->request_headers) {
		g_hash_table_foreach (req->request_headers,
				      (GHFunc) free_header,
				      NULL);
		g_hash_table_destroy (req->request_headers);
	}

	if (req->response_headers) {
		g_hash_table_foreach (req->response_headers,
				      (GHFunc) free_header,
				      NULL);
		g_hash_table_destroy (req->response_headers);
	}

	g_slist_foreach (req->priv->content_handlers, (GFunc) g_free, NULL);
	g_slist_free (req->priv->content_handlers);

	g_free ((gchar *) req->errorphrase);
	g_free (req->priv);
	g_free (req);
}

/**
 * soup_message_free:
 * @req: a %SoupMessage to destroy.
 * 
 * Destroys the %SoupMessage pointed to by @req. Request and response headers
 * are freed. Request and response data buffers are also freed if their
 * ownership is %SOUP_BUFFER_SYSTEM_OWNED. The message's destination context
 * will be de-referenced.
 */
void 
soup_message_free (SoupMessage *req)
{
	g_return_if_fail (req != NULL);

	soup_message_cleanup (req);

	finalize_message (req);
}

/**
 * soup_message_issue_callback:
 * @req: a %SoupMessage currently being processed.
 * @error: a %SoupErrorCode to be passed to %req's completion callback.
 * 
 * Finalizes the message request, by first freeing any temporary resources, then
 * issuing the callback function pointer passed in %soup_message_new or
 * %soup_message_new_full. If, after returning from the callback, the message
 * has not been requeued, @msg is destroyed using %soup_message_free.
 */
void
soup_message_issue_callback (SoupMessage *req)
{
	g_return_if_fail (req != NULL);

	/* 
	 * Make sure we don't have some icky recursion if the callback 
	 * runs the main loop, and the connection has some data or error 
	 * which causes the callback to be run again.
	 */
	soup_message_cleanup (req);

	if (req->priv->callback) {
		(*req->priv->callback) (req, req->priv->user_data);

		if (req->status != SOUP_STATUS_QUEUED)
			finalize_message (req);
	}
}

/**
 * soup_message_cancel:
 * @req: a %SoupMessage currently being processed.
 * 
 * Cancel a running message, and issue completion callback with a
 * %SoupTransferStatus of %SOUP_ERROR_CANCELLED. If not requeued by the
 * completion callback, the @msg will be destroyed.
 */
void 
soup_message_cancel (SoupMessage *msg) 
{
	soup_message_set_error (msg, SOUP_ERROR_CANCELLED);
	soup_message_issue_callback (msg);
}

static void 
soup_message_set_header (GHashTable  **hash,
			 const gchar  *name,
			 const gchar  *value) 
{
	gpointer old_name, old_value;

	if (!*hash) 
		*hash = g_hash_table_new (soup_str_case_hash, 
					  soup_str_case_equal);
	else if (g_hash_table_lookup_extended (*hash, 
					       name, 
					       &old_name, 
					       &old_value)) {
		g_hash_table_remove (*hash, name);
		g_free (old_name);
		g_free (old_value);
	}

	if (value)
		g_hash_table_insert (*hash, g_strdup (name), g_strdup (value));
}

/**
 * soup_message_set_request_header:
 * @req: a %SoupMessage.
 * @name: header name.
 * @value: header value.
 * 
 * Adds a new transport header to be sent on an outgoing request. Passing a NULL
 * @value will remove the header name supplied.
 */
void
soup_message_set_request_header (SoupMessage *req,
				 const gchar *name,
				 const gchar *value) 
{
	g_return_if_fail (req != NULL);
	g_return_if_fail (name != NULL || name [0] != '\0');

	soup_message_set_header (&req->request_headers, name, value);
}

/**
 * soup_message_get_request_header:
 * @req: a %SoupMessage.
 * @name: header name.
 * 
 * Lookup the transport request header with a key equal to @name.
 *
 * Return value: the header's value or NULL if not found.
 */
const gchar *
soup_message_get_request_header (SoupMessage *req,
				 const gchar *name) 
{
	g_return_val_if_fail (req != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	return req->request_headers ? 
		g_hash_table_lookup (req->request_headers, name) : NULL;
}

/**
 * soup_message_set_response_header:
 * @req: a %SoupMessage.
 * @name: header name.
 * @value: header value.
 * 
 * Adds a new transport header to be sent on an outgoing response. Passing a
 * NULL @value will remove the header name supplied.
 */
void
soup_message_set_response_header (SoupMessage *req,
				  const gchar *name,
				  const gchar *value) 
{
	g_return_if_fail (req != NULL);
	g_return_if_fail (name != NULL || name [0] != '\0');

	soup_message_set_header (&req->response_headers, name, value);
}

/**
 * soup_message_get_response_header:
 * @req: a %SoupMessage.
 * @name: header name.
 * 
 * Lookup the transport response header with a key equal to @name.
 *
 * Return value: the header's value or NULL if not found.
 */
const gchar *
soup_message_get_response_header (SoupMessage *req,
				  const gchar *name) 
{
	g_return_val_if_fail (req != NULL, NULL);
	g_return_val_if_fail (name != NULL || name [0] != '\0', NULL);

	return req->response_headers ? 
		g_hash_table_lookup (req->response_headers, name) : NULL;
}

/**
 * soup_message_queue:
 * @req: a %SoupMessage.
 * @callback: a %SoupCallbackFn which will be called after the message completes
 * or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message @req for sending. All messages are processed while the
 * glib main loop runs. If this %SoupMessage has been processed before, any
 * resources related to the time it was last sent are freed.
 *
 * If the response %SoupDataBuffer has an owner of %SOUP_BUFFER_USER_OWNED, the
 * message will not be queued, and @callback will be called with a
 * %SoupErrorCode of %SOUP_ERROR_CANCELLED.
 *
 * Upon message completetion, the callback specified in @callback will be
 * invoked. If after returning from this callback the message has not been
 * requeued using %soup_message_queue, %soup_message_free will be called on
 * @req.
 */
void 
soup_message_queue (SoupMessage    *req,
		    SoupCallbackFn  callback, 
		    gpointer        user_data)
{
	soup_queue_message (req, callback, user_data);
}

/**
 * soup_message_send:
 * @msg: a %SoupMessage.
 * 
 * Syncronously send @msg. This call will not return until the transfer is
 * finished successfully or there is an unrecoverable error. 
 *
 * @msg is not free'd upon return.
 *
 * Return value: the %SoupErrorClass of the error encountered while sending or
 * reading the response.
 */
SoupErrorClass
soup_message_send (SoupMessage *msg)
{
	soup_message_queue (msg, NULL, NULL);

	while (1) {
		g_main_iteration (TRUE); 
		if (msg->status == SOUP_STATUS_FINISHED || 
		    msg->errorcode != 0)
			break;
	}

	return msg->errorclass;
}

static void 
authorize_handler (SoupMessage *msg, gboolean proxy)
{
	const char *auth_header;
	SoupAuth *auth;
	SoupContext *ctx;

	ctx = proxy ? soup_get_proxy () : msg->context;

	if (!soup_context_get_uri (ctx)->user) 
		goto THROW_CANT_AUTHENTICATE;

	auth_header = 
		soup_message_get_response_header (
			msg, 
			proxy ? "Proxy-Authenticate" : "WWW-Authenticate");
	if (!auth_header) goto THROW_CANT_AUTHENTICATE;

        auth = soup_auth_new_from_header (ctx, auth_header);
	if (!auth) {
		soup_message_set_error_full (
			msg, 
			proxy ? 
			        SOUP_ERROR_CANT_AUTHENTICATE_PROXY : 
			        SOUP_ERROR_CANT_AUTHENTICATE,
			proxy ? 
			        "Unknown authentication scheme "
			        "required by proxy" :
			        "Unknown authentication scheme "
			        "required");
		return;
	}

	if (ctx->auth) {
		if (soup_auth_invalidates_prior (auth, ctx->auth))
			soup_auth_free (ctx->auth);
		else {
			soup_auth_free (auth);
			goto THROW_CANT_AUTHENTICATE;
		}
	}

	ctx->auth = auth;

	soup_message_queue (msg, msg->priv->callback, msg->priv->user_data);

        return;

 THROW_CANT_AUTHENTICATE:
	soup_message_set_error (msg, 
				proxy ? 
			                SOUP_ERROR_CANT_AUTHENTICATE_PROXY : 
			                SOUP_ERROR_CANT_AUTHENTICATE);
}

static void 
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	const gchar *new_url;

	if (msg->errorclass != SOUP_ERROR_CLASS_REDIRECT || 
	    msg->priv->msg_flags & SOUP_MESSAGE_NO_REDIRECT) return;

	new_url = soup_message_get_response_header (msg, "Location");

	if (new_url) {
		SoupContext *new_ctx, *old_ctx;

		new_ctx = soup_context_get (new_url);
		if (!new_ctx) {
			soup_message_set_error_full (msg, 
						     SOUP_ERROR_MALFORMED,
						     "Invalid Redirect URL");
			return;
		}

		old_ctx = msg->context;
		msg->context = new_ctx;

		soup_message_queue (msg,
				    msg->priv->callback, 
				    msg->priv->user_data);

		soup_context_unref (old_ctx);
	}
}

typedef enum {
	RESPONSE_HEADER_HANDLER = 1,
	RESPONSE_ERROR_CODE_HANDLER,
	RESPONSE_ERROR_CLASS_HANDLER
} SoupHandlerKind;

typedef struct {
	SoupHandlerType   type;
	SoupCallbackFn    handler_cb;
	gpointer          user_data;

	SoupHandlerKind   kind;
	union {
		guint             errorcode;
		SoupErrorClass    errorclass;
		const gchar      *header;
	} data;
} SoupHandlerData;

static SoupHandlerData global_handlers [] = {
	/* 
	 * Handle authorization.
	 */
	{
		SOUP_HANDLER_PRE_BODY,
		(SoupCallbackFn) authorize_handler, 
		GINT_TO_POINTER (FALSE), 
		RESPONSE_ERROR_CODE_HANDLER, 
		{ 401 }
	},
	/* 
	 * Handle proxy authorization.
	 */
	{
		SOUP_HANDLER_PRE_BODY,
		(SoupCallbackFn) authorize_handler, 
		GINT_TO_POINTER (TRUE), 
		RESPONSE_ERROR_CODE_HANDLER, 
		{ 407 }
	},
	/* 
	 * Handle redirect response codes 300, 301, 302, 303, and 305.
	 */
	{
		SOUP_HANDLER_PRE_BODY,
		redirect_handler, 
		NULL, 
		RESPONSE_HEADER_HANDLER, 
		{ (guint) "Location" }
	},
	{ 0 }
};

static inline void 
run_handler (SoupMessage     *msg, 
	     SoupHandlerType  invoke_type, 
	     SoupHandlerData *data)
{
	if (data->type != invoke_type) return;

	switch (data->kind) {
	case RESPONSE_HEADER_HANDLER:
		if (!soup_message_get_response_header (msg,
						       data->data.header))
			return;
		break;
	case RESPONSE_ERROR_CODE_HANDLER:
		if (msg->errorcode != data->data.errorcode) return;
		break;
	case RESPONSE_ERROR_CLASS_HANDLER:
		if (msg->errorclass != data->data.errorclass) return;
		break;
	default:
		break;
	}

	(*data->handler_cb) (msg, data->user_data);
}

/*
 * Run each handler with matching criteria (first per-message then global
 * handlers). If a handler requeues a message, we stop processing and terminate
 * the current request. 
 *
 * After running all handlers, if there is an error set or the invoke type was
 * post_body, issue the final callback.  
 *
 * FIXME: If the errorcode is changed by a handler, we should restart the
 * processing.  
 */
gboolean
soup_message_run_handlers (SoupMessage *msg, SoupHandlerType invoke_type)
{
	GSList *list;
	SoupHandlerData *data;

	g_return_val_if_fail (msg != NULL, FALSE);

	for (list = msg->priv->content_handlers; list; list = list->next) {
		data = list->data;

		run_handler (msg, invoke_type, data);

		if (msg->status == SOUP_STATUS_QUEUED) return TRUE;
	}

	for (data = global_handlers; data->type; data++) {
		run_handler (msg, invoke_type, data);

		if (msg->status == SOUP_STATUS_QUEUED) return TRUE;
	}

	/*
	 * Issue final callback if the invoke_type is POST_BODY and the error
	 * class is not INFORMATIONAL. 
	 */
	if (invoke_type == SOUP_HANDLER_POST_BODY && 
	    msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL) {
		soup_message_issue_callback (msg);
		return TRUE;
	}

	return FALSE;
}

static void 
add_handler (SoupMessage      *msg,
	     SoupHandlerType   type,
	     SoupCallbackFn    handler_cb,
	     gpointer          user_data,
	     SoupHandlerKind   kind,
	     const gchar      *header,
	     guint             errorcode,
	     guint             errorclass)
{
	SoupHandlerData *data;

	data = g_new0 (SoupHandlerData, 1);
	data->type = type;
	data->handler_cb = handler_cb;
	data->user_data = user_data;
	data->kind = kind;

	switch (kind) {
	case RESPONSE_HEADER_HANDLER:
		data->data.header = header;
		break;
	case RESPONSE_ERROR_CODE_HANDLER:
		data->data.errorcode = errorcode;
		break;
	case RESPONSE_ERROR_CLASS_HANDLER:
		data->data.errorclass = errorclass;
		break;
	default:
		break;
	}

	msg->priv->content_handlers = 
		g_slist_append (msg->priv->content_handlers, data);
}

void 
soup_message_add_header_handler (SoupMessage      *msg,
				 const gchar      *header,
				 SoupHandlerType   type,
				 SoupCallbackFn    handler_cb,
				 gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (header != NULL);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, 
		     type, 
		     handler_cb, 
		     user_data, 
		     RESPONSE_HEADER_HANDLER, 
		     header, 
		     0,
		     0);
}

void 
soup_message_add_error_code_handler (SoupMessage      *msg,
				     guint             errorcode,
				     SoupHandlerType   type,
				     SoupCallbackFn    handler_cb,
				     gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (errorcode != 0);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, 
		     type, 
		     handler_cb, 
		     user_data, 
		     RESPONSE_ERROR_CODE_HANDLER, 
		     NULL, 
		     errorcode,
		     0);
}

void 
soup_message_add_error_class_handler (SoupMessage      *msg,
				      SoupErrorClass    errorclass,
				      SoupHandlerType   type,
				      SoupCallbackFn    handler_cb,
				      gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (errorclass != 0);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, 
		     type, 
		     handler_cb, 
		     user_data, 
		     RESPONSE_ERROR_CLASS_HANDLER, 
		     NULL, 
		     0,
		     errorclass);
}

void 
soup_message_add_handler (SoupMessage      *msg,
			  SoupHandlerType   type,
			  SoupCallbackFn    handler_cb,
			  gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (handler_cb != NULL);

	add_handler (msg, 
		     type, 
		     handler_cb, 
		     user_data, 
		     0, 
		     NULL, 
		     0,
		     0);
}

void
soup_message_remove_handler (SoupMessage     *msg, 
			     SoupHandlerType  type,
			     SoupCallbackFn   handler_cb,
			     gpointer         user_data)
{
	GSList *iter = msg->priv->content_handlers;

	while (iter) {
		SoupHandlerData *data = iter->data;

		if (data->handler_cb == handler_cb &&
		    data->user_data == user_data &&
		    data->type == type) {
			msg->priv->content_handlers = 
				g_slist_remove_link (
					msg->priv->content_handlers,
					iter);
			g_free (data);
			break;
		}
		
		iter = iter->next;
	}
}

static inline gboolean
ADDED_FLAG (SoupMessage *msg, guint newflags, SoupMessageFlags find)
{
	return ((newflags & find) && !(msg->priv->msg_flags & find));
}

static inline gboolean
REMOVED_FLAG (SoupMessage *msg, guint newflags, SoupMessageFlags find)
{
	return (!(newflags & find) && (msg->priv->msg_flags & find));
}

void
soup_message_set_flags (SoupMessage *msg, guint flags)
{
	g_return_if_fail (msg != NULL);

	msg->priv->msg_flags = flags;
}

guint
soup_message_get_flags (SoupMessage *msg)
{
	g_return_val_if_fail (msg != NULL, 0);

	return msg->priv->msg_flags;
}

void 
soup_message_set_http_version  (SoupMessage *msg, SoupHttpVersion version)
{
	g_return_if_fail (msg != NULL);

	msg->priv->http_version = version;
}

void
soup_message_set_error (SoupMessage *msg, SoupKnownErrorCode errcode)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (errcode != 0);

	g_free ((gchar *) msg->errorphrase);

	msg->errorcode = errcode;
	msg->errorclass = soup_get_error_class (errcode);
	msg->errorphrase = g_strdup (soup_get_error_phrase (errcode));
}

void
soup_message_set_error_full (SoupMessage *msg, 
			     guint        errcode, 
			     const gchar *errphrase)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (errcode != 0);
	g_return_if_fail (errphrase != NULL);

	g_free ((gchar *) msg->errorphrase);

	msg->errorcode = errcode;
	msg->errorclass = soup_get_error_class (errcode);
	msg->errorphrase = g_strdup (errphrase);
}

void
soup_message_set_handler_error (SoupMessage *msg, 
				guint        errcode, 
				const gchar *errphrase)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (errcode != 0);
	g_return_if_fail (errphrase != NULL);

	g_free ((gchar *) msg->errorphrase);

	msg->errorcode = errcode;
	msg->errorclass = SOUP_ERROR_CLASS_HANDLER;
	msg->errorphrase = g_strdup (errphrase);
}

struct {
	guint sc;
	const gchar *phrase;
} error_code_phrases [] = {
	/* 
	 * SOUP_ERROR_CLASS_TRANSPORT 
	 */
	{ SOUP_ERROR_CANCELLED,               "Cancelled" },
	{ SOUP_ERROR_CANT_CONNECT,            "Cannot connect to destination" },
	{ SOUP_ERROR_CANT_CONNECT_PROXY,      "Cannot connect to proxy" },
	{ SOUP_ERROR_IO,                      "Connection terminated "
	                                      "unexpectadly" },
	{ SOUP_ERROR_MALFORMED,               "Message Corrupt" },
	{ SOUP_ERROR_CANT_AUTHENTICATE,       "Authentication Failed" },
	{ SOUP_ERROR_CANT_AUTHENTICATE_PROXY, "Proxy Authentication Failed" },

	/* 
	 * SOUP_ERROR_CLASS_INFORMATIONAL 
	 */
	{ SOUP_ERROR_CONTINUE,        "Continue" },
	{ SOUP_ERROR_PROTOCOL_SWITCH, "Protocol Switch" },
	{ SOUP_ERROR_DAV_PROCESSING,  "Processing" },

	/* 
	 * SOUP_ERROR_CLASS_SUCCESS 
	 */
	{ SOUP_ERROR_OK,                "OK" },
	{ SOUP_ERROR_CREATED,           "Created" },
	{ SOUP_ERROR_ACCEPTED,          "Accepted" },
	{ SOUP_ERROR_NON_AUTHORITATIVE, "Non-Authoritative" },
	{ SOUP_ERROR_NO_CONTENT,        "No Content" },
	{ SOUP_ERROR_RESET_CONTENT,     "Reset Content" },
	{ SOUP_ERROR_PARTIAL_CONTENT,   "Partial Content" },
	{ SOUP_ERROR_DAV_MULTISTATUS,   "Multi-Status" },

	/* 
	 * SOUP_ERROR_CLASS_REDIRECT 
	 */
	{ SOUP_ERROR_MULTIPLE_CHOICES,   "Multiple Choices" },
	{ SOUP_ERROR_MOVED_PERMANANTLY,  "Moved Permanantly" },
	{ SOUP_ERROR_FOUND,              "Found" },
	{ SOUP_ERROR_SEE_OTHER,          "See Other" },
	{ SOUP_ERROR_NOT_MODIFIED,       "Not Modified" },
	{ SOUP_ERROR_USE_PROXY,          "Use Proxy" },
	{ SOUP_ERROR_TEMPORARY_REDIRECT, "Temporary Redirect" },

	/* 
	 * SOUP_ERROR_CLASS_CLIENT_ERROR 
	 */
	{ SOUP_ERROR_BAD_REQUEST,           "Bad Request" },
	{ SOUP_ERROR_UNAUTHORIZED,          "Unauthorized" },
	{ SOUP_ERROR_PAYMENT_REQUIRED,      "Payment Required" },
	{ SOUP_ERROR_FORBIDDEN,             "Forbidden" },
	{ SOUP_ERROR_NOT_FOUND,             "Not Found" },
	{ SOUP_ERROR_METHOD_NOT_ALLOWED,    "Method Not Allowed" },
	{ SOUP_ERROR_NOT_ACCEPTABLE,        "Not Acceptable" },
	{ SOUP_ERROR_PROXY_UNAUTHORIZED,    "Proxy Unauthorized" },
	{ SOUP_ERROR_TIMED_OUT,             "Timed Out" },
	{ SOUP_ERROR_CONFLICT,              "Conflict" },
	{ SOUP_ERROR_GONE,                  "Gone" },
	{ SOUP_ERROR_LENGTH_REQUIRED,       "Length Required" },
	{ SOUP_ERROR_PRECONDITION_FAILED,   "Precondition Failed" },
	{ SOUP_ERROR_BODY_TOO_LARGE,        "Entity Body Too Large" },
	{ SOUP_ERROR_URI_TOO_LARGE,         "Request-URI Too Large" },
	{ SOUP_ERROR_UNKNOWN_MEDIA_TYPE,    "Unknown Media Type" },
	{ SOUP_ERROR_INVALID_RANGE,         "Invalid Range" },
	{ SOUP_ERROR_EXPECTATION_FAILED,    "Expectation Failed" },
	{ SOUP_ERROR_DAV_UNPROCESSABLE,     "Unprocessable Entity" },
	{ SOUP_ERROR_DAV_LOCKED,            "Locked" },
	{ SOUP_ERROR_DAV_DEPENDENCY_FAILED, "Dependency Failed" },

	/* 
	 * SOUP_ERROR_CLASS_SERVER_ERROR 
	 */
	{ SOUP_ERROR_INTERNAL,            "Internal Server Error" },
	{ SOUP_ERROR_NOT_IMPLEMENTED,     "Not Implemented" },
	{ SOUP_ERROR_BAD_GATEWAY,         "Bad Gateway" },
	{ SOUP_ERROR_SERVICE_UNAVAILABLE, "Service Unavailable" },
	{ SOUP_ERROR_GATEWAY_TIMEOUT,     "Gateway Timeout" },
	{ SOUP_ERROR_VERSION_UNSUPPORTED, "Version Unsupported" },
	{ SOUP_ERROR_DAV_OUT_OF_SPACE,    "Out Of Space" },

	{ 0 }
};

const gchar *
soup_get_error_phrase (SoupKnownErrorCode errcode)
{
	gint i;

	for (i = 0; error_code_phrases [i].sc; i++) {
		if (error_code_phrases [i].sc == (guint) errcode)
			return error_code_phrases [i].phrase;
	}

	return "Unknown Error";
}

SoupErrorClass
soup_get_error_class (SoupKnownErrorCode errcode)
{
	if (errcode < 100) return SOUP_ERROR_CLASS_TRANSPORT;
	if (errcode < 200) return SOUP_ERROR_CLASS_INFORMATIONAL;
	if (errcode < 300) return SOUP_ERROR_CLASS_SUCCESS;
	if (errcode < 400) return SOUP_ERROR_CLASS_REDIRECT;
	if (errcode < 500) return SOUP_ERROR_CLASS_CLIENT_ERROR;
	if (errcode < 600) return SOUP_ERROR_CLASS_SERVER_ERROR;
	return SOUP_ERROR_CLASS_UNKNOWN;
}
