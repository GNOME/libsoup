/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include "soup-message.h"
#include "soup-context.h"
#include "soup-private.h"

/**
 * soup_message_new:
 * @context: a %SoupContext for the destination endpoint.
 * @action: a string which will be used as the SOAPAction header for the created
 * request.
 * 
 * Creates a new empty %SoupMessage, which will connect to the URL represented
 * by @context. The new message has a status of @SOUP_STATUS_IDLE.
 *
 * Return value: the new %SoupMessage.
 */
SoupMessage *
soup_message_new (SoupContext *context, SoupAction action) 
{
	SoupMessage *ret;
	ret          = g_new0 (SoupMessage, 1);
	ret->priv    = g_new0 (SoupMessagePrivate, 1);
	ret->status  = SOUP_STATUS_IDLE;
	ret->action  = g_strdup (action);
	ret->context = context;
	ret->method  = SOUP_METHOD_POST;

	soup_context_ref (context);

	return ret;
}

/**
 * soup_message_new_full:
 * @context: a %SoupContext for the destination endpoint.
 * @action: a string which will be used as the SOAPAction header for the created
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
		       SoupAction     action,
		       SoupOwnership  req_owner,
		       gchar         *req_body,
		       gulong         req_length)
{
	SoupMessage *ret = soup_message_new (context, action);

	ret->request.owner = req_owner;
	ret->request.body = req_body;
	ret->request.length = req_length;

	return ret;
}

#define source_remove(_src) \
        ({ if ((_src)) { g_source_remove ((_src)); (_src) = 0; }})

/**
 * soup_message_cleanup:
 * @req: a %SoupMessage.
 * @action: a string which will be used as the SOAPAction header for the created
 * request.
 * 
 * Frees any temporary resources created in the processing of @req. Request and
 * response data buffers are left intact.
 */
void 
soup_message_cleanup (SoupMessage *req)
{
	g_return_if_fail (req != NULL);

	source_remove (req->priv->read_tag);
	source_remove (req->priv->write_tag);
	source_remove (req->priv->error_tag);
	source_remove (req->priv->timeout_tag);

	if (req->priv->connect_tag) {
		soup_context_cancel_connect (req->priv->connect_tag);
		req->priv->connect_tag = NULL;
	}
	if (req->priv->conn) {
		soup_connection_release (req->priv->conn);
		req->priv->conn = NULL;
	}
	if (req->priv->recv_buf) {
		g_byte_array_free (req->priv->recv_buf, FALSE);
		req->priv->recv_buf = NULL;
	}

	req->priv->write_len = 0;
	req->priv->headers_done = FALSE;
	req->priv->content_length = 0;
	req->priv->is_chunked = FALSE;
	req->priv->cur_chunk_len = 0;
	req->priv->cur_chunk_idx = 0;

	soup_active_requests = g_slist_remove (soup_active_requests, req);
}

static void
soup_message_remove_header (gchar *name, gchar *value, gpointer unused)
{
	g_free (name);
	g_free (value);
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

	soup_context_unref (req->context);

	if (req->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->request.body);
	if (req->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->response.body);

	if (req->priv->req_header) 
		g_string_free (req->priv->req_header, TRUE);

	if (req->request_headers) {
		g_hash_table_foreach (req->request_headers,
				      (GHFunc) soup_message_remove_header,
				      NULL);
		g_hash_table_destroy (req->request_headers);
	}

	if (req->response_headers) {
		g_hash_table_foreach (req->response_headers,
				      (GHFunc) soup_message_remove_header,
				      NULL);
		g_hash_table_destroy (req->response_headers);
	}

	g_slist_foreach (req->priv->content_handlers, (GFunc) g_free, NULL);
	g_slist_free (req->priv->content_handlers);

	g_free (req->priv);
	g_free (req->action);
	g_free (req);
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
soup_message_issue_callback (SoupMessage *req, SoupErrorCode error)
{
	g_return_if_fail (req != NULL);

	/* make sure we don't have some icky recursion if the callback 
	   runs the main loop, and the connection has some data or error 
	   which causes the callback to be run again */
	soup_message_cleanup (req);

	req->priv->errorcode = error;

	if (req->priv->callback) {
		(*req->priv->callback) (req, error, req->priv->user_data);

		/* Free it only if callback exist, its probably a sync call */
		if (req->status != SOUP_STATUS_QUEUED)
			soup_message_free (req);
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
soup_message_cancel (SoupMessage *req) 
{
	soup_message_issue_callback (req, SOUP_ERROR_CANCELLED);
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

	g_hash_table_insert (*hash, g_strdup (name), g_strdup (value));
}

/**
 * soup_message_set_request_header:
 * @req: a %SoupMessage.
 * @name: header name.
 * @value: header value.
 * 
 * Adds a new transport header to be sent on an outgoing request.
 */
void
soup_message_set_request_header (SoupMessage *req,
				 const gchar *name,
				 const gchar *value) 
{
	g_return_if_fail (req != NULL);
	g_return_if_fail (name != NULL || name [0] != '\0');

	if (req->priv->req_header) {
		g_string_free (req->priv->req_header, TRUE);
		req->priv->req_header = NULL;
	}

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
 * Adds a new transport header to be sent on an outgoing response.
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
 * soup_message_send:
 * @msg: a %SoupMessage.
 * 
 * Syncronously send @msg. This call will not return until the transfer is
 * finished successfully or there is an unrecoverable error. 
 *
 * @msg is not free'd upon return.
 *
 * Return value: the %SoupErrorCode of the error encountered while sending, or
 * SOUP_ERROR_NONE.
 */
SoupErrorCode 
soup_message_send (SoupMessage *msg)
{
	soup_message_queue (msg, NULL, NULL);

	while (1) {
		g_main_iteration (TRUE); 
		if (msg->status == SOUP_STATUS_FINISHED ||
		    msg->priv->errorcode != SOUP_ERROR_NONE)
			return msg->priv->errorcode;
	}

	return SOUP_ERROR_NONE;
}

void
soup_message_set_method (SoupMessage *msg, const gchar *method)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (method != NULL);

	msg->method = method;
}

const gchar *
soup_message_get_method (SoupMessage *msg)
{
	g_return_val_if_fail (msg != NULL, NULL);

	return msg->method;
}

typedef enum {
	RESPONSE_HEADER_HANDLER,
	RESPONSE_CODE_HANDLER,
	RESPONSE_BODY_HANDLER
} SoupHandlerKind;

typedef struct {
	SoupHandlerType   type;
	SoupHandlerFn     handler_cb;
	gpointer          user_data;

	SoupHandlerKind   kind;
	const gchar      *header;
	guint             code;
} SoupHandlerData;

static void 
soup_message_add_handler (SoupMessage      *msg,
			  SoupHandlerType   type,
			  SoupHandlerFn     handler_cb,
			  gpointer          user_data,
			  SoupHandlerKind   kind,
			  const gchar      *header,
			  guint             code)
{
	SoupHandlerData *data;

	data = g_new0 (SoupHandlerData, 1);
	data->type = type;
	data->handler_cb = handler_cb;
	data->user_data = user_data;
	data->kind = kind;
	data->header = header;
	data->code = code;

	msg->priv->content_handlers = 
		g_slist_append (msg->priv->content_handlers, data);
}

void 
soup_message_add_header_handler (SoupMessage      *msg,
				 const gchar      *header,
				 SoupHandlerType   type,
				 SoupHandlerFn     handler_cb,
				 gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (header != NULL);
	g_return_if_fail (handler_cb != NULL);

	soup_message_add_handler (msg, 
				  type, 
				  handler_cb, 
				  user_data, 
				  RESPONSE_HEADER_HANDLER, 
				  header, 
				  0);
}

void 
soup_message_add_response_code_handler (SoupMessage      *msg,
					guint             code,
					SoupHandlerType   type,
					SoupHandlerFn     handler_cb,
					gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (code != 0);
	g_return_if_fail (handler_cb != NULL);

	soup_message_add_handler (msg, 
				  type, 
				  handler_cb, 
				  user_data, 
				  RESPONSE_CODE_HANDLER, 
				  NULL, 
				  code);
}

void 
soup_message_add_body_handler (SoupMessage      *msg,
			       SoupHandlerType   type,
			       SoupHandlerFn     handler_cb,
			       gpointer          user_data)
{
	g_return_if_fail (msg != NULL);
	g_return_if_fail (handler_cb != NULL);

	soup_message_add_handler (msg, 
				  type, 
				  handler_cb, 
				  user_data, 
				  RESPONSE_BODY_HANDLER, 
				  NULL, 
				  0);
}

SoupErrorCode 
soup_message_run_handlers (SoupMessage *msg, SoupHandlerType invoke_type)
{
	GSList *list;
	SoupErrorCode retval = SOUP_ERROR_NONE;

	g_return_val_if_fail (msg != NULL, retval);
	
	for (list = msg->priv->content_handlers; list; list = list->next) {
		SoupHandlerData *data = list->data;
		
		if (data->type != invoke_type) continue;

		switch (data->kind) {
		case RESPONSE_HEADER_HANDLER:
			if (!soup_message_get_response_header (msg,
							       data->header))
				continue;
			break;
		case RESPONSE_CODE_HANDLER:
			if (msg->response_code != data->code) continue;
			break;
		case RESPONSE_BODY_HANDLER:
			break;
		}

		retval = (*data->handler_cb) (msg, data->user_data);

		if (retval != SOUP_ERROR_NONE) break;
		if (msg->status == SOUP_STATUS_QUEUED) break;
	}

	return retval;
}

static void
soup_message_remove_handler (SoupMessage   *msg, 
			     SoupHandlerFn  handler_cb,
			     gpointer       user_data)
{
	GSList *iter = msg->priv->content_handlers;

	while (iter) {
		SoupHandlerData *data = iter->data;

		if (data->handler_cb == handler_cb &&
		    data->user_data == user_data) {
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

static SoupErrorCode 
soup_message_redirect (SoupMessage *msg, gpointer user_data)
{
	const gchar *new_url;

	switch (msg->response_code) {
	case 300: /* Multiple Choices */
	case 301: /* Moved Permanently */
	case 302: /* Moved Temporarily */
	case 303: /* See Other */
	case 305: /* Use Proxy */
		break;
	default:
		return SOUP_ERROR_NONE;
	}

	if (!(msg->priv->msg_flags & SOUP_MESSAGE_FOLLOW_REDIRECT)) 
		return SOUP_ERROR_NONE;

	new_url = soup_message_get_response_header (msg, "Location");
	if (new_url) {
		soup_context_unref (msg->context);
		msg->context = soup_context_get (new_url);

		if (!msg->context) return SOUP_ERROR_MALFORMED_HEADER;

		soup_message_queue (msg,
				    msg->priv->callback, 
				    msg->priv->user_data);
	}

	return SOUP_ERROR_NONE;
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

	if (ADDED_FLAG (msg, flags, SOUP_MESSAGE_FOLLOW_REDIRECT))
		soup_message_add_header_handler (msg,
						 "Location",
						 SOUP_HANDLER_PRE_BODY,
						 soup_message_redirect,
						 NULL);
	else if (REMOVED_FLAG (msg, flags, SOUP_MESSAGE_FOLLOW_REDIRECT))
		soup_message_remove_handler (msg, 
					     soup_message_redirect,
					     NULL);

	msg->priv->msg_flags = flags;
}

guint
soup_message_get_flags (SoupMessage *msg)
{
	return msg->priv->msg_flags;
}
