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

	if (req->priv->connect_tag) 
		soup_context_cancel_connect (req->priv->connect_tag);
	if (req->priv->conn) 
		soup_connection_release (req->priv->conn);

	req->priv->connect_tag = NULL;
	req->priv->conn = NULL;
	req->priv->write_len = 0;
	req->priv->header_len = 0;
	req->priv->content_length = 0;
	req->priv->is_chunked = FALSE;

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

	if (req->priv->recv_buf) 
		g_byte_array_free (req->priv->recv_buf, TRUE);

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

	if (req->priv->callback)
		(*req->priv->callback) (req, 
					error, 
					req->priv->user_data);

	if (req->status != SOUP_STATUS_QUEUED) soup_message_free (req);
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
	if (!*hash) 
		*hash = g_hash_table_new (soup_str_case_hash, 
					  soup_str_case_equal);

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
soup_message_set_flags (SoupMessage *msg, guint flags)
{
	msg->priv->msg_flags = flags;
}

guint
soup_message_get_flags (SoupMessage *msg)
{
	return msg->priv->msg_flags;
}
