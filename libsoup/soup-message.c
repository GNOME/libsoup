/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include "soup-message.h"
#include "soup-queue.h"
#include "soup-context.h"
#include "soup-private.h"

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

void 
soup_message_free (SoupMessage *req)
{
	g_return_if_fail (req != NULL);

	soup_message_cleanup (req);

	soup_context_unref (req->context);

	if (req->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->request.body);

	if (req->priv->req_header) 
		g_string_free (req->priv->req_header, TRUE);
	if (req->request_headers) 
		g_hash_table_destroy (req->request_headers);
	if (req->response_headers) 
		g_hash_table_destroy (req->response_headers);
	if (req->priv->recv_buf) 
		g_byte_array_free (req->priv->recv_buf, TRUE);

	g_free (req->priv);
	g_free (req->action);
	g_free (req);
}

void
soup_message_issue_callback (SoupMessage *req, SoupErrorCode error)
{
	g_return_if_fail (req != NULL);

	/* make sure we don't have some icky recursion if the callback 
	   runs the main loop, and the connection has some data or error 
	   which causes the callback to be run again */
	soup_message_cleanup (req);

	if (req->priv->callback)
		(*req->priv->callback) (req, 
					error, 
					req->priv->user_data);

	if (req->status != SOUP_STATUS_QUEUED) soup_message_free (req);
}

void 
soup_message_cancel (SoupMessage *req) 
{
	soup_message_issue_callback (req, SOUP_ERROR_CANCELLED);
}

void
soup_message_add_header (SoupMessage *req,
			 gchar       *name,
			 gchar       *value) 
{
	g_return_if_fail (req != NULL);

	if (!req->request_headers)
		req->request_headers = g_hash_table_new (soup_str_case_hash, 
							 soup_str_case_equal);

	if (req->priv->req_header)
		g_string_free (req->priv->req_header, TRUE);

	req->priv->req_header = NULL;

	g_hash_table_insert (req->request_headers, name, value);
}
