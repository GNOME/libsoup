/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "soup-auth.h"
#include "soup-message.h"
#include "soup-context.h"
#include "soup-headers.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-socks.h"
#include "soup-transfer.h"

GSList *soup_active_requests = NULL;

static guint soup_queue_idle_tag = 0;

static void
soup_debug_print_a_header (gchar *key, gchar *val, gpointer not_used)
{
	g_print ("\tKEY: \"%s\", VALUE: \"%s\"\n", key, val);
}

void 
soup_debug_print_headers (SoupMessage *req)
{
	g_hash_table_foreach (req->response_headers,
			      (GHFunc) soup_debug_print_a_header,
			      NULL); 
}

static gboolean
soup_parse_headers (const GString *headers, SoupMessage *req)
{
	if (req->response_headers) 
		g_hash_table_destroy (req->response_headers);

	req->response_headers = g_hash_table_new (soup_str_case_hash, 
						  soup_str_case_equal);

	if (!soup_headers_parse_response (headers->str, 
					  headers->len, 
					  req->response_headers,
					  &req->response_code,
					  &req->response_phrase))
		goto THROW_MALFORMED_HEADER;

	return TRUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req, SOUP_ERROR_MALFORMED_HEADER);
	return FALSE;
}

static SoupTransferDone
soup_queue_read_headers_cb (const GString *headers,
			    guint         *content_len,
			    SoupMessage   *req)
{
	gchar *connection, *length, *enc;
	SoupErrorCode err = SOUP_ERROR_MALFORMED_HEADER;

	if (!soup_parse_headers (headers, req)) 
		return SOUP_TRANSFER_END;

	/* 
	 * Handle connection persistence 
	 */
	connection = g_hash_table_lookup (req->response_headers, "Connection");

	if (connection && g_strcasecmp (connection, "close") == 0)
		soup_connection_set_keep_alive (req->priv->conn, FALSE);

	if (!g_strcasecmp (req->method, "HEAD")) 
		goto RUN_HANDLERS;

	/* 
	 * Handle Content-Length or Chunked encoding 
	 */
	length = g_hash_table_lookup (req->response_headers, "Content-Length");
	enc = g_hash_table_lookup (req->response_headers, "Transfer-Encoding");

	if (length) {
		*content_len = atoi (length);
		if (*content_len < 0) 
			goto THROW_MALFORMED_HEADER;
	} else if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			*content_len = SOUP_TRANSFER_CHUNKED;
		else {
			g_warning ("Unknown encoding type in HTTP response.");
			goto THROW_MALFORMED_HEADER;
		}
	}

 RUN_HANDLERS:
	err = soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY);
	if (err) goto THROW_MALFORMED_HEADER;
	if (req->status == SOUP_STATUS_QUEUED) return FALSE;

	return SOUP_TRANSFER_CONTINUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req, err);
	return SOUP_TRANSFER_END;
}

static SoupTransferDone
soup_queue_read_chunk_cb (const SoupDataBuffer *data,
			  SoupMessage          *req)
{
	SoupErrorCode err;

	req->response.owner = data->owner;
	req->response.length = data->length;
	req->response.body = data->body;

	err = soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK);
	if (err) { 
		soup_message_issue_callback (req, err); 
		return FALSE;
	} else if (req->status == SOUP_STATUS_QUEUED) 
		return FALSE;

	return TRUE;
}

static void
soup_queue_read_done_cb (const SoupDataBuffer *data,
			 SoupMessage          *req)
{
	SoupErrorCode err;

	req->response.owner = data->owner;
	req->response.length = data->length;
	req->response.body = data->body;

	req->status = SOUP_STATUS_FINISHED;

	req->priv->read_tag = 0;

	err = soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
	if (req->status == SOUP_STATUS_QUEUED) return;
	if (err)
		soup_message_issue_callback (req, err); 
	else 
		soup_message_issue_callback (req, SOUP_ERROR_NONE);
}

static gboolean 
soup_queue_error_cb (gboolean     body_started, 
		     SoupMessage *req)
{
	/*
	gboolean conn_closed = soup_connection_is_keep_alive (req->priv->conn);
	*/

	soup_connection_set_keep_alive (req->priv->conn, FALSE);

	req->priv->read_tag = 0;
	req->priv->write_tag = 0;

	switch (req->status) {
	case SOUP_STATUS_IDLE:
	case SOUP_STATUS_QUEUED:
	case SOUP_STATUS_FINISHED:
		break;
	case SOUP_STATUS_CONNECTING:
		soup_message_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
		break;
	case SOUP_STATUS_SENDING_REQUEST:
		if (!body_started) {
			g_warning ("Requeueing request which failed in "
				   "the sending headers phase");
			soup_message_queue (req, 
					    req->priv->callback, 
					    req->priv->user_data);
			break;
		}

		soup_message_issue_callback (req, SOUP_ERROR_IO);
		break;
	case SOUP_STATUS_READING_RESPONSE:
		/* FIXME: Remove this ?? */
		/*
		if (body_started && !conn_closed) {
			soup_finish_read (req);
			break;
		}
		*/

		soup_message_issue_callback (req, SOUP_ERROR_IO);
		break;
	default:
		soup_message_issue_callback (req, SOUP_ERROR_IO);
		break;
	}

	return FALSE;
}

static void
soup_encode_http_auth (SoupMessage *msg, GString *header, gboolean proxy_auth)
{
	SoupContext *ctx;
	char *token;

	ctx = proxy_auth ? soup_get_proxy () : msg->context;

	if (ctx->auth) {
		token = soup_auth_authorize (ctx->auth, msg);
		if (token) {
			g_string_sprintfa (
				header, 
				"%s: %s\r\n",
				proxy_auth ? 
				        "Proxy-Authorization" : 
				        "Authorization",
				token);

			g_free (token);
		}
 	}
}

struct SoupUsedHeaders {
	gboolean host;
	gboolean user_agent;
	gboolean content_type;
	gboolean soapaction;
	gboolean connection;
	gboolean proxy_auth;
	gboolean auth;

	GString *out;
};

static inline void 
soup_check_used_headers (gchar *key, 
			 gchar *value, 
			 struct SoupUsedHeaders *hdrs)
{
	switch (toupper (key [0])) {
	case 'H':
		if (!g_strcasecmp (key+1, "ost")) 
			hdrs->host = TRUE;
		break;
	case 'U':
		if (!g_strcasecmp (key+1, "ser-Agent")) 
			hdrs->user_agent = TRUE;
		break;
	case 'S':
		if (!g_strcasecmp (key+1, "OAPAction")) 
			hdrs->soapaction = TRUE;
		break;
	case 'A':
		if (!g_strcasecmp (key+1, "uthorization")) 
			hdrs->auth = TRUE;
		break;
	case 'P':
		if (!g_strcasecmp (key+1, "roxy-Authorization")) 
			hdrs->proxy_auth = TRUE;
		break;
	case 'C':
		if (!g_strcasecmp (key+1, "onnection")) 
			hdrs->connection = TRUE;
		else if (!g_strcasecmp (key+1, "ontent-Type"))
			hdrs->content_type = TRUE;
		else if (!g_strcasecmp (key+1, "ontent-Length")) {
			g_warning ("Content-Length set as custom request "
				   "header is not allowed.");
			return;
		}
		break;
	}

	g_string_sprintfa (hdrs->out, "%s: %s\r\n", key, value);
}

static GString *
soup_get_request_header (SoupMessage *req)
{
	GString *header;
	gchar *uri;
	gboolean action;
	SoupContext *proxy;
	const SoupUri *suri;
	struct SoupUsedHeaders hdrs = {
		FALSE, 
		FALSE, 
		FALSE, 
		FALSE, 
		FALSE, 
		FALSE, 
		FALSE, 
		NULL
	};

	header = hdrs.out = g_string_new (NULL);
	proxy = soup_get_proxy ();
	suri = soup_context_get_uri (req->context);

	if (proxy)
		uri = soup_uri_to_string (suri, FALSE);
	else if (suri->querystring)
		uri = g_strconcat (suri->path, "?", suri->querystring, NULL);
	else
		uri = g_strdup (suri->path);

	g_string_sprintfa (header,
			   req->priv->http_version == SOUP_HTTP_1_1 ? 
			           "%s %s HTTP/1.1\r\n" : 
			           "%s %s HTTP/1.0\r\n",
			   req->method,
			   uri);

	g_free (uri);

	/*
	 * FIXME: Add a 411 "Length Required" response code handler here?
	 */
	if (req->request.length > 0) {
		g_string_sprintfa (header,
				   "Content-Length: %d\r\n",
				   req->request.length);
	}

	if (req->request_headers) 
		g_hash_table_foreach (req->request_headers, 
				      (GHFunc) soup_check_used_headers,
				      &hdrs);

	action = hdrs.soapaction || !req->action;

	/* 
	 * If we specify an absoluteURI in the request line, the Host header
	 * MUST be ignored by the proxy.  
	 */
	g_string_sprintfa (header, 
			   "%s%s%s%s%s%s%s%s%s%s",
			   hdrs.host ? "" : "Host: ",
			   hdrs.host ? "" : suri->host,
			   hdrs.host ? "" : "\r\n",
			   action ? "" : "SOAPAction: ",
			   action ? "" : req->action,
			   action ? "" : "\r\n",
			   hdrs.content_type ? "" : "Content-Type: text/xml; ",
			   hdrs.content_type ? "" : "charset=utf-8\r\n",
			   hdrs.connection ? "" : "Connection: keep-alive\r\n",
			   hdrs.user_agent ? 
			           "" : 
			           "User-Agent: Soup/" VERSION "\r\n");

	/* 
	 * Proxy-Authorization from the proxy Uri 
	 */
	if (!hdrs.proxy_auth && proxy && soup_context_get_uri (proxy)->user)
		soup_encode_http_auth (req, header, TRUE);

	/* 
	 * Authorization from the context Uri 
	 */
	if (!hdrs.auth && suri->user)
		soup_encode_http_auth (req, header, FALSE);

	g_string_append (header, "\r\n");

	return header;
}

static void 
soup_queue_write_done_cb (SoupMessage *req)
{
	GIOChannel *channel;

	channel = soup_connection_get_iochannel (req->priv->conn);

	req->priv->write_tag = 0;

	req->priv->read_tag = 
		soup_transfer_read (
			channel,
			req->priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS,
			(SoupReadHeadersDoneFn) soup_queue_read_headers_cb,
			(SoupReadChunkFn) soup_queue_read_chunk_cb,
			(SoupReadDoneFn) soup_queue_read_done_cb,
			(SoupReadErrorFn) soup_queue_error_cb,
			req);

	g_io_channel_unref (channel);

	req->status = SOUP_STATUS_READING_RESPONSE;
}

static void
soup_queue_connect_cb (SoupContext          *ctx,
		       SoupConnectErrorCode  err,
		       SoupConnection       *conn,
		       gpointer              user_data)
{
	SoupMessage *req = user_data;
	SoupProtocol proto;
	GIOChannel *channel;

	req->priv->connect_tag = NULL;

	switch (err) {
	case SOUP_CONNECT_ERROR_NONE:
		proto = soup_context_get_uri (ctx)->protocol;

		if (soup_connection_is_new (conn) &&
		    (proto == SOUP_PROTOCOL_SOCKS4 ||
		     proto == SOUP_PROTOCOL_SOCKS5)) {
			soup_connect_socks_proxy (conn, 
						  req->context, 
						  soup_queue_connect_cb,
						  req);
			return;
		}

		if (req->priv->req_header) {
			g_string_free (req->priv->req_header, TRUE);
			req->priv->req_header = NULL;
		}

		req->priv->req_header = soup_get_request_header (req);

		channel = soup_connection_get_iochannel (conn);

		req->priv->write_tag = 
			soup_transfer_write (
				channel,
				req->priv->req_header,
				&req->request,
				NULL,
				(SoupWriteDoneFn) soup_queue_write_done_cb,
				(SoupWriteErrorFn) soup_queue_error_cb,
				req);

		g_io_channel_unref (channel);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->priv->conn = conn;

		break;
	case SOUP_CONNECT_ERROR_ADDR_RESOLVE:
	case SOUP_CONNECT_ERROR_NETWORK:
		soup_message_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
		break;
	}

	return;
}

static gboolean 
soup_idle_handle_new_requests (gpointer unused)
{
        GSList *iter;

	for (iter = soup_active_requests; iter; iter = iter->next) {
		SoupMessage *req = iter->data;
		SoupContext *ctx, *proxy;

		if (req->status != SOUP_STATUS_QUEUED)
			continue;

		proxy = soup_get_proxy ();
		ctx = proxy ? proxy : req->context;

		req->status = SOUP_STATUS_CONNECTING;
		req->priv->connect_tag =
			soup_context_get_connection (ctx, 
						     soup_queue_connect_cb, 
						     req);
	}

	soup_queue_idle_tag = 0;
	return FALSE;
}

static void
soup_queue_remove_header (gchar *name, gchar *value, gpointer unused)
{
	g_free (name);
	g_free (value);
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
	g_return_if_fail (req != NULL);

	if (!soup_initialized)
		soup_load_config (NULL);

	if (!soup_queue_idle_tag)
		soup_queue_idle_tag = 
			g_idle_add (soup_idle_handle_new_requests, NULL);

	if (req->status != SOUP_STATUS_IDLE)
		soup_message_cleanup (req);

	req->priv->callback = callback;
	req->priv->user_data = user_data;

	if (req->response.owner == SOUP_BUFFER_USER_OWNED) {
		g_warning ("Attempted to queue a message with a user owned "
			   "response buffer.");
		soup_message_issue_callback (req, SOUP_ERROR_CANCELLED);
		return;
	}

	g_free (req->response.body);
	req->response.body = NULL;
	req->response.length = 0;

	if (req->response_headers) {
		g_hash_table_foreach (req->response_headers,
				      (GHFunc) soup_queue_remove_header,
				      NULL);
		g_hash_table_destroy (req->response_headers);
		req->response_headers = NULL;
	}

	if (req->response_phrase) {
		g_free (req->response_phrase);
		req->response_phrase = NULL;
	}

	req->response_code = 0;
	req->status = SOUP_STATUS_QUEUED;

	soup_active_requests = g_slist_prepend (soup_active_requests, req);
}

/**
 * soup_queue_shutdown:
 * 
 * Shut down the message queue by calling %soup_message_cancel on all active
 * requests.
 */
void 
soup_queue_shutdown (void)
{
        GSList *iter;

	g_source_remove (soup_queue_idle_tag);
	soup_queue_idle_tag = 0;

	for (iter = soup_active_requests; iter; iter = iter->next)
		soup_message_cancel (iter->data);
}
