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

#include "soup-queue.h"
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
soup_debug_print_a_header (gchar *key, GSList *vals, gpointer not_used)
{
	while (vals) {
		g_print ("\tKEY: \"%s\", VALUE: \"%s\"\n", 
			 key, 
			 (gchar *) vals->data);
		vals = vals->next;
	}
}

void 
soup_debug_print_headers (SoupMessage *req)
{
	g_hash_table_foreach (req->response_headers,
			      (GHFunc) soup_debug_print_a_header,
			      NULL); 
}

static void 
soup_queue_error_cb (gboolean body_started, gpointer user_data)
{
	SoupMessage *req = user_data;

	soup_connection_set_keep_alive (req->connection, FALSE);

	req->priv->read_tag = 0;
	req->priv->write_tag = 0;

	switch (req->status) {
	case SOUP_STATUS_IDLE:
	case SOUP_STATUS_QUEUED:
	case SOUP_STATUS_FINISHED:
		break;

	case SOUP_STATUS_CONNECTING:
		soup_message_set_error (req, SOUP_ERROR_CANT_CONNECT);
		soup_message_issue_callback (req);
		break;

	case SOUP_STATUS_READING_RESPONSE:
	case SOUP_STATUS_SENDING_REQUEST:
		if (!body_started) {
			/*
			 * FIXME: Use exponential backoff here
			 */
			soup_message_queue (req, 
					    req->priv->callback, 
					    req->priv->user_data);
		} else {
			soup_message_set_error (req, SOUP_ERROR_IO);
			soup_message_issue_callback (req);
		}
		break;

	default:
		soup_message_set_error (req, SOUP_ERROR_IO);
		soup_message_issue_callback (req);
		break;
	}
}

static gboolean
soup_parse_headers (const GString   *headers, 
		    SoupHttpVersion *version,
		    SoupMessage     *req)
{
	if (!soup_headers_parse_response (headers->str, 
					  headers->len, 
					  req->response_headers,
					  version,
					  &req->errorcode,
					  (gchar **) &req->errorphrase)) {
		soup_message_set_error (req, SOUP_ERROR_MALFORMED);
		soup_message_issue_callback (req);
		return FALSE;
	}

	req->errorclass = soup_error_get_class (req->errorcode);

	return TRUE;
}

static SoupTransferDone
soup_queue_read_headers_cb (const GString        *headers,
                            SoupTransferEncoding *encoding,
			    gint                 *content_len,
			    gpointer              user_data)
{
	SoupMessage *req = user_data;

	const gchar *connection, *length, *enc;
	SoupHttpVersion version;

	if (!soup_parse_headers (headers, &version, req)) 
		return SOUP_TRANSFER_END;

	/* 
	 * Handle connection persistence 
	 */
	connection = soup_message_get_header (req->response_headers,
					      "Connection");

	if ((connection && !g_strcasecmp (connection, "close")) ||
	    (!connection && version == SOUP_HTTP_1_0))
		soup_connection_set_keep_alive (req->connection, FALSE);

	/* 
	 * Special case handling for:
	 *   - HEAD requests (where content-length must be ignored) 
	 *   - 1xx Informational responses (where no body is allowed)
	 */
	if (!g_strcasecmp (req->method, "HEAD") ||
	    req->errorclass == SOUP_ERROR_CLASS_INFORMATIONAL) {
                *encoding = SOUP_TRANSFER_CONTENT_LENGTH;
                *content_len = 0;
		goto RUN_HANDLERS;
	}

	/* 
	 * Handle Content-Length or Chunked encoding 
	 */
	length = soup_message_get_header (req->response_headers, 
					  "Content-Length");
	enc = soup_message_get_header (req->response_headers, 
				       "Transfer-Encoding");

	if (length) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = atoi (length);
		if (*content_len < 0) {
			soup_message_set_error_full (req, 
						     SOUP_ERROR_MALFORMED,
						     "Invalid Content-Length");
			goto THROW_MALFORMED_HEADER;
		}
	}
	else if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			*encoding = SOUP_TRANSFER_CHUNKED;
		else {
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_MALFORMED,
				"Unknown Response Encoding");
			goto THROW_MALFORMED_HEADER;
		}
	}

 RUN_HANDLERS:
	if (soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY))
		return SOUP_TRANSFER_END;

	return SOUP_TRANSFER_CONTINUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req);
	return SOUP_TRANSFER_END;
}

static SoupTransferDone
soup_queue_read_chunk_cb (const SoupDataBuffer *data,
			  gpointer              user_data)
{
	SoupMessage *req = user_data;

	req->response.owner = data->owner;
	req->response.length = data->length;
	req->response.body = data->body;

	if (soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK))
		return SOUP_TRANSFER_END;

	return SOUP_TRANSFER_CONTINUE;
}

static void
soup_queue_read_done_cb (const SoupDataBuffer *data,
			 gpointer              user_data)
{
	SoupMessage *req = user_data;

	req->response.owner = data->owner;
	req->response.length = data->length;
	req->response.body = data->body;

	if (req->errorclass == SOUP_ERROR_CLASS_INFORMATIONAL) {
		GIOChannel *channel;
		gboolean overwrt;

		channel = soup_connection_get_iochannel (req->connection);
		overwrt = req->priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS;

		req->priv->read_tag = 
			soup_transfer_read (channel,
					    overwrt,
					    soup_queue_read_headers_cb,
					    soup_queue_read_chunk_cb,
					    soup_queue_read_done_cb,
					    soup_queue_error_cb,
					    req);

		g_io_channel_unref (channel);
	} 
	else {
		req->status = SOUP_STATUS_FINISHED;
		req->priv->read_tag = 0;
	}

	soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
}

static void
soup_encode_http_auth (SoupMessage *msg, GString *header, gboolean proxy_auth)
{
	SoupAuth *auth;
	SoupContext *ctx;
	char *token;

	ctx = proxy_auth ? soup_get_proxy () : msg->context;

	auth = soup_auth_lookup (ctx);
	if (auth) {
		token = soup_auth_authorize (auth, msg);
		if (token) {
			g_string_sprintfa (header, 
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
	gboolean connection;
	gboolean proxy_auth;
	gboolean auth;

	GString *out;
};

static void 
soup_check_used_headers (gchar  *key, 
			 GSList *vals, 
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

	while (vals) {
		g_string_sprintfa (hdrs->out, 
				   "%s: %s\r\n", 
				   key, 
				   (gchar *) vals->data);
		vals = vals->next;
	}
}

static GString *
soup_get_request_header (SoupMessage *req)
{
	GString *header;
	gchar *uri;
	SoupContext *proxy;
	const SoupUri *suri;
	struct SoupUsedHeaders hdrs = {
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

	g_hash_table_foreach (req->request_headers, 
			      (GHFunc) soup_check_used_headers,
			      &hdrs);

	/* 
	 * If we specify an absoluteURI in the request line, the Host header
	 * MUST be ignored by the proxy.  
	 */
	g_string_sprintfa (header, 
			   "%s%s%s%s%s%s%s",
			   hdrs.host ? "" : "Host: ",
			   hdrs.host ? "" : suri->host,
			   hdrs.host ? "" : "\r\n",
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
	if (!hdrs.auth)
		soup_encode_http_auth (req, header, FALSE);

	g_string_append (header, "\r\n");

	return header;
}

static void 
soup_queue_write_done_cb (gpointer user_data)
{
	SoupMessage *req = user_data;

	req->priv->write_tag = 0;
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
	gboolean overwrt; 

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

		channel = soup_connection_get_iochannel (conn);
		if (!channel) {
			gchar *phrase;

			if (proto == SOUP_PROTOCOL_HTTPS)
				phrase = "Unable to create secure data channel";
			else
				phrase = "Unable to create data channel";

			if (ctx != req->context)
				soup_message_set_error_full (
					req, 
					SOUP_ERROR_CANT_CONNECT_PROXY,
					phrase);
			else 
				soup_message_set_error_full (
					req, 
					SOUP_ERROR_CANT_CONNECT,
					phrase);

			soup_message_issue_callback (req);
			return;
		}

		if (req->priv->req_header) {
			g_string_free (req->priv->req_header, TRUE);
			req->priv->req_header = NULL;
		}

		req->priv->req_header = soup_get_request_header (req);

		req->priv->write_tag = 
			soup_transfer_write (channel,
					     req->priv->req_header,
					     &req->request,
					     NULL,
					     soup_queue_write_done_cb,
					     soup_queue_error_cb,
					     req);

		overwrt = req->priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS;

		req->priv->read_tag = 
			soup_transfer_read (channel,
					    overwrt,
					    soup_queue_read_headers_cb,
					    soup_queue_read_chunk_cb,
					    soup_queue_read_done_cb,
					    soup_queue_error_cb,
					    req);

		g_io_channel_unref (channel);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->connection = conn;

		break;

	case SOUP_CONNECT_ERROR_ADDR_RESOLVE:
		if (ctx != req->context)
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_CANT_CONNECT_PROXY,
				"Unable to resolve proxy hostname");
		else 
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_CANT_CONNECT,
				"Unable to resolve hostname");

		soup_message_issue_callback (req);
		break;

	case SOUP_CONNECT_ERROR_NETWORK:
		if (ctx != req->context)
			soup_message_set_error (req, 
						SOUP_ERROR_CANT_CONNECT_PROXY);
		else
			soup_message_set_error (req, 
						SOUP_ERROR_CANT_CONNECT);

		soup_message_issue_callback (req);
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

void 
soup_queue_message (SoupMessage    *req,
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

	if (req->errorphrase) {
		g_free ((gchar *) req->errorphrase);
		req->errorphrase = NULL;
	}

	req->errorcode = 0;
	req->errorclass = 0;

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
