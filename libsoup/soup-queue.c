/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <config.h>
#include <ctype.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "soup-message.h"
#include "soup-context.h"
#include "soup-headers.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-socks.h"

GSList *soup_active_requests = NULL;

static guint soup_queue_idle_tag = 0;

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

static gboolean
soup_parse_headers (SoupMessage *req)
{
	if (req->response_headers) 
		g_hash_table_destroy (req->response_headers);

	req->response_headers = g_hash_table_new (soup_str_case_hash, 
						  soup_str_case_equal);

	if (!soup_headers_parse_response (req->priv->recv_buf->data, 
					  req->priv->recv_buf->len, 
					  req->response_headers,
					  &req->response_code,
					  &req->response_phrase))
		goto THROW_MALFORMED_HEADER;

	return TRUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req, SOUP_ERROR_MALFORMED_HEADER);
	return FALSE;
}

/* returns TRUE to continue processing, FALSE if a callback was issued */
static gboolean 
soup_process_headers (SoupMessage *req)
{
	gchar *connection, *length, *enc;

	/* Handle connection persistence */
	connection = g_hash_table_lookup (req->response_headers, "Connection");

	if (connection && g_strcasecmp (connection, "close") == 0)
		soup_connection_set_keep_alive (req->priv->conn, FALSE);

	/* Handle Content-Length or Chunked encoding */
	length = g_hash_table_lookup (req->response_headers, "Content-Length");
	enc = g_hash_table_lookup (req->response_headers, "Transfer-Encoding");
	
	if (length)
		req->priv->content_length = atoi (length);
	else if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			req->priv->is_chunked = TRUE;
		else {
			g_warning ("Unknown encoding type in HTTP response.");
			goto THROW_MALFORMED_HEADER;
		}
	}

	return TRUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req, SOUP_ERROR_MALFORMED_HEADER);
	return FALSE;
}

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
soup_read_chunk (SoupMessage *req) 
{
	guint chunk_idx = req->priv->cur_chunk_idx;
	gint chunk_len = req->priv->cur_chunk_len;
	GByteArray *arr = req->priv->recv_buf;
	
	if (!chunk_idx) {
		chunk_len = 0;
		chunk_idx = req->priv->header_len;
	}

	while (chunk_idx + chunk_len + 5 <= arr->len) {
		gint new_len = 0;
		gint len = 0, j;
		gchar *i = &arr->data [chunk_idx + chunk_len];

		/* remove \r\n after previous chunk body */
		if (chunk_len) {
			g_memmove (i, 
				   i + 2, 
				   arr->len - chunk_idx - chunk_len - 2);
			g_byte_array_set_size (arr, arr->len - 2);
		}

		while ((tolower (*i) >= 'a' && tolower (*i) <= 'f') ||
		       (*i >= '0' && *i <= '9'))
			len++, i++;
		
		for (i -= len, j = len - 1; j + 1; i++, j--)
			new_len += (*i > '9') ? 
				(tolower (*i) - 0x57) << (4*j) :
				(tolower (*i) - 0x30) << (4*j);

		chunk_idx = chunk_idx + chunk_len;
		chunk_len = new_len;

		if (chunk_len == 0) {
			/* FIXME: Add entity headers we find here to
			          req->response_headers. */
			len += soup_substring_index (&arr->data [chunk_idx + 3],
						     arr->len - chunk_idx - 3,
						     "\r\n");
			len += 2;
		}

		/* trailing \r\n after chunk length */
		g_memmove (&arr->data [chunk_idx], 
			   &arr->data [chunk_idx + len + 2],
			   arr->len - chunk_idx - len - 2);
		g_byte_array_set_size (arr, arr->len - len - 2);

		/* zero-length chunk closes transfer */
		if (chunk_len == 0) return TRUE;
	}

	req->priv->cur_chunk_len = chunk_len;
	req->priv->cur_chunk_idx = chunk_idx;

	return FALSE;
}

static void
soup_finish_read (SoupMessage *req)
{
	GByteArray *arr = req->priv->recv_buf;
	gint index = req->priv->header_len;

	req->response.owner = SOUP_BUFFER_SYSTEM_OWNED;
	req->response.length = arr->len - index ;
	req->response.body = g_memdup (&arr->data [index],
				       req->response.length + 1);
	req->response.body [req->response.length] = '\0';
	
	/* Headers are zero-terminated */
	g_byte_array_set_size (arr, index);
	
	req->status = SOUP_STATUS_FINISHED;
	soup_message_issue_callback (req, SOUP_ERROR_NONE);
}

static gboolean 
soup_queue_read_async (GIOChannel* iochannel, 
		       GIOCondition condition, 
		       SoupMessage *req)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gint bytes_read = 0;
	gboolean read_done = FALSE;
	gint index = req->priv->header_len;
	GByteArray *arr = req->priv->recv_buf;
	GIOError error;

	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;
	
	if (error != G_IO_ERROR_NONE) {
		soup_message_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	if (!arr) arr = req->priv->recv_buf = g_byte_array_new ();

	if (bytes_read) g_byte_array_append (arr, read_buf, bytes_read);

	if (!index) {
		index = soup_substring_index (arr->data, arr->len, "\r\n\r\n");
		if (index < 0) return TRUE;

		req->priv->header_len = index + 4;

		/* Terminate Headers */
		arr->data [index + 3] = '\0';

		if (!soup_parse_headers (req) || !soup_process_headers (req)) 
			return FALSE;
	}

	if (bytes_read == 0) read_done = TRUE;
	else if (req->priv->is_chunked) read_done = soup_read_chunk (req);
	else if (req->priv->content_length==arr->len-index-4) read_done = TRUE;

	if (read_done) {
		soup_finish_read (req);
		return FALSE;
	}

	return TRUE;
}

static gboolean 
soup_queue_error_async (GIOChannel* iochannel, 
			GIOCondition condition, 
			SoupMessage *req)
{
	gboolean conn_closed = soup_connection_is_keep_alive (req->priv->conn);

	soup_connection_set_keep_alive (req->priv->conn, FALSE);

	switch (req->status) {
	case SOUP_STATUS_IDLE:
	case SOUP_STATUS_QUEUED:
	case SOUP_STATUS_FINISHED:
		break;
	case SOUP_STATUS_CONNECTING:
		soup_message_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
		break;
	case SOUP_STATUS_SENDING_REQUEST:
		if (req->priv->req_header && 
		    req->priv->req_header->len >= req->priv->write_len) {
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
		if (req->priv->header_len && !conn_closed) {
			soup_finish_read (req);
			break;
		}

		soup_message_issue_callback (req, SOUP_ERROR_IO);
		break;
	default:
		soup_message_issue_callback (req, SOUP_ERROR_IO);
		break;
	}

	return FALSE;
}

static void
soup_encode_http_auth (SoupUri *uri, GString *header, gboolean proxy_auth)
{
	if (!uri->authmech) {
		gchar *authpass, *encoded;
		authpass = g_strconcat (uri->user, ":", uri->passwd, NULL);
		encoded = soup_base64_encode (authpass, strlen (authpass));
		g_string_sprintfa (header,
				   "%s: Basic %s\r\n",
				   proxy_auth ? 
				           "Proxy-Authorization" : 
				           "Authorization",
				   encoded);
		g_free (encoded);
		g_free (authpass);
	}
}

struct SoupCustomHeader {
	gchar *key;
	gchar *val;
};

struct SoupUsedHeaders {
	gchar  *host;
	gchar  *user_agent;
	gchar  *content_type;
	gchar  *soapaction;
	gchar  *connection;
	gchar  *proxy_auth;
	gchar  *auth;

	GSList *custom_headers;
};

static inline void 
soup_check_used_headers (gchar *key, 
			 gchar *value, 
			 struct SoupUsedHeaders *hdrs)
{
	if (strcasecmp (key, "Host") == 0) hdrs->host = value;
	else if (strcasecmp (key, "User-Agent") == 0) hdrs->user_agent = value;
	else if (strcasecmp (key, "SOAPAction") == 0) hdrs->soapaction = value;
	else if (strcasecmp (key, "Connection") == 0) hdrs->connection = value;
	else if (strcasecmp (key, "Authorization") == 0) hdrs->auth = value;
	else if (strcasecmp (key, "Proxy-Authorization") == 0) 
		hdrs->proxy_auth = value;
	else if (strcasecmp (key, "Content-Type") == 0) 
		hdrs->content_type = value;
	else if (strcasecmp (key, "Content-Length"))
		g_warning ("Content-Length set as custom request header "
			   "is not allowed.");
	else {
		struct SoupCustomHeader *cust; 
		cust = g_new (struct SoupCustomHeader, 1);
		cust->key = key;
		cust->val = value;
		hdrs->custom_headers = g_slist_prepend (hdrs->custom_headers, 
							cust);
	}
}

static GString *
soup_get_request_header (SoupMessage *req)
{
	GString *header = g_string_new ("");
	gchar *uri;
	SoupContext *proxy = soup_get_proxy ();
	SoupUri *suri = soup_context_get_uri (req->context);

	struct SoupUsedHeaders hdrs = {
		suri->host, 
		"Soup/0.1", 
		"text/xml; charset=utf-8", 
		req->action,
		"keep-alive",
		NULL,
		NULL,
		NULL
	};

	if (req->request_headers) 
		g_hash_table_foreach (req->request_headers, 
				      (GHFunc) soup_check_used_headers,
				      &hdrs);

	if (proxy)
		uri = soup_uri_to_string (suri, FALSE);
	else if (suri->querystring)
		uri = g_strconcat (suri->path, "?", suri->querystring, NULL);
	else
		uri = g_strdup (suri->path);

	/* If we specify an absoluteURI in the request line, the 
	   Host header MUST be ignored by the proxy. */
	g_string_sprintfa (header,
			   "POST %s HTTP/1.1\r\n"
			   "Host: %s\r\n"
			   "User-Agent: %s\r\n"
			   "Content-Type: %s;\r\n"
			   "Content-Length: %d\r\n"
			   "SOAPAction: %s\r\n"
			   "Connection: %s\r\n",
			   uri,
			   hdrs.host,
			   hdrs.user_agent,
			   hdrs.content_type,
			   req->request.length,
			   hdrs.soapaction,
			   hdrs.connection);
	g_free (uri);

	/* Proxy-Authorization from the proxy Uri */
	if (hdrs.proxy_auth)
		g_string_sprintfa (header, 
				   "Proxy-Authorization: %s\r\n",
				   hdrs.proxy_auth);
	else if (proxy && soup_context_get_uri(proxy)->user)
		soup_encode_http_auth (soup_context_get_uri(proxy), 
				       header, 
				       TRUE);

	/* Authorization from the context Uri */
	if (hdrs.auth)
		g_string_sprintfa (header, "Authorization: %s\r\n", hdrs.auth);
	else if (suri->user)
		soup_encode_http_auth (suri, header, FALSE);

	/* Append custom headers for this request */
	if (hdrs.custom_headers) {
		GSList *iter;
		for (iter = hdrs.custom_headers; iter; iter = iter->next) {
			struct SoupCustomHeader *cust_hdr = iter->data;
			g_string_sprintfa (header, 
					   "%s: %s\r\n", 
					   cust_hdr->key, 
					   cust_hdr->val);
			g_free (cust_hdr);
		}
		g_slist_free (hdrs.custom_headers);
	}

	g_string_append (header, "\r\n");

	return header;
}

static gboolean 
soup_queue_write_async (GIOChannel* iochannel, 
			GIOCondition condition, 
			SoupMessage *req)
{
	guint head_len, body_len, total_len, total_written, bytes_written;
	GIOError error;
	gchar *write_buf;
	guint  write_len;
	void *pipe_handler;

	if (!req->priv->req_header)
		req->priv->req_header = soup_get_request_header (req);

	head_len = req->priv->req_header->len;
	body_len = req->request.length;
	total_len = head_len + body_len;
	total_written = req->priv->write_len;

	pipe_handler = signal (SIGPIPE, SIG_IGN);
	errno = 0;

 WRITE_SOME_MORE:
	if (total_written < head_len) {
		/* send rest of headers */
		write_buf = &req->priv->req_header->str [total_written];
		write_len = head_len - total_written;
	} else {
		/* send rest of body */
		guint offset = total_written - head_len;
		write_buf = &req->request.body [offset];
		write_len = body_len - offset;
	}

	error = g_io_channel_write (iochannel, 
				    write_buf, 
				    write_len, 
				    &bytes_written);

	if (error == G_IO_ERROR_AGAIN) {
		signal (SIGPIPE, pipe_handler);
		return TRUE;
	}

	if (errno != 0 || error != G_IO_ERROR_NONE) {
		soup_queue_error_async (iochannel, G_IO_HUP, req);
		goto DONE_WRITING;
	}

	total_written = (req->priv->write_len += bytes_written);

	if (total_written == total_len) {
		req->status = SOUP_STATUS_READING_RESPONSE;
		req->priv->read_tag = 
			g_io_add_watch (iochannel, 
					G_IO_IN, 
					(GIOFunc) soup_queue_read_async, 
					req);
		goto DONE_WRITING;
	}

	goto WRITE_SOME_MORE;

 DONE_WRITING:
	signal (SIGPIPE, pipe_handler);
	return FALSE;
}

static void
soup_queue_connect (SoupContext          *ctx,
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
						  soup_queue_connect,
						  req);
			return;
		}

		channel = soup_connection_get_iochannel (conn);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->priv->conn = conn;
		req->priv->write_tag = 
			g_io_add_watch (channel, 
					G_IO_OUT, 
					(GIOFunc) soup_queue_write_async, 
					req);
		req->priv->error_tag = 
			g_io_add_watch (channel, 
					G_IO_HUP | G_IO_ERR | G_IO_NVAL, 
					(GIOFunc) soup_queue_error_async, 
					req);

		g_io_channel_unref (channel);
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
						     soup_queue_connect, 
						     req);
	}

	soup_queue_idle_tag = 0;
	return FALSE;
}

/**
 * soup_message_queue:
 * @req: a %SoupMessage.
 * @callback: a %SoupCallbackFn which will be called after the message completes
 * or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message %req for sending. All messages are processed while the
 * glib main loop runs. If this %SoupMessage has been processed before, any
 * resources related to the last it was sent are freed.
 *
 * If the response %SoupDataBuffer has an owner of %SOUP_BUFFER_USER_OWNED, the
 * message will not be queued, and @callback will be called with a
 * %SoupErrorCode of %SOUP_ERROR_CANCELLED.
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

	if (req->response_headers)
		g_hash_table_destroy (req->response_headers);
	if (req->priv->recv_buf) 
		g_byte_array_free (req->priv->recv_buf, TRUE);

	req->response_code = 0;
	req->response_phrase = NULL;
	req->response_headers = NULL;
	req->priv->recv_buf = NULL;
	req->status = SOUP_STATUS_QUEUED;

	soup_active_requests = g_slist_prepend (soup_active_requests, req);
}
