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
	SoupErrorCode err = SOUP_ERROR_MALFORMED_HEADER;

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

	err = soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY);
	if (err) goto THROW_MALFORMED_HEADER;
	if (req->status == SOUP_STATUS_QUEUED) return FALSE;

	return TRUE;

 THROW_MALFORMED_HEADER:
	soup_message_issue_callback (req, err);
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

		/* Convert the size of the next chunk from hex */
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
	SoupErrorCode err;

	req->response.owner = SOUP_BUFFER_SYSTEM_OWNED;
	req->response.length = req->priv->recv_buf->len;
	req->response.body = req->priv->recv_buf->data;

	req->status = SOUP_STATUS_FINISHED;

	err = soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
	if (req->status == SOUP_STATUS_QUEUED) return;

	if (err)
		soup_message_issue_callback (req, err); 
	else 
		soup_message_issue_callback (req, SOUP_ERROR_NONE);
}

static gboolean 
soup_queue_read_cb (GIOChannel* iochannel, 
		    GIOCondition condition, 
		    SoupMessage *req)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gint bytes_read = 0;
	gboolean read_done = FALSE;
	GByteArray *arr;
	GIOError error;
	SoupErrorCode err;

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

	arr = req->priv->recv_buf;

	if (!arr) arr = req->priv->recv_buf = g_byte_array_new ();

	if (req->priv->headers_done && 
	    req->priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS) {
		req->priv->cur_chunk_len -= arr->len - req->priv->cur_chunk_idx;
		req->priv->cur_chunk_idx = 0;
		req->priv->content_length -= arr->len;
		g_byte_array_set_size (arr, 0);
	}

	if (bytes_read) 
		g_byte_array_append (arr, read_buf, bytes_read);

	if (!req->priv->headers_done) {
		gint index = soup_substring_index (arr->data, 
						   arr->len, 
						   "\r\n\r\n");
		if (index < 0) return TRUE;

		/* Terminate Headers */
		arr->data [index + 3] = '\0';
		index += 4;

		if (!soup_parse_headers (req) || !soup_process_headers (req)) 
			return FALSE;

		g_memmove (arr->data, &arr->data [index], arr->len - index);
		g_byte_array_set_size (arr, arr->len - index);

		req->priv->headers_done = TRUE;
	}

	/* Allow the chunk parser to strip the data stream */
	if (bytes_read == 0) 
		read_done = TRUE;
	else if (req->priv->is_chunked) 
		read_done = soup_read_chunk (req);
	else if (req->priv->content_length == arr->len) 
		read_done = TRUE;

	/* Don't call chunk handlers if we didn't actually read anything */
	if (bytes_read != 0) {
		req->response.owner = SOUP_BUFFER_SYSTEM_OWNED;
		req->response.length = arr->len;
		req->response.body = arr->data;

		err = soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK);
		if (err) { 
			soup_message_issue_callback (req, err); 
			return FALSE;
		} else if (req->status == SOUP_STATUS_QUEUED) 
			return FALSE;
	}

	if (read_done) {
		soup_finish_read (req);
		return FALSE;
	}

	return TRUE;
}

static gboolean 
soup_queue_error_cb (GIOChannel* iochannel, 
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
		if (req->priv->headers_done && !conn_closed) {
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
	switch (key [0]) {
	case 'H':
	case 'h':
		if (!g_strcasecmp (key+1, "ost")) hdrs->host = TRUE;
		break;
	case 'U':
	case 'u':
		if (!g_strcasecmp (key+1, "ser-Agent")) hdrs->user_agent = TRUE;
		break;
	case 'S':
	case 's':
		if (!g_strcasecmp (key+1, "OAPAction")) hdrs->soapaction = TRUE;
		break;
	case 'A':
	case 'a':
		if (!g_strcasecmp (key+1, "uthorization")) hdrs->auth = TRUE;
		break;
	case 'P':
	case 'p':
		if (!g_strcasecmp (key+1, "roxy-Authorization")) 
			hdrs->proxy_auth = TRUE;
		break;
	case 'C':
	case 'c':
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
	SoupContext *proxy;
	SoupUri *suri;
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
			   "%s %s HTTP/1.1\r\n"
			   "Content-Length: %d\r\n",
			   req->method,
			   uri,
			   req->request.length);
	g_free (uri);

	if (req->request_headers) 
		g_hash_table_foreach (req->request_headers, 
				      (GHFunc) soup_check_used_headers,
				      &hdrs);

	/* If we specify an absoluteURI in the request line, the 
	   Host header MUST be ignored by the proxy. */
	g_string_sprintfa (header, 
			   "%s%s%s%s%s%s%s%s%s%s",
			   hdrs.host ? "" : "Host: ",
			   hdrs.host ? "" : suri->host,
			   hdrs.host ? "" : "\r\n",
			   hdrs.soapaction ? "" : "SOAPAction: ",
			   hdrs.soapaction ? "" : req->action,
			   hdrs.soapaction ? "" : "\r\n",
			   hdrs.content_type ? "" : "Content-Type: text/xml; ",
			   hdrs.content_type ? "" : "charset=utf-8\r\n",
			   hdrs.connection ? "" : "Connection: keep-alive\r\n",
			   hdrs.user_agent ? "" : "User-Agent: Soup/0.1\r\n");

	/* Proxy-Authorization from the proxy Uri */
	if (!hdrs.proxy_auth && proxy && soup_context_get_uri (proxy)->user)
		soup_encode_http_auth (soup_context_get_uri (proxy), 
				       header, 
				       TRUE);

	/* Authorization from the context Uri */
	if (!hdrs.auth && suri->user)
		soup_encode_http_auth (suri, header, FALSE);

	g_string_append (header, "\r\n");

	return header;
}

static gboolean 
soup_queue_write_cb (GIOChannel* iochannel, 
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
		soup_queue_error_cb (iochannel, G_IO_HUP, req);
		goto DONE_WRITING;
	}

	total_written = (req->priv->write_len += bytes_written);

	if (total_written == total_len) {
		req->status = SOUP_STATUS_READING_RESPONSE;
		req->priv->read_tag = 
			g_io_add_watch (iochannel, 
					G_IO_IN, 
					(GIOFunc) soup_queue_read_cb, 
					req);
		goto DONE_WRITING;
	}

	goto WRITE_SOME_MORE;

 DONE_WRITING:
	signal (SIGPIPE, pipe_handler);
	return FALSE;
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

		channel = soup_connection_get_iochannel (conn);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->priv->conn = conn;
		req->priv->write_tag = 
			g_io_add_watch (channel, 
					G_IO_OUT, 
					(GIOFunc) soup_queue_write_cb, 
					req);
		req->priv->error_tag = 
			g_io_add_watch (channel, 
					G_IO_HUP | G_IO_ERR | G_IO_NVAL, 
					(GIOFunc) soup_queue_error_cb, 
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

	req->response_code = 0;
	req->response_phrase = NULL;
	req->priv->recv_buf = NULL;
	req->status = SOUP_STATUS_QUEUED;

	soup_active_requests = g_slist_prepend (soup_active_requests, req);
}
