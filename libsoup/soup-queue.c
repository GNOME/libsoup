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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "soup-queue.h"
#include "soup-context.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-socks.h"

GSList *soup_active_requests = NULL;

static guint soup_queue_idle_tag = 0;

/*
 * "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n          567\r\n\r\n"
 *                     ^             ^ ^    ^            ^   ^
 *                     |             | |    |            |   |
 *                    key            0 val  0          val+  0
 *                                         , <---memmove-...
 * 
 * key: "Content-Length"
 * val: "1234, 567"
 */
static gboolean
soup_parse_headers (SoupMessage *req)
{
	guint http_major, http_minor, status_code, phrase_start = 0;
	guint len = req->priv->recv_buf->len;
	gchar *str = req->priv->recv_buf->data;
	gchar *key = NULL, *val = NULL;
	gint offset = 0, lws = 0;

	if (req->response_headers) 
		g_hash_table_destroy (req->response_headers);

	req->response_headers = g_hash_table_new (soup_str_case_hash, 
						  soup_str_case_equal);

	if (!str || !*str || len < sizeof ("HTTP/0.0 000 A\r\n\r\n"))
		goto THROW_MALFORMED_HEADER;

	if (sscanf (str, 
		    "HTTP/%1u.%1u %3u %n", 
		    &http_major,
		    &http_minor,
		    &status_code, 
		    &phrase_start) < 3 || !phrase_start)
		goto THROW_MALFORMED_HEADER;

	req->response_code = status_code; 
	req->response_phrase = &str [phrase_start];

	key = strstr (str, "\r\n");
	key += 2;

	/* FIXME: Do better error checking. */

	/* join continuation headers, using a comma */
	while ((key = strstr (key, "\r\n"))) {
		key += 2;
		offset = key - str;

		/* pointing at another \r means end of header */
		if (*key == '\r') break;

		/* check if first character on the line is whitespace */
		if (*key == ' ' || *key == '\t') {
			key -= 2;

			/* eat any trailing space from the previous line*/
			while (key [-1] == ' ' || key [-1] == '\t') key--;

			/* count how many characters are whitespace */
			lws = strspn (key, " \t\r\n");

			/* if continuation line, replace whitespace with ", " */
			if (key [-1] != ':') {
				lws -= 2;
				key [0] = ',';
				key [1] = ' ';
			}

			g_memmove (key, &key [lws], len - offset - lws);
			g_byte_array_set_size (req->priv->recv_buf, len - lws);
		}
	}

	key = str;

	/* set eos for header key and value and add to hashtable */
        while ((key = strstr (key, "\r\n"))) {
		/* set end of last val, or end of http reason phrase */
                key [0] = '\0';
		key += 2;

		/* pointing at another \r means end of header */
		if (*key == '\r') break;

                val = strchr (key, ':'); /* find start of val */

		if (!val || val > strchr (key, '\r'))
			goto THROW_MALFORMED_HEADER;

		/* set end of key */
		val [0] = '\0';
		
		val++;
		val += strspn (val, " \t");  /* skip whitespace */
		g_hash_table_insert (req->response_headers, key, val);
		
		key = val;
        }

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

static void 
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
		chunk_idx = req->priv->header_len + 4;
	}

	while (chunk_idx + chunk_len + 5 <= arr->len) {
		gint new_len = 0;
		gint len = 0, j;
		gchar *i = &arr->data [chunk_idx + chunk_len];

		/* remove \r\n after previous chunk body */
		if (chunk_len) {
			g_memmove (i, i + 2, arr->len - chunk_idx - 2);
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

	req->response.length = arr->len - index - 4 ;
	req->response.body = g_memdup (&arr->data [index + 4],
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
		req->priv->header_len = index;
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

static void
soup_encode_http_auth (SoupUri *uri, GString *header, gboolean proxy_auth)
{
	if (!uri->authmech) {
		gchar *authpass, *encoded;
		authpass = g_strconcat (uri->user, ":", uri->passwd);
		encoded = soup_base64_encode (authpass);
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
		"text/xml\r\n\tcharset=\"utf-8\"", 
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

	if (!req->priv->req_header)
		req->priv->req_header = soup_get_request_header (req);

	head_len = req->priv->req_header->len;
	body_len = req->request.length;
	total_len = head_len + body_len;
	total_written = req->priv->write_len;	

	if (total_written < head_len) {
		/* headers not done yet */
		/* send rest of headers and all of body */
		/* maybe we should just send the rest of the headers here, 
		   and avoid memcpy/alloca altogether at the loss of cpu 
		   cycles */
		write_buf = &req->priv->req_header->str [total_written];
		write_len = head_len - total_written;
		/*
		guint offset = head_len - total_written;
		write_len = offset + body_len;
		write_buf = alloca (write_len + 1);
		memcpy (write_buf, 
			&req->priv->req_header->str [total_written],
			offset);
		memcpy (&write_buf [offset],
			req->request.body,
			req->request.length);
		write_buf [write_len + 1] = '\0';
		*/
	} else {
		/* headers done, maybe some of body */
		/* send rest of body */
		guint offset = total_written - head_len;
		write_buf = &req->request.body [offset];
		write_len = body_len - offset;
	}

	error = g_io_channel_write (iochannel, 
				    write_buf, 
				    write_len, 
				    &bytes_written);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;
	
	if (error != G_IO_ERROR_NONE) {
		soup_message_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	total_written = (req->priv->write_len += bytes_written);

	if (total_written == total_len) {
		req->status = SOUP_STATUS_READING_RESPONSE;
		req->priv->read_tag = 
			g_io_add_watch (iochannel, 
					G_IO_IN, 
					(GIOFunc) soup_queue_read_async, 
					req);
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
			soup_queue_message (req, 
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
soup_setup_socket (GIOChannel *channel)
{
#ifdef TCP_NODELAY
	{
		int on, fd;
		on = 1;
		fd = g_io_channel_unix_get_fd (channel);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}
#endif
}

static void
soup_queue_connect (SoupContext          *ctx,
		    SoupConnectErrorCode  err,
		    SoupConnection       *conn,
		    gpointer              user_data)
{
	SoupMessage *req = user_data;
	GIOChannel *channel;

	req->priv->connect_tag = NULL;

	switch (err) {
	case SOUP_CONNECT_ERROR_NONE:
		channel = soup_connection_get_iochannel (conn);

		if (!channel) goto THROW_CANT_CONNECT;

		soup_setup_socket (channel);

		if (soup_connection_is_new (conn) &&
		    soup_context_get_protocol (ctx) & (SOUP_PROTOCOL_SOCKS4 | 
						       SOUP_PROTOCOL_SOCKS5)) {
			soup_connect_socks_proxy (conn, 
						  req->context, 
						  soup_queue_connect,
						  req);
			return;
		}

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
		goto THROW_CANT_CONNECT;
		break;
	}

	return;

 THROW_CANT_CONNECT:
	soup_message_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
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
	req->status = SOUP_STATUS_QUEUED;

	soup_active_requests = g_slist_prepend (soup_active_requests, req);
}

void 
soup_queue_shutdown ()
{
        GSList *iter;

	g_source_remove (soup_queue_idle_tag);
	soup_queue_idle_tag = 0;

	for (iter = soup_active_requests; iter; iter = iter->next)
		soup_message_cancel (iter->data);
}
