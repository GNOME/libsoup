/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * soup_base64_encode() written by Joe Orton, borrowed from ghttp.
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <config.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <gnet/gnet.h>
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

GSList *active_requests = NULL;

static guint soup_queue_idle_tag = 0;

static gint
soup_substring_index (gchar *str, gint len, gchar *substr) 
{
	int i, sublen = strlen (substr);
	
	for (i = 0; i < len; ++i)
		if (str[i] == substr[0])
			if (memcmp (&str[i], substr, sublen) == 0)
				return i;

	return -1;
}

static inline gchar**
soup_split_headers (gchar *str, guint len)
{
	return NULL;
}

/* returns TRUE to continue processing, FALSE if a callback was issued */
static gboolean 
soup_process_headers (SoupRequest *req, gchar *str, guint len)
{
	gchar **headers, *header;
	gchar reason_phrase[512];
	gint http_major, http_minor, status_code, read_count, index;

	read_count = sscanf (str, 
			     "HTTP/%d.%d %u %512s\r\n", 
			     &http_major,
			     &http_minor,
			     &status_code, 
			     reason_phrase);

	req->response_code = status_code;
	req->response_phrase = g_strdup (reason_phrase);

	if (read_count != 4) {
		soup_request_issue_callback (req, SOUP_ERROR_MALFORMED_HEADER);
		return FALSE;
	}

	index = soup_substring_index (str, len, "\r\n");

	headers = g_strsplit (str, "\r\n", 0);
	g_strfreev (headers);

	return TRUE;
}

static gboolean 
soup_queue_read_async (GIOChannel* iochannel, 
		       GIOCondition condition, 
		       SoupRequest *req)
{
	gchar read_buf[RESPONSE_BLOCK_SIZE];
	guint bytes_read;
	gint index;
	GIOError error;

	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;
	
	if (error != G_IO_ERROR_NONE) {
		soup_request_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	if (!req->priv->recv_buf) 
		req->priv->recv_buf = g_byte_array_new ();

	/* Read EOF. Set Response body and process headers. Set status to
	   FINISHED. Initiate callback with ERROR_NONE if header parsing 
	   was successful */

	if (bytes_read == 0) {
		index = soup_substring_index (req->priv->recv_buf->data, 
					      req->priv->recv_buf->len,
					      "\r\n\r\n");

		req->response.length = req->priv->recv_buf->len - index + 4;
		req->response.body = 
			g_memdup (&req->priv->recv_buf->data [index + 4],
				  req->response.length + 1);
		req->response.body [req->response.length] = '\0';

		g_byte_array_free (req->priv->recv_buf, TRUE);
		req->priv->recv_buf = NULL;
		
		req->status = SOUP_STATUS_FINISHED;

		if (soup_process_headers (req, 
					  req->priv->recv_buf->data,
					  index + 2))
			soup_request_issue_callback (req, SOUP_ERROR_NONE);

		return FALSE;
	}

	g_byte_array_append (req->priv->recv_buf,
			     read_buf,
			     bytes_read);
	
	req->priv->read_len += bytes_read;

	return TRUE;
}

const char base64_alphabet[65] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static gchar *
soup_base64_encode (gchar *text)
{
	char *buffer = NULL;
	char *point = NULL;
	int inlen = 0;
	int outlen = 0;

	/* check our args */
	if (text == NULL)
		return NULL;
  
	/* Use 'buffer' to store the output. Work out how big it should be...
	 * This must be a multiple of 4 bytes */
  
	inlen = strlen (text);
	/* check our arg...avoid a pesky FPE */
	if (inlen == 0) {
		buffer = malloc (sizeof(char));
		buffer[0] = '\0';
		return buffer;
	}

	outlen = (inlen*4)/3;
	if ((inlen % 3) > 0) /* got to pad */
		outlen += 4 - (inlen % 3);
  
	buffer = malloc (outlen + 1); /* +1 for the \0 */
	memset (buffer, 0, outlen + 1); /* initialize to zero */
  
	/* now do the main stage of conversion, 3 bytes at a time,
	 * leave the trailing bytes (if there are any) for later */
  
	for (point=buffer; inlen>=3; inlen-=3, text+=3) {
		*(point++) = base64_alphabet [*text>>2]; 
		*(point++) = base64_alphabet [(*text<<4 & 0x30) | 
					     *(text+1)>>4]; 
		*(point++) = base64_alphabet [(*(text+1)<<2 & 0x3c) | 
					     *(text+2)>>6];
		*(point++) = base64_alphabet [*(text+2) & 0x3f];
	}
  
	/* Now deal with the trailing bytes */
	if (inlen) {
		/* We always have one trailing byte */
		*(point++) = base64_alphabet [*text>>2];
		*(point++) = base64_alphabet [(*text<<4 & 0x30) |
					     (inlen==2?*(text+1)>>4:0)]; 
		*(point++) = (inlen == 1 ? 
			      '=' : 
			      base64_alphabet [*(text+1)<<2 & 0x3c]);
		*(point++) = '=';
	}
	
	*point = '\0';
	
	return buffer;
}

static void
soup_encode_http_auth (gboolean proxy_auth, SoupUri *uri, GString *header)
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

struct SoupUsedHeaders {
	gchar *host;
	gchar *user_agent;
	gchar *content_type;
	gchar *charset;
	gchar *content_length;
	gchar *soapaction;
	gchar *connection;
	gchar *proxy_auth;
	gchar *auth;

	GSList *custom_headers;
};

struct SoupCustomHeader {
	gchar *key;
	gchar *val;
};

static inline void 
soup_check_used_headers (gchar *key, 
			 gchar *value, 
			 struct SoupUsedHeaders *hdrs)
{
	if (strcmp (key, "Host")) hdrs->host = value;
	else if (strcmp (key, "User-Agent")) hdrs->user_agent = value;
	else if (strcmp (key, "Content-Type")) hdrs->content_type = value;
	else if (strcmp (key, "Charset")) hdrs->charset = value;
	else if (strcmp (key, "Content-Length")) hdrs->content_length = value;
	else if (strcmp (key, "SOAPAction")) hdrs->soapaction = value;
	else if (strcmp (key, "Connection")) hdrs->connection = value;
	else if (strcmp (key, "Proxy-Authorization")) hdrs->proxy_auth = value;
	else if (strcmp (key, "Authorization")) hdrs->auth = value;
	else {
		struct SoupCustomHeader *cust; 
		cust = g_new (struct SoupCustomHeader, 1);
		cust->key = key;
		cust->val = value;
		hdrs->custom_headers = g_slist_append (hdrs->custom_headers, 
						       cust);
	}
}

static GString *
soup_get_request_header (SoupRequest *req)
{
	GString *header = g_string_new ("");
	gchar *uri;
	SoupContext *proxy = soup_get_proxy ();
	gchar content_length_str[10];

	struct SoupUsedHeaders hdrs = {
		req->context->uri->host, 
		"Soup/0.1", 
		"text/xml", 
		"\"utf-8\"",
		NULL, 
		req->action,
		"keep-alive",
		NULL,
		NULL,
		NULL
	};

	if (req->custom_headers) 
		g_hash_table_foreach (req->custom_headers, 
				      (GHFunc) soup_check_used_headers,
				      &hdrs);

	if (!hdrs.content_length) {
		g_snprintf (content_length_str, 10, "%d", req->request.length);
		hdrs.content_length = content_length_str;
	}

	if (proxy)
		uri = soup_uri_to_string (proxy->uri, FALSE);
	else 
		uri = req->context->uri->path;

	/* If we specify an absoluteURI in the request line, the 
	   Host header MUST be ignored by the proxy. */

	g_string_sprintfa (header,
			   "POST %s HTTP/1.1\r\n"
			   "Host: %s\r\n"
			   "User-Agent: %s\r\n"
			   "Content-Type: %s;\r\n"
			   "charset=%s\r\n"
			   "Content-Length: %s\r\n"
			   "SOAPAction: %s\r\n"
			   "Connection: %s\r\n",
			   uri,
			   hdrs.host,
			   hdrs.user_agent,
			   hdrs.content_type,
			   hdrs.charset,
			   hdrs.content_length,
			   hdrs.soapaction,
			   hdrs.connection);

	if (!hdrs.proxy_auth) {
		if (proxy && proxy->uri->user)
			soup_encode_http_auth (TRUE, proxy->uri, header);
	} else
		g_string_sprintfa (header, 
				   "Proxy-Authorization: %s\r\n",
				   hdrs.proxy_auth);

	/* FIXME: if going through a proxy, do we use the absoluteURI on 
	          the request line, or encode the Authorization header into
		  the message? */

	if (!hdrs.auth) {
		if (req->context->uri->user)
			soup_encode_http_auth (FALSE, proxy->uri, header);
	} else 
		g_string_sprintfa (header, 
				   "Authorization: %s\r\n",
				   hdrs.auth);

	/* Append custom headers for this request */

	if (hdrs.custom_headers) {
		GSList *iter = hdrs.custom_headers;

		while (iter) {
			struct SoupCustomHeader *cust_hdr = iter->data;
			g_string_sprintfa (header, 
					   "%s: %s\r\n", 
					   cust_hdr->key, 
					   cust_hdr->val);
			g_free (cust_hdr);

			iter = iter->next;
		}

		g_slist_free (hdrs.custom_headers);
	}

	g_string_append (header, "\r\n");

	return header;
}

static gboolean 
soup_queue_write_async (GIOChannel* iochannel, 
			GIOCondition condition, 
			SoupRequest *req)
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
		guint offset = head_len - total_written;
		write_len = (offset) + body_len;
		write_buf = alloca (write_len);
		memcpy (write_buf, 
			&req->priv->req_header->str [offset],
			offset);
		memcpy (&write_buf [offset + 1],
			req->request.body,
			req->request.length);
	} else if (total_written >= head_len) {
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
		soup_request_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	total_written += bytes_written;
	req->priv->write_len = total_written;

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
			SoupRequest *req)
{
	switch (condition) {
	case G_IO_ERR:
	case G_IO_HUP:
	case G_IO_NVAL:
		switch (req->status) {
		case SOUP_STATUS_FINISHED:
			break;
		case SOUP_STATUS_CONNECTING:
			soup_request_issue_callback (req, 
						     SOUP_ERROR_CANT_CONNECT);
			break;
		default:
			soup_request_issue_callback (req, 
						     SOUP_ERROR_IO);
			break;
		}
	case G_IO_IN:
	case G_IO_OUT:
	case G_IO_PRI:
		g_warning ("soup_queue_error_async(): "
			   "Non-error value passed to IO error handler.");
		return TRUE;
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
		    GTcpSocket           *socket,
		    gpointer              user_data)
{
	SoupRequest *req = user_data;
	GIOChannel *channel;

	switch (err) {
	case SOUP_CONNECT_ERROR_NONE:
		channel = gnet_tcp_socket_get_iochannel (socket);
		
		soup_setup_socket (channel);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->priv->socket = socket;
		req->priv->connect_tag = NULL;
		req->priv->write_tag = 
			g_io_add_watch (channel, 
					G_IO_OUT, 
					(GIOFunc) soup_queue_write_async, 
					req);
		req->priv->error_tag = 
			g_io_add_watch (channel, 
					G_IO_ERR|G_IO_HUP|G_IO_NVAL, 
					(GIOFunc) soup_queue_error_async, 
					req);
		break;
	case SOUP_CONNECT_ERROR_ADDR_RESOLVE:
	case SOUP_CONNECT_ERROR_NETWORK:
		soup_request_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
		break;
	}
}

static gboolean 
soup_idle_handle_new_requests (gpointer unused)
{
        GSList *iter = active_requests;
	
	while (iter) {
		SoupRequest *req = iter->data;
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

		iter = iter->next;
	}

	soup_queue_idle_tag = 0;
	return FALSE;
}

void 
soup_queue_request (SoupRequest    *req,
		    SoupCallbackFn  callback, 
		    gpointer        user_data)
{
	if (!soup_queue_idle_tag)
		soup_queue_idle_tag = 
			g_idle_add (soup_idle_handle_new_requests, NULL);

	if (req->response.owner == SOUP_BUFFER_SYSTEM_OWNED) {
		g_free (req->response.body);
		req->response.body = NULL;
		req->response.length = 0;
	}

	if (req->priv->recv_buf) {
		g_byte_array_free (req->priv->recv_buf, TRUE);
		req->priv->recv_buf = NULL;
	}

	req->priv->callback = callback;
	req->priv->user_data = user_data;
	req->status = SOUP_STATUS_QUEUED;

	soup_context_ref (req->context);

	active_requests = g_slist_append (active_requests, req);
}

void 
soup_queue_shutdown ()
{
        GSList *iter;

	g_source_remove (soup_queue_idle_tag);
	soup_queue_idle_tag = 0;

	for (iter = active_requests; iter; iter = iter->next)
		soup_request_cancel (iter->data);
}
