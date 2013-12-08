/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http1-input-stream.c
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup-http1-input-stream.h"
#include "soup.h"
#include "soup-body-input-stream.h"

G_DEFINE_TYPE (SoupHTTP1InputStream, soup_http1_input_stream, SOUP_TYPE_HTTP_INPUT_STREAM)

typedef struct {
	GByteArray *header_buf;
	gboolean headers_complete;

	SoupEncoding encoding;
	goffset content_length;
} SoupHTTP1InputStreamPrivate;
#define SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP1_INPUT_STREAM, SoupHTTP1InputStreamPrivate))

static void
soup_http1_input_stream_init (SoupHTTP1InputStream *http1)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http1);

	priv->header_buf = g_byte_array_new ();
	priv->encoding = SOUP_ENCODING_NONE;
	priv->content_length = -1;
}

static void
soup_http1_input_stream_finalize (GObject *object)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (object);

	g_byte_array_unref (priv->header_buf);

	G_OBJECT_CLASS (soup_http1_input_stream_parent_class)->finalize (object);
}

#define READ_BUFFER_SIZE 8192

static gboolean
soup_http1_input_stream_read_headers (SoupHTTPInputStream  *http,
				      gboolean              blocking,
				      GCancellable         *cancellable,
				      GError              **error)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http);
	SoupFilterInputStream *istream = SOUP_FILTER_INPUT_STREAM (G_FILTER_INPUT_STREAM (http)->base_stream);
	gssize nread, old_len;
	gboolean got_lf;

	if (priv->headers_complete) {
		/* restart */
		g_byte_array_set_size (priv->header_buf, 0);
		priv->headers_complete = FALSE;
	}

	while (1) {
		old_len = priv->header_buf->len;
		g_byte_array_set_size (priv->header_buf, old_len + READ_BUFFER_SIZE);
		nread = soup_filter_input_stream_read_line (istream,
							    priv->header_buf->data + old_len,
							    READ_BUFFER_SIZE,
							    blocking,
							    &got_lf,
							    cancellable, error);
		priv->header_buf->len = old_len + MAX (nread, 0);

		if (nread < 0)
			return FALSE;
		else if (nread == 0) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
					     _("Connection terminated unexpectedly"));
			return FALSE;
		}

		if (got_lf) {
			if (nread == 1 && old_len >= 2 &&
			    !strncmp ((char *)priv->header_buf->data +
				      priv->header_buf->len - 2,
				      "\n\n", 2))
				break;
			else if (nread == 2 && old_len >= 3 &&
				 !strncmp ((char *)priv->header_buf->data +
					   priv->header_buf->len - 3,
					   "\n\r\n", 3))
				break;
		}
	}

	/* We need to "rewind" priv->header_buf back one line.
	 * That SHOULD be two characters (CR LF), but if the
	 * web server was stupid, it might only be one.
	 */
	if (priv->header_buf->len < 3 ||
	    priv->header_buf->data[priv->header_buf->len - 2] == '\n')
		priv->header_buf->len--;
	else
		priv->header_buf->len -= 2;
	priv->header_buf->data[priv->header_buf->len] = '\0';

	priv->headers_complete = TRUE;
	return TRUE;
}

static guint
soup_http1_input_stream_parse_request_headers (SoupHTTPInputStream  *http,
					       SoupSocket           *sock,
					       char                **method,
					       SoupURI             **request_uri,
					       SoupHTTPVersion      *version,
					       SoupMessageHeaders   *headers,
					       GError              **error)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http);
	guint status;
	char *req_method, *req_path, *uri_string;
	const char *req_host;
	SoupURI *uri;

	status = soup_headers_parse_request ((const char *)priv->header_buf->data,
					     priv->header_buf->len,
					     headers,
					     &req_method, &req_path, version);
	if (status != SOUP_STATUS_OK) {
	failed:
		g_set_error_literal (error, SOUP_REQUEST_ERROR,
				     SOUP_REQUEST_ERROR_PARSING,
				     _("Could not parse HTTP request"));
		return status;
	}

	/* Handle request body encoding */
	priv->encoding = soup_message_headers_get_encoding (headers);
	if (priv->encoding == SOUP_ENCODING_UNRECOGNIZED) {
		g_free (req_method);
		g_free (req_path);
		if (soup_message_headers_get_list (headers, "Transfer-Encoding"))
			status = SOUP_STATUS_NOT_IMPLEMENTED;
		else
			status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}
	if (priv->encoding == SOUP_ENCODING_CONTENT_LENGTH)
		priv->content_length = soup_message_headers_get_content_length (headers);
	else
		priv->content_length = -1;

	/* Generate correct context for request */
	req_host = soup_message_headers_get_one (headers, "Host");
	if (req_host && strchr (req_host, '/')) {
		g_free (req_method);
		g_free (req_path);
		status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}

	if (!strcmp (req_path, "*") && req_host) {
		/* Eg, "OPTIONS * HTTP/1.1" */
		uri_string = g_strdup_printf ("%s://%s",
					      soup_socket_is_ssl (sock) ? "https" : "http",
					      req_host);
		uri = soup_uri_new (uri_string);
		if (uri)
			soup_uri_set_path (uri, "*");
		g_free (uri_string);
	} else if (*req_path != '/') {
		/* Must be an absolute URI */
		uri = soup_uri_new (req_path);
	} else if (req_host) {
		uri_string = g_strdup_printf ("%s://%s%s",
					      soup_socket_is_ssl (sock) ? "https" : "http",
					      req_host, req_path);
		uri = soup_uri_new (uri_string);
		g_free (uri_string);
	} else if (*version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (sock);

		uri = soup_uri_new (NULL);
		soup_uri_set_scheme (uri, soup_socket_is_ssl (sock) ? "https" : "http");
		soup_uri_set_host (uri, soup_address_get_physical (addr));
		soup_uri_set_port (uri, soup_address_get_port (addr));
		soup_uri_set_path (uri, req_path);
	} else
		uri = NULL;

	g_free (req_path);

	if (!uri || !uri->host) {
		g_free (req_method);
		if (uri)
			soup_uri_free (uri);
		status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}

	*method = req_method;
	*request_uri = uri;
	return SOUP_STATUS_OK;
}

static gboolean
soup_http1_input_stream_parse_response_headers (SoupHTTPInputStream  *http,
						const char           *request_method,
						SoupHTTPVersion      *version,
						guint                *status_code,
						char                **reason_phrase,
						SoupMessageHeaders   *headers,
						GError              **error)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http);

	if (!soup_headers_parse_response ((const char *)priv->header_buf->data,
					  priv->header_buf->len,
					  headers, version, status_code, reason_phrase)) {
		g_set_error_literal (error, SOUP_REQUEST_ERROR,
				     SOUP_REQUEST_ERROR_PARSING,
				     _("Could not parse HTTP response"));
		return FALSE;
	}

	if (request_method == SOUP_METHOD_HEAD ||
	    *status_code == SOUP_STATUS_NO_CONTENT ||
	    *status_code == SOUP_STATUS_NOT_MODIFIED ||
	    SOUP_STATUS_IS_INFORMATIONAL (*status_code) ||
	    (request_method == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (*status_code)))
		priv->encoding = SOUP_ENCODING_NONE;
	else {
		priv->encoding = soup_message_headers_get_encoding (headers);

		if (priv->encoding == SOUP_ENCODING_UNRECOGNIZED) {
			g_set_error_literal (error, SOUP_REQUEST_ERROR,
					     SOUP_REQUEST_ERROR_ENCODING,
					     _("Unrecognized HTTP encoding"));
			return FALSE;
		}
	}

	if (priv->encoding == SOUP_ENCODING_CONTENT_LENGTH) {
		const char *conn;

		priv->content_length = soup_message_headers_get_content_length (headers);

		/* Some servers suck and send incorrect Content-Length
		 * values, so if the message isn't keepalive anyway, allow
		 * EOF termination.
		 */
		conn = soup_message_headers_get_one (headers, "Connection");
		if (*version == SOUP_HTTP_1_0 &&
		    (!conn || !soup_header_contains (conn, "Keep-Alive")))
			priv->encoding = SOUP_ENCODING_EOF;
		else if (*version == SOUP_HTTP_1_1 && conn &&
			 soup_header_contains (conn, "close"))
			priv->encoding = SOUP_ENCODING_EOF;
	} else
		priv->content_length = -1;

	return TRUE;
}

static gboolean
soup_http1_input_stream_failed_immediately (SoupHTTPInputStream *http)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http);

	return priv->header_buf->len == 0;
}

static GInputStream *
soup_http1_input_stream_get_body_stream (SoupHTTPInputStream  *http)
{
	SoupHTTP1InputStreamPrivate *priv = SOUP_HTTP1_INPUT_STREAM_GET_PRIVATE (http);

	return soup_body_input_stream_new (G_FILTER_INPUT_STREAM (http)->base_stream,
					   priv->encoding,
					   priv->content_length);
}

static void
soup_http1_input_stream_class_init (SoupHTTP1InputStreamClass *http1_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (http1_class);
	SoupHTTPInputStreamClass *http_class = SOUP_HTTP_INPUT_STREAM_CLASS (http1_class);

	g_type_class_add_private (http1_class, sizeof (SoupHTTP1InputStreamPrivate));

	object_class->finalize = soup_http1_input_stream_finalize;

	http_class->read_headers = soup_http1_input_stream_read_headers;
	http_class->parse_request_headers = soup_http1_input_stream_parse_request_headers;
	http_class->parse_response_headers = soup_http1_input_stream_parse_response_headers;
	http_class->failed_immediately = soup_http1_input_stream_failed_immediately;
	http_class->get_body_stream = soup_http1_input_stream_get_body_stream;
}

GInputStream *
soup_http1_input_stream_new (GInputStream *base_stream)
{
	g_return_val_if_fail (SOUP_IS_FILTER_INPUT_STREAM (base_stream), NULL);

	return g_object_new (SOUP_TYPE_HTTP1_INPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}
