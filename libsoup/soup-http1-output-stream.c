/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http1-output-stream.c
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup-http1-output-stream.h"
#include "soup.h"
#include "soup-body-output-stream.h"

G_DEFINE_TYPE (SoupHTTP1OutputStream, soup_http1_output_stream, SOUP_TYPE_HTTP_OUTPUT_STREAM)

typedef struct {
	GString *header_buf;
	gsize nwritten;

	SoupEncoding encoding;
	goffset content_length;
} SoupHTTP1OutputStreamPrivate;
#define SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP1_OUTPUT_STREAM, SoupHTTP1OutputStreamPrivate))

static void
soup_http1_output_stream_init (SoupHTTP1OutputStream *http1)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http1);

	priv->header_buf = g_string_new (NULL);
	priv->encoding = SOUP_ENCODING_NONE;
	priv->content_length = -1;
}

static void
soup_http1_output_stream_finalize (GObject *object)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (object);

	g_string_free (priv->header_buf, TRUE);

	G_OBJECT_CLASS (soup_http1_output_stream_parent_class)->finalize (object);
}

static void
start_build_headers (SoupHTTPOutputStream *http)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);

	g_string_truncate (priv->header_buf, 0);
	priv->nwritten = 0;
}

static void
finish_build_headers (SoupHTTPOutputStream *http,
		      SoupMessageHeaders   *headers)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (priv->encoding == SOUP_ENCODING_CONTENT_LENGTH)
		priv->content_length = soup_message_headers_get_content_length (headers);

	soup_message_headers_iter_init (&iter, headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_string_append_printf (priv->header_buf, "%s: %s\r\n", name, value);
	g_string_append (priv->header_buf, "\r\n");
}

static void
soup_http1_output_stream_build_request_headers (SoupHTTPOutputStream  *http,
						gboolean               via_proxy,
						const char            *method,
						SoupURI               *request_uri,
						SoupHTTPVersion        version,
						SoupMessageHeaders    *headers)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);
	char *uri_host;
	char *uri_string;

	start_build_headers (http);

	if (strchr (request_uri->host, ':'))
		uri_host = g_strdup_printf ("[%.*s]", (int) strcspn (request_uri->host, "%"), request_uri->host);
	else if (g_hostname_is_non_ascii (request_uri->host))
		uri_host = g_hostname_to_ascii (request_uri->host);
	else
		uri_host = request_uri->host;

	if (method == SOUP_METHOD_CONNECT) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri_host, request_uri->port);
	} else {
		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		uri_string = soup_uri_to_string (request_uri, !via_proxy);

		if (via_proxy && request_uri->fragment) {
			/* Strip fragment */
			char *fragment = strchr (uri_string, '#');
			if (fragment)
				*fragment = '\0';
		}
	}

	g_string_append_printf (priv->header_buf, "%s %s HTTP/1.%d\r\n",
				method, uri_string,
				(version == SOUP_HTTP_1_0) ? 0 : 1);

	if (!soup_message_headers_get_one (headers, "Host")) {
		if (soup_uri_uses_default_port (request_uri)) {
			g_string_append_printf (priv->header_buf, "Host: %s\r\n",
						uri_host);
		} else {
			g_string_append_printf (priv->header_buf, "Host: %s:%d\r\n",
						uri_host, request_uri->port);
		}
	}
	g_free (uri_string);
	if (uri_host != request_uri->host)
		g_free (uri_host);

	priv->encoding = soup_message_headers_get_encoding (headers);
	finish_build_headers (http, headers);
}

static void
soup_http1_output_stream_build_response_headers (SoupHTTPOutputStream  *http,
						 const char            *request_method,
						 SoupHTTPVersion        version,
						 guint                  status_code,
						 const char            *reason_phrase,
						 SoupMessageHeaders    *headers)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);
	SoupEncoding claimed_encoding;

	start_build_headers (http);

	g_string_append_printf (priv->header_buf, "HTTP/1.%c %d %s\r\n",
				(version == SOUP_HTTP_1_0) ? '0' : '1',
				status_code, reason_phrase);

	claimed_encoding = soup_message_headers_get_encoding (headers);
	if ((request_method == SOUP_METHOD_HEAD ||
	     status_code  == SOUP_STATUS_NO_CONTENT ||
	     status_code  == SOUP_STATUS_NOT_MODIFIED ||
	     SOUP_STATUS_IS_INFORMATIONAL (status_code)) ||
	    (request_method == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (status_code)))
		priv->encoding = SOUP_ENCODING_NONE;
	else
		priv->encoding = claimed_encoding;

	finish_build_headers (http, headers);
}

static gboolean
soup_http1_output_stream_write_headers (SoupHTTPOutputStream  *http,
					gboolean               blocking,
					GCancellable          *cancellable,
					GError               **error)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);
	GOutputStream *ostream = G_FILTER_OUTPUT_STREAM (http)->base_stream;
	gssize nwrote;

	while (priv->nwritten < priv->header_buf->len) {
		nwrote = g_pollable_stream_write (ostream,
						  priv->header_buf->str + priv->nwritten,
						  priv->header_buf->len - priv->nwritten,
						  blocking, cancellable, error);
		if (nwrote == -1)
			return FALSE;
		priv->nwritten += nwrote;
	}

	return TRUE;
}

static GOutputStream *
soup_http1_output_stream_get_body_stream (SoupHTTPOutputStream  *http)
{
	SoupHTTP1OutputStreamPrivate *priv = SOUP_HTTP1_OUTPUT_STREAM_GET_PRIVATE (http);

	return soup_body_output_stream_new (G_FILTER_OUTPUT_STREAM (http)->base_stream,
					    priv->encoding,
					    priv->content_length);
}

static void
soup_http1_output_stream_class_init (SoupHTTP1OutputStreamClass *http1_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (http1_class);
	SoupHTTPOutputStreamClass *http_class = SOUP_HTTP_OUTPUT_STREAM_CLASS (http1_class);

	g_type_class_add_private (http1_class, sizeof (SoupHTTP1OutputStreamPrivate));

	object_class->finalize = soup_http1_output_stream_finalize;

	http_class->build_request_headers = soup_http1_output_stream_build_request_headers;
	http_class->build_response_headers = soup_http1_output_stream_build_response_headers;
	http_class->write_headers = soup_http1_output_stream_write_headers;
	http_class->get_body_stream = soup_http1_output_stream_get_body_stream;
}

GOutputStream *
soup_http1_output_stream_new (GOutputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_HTTP1_OUTPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}
