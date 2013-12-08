/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http-output-stream.c
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-http-output-stream.h"
#include "soup.h"
#include "soup-filter-output-stream.h"

G_DEFINE_ABSTRACT_TYPE (SoupHTTPOutputStream, soup_http_output_stream, SOUP_TYPE_FILTER_OUTPUT_STREAM)

static void
soup_http_output_stream_init (SoupHTTPOutputStream *http)
{
}

static void
soup_http_output_stream_class_init (SoupHTTPOutputStreamClass *http_class)
{
}

void
soup_http_output_stream_build_request_headers (SoupHTTPOutputStream  *http,
					       gboolean               via_proxy,
					       const char            *method,
					       SoupURI               *request_uri,
					       SoupHTTPVersion        version,
					       SoupMessageHeaders    *headers)
{
	return SOUP_HTTP_OUTPUT_STREAM_GET_CLASS (http)->
		build_request_headers (http, via_proxy,
				       method, request_uri, version,
				       headers);
}

void
soup_http_output_stream_build_response_headers (SoupHTTPOutputStream  *http,
						const char            *request_method,
						SoupHTTPVersion        version,
						guint                  status_code,
						const char            *reason_phrase,
						SoupMessageHeaders    *headers)
{
	return SOUP_HTTP_OUTPUT_STREAM_GET_CLASS (http)->
		build_response_headers (http, request_method,
					version, status_code, reason_phrase,
					headers);
}

gboolean
soup_http_output_stream_write_headers (SoupHTTPOutputStream  *http,
				       gboolean               blocking,
				       GCancellable          *cancellable,
				       GError               **error)
{
	return SOUP_HTTP_OUTPUT_STREAM_GET_CLASS (http)->
		write_headers (http, blocking, cancellable, error);
}

GOutputStream *
soup_http_output_stream_get_body_stream (SoupHTTPOutputStream *http)
{
	return SOUP_HTTP_OUTPUT_STREAM_GET_CLASS (http)->
		get_body_stream (http);
}
