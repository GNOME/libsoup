/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http-input-stream.c
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-http-input-stream.h"
#include "soup.h"
#include "soup-filter-input-stream.h"

G_DEFINE_ABSTRACT_TYPE (SoupHTTPInputStream, soup_http_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM)

static void
soup_http_input_stream_init (SoupHTTPInputStream *http)
{
}

static void
soup_http_input_stream_class_init (SoupHTTPInputStreamClass *http_class)
{
}

gboolean
soup_http_input_stream_read_headers (SoupHTTPInputStream  *http,
				     gboolean              blocking,
				     GCancellable         *cancellable,
				     GError              **error)
{
	return SOUP_HTTP_INPUT_STREAM_GET_CLASS (http)->
		read_headers (http, blocking, cancellable, error);
}

guint
soup_http_input_stream_parse_request_headers (SoupHTTPInputStream  *http,
					      SoupSocket           *sock,
					      char                **method,
					      SoupURI             **request_uri,
					      SoupHTTPVersion      *version,
					      SoupMessageHeaders   *headers,
					      GError              **error)
{
	return SOUP_HTTP_INPUT_STREAM_GET_CLASS (http)->
		parse_request_headers (http, sock,
				       method, request_uri, version,
				       headers,
				       error);
}

gboolean
soup_http_input_stream_parse_response_headers (SoupHTTPInputStream  *http,
					       const char           *request_method,
					       SoupHTTPVersion      *version,
					       guint                *status_code,
					       char                **reason_phrase,
					       SoupMessageHeaders   *headers,
					       GError              **error)
{
	return SOUP_HTTP_INPUT_STREAM_GET_CLASS (http)->
		parse_response_headers (http, request_method,
					version, status_code, reason_phrase,
					headers,
					error);
}

gboolean
soup_http_input_stream_failed_immediately (SoupHTTPInputStream *http)
{
	return SOUP_HTTP_INPUT_STREAM_GET_CLASS (http)->
		failed_immediately (http);
}

GInputStream *
soup_http_input_stream_get_body_stream (SoupHTTPInputStream  *http)
{
	return SOUP_HTTP_INPUT_STREAM_GET_CLASS (http)->
		get_body_stream (http);
}
