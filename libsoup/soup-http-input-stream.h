/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_HTTP_INPUT_STREAM_H
#define SOUP_HTTP_INPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-filter-input-stream.h"
#include "soup-message.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP_INPUT_STREAM            (soup_http_input_stream_get_type ())
#define SOUP_HTTP_INPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP_INPUT_STREAM, SoupHTTPInputStream))
#define SOUP_HTTP_INPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP_INPUT_STREAM, SoupHTTPInputStreamClass))
#define SOUP_IS_HTTP_INPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP_INPUT_STREAM))
#define SOUP_IS_HTTP_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP_INPUT_STREAM))
#define SOUP_HTTP_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP_INPUT_STREAM, SoupHTTPInputStreamClass))

typedef struct {
	SoupFilterInputStream parent;

} SoupHTTPInputStream;

typedef struct {
	SoupFilterInputStreamClass parent_class;

	gboolean      (*read_headers)           (SoupHTTPInputStream  *http,
						 gboolean              blocking,
						 GCancellable         *cancellable,
						 GError              **error);
	guint         (*parse_request_headers)  (SoupHTTPInputStream  *http,
						 SoupSocket           *sock,
						 char                **method,
						 SoupURI             **request_uri,
						 SoupHTTPVersion      *version,
						 SoupMessageHeaders   *headers,
						 GError              **error);
	gboolean      (*parse_response_headers) (SoupHTTPInputStream  *http,
						 const char           *request_method,
						 SoupHTTPVersion      *version,
						 guint                *status_code,
						 char                **reason_phrase,
						 SoupMessageHeaders   *headers,
						 GError              **error);

	gboolean      (*failed_immediately)     (SoupHTTPInputStream  *http);

	GInputStream *(*get_body_stream)        (SoupHTTPInputStream  *http);

} SoupHTTPInputStreamClass;

GType soup_http_input_stream_get_type (void);

gboolean      soup_http_input_stream_read_headers           (SoupHTTPInputStream  *http,
							     gboolean              blocking,
							     GCancellable         *cancellable,
							     GError              **error);
guint         soup_http_input_stream_parse_request_headers  (SoupHTTPInputStream  *http,
							     SoupSocket           *sock,
							     char                **method,
							     SoupURI             **request_uri,
							     SoupHTTPVersion      *version,
							     SoupMessageHeaders   *headers,
							     GError              **error);
gboolean      soup_http_input_stream_parse_response_headers (SoupHTTPInputStream  *http,
							     const char           *request_method,
							     SoupHTTPVersion      *version,
							     guint                *status_code,
							     char                **reason_phrase,
							     SoupMessageHeaders   *headers,
							     GError              **error);

gboolean      soup_http_input_stream_failed_immediately     (SoupHTTPInputStream  *http);

GInputStream *soup_http_input_stream_get_body_stream        (SoupHTTPInputStream  *http);

G_END_DECLS

#endif /* SOUP_HTTP_INPUT_STREAM_H */
