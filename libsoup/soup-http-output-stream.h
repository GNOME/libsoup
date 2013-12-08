/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_HTTP_OUTPUT_STREAM_H
#define SOUP_HTTP_OUTPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-filter-output-stream.h"
#include "soup-message.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP_OUTPUT_STREAM            (soup_http_output_stream_get_type ())
#define SOUP_HTTP_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP_OUTPUT_STREAM, SoupHTTPOutputStream))
#define SOUP_HTTP_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP_OUTPUT_STREAM, SoupHTTPOutputStreamClass))
#define SOUP_IS_HTTP_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP_OUTPUT_STREAM))
#define SOUP_IS_HTTP_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP_OUTPUT_STREAM))
#define SOUP_HTTP_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP_OUTPUT_STREAM, SoupHTTPOutputStreamClass))

typedef struct {
	SoupFilterOutputStream parent;

} SoupHTTPOutputStream;

typedef struct {
	SoupFilterOutputStreamClass parent_class;

	void           (*build_request_headers)  (SoupHTTPOutputStream  *http,
						  gboolean               via_proxy,
						  const char            *method,
						  SoupURI               *request_uri,
						  SoupHTTPVersion        version,
						  SoupMessageHeaders    *headers);
	void           (*build_response_headers) (SoupHTTPOutputStream  *http,
						  const char            *request_method,
						  SoupHTTPVersion        version,
						  guint                  status_code,
						  const char            *reason_phrase,
						  SoupMessageHeaders    *headers);

	gboolean       (*write_headers)          (SoupHTTPOutputStream  *http,
						  gboolean               blocking,
						  GCancellable          *cancellable,
						  GError               **error);

	GOutputStream *(*get_body_stream)        (SoupHTTPOutputStream  *http);

} SoupHTTPOutputStreamClass;

GType soup_http_output_stream_get_type (void);

void           soup_http_output_stream_build_request_headers  (SoupHTTPOutputStream  *http,
							       gboolean               via_proxy,
							       const char            *method,
							       SoupURI               *request_uri,
							       SoupHTTPVersion        version,
							       SoupMessageHeaders    *headers);
void           soup_http_output_stream_build_response_headers (SoupHTTPOutputStream  *http,
							       const char            *request_method,
							       SoupHTTPVersion        version,
							       guint                  status_code,
							       const char            *reason_phrase,
							       SoupMessageHeaders    *headers);

gboolean       soup_http_output_stream_write_headers          (SoupHTTPOutputStream  *http,
							       gboolean               blocking,
							       GCancellable          *cancellable,
							       GError               **error);

GOutputStream *soup_http_output_stream_get_body_stream        (SoupHTTPOutputStream  *http);

G_END_DECLS

#endif /* SOUP_HTTP_OUTPUT_STREAM_H */
