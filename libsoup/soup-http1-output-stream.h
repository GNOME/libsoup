/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_HTTP1_OUTPUT_STREAM_H
#define SOUP_HTTP1_OUTPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-http-output-stream.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP1_OUTPUT_STREAM            (soup_http1_output_stream_get_type ())
#define SOUP_HTTP1_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP1_OUTPUT_STREAM, SoupHTTP1OutputStream))
#define SOUP_HTTP1_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP1_OUTPUT_STREAM, SoupHTTP1OutputStreamClass))
#define SOUP_IS_HTTP1_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP1_OUTPUT_STREAM))
#define SOUP_IS_HTTP1_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP1_OUTPUT_STREAM))
#define SOUP_HTTP1_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP1_OUTPUT_STREAM, SoupHTTP1OutputStreamClass))

typedef struct {
	SoupHTTPOutputStream parent;

} SoupHTTP1OutputStream;

typedef struct {
	SoupHTTPOutputStreamClass parent_class;

} SoupHTTP1OutputStreamClass;

GType soup_http1_output_stream_get_type (void);

GOutputStream *soup_http1_output_stream_new (GOutputStream *base_stream);

G_END_DECLS

#endif /* SOUP_HTTP1_OUTPUT_STREAM_H */
