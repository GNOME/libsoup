/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_HTTP1_INPUT_STREAM_H
#define SOUP_HTTP1_INPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-http-input-stream.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP1_INPUT_STREAM            (soup_http1_input_stream_get_type ())
#define SOUP_HTTP1_INPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP1_INPUT_STREAM, SoupHTTP1InputStream))
#define SOUP_HTTP1_INPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP1_INPUT_STREAM, SoupHTTP1InputStreamClass))
#define SOUP_IS_HTTP1_INPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP1_INPUT_STREAM))
#define SOUP_IS_HTTP1_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP1_INPUT_STREAM))
#define SOUP_HTTP1_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP1_INPUT_STREAM, SoupHTTP1InputStreamClass))

typedef struct {
	SoupHTTPInputStream parent;

} SoupHTTP1InputStream;

typedef struct {
	SoupHTTPInputStreamClass parent_class;

} SoupHTTP1InputStreamClass;

GType soup_http1_input_stream_get_type (void);

GInputStream *soup_http1_input_stream_new (GInputStream *base_stream);

G_END_DECLS

#endif /* SOUP_HTTP1_INPUT_STREAM_H */
