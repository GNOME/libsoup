/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef SOUP_HTTP2_OUTPUT_STREAM_H
#define SOUP_HTTP2_OUTPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-http2-channel.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP2_OUTPUT_STREAM            (soup_http2_output_stream_get_type ())
#define SOUP_HTTP2_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP2_OUTPUT_STREAM, SoupHTTP2OutputStream))
#define SOUP_HTTP2_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP2_OUTPUT_STREAM, SoupHTTP2OutputStreamClass))
#define SOUP_IS_HTTP2_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP2_OUTPUT_STREAM))
#define SOUP_IS_HTTP2_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP2_OUTPUT_STREAM))
#define SOUP_HTTP2_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP2_OUTPUT_STREAM, SoupHTTP2OutputStreamClass))

typedef struct {
  GOutputStream parent;

} SoupHTTP2OutputStream;

typedef struct {
  GOutputStreamClass parent_class;

} SoupHTTP2OutputStreamClass;

GType soup_http2_output_stream_get_type (void);

GOutputStream *soup_http2_output_stream_new           (SoupHTTP2Channel      *chan,
						       guint32                stream_id);

guint32        soup_http2_output_stream_get_stream_id (SoupHTTP2OutputStream *h2o)

void           soup_http2_output_stream_set_writable  (SoupHTTP2OutputStream *h2o,
						       gboolean               writable);
void           soup_http2_output_stream_push_error    (SoupHTTP2OutputStream *h2o,
						       GError                *error);

G_END_DECLS

#endif /* SOUP_HTTP2_OUTPUT_STREAM_H */
