/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef SOUP_HTTP2_INPUT_STREAM_H
#define SOUP_HTTP2_INPUT_STREAM_H 1

#include "soup-types.h"
#include "soup-http2-channel.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HTTP2_INPUT_STREAM            (soup_http2_input_stream_get_type ())
#define SOUP_HTTP2_INPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP2_INPUT_STREAM, SoupHTTP2InputStream))
#define SOUP_HTTP2_INPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP2_INPUT_STREAM, SoupHTTP2InputStreamClass))
#define SOUP_IS_HTTP2_INPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP2_INPUT_STREAM))
#define SOUP_IS_HTTP2_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP2_INPUT_STREAM))
#define SOUP_HTTP2_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP2_INPUT_STREAM, SoupHTTP2InputStreamClass))

typedef struct {
	GInputStream parent;

} SoupHTTP2InputStream;

typedef struct {
	GInputStreamClass parent_class;

} SoupHTTP2InputStreamClass;

GType soup_http2_input_stream_get_type (void);

GInputStream *soup_http2_input_stream_new           (SoupHTTP2Channel     *chan,
						     guint32               stream_id);

guint32       soup_http2_input_stream_get_stream_id (SoupHTTP2InputStream *h2i)

void          soup_http2_input_stream_push_data     (SoupHTTP2InputStream *h2i,
						     const guchar         *data,
						     gsize                 len);
void          soup_http2_input_stream_push_eof      (SoupHTTP2InputStream *h2i);
void          soup_http2_input_stream_push_error    (SoupHTTP2InputStream *h2i,
						     GError               *error);

G_END_DECLS

#endif /* SOUP_HTTP2_INPUT_STREAM_H */
