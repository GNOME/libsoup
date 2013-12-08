/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_FILTER_OUTPUT_STREAM_H
#define SOUP_FILTER_OUTPUT_STREAM_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_FILTER_OUTPUT_STREAM            (soup_filter_output_stream_get_type ())
#define SOUP_FILTER_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_FILTER_OUTPUT_STREAM, SoupFilterOutputStream))
#define SOUP_FILTER_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_FILTER_OUTPUT_STREAM, SoupFilterOutputStreamClass))
#define SOUP_IS_FILTER_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_FILTER_OUTPUT_STREAM))
#define SOUP_IS_FILTER_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_FILTER_OUTPUT_STREAM))
#define SOUP_FILTER_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_FILTER_OUTPUT_STREAM, SoupFilterOutputStreamClass))

typedef struct _SoupFilterOutputStreamPrivate SoupFilterOutputStreamPrivate;

typedef struct {
	GFilterOutputStream parent;

	SoupFilterOutputStreamPrivate *priv;
} SoupFilterOutputStream;

typedef struct {
	GFilterOutputStreamClass parent_class;

} SoupFilterOutputStreamClass;

GType soup_filter_output_stream_get_type (void);

GOutputStream *soup_filter_output_stream_new (GOutputStream *base_stream);

G_END_DECLS

#endif /* SOUP_FILTER_OUTPUT_STREAM_H */
