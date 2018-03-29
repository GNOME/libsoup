/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2015 Igalia S.L.
 */

#ifndef __SOUP_CACHE_CLIENT_INPUT_STREAM_H__
#define __SOUP_CACHE_CLIENT_INPUT_STREAM_H__ 1

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM            (soup_cache_client_input_stream_get_type ())
#define SOUP_CACHE_CLIENT_INPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM, SoupCacheClientInputStream))
#define SOUP_CACHE_CLIENT_INPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM, SoupCacheClientInputStreamClass))
#define SOUP_IS_CACHE_CLIENT_INPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM))
#define SOUP_IS_CACHE_CLIENT_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM))
#define SOUP_CACHE_CLIENT_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM, SoupCacheClientInputStreamClass))

typedef struct _SoupCacheClientInputStreamPrivate SoupCacheClientInputStreamPrivate;

typedef struct {
	GFilterInputStream parent;
} SoupCacheClientInputStream;

typedef struct {
	GFilterInputStreamClass parent_class;
} SoupCacheClientInputStreamClass;

GType soup_cache_client_input_stream_get_type (void);

GInputStream *soup_cache_client_input_stream_new (GInputStream *base_stream);

G_END_DECLS

#endif /* __SOUP_CACHE_CLIENT_INPUT_STREAM_H__ */
