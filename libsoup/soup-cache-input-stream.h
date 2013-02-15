/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cache-input-stream.h - Header for SoupCacheInputStream
 */

#ifndef __SOUP_CACHE_INPUT_STREAM_H__
#define __SOUP_CACHE_INPUT_STREAM_H__

#include "soup-filter-input-stream.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHE_INPUT_STREAM		(soup_cache_input_stream_get_type())
#define SOUP_CACHE_INPUT_STREAM(obj)		(G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CACHE_INPUT_STREAM, SoupCacheInputStream))
#define SOUP_CACHE_INPUT_STREAM_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CACHE_INPUT_STREAM, SoupCacheInputStreamClass))
#define SOUP_IS_CACHE_INPUT_STREAM(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CACHE_INPUT_STREAM))
#define SOUP_IS_CACHE_INPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_CACHE_INPUT_STREAM))
#define SOUP_CACHE_INPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CACHE_INPUT_STREAM, SoupCacheInputStreamClass))

typedef struct _SoupCacheInputStream      SoupCacheInputStream;
typedef struct _SoupCacheInputStreamClass SoupCacheInputStreamClass;
typedef struct _SoupCacheInputStreamPrivate SoupCacheInputStreamPrivate;

struct _SoupCacheInputStreamClass
{
	SoupFilterInputStreamClass parent_class;

	/* signals */
	void     (*caching_finished) (SoupCacheInputStream *istream, gsize bytes_written, GError *error);
};

struct _SoupCacheInputStream
{
	SoupFilterInputStream parent;

	SoupCacheInputStreamPrivate *priv;
};

GType soup_cache_input_stream_get_type (void) G_GNUC_CONST;

GInputStream *soup_cache_input_stream_new (GInputStream *base_stream,
					   GFile        *file);

G_END_DECLS

#endif /* __SOUP_CACHE_INPUT_STREAM_H__ */
