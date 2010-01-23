/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-coding-gzip.c: "gzip" coding
 *
 * Copyright (C) 2005 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-coding-gzip.h"

#include <zlib.h>

typedef struct {
	z_stream stream;

} SoupCodingGzipPrivate;
#define SOUP_CODING_GZIP_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_CODING_GZIP, SoupCodingGzipPrivate))

G_DEFINE_TYPE (SoupCodingGzip, soup_coding_gzip, SOUP_TYPE_CODING)

static void             constructed (GObject *object);
static void             finalize    (GObject *object);
static SoupCodingStatus apply_into  (SoupCoding *coding,
				     gconstpointer input, gsize input_length,
				     gsize *input_used,
				     gpointer output, gsize output_length,
				     gsize *output_used,
				     gboolean done, GError **error);

static void
soup_coding_gzip_init (SoupCodingGzip *gzip)
{
	SoupCodingGzipPrivate *priv = SOUP_CODING_GZIP_GET_PRIVATE (gzip);

	priv->stream.zalloc = Z_NULL;
	priv->stream.zfree = Z_NULL;
	priv->stream.opaque = Z_NULL;
}

static void
soup_coding_gzip_class_init (SoupCodingGzipClass *gzip_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (gzip_class);
	SoupCodingClass *coding_class = SOUP_CODING_CLASS (gzip_class);

	g_type_class_add_private (gzip_class, sizeof (SoupCodingGzipPrivate));

	coding_class->name = "gzip";

	object_class->constructed = constructed;
	object_class->finalize = finalize;

	coding_class->apply_into = apply_into;
}

static void
constructed (GObject *object)
{
	SoupCodingGzipPrivate *priv = SOUP_CODING_GZIP_GET_PRIVATE (object);

	/* All of these values are the defaults according to the zlib
	 * documentation. "16" is a magic number that means gzip
	 * instead of zlib.
	 */
	if (SOUP_CODING (object)->direction == SOUP_CODING_ENCODE) {
		deflateInit2 (&priv->stream, Z_DEFAULT_COMPRESSION,
			      Z_DEFLATED, MAX_WBITS | 16, 8,
			      Z_DEFAULT_STRATEGY);
	} else
		inflateInit2 (&priv->stream, MAX_WBITS | 16);
}

static void
finalize (GObject *object)
{
	SoupCodingGzipPrivate *priv = SOUP_CODING_GZIP_GET_PRIVATE (object);

	if (SOUP_CODING (object)->direction == SOUP_CODING_ENCODE)
		deflateEnd (&priv->stream);
	else
		inflateEnd (&priv->stream);

	G_OBJECT_CLASS (soup_coding_gzip_parent_class)->finalize (object);
}

static SoupCodingStatus
apply_into (SoupCoding *coding,
	    gconstpointer input, gsize input_length, gsize *input_used,
	    gpointer output, gsize output_length, gsize *output_used,
	    gboolean done, GError **error)
{
	SoupCodingGzipPrivate *priv = SOUP_CODING_GZIP_GET_PRIVATE (coding);
	int ret;

	priv->stream.avail_in = input_length;
	priv->stream.next_in  = (gpointer)input;
	priv->stream.total_in = 0;

	priv->stream.avail_out = output_length;
	priv->stream.next_out  = output;
	priv->stream.total_out = 0;

	if (coding->direction == SOUP_CODING_ENCODE)
		ret = deflate (&priv->stream, done ? Z_FINISH : Z_NO_FLUSH);
	else
		ret = inflate (&priv->stream, Z_SYNC_FLUSH);

	*input_used = priv->stream.total_in;
	*output_used = priv->stream.total_out;

	switch (ret) {
	case Z_NEED_DICT:
	case Z_DATA_ERROR:
	case Z_STREAM_ERROR:
		g_set_error_literal (error, SOUP_CODING_ERROR,
				     SOUP_CODING_ERROR_DATA_ERROR,
				     priv->stream.msg ? priv->stream.msg : "Bad data");
		return SOUP_CODING_STATUS_ERROR;

	case Z_BUF_ERROR:
	case Z_MEM_ERROR:
		g_set_error_literal (error, SOUP_CODING_ERROR,
				     SOUP_CODING_ERROR_INTERNAL_ERROR,
				     priv->stream.msg ? priv->stream.msg : "Internal error");
		return SOUP_CODING_STATUS_ERROR;

	case Z_STREAM_END:
		/* Discard any trailing junk, for compatibility with
		 * other browsers. FIXME: this really belongs in
		 * soup-message-io, but it's not possible to do there
		 * with the current API.
		 */
		*input_used = input_length;
		return SOUP_CODING_STATUS_COMPLETE;

	case Z_OK:
	default:
		if (*output_used == output_length &&
		    *input_used < input_length)
			return SOUP_CODING_STATUS_NEED_SPACE;
		else
			return SOUP_CODING_STATUS_OK;
	}
}
