/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cache-client-input-stream.c
 *
 * Copyright 2015 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-cache-client-input-stream.h"
#include "soup.h"
#include "soup-message-private.h"

enum {
	SIGNAL_EOF,
	SIGNAL_CLOSED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE (SoupCacheClientInputStream, soup_cache_client_input_stream, G_TYPE_FILTER_INPUT_STREAM)

static void
soup_cache_client_input_stream_init (SoupCacheClientInputStream *stream)
{
}

static gssize
soup_cache_client_input_stream_read_fn (GInputStream  *stream,
					void          *buffer,
					gsize          count,
					GCancellable  *cancellable,
					GError       **error)
{
	gssize nread;

	nread = G_INPUT_STREAM_CLASS (soup_cache_client_input_stream_parent_class)->
		read_fn (stream, buffer, count, cancellable, error);

	if (nread == 0)
		g_signal_emit (stream, signals[SIGNAL_EOF], 0);

	return nread;
}


static gboolean
soup_cache_client_input_stream_close_fn (GInputStream  *stream,
					 GCancellable  *cancellable,
					 GError       **error)
{
	gboolean success;

	success = G_INPUT_STREAM_CLASS (soup_cache_client_input_stream_parent_class)->
		close_fn (stream, cancellable, error);

	g_signal_emit (stream, signals[SIGNAL_CLOSED], 0);

	return success;
}

static void
soup_cache_client_input_stream_class_init (SoupCacheClientInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	input_stream_class->read_fn = soup_cache_client_input_stream_read_fn;
	input_stream_class->close_fn = soup_cache_client_input_stream_close_fn;

	signals[SIGNAL_EOF] =
		g_signal_new ("eof",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);
	signals[SIGNAL_CLOSED] =
		g_signal_new ("closed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);
}

GInputStream *
soup_cache_client_input_stream_new (GInputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM,
			     "base-stream", base_stream,
			     NULL);
}
