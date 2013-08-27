/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket-io-stream.c
 *
 * Copyright 2012, 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-socket-io-stream.h"
#include "soup.h"
#include "soup-filter-input-stream.h"

struct _SoupSocketIOStreamPrivate {
	GIOStream *base_iostream;

	GInputStream *istream;
	GOutputStream *ostream;
	gboolean disposing;
};

enum {
	PROP_0,

	PROP_BASE_IOSTREAM
};

G_DEFINE_TYPE (SoupSocketIOStream, soup_socket_io_stream, G_TYPE_IO_STREAM)

static void
soup_socket_io_stream_init (SoupSocketIOStream *stream)
{
	stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream,
						    SOUP_TYPE_SOCKET_IO_STREAM,
						    SoupSocketIOStreamPrivate);
}

static void
soup_socket_io_stream_set_property (GObject *object, guint prop_id,
				    const GValue *value, GParamSpec *pspec)
{
	SoupSocketIOStream *ssios = SOUP_SOCKET_IO_STREAM (object);
	GIOStream *io;

	switch (prop_id) {
	case PROP_BASE_IOSTREAM:
		io = ssios->priv->base_iostream = g_value_dup_object (value);
		if (io) {
			ssios->priv->istream =
				soup_filter_input_stream_new (g_io_stream_get_input_stream (io));
			ssios->priv->ostream =
				g_object_ref (g_io_stream_get_output_stream (io));
		} else {
			g_clear_object (&ssios->priv->istream);
			g_clear_object (&ssios->priv->ostream);
		}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_socket_io_stream_get_property (GObject *object, guint prop_id,
				    GValue *value, GParamSpec *pspec)
{
	SoupSocketIOStream *ssios = SOUP_SOCKET_IO_STREAM (object);

	switch (prop_id) {
	case PROP_BASE_IOSTREAM:
		g_value_set_object (value, ssios->priv->base_iostream);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_socket_io_stream_dispose (GObject *object)
{
	SoupSocketIOStream *ssios = SOUP_SOCKET_IO_STREAM (object);

	ssios->priv->disposing = TRUE;

	G_OBJECT_CLASS (soup_socket_io_stream_parent_class)->dispose (object);
}

static void
soup_socket_io_stream_finalize (GObject *object)
{
	SoupSocketIOStream *ssios = SOUP_SOCKET_IO_STREAM (object);

	g_clear_object (&ssios->priv->base_iostream);
	g_clear_object (&ssios->priv->istream);
	g_clear_object (&ssios->priv->ostream);

	G_OBJECT_CLASS (soup_socket_io_stream_parent_class)->finalize (object);
}

static GInputStream *
soup_socket_io_stream_get_input_stream (GIOStream *stream)
{
	return SOUP_SOCKET_IO_STREAM (stream)->priv->istream;
}

static GOutputStream *
soup_socket_io_stream_get_output_stream (GIOStream *stream)
{
	return SOUP_SOCKET_IO_STREAM (stream)->priv->ostream;
}


static gboolean
soup_socket_io_stream_close (GIOStream     *stream,
			     GCancellable  *cancellable,
			     GError       **error)
{
	SoupSocketIOStream *ssios = SOUP_SOCKET_IO_STREAM (stream);

	if (ssios->priv->disposing)
		return TRUE;

	return g_io_stream_close (ssios->priv->base_iostream,
				  cancellable, error);
}

static void    
soup_socket_io_stream_close_async (GIOStream           *stream,
				   int                  io_priority,
				   GCancellable        *cancellable,
				   GAsyncReadyCallback  callback,
				   gpointer             user_data)
{
	g_io_stream_close_async (SOUP_SOCKET_IO_STREAM (stream)->priv->base_iostream,
				 io_priority, cancellable, callback, user_data);
}

static gboolean
soup_socket_io_stream_close_finish (GIOStream     *stream,
				    GAsyncResult  *result,
				    GError       **error)
{
	return g_io_stream_close_finish (SOUP_SOCKET_IO_STREAM (stream)->priv->base_iostream,
					 result, error);
}

static void
soup_socket_io_stream_class_init (SoupSocketIOStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GIOStreamClass *io_stream_class = G_IO_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupSocketIOStreamPrivate));

	object_class->set_property = soup_socket_io_stream_set_property;
	object_class->get_property = soup_socket_io_stream_get_property;
	object_class->dispose = soup_socket_io_stream_dispose;
	object_class->finalize = soup_socket_io_stream_finalize;

	io_stream_class->get_input_stream = soup_socket_io_stream_get_input_stream;
	io_stream_class->get_output_stream = soup_socket_io_stream_get_output_stream;
	io_stream_class->close_fn = soup_socket_io_stream_close;
	io_stream_class->close_async = soup_socket_io_stream_close_async;
	io_stream_class->close_finish = soup_socket_io_stream_close_finish;

	g_object_class_install_property (
		object_class, PROP_BASE_IOSTREAM,
		g_param_spec_object ("base-iostream",
				     "Base IOStream",
				     "Base GIOStream",
				     G_TYPE_IO_STREAM,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY));
}

GIOStream *
soup_socket_io_stream_new (GIOStream *base_iostream)
{
	return g_object_new (SOUP_TYPE_SOCKET_IO_STREAM,
			     "base-iostream", base_iostream,
			     NULL);
}
