/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-io-stream.c
 *
 * Copyright 2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-io-stream.h"
#include "soup.h"
#include "soup-filter-input-stream.h"

struct _SoupIOStream {
	GIOStream parent_instance;
};

typedef struct {
	GIOStream *base_iostream;
	gboolean close_on_dispose;

	GInputStream *istream;
	GOutputStream *ostream;
	gboolean disposing;
} SoupIOStreamPrivate;

enum {
	PROP_0,

	PROP_BASE_IOSTREAM,
	PROP_CLOSE_ON_DISPOSE,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupIOStream, soup_io_stream, G_TYPE_IO_STREAM)

static void
soup_io_stream_init (SoupIOStream *stream)
{
}

static void
soup_io_stream_set_property (GObject *object, guint prop_id,
			     const GValue *value, GParamSpec *pspec)
{
	SoupIOStream *siostream = SOUP_IO_STREAM (object);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);
	GIOStream *io;

	switch (prop_id) {
	case PROP_BASE_IOSTREAM:
		io = priv->base_iostream = g_value_dup_object (value);
		if (io) {
			priv->istream =
				soup_filter_input_stream_new (g_io_stream_get_input_stream (io));
			priv->ostream =
				g_object_ref (g_io_stream_get_output_stream (io));
		} else {
			g_clear_object (&priv->istream);
			g_clear_object (&priv->ostream);
		}
		break;
	case PROP_CLOSE_ON_DISPOSE:
		priv->close_on_dispose = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_io_stream_get_property (GObject *object, guint prop_id,
			     GValue *value, GParamSpec *pspec)
{
	SoupIOStream *siostream = SOUP_IO_STREAM (object);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);

	switch (prop_id) {
	case PROP_BASE_IOSTREAM:
		g_value_set_object (value, priv->base_iostream);
		break;
	case PROP_CLOSE_ON_DISPOSE:
		g_value_set_boolean (value, priv->close_on_dispose);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_io_stream_dispose (GObject *object)
{
	SoupIOStream *siostream = SOUP_IO_STREAM (object);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);

	priv->disposing = TRUE;

	G_OBJECT_CLASS (soup_io_stream_parent_class)->dispose (object);
}

static void
soup_io_stream_finalize (GObject *object)
{
	SoupIOStream *siostream = SOUP_IO_STREAM (object);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);

	g_clear_object (&priv->base_iostream);
	g_clear_object (&priv->istream);
	g_clear_object (&priv->ostream);

	G_OBJECT_CLASS (soup_io_stream_parent_class)->finalize (object);
}

static GInputStream *
soup_io_stream_get_input_stream (GIOStream *stream)
{
        SoupIOStream *siostream = SOUP_IO_STREAM (stream);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);
	return priv->istream;
}

static GOutputStream *
soup_io_stream_get_output_stream (GIOStream *stream)
{
        SoupIOStream *siostream = SOUP_IO_STREAM (stream);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);
	return priv->ostream;
}


static gboolean
soup_io_stream_close (GIOStream     *stream,
		      GCancellable  *cancellable,
		      GError       **error)
{
	SoupIOStream *siostream = SOUP_IO_STREAM (stream);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);

	if (priv->disposing &&
	    !priv->close_on_dispose)
		return TRUE;

	return g_io_stream_close (priv->base_iostream,
				  cancellable, error);
}

static void
close_async_complete (GObject      *object,
		      GAsyncResult *result,
		      gpointer      user_data)
{
	GTask *task = user_data;
	GError *error = NULL;

	if (g_io_stream_close_finish (G_IO_STREAM (object), result, &error))
		g_task_return_boolean (task, TRUE);
	else
		g_task_return_error (task, error);
	g_object_unref (task);
}

static void    
soup_io_stream_close_async (GIOStream           *stream,
			    int                  io_priority,
			    GCancellable        *cancellable,
			    GAsyncReadyCallback  callback,
			    gpointer             user_data)
{
	GTask *task;
        SoupIOStream *siostream = SOUP_IO_STREAM (stream);
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (siostream);

	task = g_task_new (stream, cancellable, callback, user_data);
	g_task_set_source_tag (task, soup_io_stream_close_async);
	g_io_stream_close_async (priv->base_iostream,
				 io_priority, cancellable,
				 close_async_complete, task);
}

static gboolean
soup_io_stream_close_finish (GIOStream     *stream,
                             GAsyncResult  *result,
			     GError       **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
soup_io_stream_class_init (SoupIOStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GIOStreamClass *io_stream_class = G_IO_STREAM_CLASS (stream_class);

	object_class->set_property = soup_io_stream_set_property;
	object_class->get_property = soup_io_stream_get_property;
	object_class->dispose = soup_io_stream_dispose;
	object_class->finalize = soup_io_stream_finalize;

	io_stream_class->get_input_stream = soup_io_stream_get_input_stream;
	io_stream_class->get_output_stream = soup_io_stream_get_output_stream;
	io_stream_class->close_fn = soup_io_stream_close;
	io_stream_class->close_async = soup_io_stream_close_async;
	io_stream_class->close_finish = soup_io_stream_close_finish;

        properties[PROP_BASE_IOSTREAM] =
		g_param_spec_object ("base-iostream",
				     "Base IOStream",
				     "Base GIOStream",
				     G_TYPE_IO_STREAM,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        properties[PROP_CLOSE_ON_DISPOSE] =
		g_param_spec_boolean ("close-on-dispose",
				      "Close base stream",
				      "Close base GIOStream when closing",
				      TRUE,
				      G_PARAM_READWRITE |
				      G_PARAM_CONSTRUCT_ONLY |
				      G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

GIOStream *
soup_io_stream_new (GIOStream *base_iostream,
		    gboolean   close_on_dispose)
{
	return g_object_new (SOUP_TYPE_IO_STREAM,
			     "base-iostream", base_iostream,
			     "close-on-dispose", close_on_dispose,
			     NULL);
}

GIOStream *
soup_io_stream_get_base_iostream (SoupIOStream *stream)
{
        SoupIOStreamPrivate *priv = soup_io_stream_get_instance_private (stream);

	g_return_val_if_fail (SOUP_IS_IO_STREAM (stream), NULL);

	return priv->base_iostream;
}
