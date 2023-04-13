/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-client-input-stream.c
 *
 * Copyright 2010-2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-client-input-stream.h"
#include "soup.h"
#include "soup-message-private.h"
#include "soup-message-metrics-private.h"
#include "soup-misc.h"

struct _SoupClientInputStream {
	SoupFilterInputStream parent_instance;
};

typedef struct {
	SoupMessage  *msg;
        SoupMessageMetrics *metrics;
} SoupClientInputStreamPrivate;

enum {
	SIGNAL_EOF,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_MESSAGE,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

static GPollableInputStreamInterface *soup_client_input_stream_parent_pollable_interface;
static void soup_client_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupClientInputStream, soup_client_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM,
                               G_ADD_PRIVATE (SoupClientInputStream)
			       G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						      soup_client_input_stream_pollable_init))

static void
soup_client_input_stream_init (SoupClientInputStream *stream)
{
}

static void
soup_client_input_stream_finalize (GObject *object)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (object);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);

	g_clear_object (&priv->msg);

	G_OBJECT_CLASS (soup_client_input_stream_parent_class)->finalize (object);
}

static void
soup_client_input_stream_set_property (GObject *object, guint prop_id,
				       const GValue *value, GParamSpec *pspec)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (object);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);

	switch (prop_id) {
	case PROP_MESSAGE:
		priv->msg = g_value_dup_object (value);
                priv->metrics = soup_message_get_metrics (priv->msg);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_client_input_stream_get_property (GObject *object, guint prop_id,
				       GValue *value, GParamSpec *pspec)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (object);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);

	switch (prop_id) {
	case PROP_MESSAGE:
		g_value_set_object (value, priv->msg);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gssize
soup_client_input_stream_read_fn (GInputStream  *stream,
				  void          *buffer,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (SOUP_CLIENT_INPUT_STREAM (stream));
	gssize nread;

        if (g_cancellable_set_error_if_cancelled (soup_message_io_get_cancellable (priv->msg), error))
                return -1;

	nread = G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
		read_fn (stream, buffer, count, cancellable, error);

        if (priv->metrics && nread > 0)
                priv->metrics->response_body_size += nread;

	if (nread == 0)
		g_signal_emit (stream, signals[SIGNAL_EOF], 0);

	return nread;
}

static gssize
soup_client_input_stream_skip (GInputStream  *stream,
                               gsize          count,
                               GCancellable  *cancellable,
                               GError       **error)
{
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (SOUP_CLIENT_INPUT_STREAM (stream));
        gssize nread;

        if (g_cancellable_set_error_if_cancelled (soup_message_io_get_cancellable (priv->msg), error))
                return -1;

        nread = G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
                skip (stream, count, cancellable, error);

        if (priv->metrics && nread > 0)
	        priv->metrics->response_body_size += nread;

        if (nread == 0)
                g_signal_emit (stream, signals[SIGNAL_EOF], 0);

        return nread;
}

static gssize
soup_client_input_stream_read_nonblocking (GPollableInputStream  *stream,
					   void                  *buffer,
					   gsize                  count,
					   GError               **error)
{
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (SOUP_CLIENT_INPUT_STREAM (stream));
	gssize nread;

        if (g_cancellable_set_error_if_cancelled (soup_message_io_get_cancellable (priv->msg), error))
                return -1;

	nread = soup_client_input_stream_parent_pollable_interface->
		read_nonblocking (stream, buffer, count, error);

        if (priv->metrics && nread > 0)
	        priv->metrics->response_body_size += nread;

	if (nread == 0)
		g_signal_emit (stream, signals[SIGNAL_EOF], 0);

	return nread;
}

static gboolean
soup_client_input_stream_close_fn (GInputStream  *stream,
				   GCancellable  *cancellable,
				   GError       **error)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (stream);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);
	gboolean success;

	success = soup_message_io_skip (priv->msg, TRUE, cancellable, error);
	soup_message_io_finished (priv->msg);
	return success;
}

static gboolean
close_async_ready (SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupClientInputStream *cistream = g_task_get_source_object (task);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);
	GError *error = NULL;

	if (!soup_message_io_skip (priv->msg, FALSE, g_task_get_cancellable (task), &error) &&
	    g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_error_free (error);
		return TRUE;
	}

	soup_message_io_finished (priv->msg);

	if (error)
		g_task_return_error (task, error);
        else
                g_task_return_boolean (task, TRUE);
        g_object_unref (task);

	return FALSE;
}

static void
soup_client_input_stream_close_async (GInputStream        *stream,
				      gint                 priority,
				      GCancellable        *cancellable,
				      GAsyncReadyCallback  callback,
				      gpointer             user_data)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (stream);
        SoupClientInputStreamPrivate *priv = soup_client_input_stream_get_instance_private (cistream);
	GTask *task;
	GSource *source;

	task = g_task_new (stream, cancellable, callback, user_data);
	g_task_set_source_tag (task, soup_client_input_stream_close_async);
	g_task_set_priority (task, priority);

	if (close_async_ready (priv->msg, task) == G_SOURCE_CONTINUE) {
                /* When SoupClientInputStream is created we always have a body input stream,
                 * and we finished writing, so it's safe to pass NULL for the streams
                 */
		source = soup_message_io_data_get_source ((SoupMessageIOData *)soup_message_get_io_data (priv->msg),
							  G_OBJECT (priv->msg),
                                                          NULL, NULL,
							  cancellable, NULL, NULL);

		g_task_attach_source (task, source, (GSourceFunc) close_async_ready);
		g_source_unref (source);
	}
}

static gboolean
soup_client_input_stream_close_finish (GInputStream  *stream,
				       GAsyncResult  *result,
				       GError       **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
soup_client_input_stream_class_init (SoupClientInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	object_class->finalize = soup_client_input_stream_finalize;
	object_class->set_property = soup_client_input_stream_set_property;
	object_class->get_property = soup_client_input_stream_get_property;

	input_stream_class->read_fn = soup_client_input_stream_read_fn;
	input_stream_class->skip = soup_client_input_stream_skip;
	input_stream_class->close_fn = soup_client_input_stream_close_fn;
	input_stream_class->close_async = soup_client_input_stream_close_async;
	input_stream_class->close_finish = soup_client_input_stream_close_finish;

	signals[SIGNAL_EOF] =
		g_signal_new ("eof",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

        properties[PROP_MESSAGE] =
		g_param_spec_object ("message",
				     "Message",
				     "Message",
				     SOUP_TYPE_MESSAGE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

static void
soup_client_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
					gpointer interface_data)
{
	soup_client_input_stream_parent_pollable_interface =
		g_type_interface_peek_parent (pollable_interface);

	pollable_interface->read_nonblocking = soup_client_input_stream_read_nonblocking;
}

GInputStream *
soup_client_input_stream_new (GInputStream *base_stream,
			      SoupMessage  *msg)
{
	return g_object_new (SOUP_TYPE_CLIENT_INPUT_STREAM,
			     "base-stream", base_stream,
			     "message", msg,
			     NULL);
}
