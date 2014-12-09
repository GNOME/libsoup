/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http2-input-stream.c
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-http2-input-stream.h"
#include "soup.h"
#include "soup-message-private.h"

static void soup_http2_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupHTTP2InputStream, soup_http2_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						soup_http2_input_stream_pollable_init))

enum {
	CLOSE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_CHANNEL,
	PROP_STREAM_ID
};

struct _SoupHTTP2InputStreamPrivate {
	SoupHTTP2Channel *chan;
	guint32 stream_id;

	GAsyncQueue *queue;
	GBytes *current;

	GMutex *mutex;
	GError *error;
	gboolean eof;
};
#define SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP2_INPUT_STREAM, SoupHTTP2InputStreamPrivate))

static void
soup_http2_input_stream_init (SoupHTTP2InputStream *stream)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (stream);

	g_mutex_init (&priv->mutex);
	priv->queue = g_async_queue_new_full ((GDestroyNotify) g_byte_array_unref);
}

static void
soup_http2_input_stream_finalize (GObject *object)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);

	g_mutex_clear (&priv->mutex);
	g_clear_object (&priv->chan);
	g_clear_pointer (&priv->current, g_bytes_unref);
	g_clear_pointer (&priv->queue, g_async_queue_unref);
	g_clear_error (&priv->error);

	G_OBJECT_CLASS (soup_http2_input_stream_parent_class)->finalize (object);
}

static void
soup_http2_input_stream_set_property (GObject *object, guint prop_id,
				      const GValue *value, GParamSpec *pspec)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CHANNEL:
		priv->chan = g_value_dup_object (value);
		break;
	case PROP_STREAM_ID:
		priv->stream_id = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_http2_input_stream_get_property (GObject *object, guint prop_id,
				      GValue *value, GParamSpec *pspec)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CHANNEL:
		g_value_set_object (value, priv->chan);
		break;
	case PROP_STREAM_ID:
		g_value_set_uint (value, priv->stream_id);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

void
soup_http2_input_stream_push_data (SoupHTTP2InputStream *h2i,
				   const guchar         *data,
				   gsize                 len)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (h2i);

	g_async_queue_push (priv->queue, g_bytes_new (data, len));
}

void
soup_http2_input_stream_push_eof (SoupHTTP2InputStream *h2i)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (h2i);

	g_mutex_lock (&priv->mutex);
	priv->eof = TRUE;
	g_mutex_unlock (&priv->mutex);
	g_async_queue_push (priv->queue, g_bytes_new (NULL, 0));
}

void
soup_http2_input_stream_push_error (SoupHTTP2InputStream *h2i,
				    GError *error)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (h2i);

	g_mutex_lock (&priv->mutex);
	if (!priv->error) {
		priv->error = g_error_copy (error);
		g_async_queue_push (priv->queue, g_bytes_new (NULL, 0));
	}
	g_mutex_unlock (&priv->mutex);
}

static gssize
read_one_gbytes (SoupHTTP2InputStreamPrivate *priv,
		 GBytes *bytes,
		 guchar *buffer,
		 gsize   count)
{
	gconstpointer data;
	gsize length;

	g_assert (priv->current == NULL);

	data = g_bytes_get_data (bytes, &length);
	if (length > count) {
		priv->current = g_bytes_new_from_bytes (bytes, count, length - count);
		length = count;
	}

	memcpy (buffer, data, length);
	return length;
}

static gssize
read_internal (SoupHTTP2InputStreamPrivate *priv,
	       guchar        *buffer,
	       gsize          count,
	       gboolean       blocking,
	       GError       **error)
{
	GBytes *bytes;
	gssize nread, total = 0;
	gpointer (*queue_pop) (GAsyncQueue *) =
		blocking ? g_async_queue_pop : g_async_queue_try_pop;

	if (priv->current) {
		bytes = priv->current;
		priv->current = NULL;

		nread = read_one_gbytes (priv, bytes, buffer + total, count - total);
		g_bytes_unref (bytes);

		total += nread;
	}

	while (total < count && (bytes = queue_pop (priv->queue))) {
		nread = read_one_gbytes (priv, bytes, buffer + total, count - total);
		g_bytes_unref (bytes);

		if (nread == 0)
			break;

		total += nread;
	}

	if (total == 0) {
		g_mutex_lock (&priv->mutex);
		if (priv->error) {
			g_propagate_error (error, priv->error);
			priv->error = NULL;
			total = -1;
		} else if (!blocking && !priv->eof) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
					     _("Operation would block"));
			total = -1;
		}
		g_mutex_unlock (&priv->mutex);
	}

	return total;
}

static void
read_cancelled (GCancellable *cancellable,
		gpointer      user_data)
{
	SoupHTTP2InputStream *h2i = SOUP_HTTP2_INPUT_STREAM (user_data);
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (h2i);
	GError *error = NULL;

	g_cancellable_set_error_if_cancelled (cancellable, &error);
	soup_http2_input_stream_take_error (h2i, error);
}

static gssize
soup_http2_input_stream_read_fn (GInputStream  *stream,
				 void          *buffer,
				 gsize          count,
				 GCancellable  *cancellable,
				 GError       **error)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (stream);
	guint cancelled_id = 0;
	gssize nread;

	if (cancellable) {
		if (g_cancellable_set_error_if_cancelled (cancellable, error))
			return -1;

		cancelled_id = g_signal_connect (cancellable, "cancelled",
						 G_CALLBACK (read_cancelled), stream);
	}

	nread = read_internal (priv, buffer, count, TRUE, error);

	if (cancellable)
		g_signal_handler_disconnect (cancellable, cancelled_id);

	return nread;
}

static gssize
soup_http2_input_stream_read_nonblocking (GPollableInputStream  *stream,
					  void                  *buffer,
					  gsize                  count,
					  GError               **error)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);

	return read_internal (priv, buffer, count, FALSE, error);
}

static gboolean
soup_http2_input_stream_is_readable (GPollableInputStream  *stream)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);

	return (priv->current != NULL ||
		g_async_queue_length (priv->queue) > 0);
}

static GSource *
soup_http2_input_stream_create_source (GPollableInputStream  *stream,
				       GCancellable          *cancellable)
{
	SoupHTTP2InputStreamPrivate *priv = SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (object);
	GSource *base_source, *source;

	base_source = g_async_queue_create_source (priv->queue);
	source = g_pollable_source_new_full (stream, base_source, cancellable);
	g_source_unref (base_source);

	return source;
}

static gboolean
soup_http2_input_stream_close_fn (GInputStream  *stream,
				  GCancellable  *cancellable,
				  GError       **error)
{
	g_signal_emit (stream, signals[CLOSE], 0);
	return TRUE;
}

static void
soup_http2_input_stream_close_async (GInputStream        *stream,
				     gint                 priority,
				     GCancellable        *cancellable,
				     GAsyncReadyCallback  callback,
				     gpointer             user_data)
{
	GTask *task;

	g_signal_emit (stream, signals[CLOSE], 0);

	task = g_task_new (stream, cancellable, callback, user_data);
	g_task_set_priority (task, priority);
	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
}

static gboolean
soup_http2_input_stream_close_finish (GInputStream  *stream,
				      GAsyncResult  *result,
				      GError       **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
soup_http2_input_stream_class_init (SoupHTTP2InputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupHTTP2InputStreamPrivate));

	object_class->finalize = soup_http2_input_stream_finalize;
	object_class->set_property = soup_http2_input_stream_set_property;
	object_class->get_property = soup_http2_input_stream_get_property;

	input_stream_class->read_fn = soup_http2_input_stream_read_fn;
	input_stream_class->close_fn = soup_http2_input_stream_close_fn;
	input_stream_class->close_async = soup_http2_input_stream_close_async;
	input_stream_class->close_finish = soup_http2_input_stream_close_finish;

	signals[CLOSE] =
		g_signal_new ("close",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	g_object_class_install_property (
		object_class, PROP_CHANNEL,
		g_param_spec_object ("channel",
				     "Channel",
				     "SoupHTTP2Channel",
				     SOUP_TYPE_HTTP2_CHANNEL,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (
		object_class, PROP_STREAM_ID,
		g_param_spec_uint ("stream-id",
				   "Stream ID",
				   "HTTP/2 stream ID",
				   0, G_MAXUINT32, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_STRINGS));
}

static void
soup_http2_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
				       gpointer interface_data)
{
	pollable_interface->is_readable = soup_http2_input_stream_is_readable;
	pollable_interface->create_source = soup_http2_input_stream_create_source;
	pollable_interface->read_nonblocking = soup_http2_input_stream_read_nonblocking;
}

GInputStream *
soup_http2_input_stream_new (SoupHTTP2Channel *chan,
			     guint32 stream_id)
{
	return g_object_new (SOUP_TYPE_HTTP2_INPUT_STREAM,
			     "channel", chan,
			     "stream-id", stream_id,
			     NULL);
}

guint32
soup_http2_input_stream_get_stream_id (SoupHTTP2InputStream *h2i)
{
	return SOUP_HTTP2_INPUT_STREAM_GET_PRIVATE (h2i)->stream_id;
}
