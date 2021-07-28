/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia, S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>
#include "soup-cache-input-stream.h"
#include "soup-message-body.h"

enum {
	CACHING_FINISHED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _SoupCacheInputStream {
	SoupFilterInputStream parent_instance;
};

typedef struct {
	GOutputStream *output_stream;
	GCancellable *cancellable;
	gsize bytes_written;

	gboolean read_finished;
	GBytes *current_writing_buffer;
	GQueue *buffer_queue;
} SoupCacheInputStreamPrivate;

static void soup_cache_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupCacheInputStream, soup_cache_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM,
                               G_ADD_PRIVATE (SoupCacheInputStream)
                               G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
                                                      soup_cache_input_stream_pollable_init))


static void soup_cache_input_stream_write_next_buffer (SoupCacheInputStream *istream);

static inline void
notify_and_clear (SoupCacheInputStream *istream, GError *error)
{
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);

	g_signal_emit (istream, signals[CACHING_FINISHED], 0, priv->bytes_written, error);

	g_clear_object (&priv->cancellable);
	g_clear_object (&priv->output_stream);
	g_clear_error (&error);
}

static inline void
try_write_next_buffer (SoupCacheInputStream *istream)
{
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);

	if (priv->current_writing_buffer == NULL && priv->buffer_queue->length)
		soup_cache_input_stream_write_next_buffer (istream);
	else if (priv->read_finished)
		notify_and_clear (istream, NULL);
	else if (g_input_stream_is_closed (G_INPUT_STREAM (istream))) {
		GError *error = NULL;
		g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_CLOSED,
				     _("Network stream unexpectedly closed"));
		notify_and_clear (istream, error);
	}
}

static void
file_replaced_cb (GObject      *source,
		  GAsyncResult *res,
		  gpointer      user_data)
{
	SoupCacheInputStream *istream = SOUP_CACHE_INPUT_STREAM (user_data);
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);
	GError *error = NULL;

	priv->output_stream = (GOutputStream *) g_file_replace_finish (G_FILE (source), res, &error);

	if (error)
		notify_and_clear (istream, error);
	else
		try_write_next_buffer (istream);

	g_object_unref (istream);
}

static void
soup_cache_input_stream_init (SoupCacheInputStream *self)
{
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (self);

	priv->buffer_queue = g_queue_new ();
}

static void
soup_cache_input_stream_finalize (GObject *object)
{
	SoupCacheInputStream *self = (SoupCacheInputStream *)object;
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (self);

	g_clear_object (&priv->cancellable);
	g_clear_object (&priv->output_stream);
	g_clear_pointer (&priv->current_writing_buffer, g_bytes_unref);
	g_queue_free_full (priv->buffer_queue, (GDestroyNotify) g_bytes_unref);

	G_OBJECT_CLASS (soup_cache_input_stream_parent_class)->finalize (object);
}

static void
write_ready_cb (GObject *source, GAsyncResult *result, SoupCacheInputStream *istream)
{
	GOutputStream *ostream = G_OUTPUT_STREAM (source);
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);
	gssize write_size;
	gsize pending;
	GError *error = NULL;

	write_size = g_output_stream_write_finish (ostream, result, &error);
	if (error) {
		notify_and_clear (istream, error);
		g_object_unref (istream);
		return;
	}

	/* Check that we have written everything */
	pending = g_bytes_get_size (priv->current_writing_buffer) - write_size;
	if (pending) {
		GBytes *subbuffer = g_bytes_new_from_bytes (priv->current_writing_buffer,
							    write_size, pending);
		g_queue_push_head (priv->buffer_queue, g_steal_pointer (&subbuffer));
	}

	priv->bytes_written += write_size;
	g_clear_pointer (&priv->current_writing_buffer, g_bytes_unref);

	try_write_next_buffer (istream);
	g_object_unref (istream);
}

static void
soup_cache_input_stream_write_next_buffer (SoupCacheInputStream *istream)
{
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);
	GBytes *buffer = g_queue_pop_head (priv->buffer_queue);
	int priority;

	g_assert (priv->output_stream && !g_output_stream_is_closed (priv->output_stream));

	g_clear_pointer (&priv->current_writing_buffer, g_bytes_unref);
	priv->current_writing_buffer = buffer;

	if (priv->buffer_queue->length > 10)
		priority = G_PRIORITY_DEFAULT;
	else
		priority = G_PRIORITY_LOW;

	g_output_stream_write_async (priv->output_stream,
                                     g_bytes_get_data (buffer, NULL),
                                     g_bytes_get_size (buffer),
				     priority, priv->cancellable,
				     (GAsyncReadyCallback) write_ready_cb,
				     g_object_ref (istream));
}

static gssize
read_internal (GInputStream  *stream,
	       void          *buffer,
	       gsize          count,
	       gboolean       blocking,
	       GCancellable  *cancellable,
	       GError       **error)
{
	SoupCacheInputStream *istream = SOUP_CACHE_INPUT_STREAM (stream);
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);
	GInputStream *base_stream;
	gssize nread;

	base_stream = g_filter_input_stream_get_base_stream (G_FILTER_INPUT_STREAM (stream));
	nread = g_pollable_stream_read (base_stream, buffer, count, blocking,
					cancellable, error);

	if (G_UNLIKELY (nread == -1 || priv->read_finished))
		return nread;

	if (nread == 0) {
		priv->read_finished = TRUE;

		if (priv->current_writing_buffer == NULL && priv->output_stream)
			notify_and_clear (istream, NULL);
	} else {
		GBytes *local_buffer = g_bytes_new (buffer, nread);
		g_queue_push_tail (priv->buffer_queue, g_steal_pointer (&local_buffer));

		if (priv->current_writing_buffer == NULL && priv->output_stream)
			soup_cache_input_stream_write_next_buffer (istream);
	}

	return nread;
}

static gssize
soup_cache_input_stream_read_fn (GInputStream  *stream,
				 void          *buffer,
				 gsize          count,
				 GCancellable  *cancellable,
				 GError       **error)
{
	return read_internal (stream, buffer, count, TRUE,
			      cancellable, error);
}

static gssize
soup_cache_input_stream_read_nonblocking (GPollableInputStream  *stream,
					  void                  *buffer,
					  gsize                  count,
					  GError               **error)
{
	return read_internal (G_INPUT_STREAM (stream), buffer, count, FALSE,
			      NULL, error);
}

static void
soup_cache_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
				       gpointer interface_data)
{
	pollable_interface->read_nonblocking = soup_cache_input_stream_read_nonblocking;
}

static gboolean
soup_cache_input_stream_close_fn (GInputStream  *stream,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupCacheInputStream *istream = SOUP_CACHE_INPUT_STREAM (stream);
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);

	if (!priv->read_finished) {
		if (priv->output_stream) {
			/* Cancel any pending write operation or return an error if none. */
			if (g_output_stream_has_pending (priv->output_stream))
				g_cancellable_cancel (priv->cancellable);
			else {
				GError *notify_error = NULL;
				g_set_error_literal (&notify_error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
						     _("Failed to completely cache the resource"));
				notify_and_clear (istream, notify_error);
			}
		} else if (priv->cancellable)
			/* The file_replace_async() hasn't finished yet */
			g_cancellable_cancel (priv->cancellable);
	}

	return G_INPUT_STREAM_CLASS (soup_cache_input_stream_parent_class)->close_fn (stream, cancellable, error);
}

static void
soup_cache_input_stream_class_init (SoupCacheInputStreamClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GInputStreamClass *istream_class = G_INPUT_STREAM_CLASS (klass);

	gobject_class->finalize = soup_cache_input_stream_finalize;

	istream_class->read_fn = soup_cache_input_stream_read_fn;
	istream_class->close_fn = soup_cache_input_stream_close_fn;

	signals[CACHING_FINISHED] =
		g_signal_new ("caching-finished",
			      G_OBJECT_CLASS_TYPE (gobject_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      G_TYPE_INT, G_TYPE_ERROR);
}

GInputStream *
soup_cache_input_stream_new (GInputStream *base_stream,
			     GFile        *file)
{
	SoupCacheInputStream *istream = g_object_new (SOUP_TYPE_CACHE_INPUT_STREAM,
					      "base-stream", base_stream,
					      "close-base-stream", FALSE,
					      NULL);
	SoupCacheInputStreamPrivate *priv = soup_cache_input_stream_get_instance_private (istream);

	priv->cancellable = g_cancellable_new ();
	g_file_replace_async (file, NULL, FALSE,
			      G_FILE_CREATE_PRIVATE | G_FILE_CREATE_REPLACE_DESTINATION,
			      G_PRIORITY_DEFAULT, priv->cancellable,
			      file_replaced_cb, g_object_ref (istream));

	return (GInputStream *) istream;
}
