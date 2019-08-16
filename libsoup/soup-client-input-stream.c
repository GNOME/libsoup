/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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

struct _SoupClientInputStreamPrivate {
	SoupMessage  *msg;

	goffset offset;
	goffset request_offset;
};

enum {
	SIGNAL_EOF,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_MESSAGE
};

static GPollableInputStreamInterface *soup_client_input_stream_parent_pollable_interface;
static GSeekableIface *soup_client_input_stream_seekable_interface;

static void soup_client_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);
static void soup_client_input_stream_seekable_init (GSeekableIface *seekable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupClientInputStream, soup_client_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM,
                         G_ADD_PRIVATE (SoupClientInputStream)
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						soup_client_input_stream_pollable_init)
			 G_IMPLEMENT_INTERFACE (G_TYPE_SEEKABLE,
						soup_client_input_stream_seekable_init))

static void
soup_client_input_stream_init (SoupClientInputStream *stream)
{
	stream->priv = soup_client_input_stream_get_instance_private (stream);
}

static void
soup_client_input_stream_finalize (GObject *object)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (object);

	g_clear_object (&cistream->priv->msg);

	G_OBJECT_CLASS (soup_client_input_stream_parent_class)->finalize (object);
}

static void
soup_client_input_stream_set_property (GObject *object, guint prop_id,
				       const GValue *value, GParamSpec *pspec)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (object);

	switch (prop_id) {
	case PROP_MESSAGE:
		cistream->priv->msg = g_value_dup_object (value);
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

	switch (prop_id) {
	case PROP_MESSAGE:
		g_value_set_object (value, cistream->priv->msg);
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
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM(stream);
	gssize nread;

	nread = G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
		read_fn (stream, buffer, count, cancellable, error);

	if (nread >= 0) {
		cistream->priv->offset += nread;
		if (nread == 0)
		    g_signal_emit (stream, signals[SIGNAL_EOF], 0);
	}

	return nread;
}

static gssize
soup_client_input_stream_read_nonblocking (GPollableInputStream  *stream,
					   void                  *buffer,
					   gsize                  count,
					   GError               **error)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM(stream);
	gssize nread;

	nread = soup_client_input_stream_parent_pollable_interface->
		read_nonblocking (stream, buffer, count, error);

	if (nread >= 0) {
		cistream->priv->offset += nread;
		if (nread == 0)
		    g_signal_emit (stream, signals[SIGNAL_EOF], 0);
	}

	return nread;
}

static gboolean
soup_client_input_stream_close_fn (GInputStream  *stream,
				   GCancellable  *cancellable,
				   GError       **error)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (stream);
	gboolean success;

	success = soup_message_io_run_until_finish (cistream->priv->msg, TRUE,
						    NULL, error);
	soup_message_io_finished (cistream->priv->msg);
	return success;
}

static gboolean
idle_finish_close (gpointer user_data)
{
	GTask *task = user_data;

	g_task_return_boolean (task, TRUE);
	g_object_unref (task);
	return FALSE;
}

static gboolean
close_async_ready (SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupClientInputStream *cistream = g_task_get_source_object (task);
	GError *error = NULL;

	if (!soup_message_io_run_until_finish (cistream->priv->msg, FALSE,
					       g_task_get_cancellable (task),
					       &error) &&
	    g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_error_free (error);
		return TRUE;
	}

	soup_message_io_finished (cistream->priv->msg);

	if (error) {
		g_task_return_error (task, error);
		g_object_unref (task);
		return FALSE;
	}

	/* Due to a historical accident, SoupSessionAsync relies on us
	 * waiting one extra cycle after run_until_finish() returns.
	 * Ugh. FIXME later when it's easier to do.
	 */
	soup_add_idle (g_main_context_get_thread_default (),
		       idle_finish_close, task);
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
	GTask *task;
	GSource *source;

	task = g_task_new (stream, cancellable, callback, user_data);
	g_task_set_priority (task, priority);

	if (close_async_ready (cistream->priv->msg, task) == G_SOURCE_CONTINUE) {
		source = soup_message_io_get_source (cistream->priv->msg,
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

	g_object_class_install_property (
		object_class, PROP_MESSAGE,
		g_param_spec_object ("message",
				     "Message",
				     "Message",
				     SOUP_TYPE_MESSAGE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
soup_client_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
					gpointer interface_data)
{
	soup_client_input_stream_parent_pollable_interface =
		g_type_interface_peek_parent (pollable_interface);

	pollable_interface->read_nonblocking = soup_client_input_stream_read_nonblocking;
}

static goffset
soup_client_input_stream_tell (GSeekable *seekable)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (seekable);

	return cistream->priv->offset;
}

static gboolean
soup_client_input_stream_can_seek (GSeekable *seekable)
{
	return TRUE;
}

static gboolean
soup_client_input_stream_seek (GSeekable *seekable,
			       goffset offset,
			       GSeekType type,
			       GCancellable *cancellable,
			       GError **error)
{
	GInputStream *stream = G_INPUT_STREAM (seekable);
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (seekable);

	if (type == G_SEEK_END && cistream->priv->msg) {
		goffset content_length =
		    soup_message_headers_get_content_length(cistream->priv->msg->response_headers);

		if (content_length >= 0) {
			type = G_SEEK_SET;
			offset = cistream->priv->request_offset + content_length + offset;
		}
	}

	if (type == G_SEEK_END) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
				     "G_SEEK_END not supported");
		return FALSE;
	}

	if (!g_input_stream_set_pending (stream, error))
		return FALSE;

	switch (type) {
		case G_SEEK_CUR:
			offset += cistream->priv->offset;
			/* fall through */

		case G_SEEK_SET:
			cistream->priv->request_offset = offset;
			cistream->priv->offset = offset;
			break;

		case G_SEEK_END:
			g_return_val_if_reached (FALSE);
			break;

		default:
			g_return_val_if_reached (FALSE);
	}

	g_input_stream_clear_pending (stream);
	return TRUE;
}

static gboolean
soup_client_input_stream_can_truncate (GSeekable *seekable)
{
	return FALSE;
}

static gboolean
soup_client_input_stream_truncate_fn (GSeekable *seekable,
				      goffset offset,
				      GCancellable *cancellable,
				      GError **error)
{
	g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
			     "Truncate not allowed on input stream");

	return FALSE;
}

static void
soup_client_input_stream_seekable_init (GSeekableIface *seekable_interface,
					gpointer interface_data)
{
	soup_client_input_stream_seekable_interface = seekable_interface;

	seekable_interface->tell = soup_client_input_stream_tell;
	seekable_interface->can_seek = soup_client_input_stream_can_seek;
	seekable_interface->seek = soup_client_input_stream_seek;
	seekable_interface->can_truncate = soup_client_input_stream_can_truncate;
	seekable_interface->truncate_fn = soup_client_input_stream_truncate_fn;
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
