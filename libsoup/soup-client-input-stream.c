/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-client-input-stream.c
 *
 * Copyright 2010-2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gio/gio.h>

#include "soup-client-input-stream.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-private.h"

struct _SoupClientInputStreamPrivate {
	SoupMessage  *msg;
};

enum {
	EOF,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_MESSAGE
};

static GPollableInputStreamInterface *soup_client_input_stream_parent_pollable_interface;
static void soup_client_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupClientInputStream, soup_client_input_stream, SOUP_TYPE_FILTER_INPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						soup_client_input_stream_pollable_init))

static void
soup_client_input_stream_init (SoupClientInputStream *stream)
{
	stream->priv = G_TYPE_INSTANCE_GET_PRIVATE (stream,
						    SOUP_TYPE_CLIENT_INPUT_STREAM,
						    SoupClientInputStreamPrivate);
}

static void
set_property (GObject *object, guint prop_id,
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
get_property (GObject *object, guint prop_id,
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
	gssize nread;

	nread = G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
		read_fn (stream, buffer, count, cancellable, error);

	if (nread == 0)
		g_signal_emit (stream, signals[EOF], 0);

	return nread;
}

static gssize
soup_client_input_stream_read_nonblocking (GPollableInputStream  *stream,
					   void                  *buffer,
					   gsize                  count,
					   GError               **error)
{
	gssize nread;

	nread = soup_client_input_stream_parent_pollable_interface->
		read_nonblocking (stream, buffer, count, error);

	if (nread == 0)
		g_signal_emit (stream, signals[EOF], 0);

	return nread;
}

static gboolean
soup_client_input_stream_close_fn (GInputStream  *stream,
				   GCancellable  *cancellable,
				   GError       **error)
{
	SoupClientInputStream *cistream = SOUP_CLIENT_INPUT_STREAM (stream);

	if (!soup_message_io_run_until_finish (cistream->priv->msg,
					       cancellable, error))
		return FALSE;

	return G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->close_fn (stream, cancellable, error);
}

typedef struct {
	SoupClientInputStream *cistream;
	gint priority;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
} CloseAsyncData;

static void
close_async_data_free (CloseAsyncData *cad)
{
	if (cad->cancellable)
		g_object_unref (cad->cancellable);
	g_object_unref (cad->result);
	g_slice_free (CloseAsyncData, cad);
}

static void
base_stream_closed (GObject *source, GAsyncResult *result, gpointer user_data)
{
	CloseAsyncData *cad = user_data;
	GError *error = NULL;

	if (G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
	    close_finish (G_INPUT_STREAM (cad->cistream), result, &error))
		g_simple_async_result_set_op_res_gboolean (cad->result, TRUE);
	else
		g_simple_async_result_take_error (cad->result, error);

	g_simple_async_result_complete_in_idle (cad->result);
	close_async_data_free (cad);
}

static gboolean
close_async_ready (SoupMessage *msg, gpointer user_data)
{
	CloseAsyncData *cad = user_data;
	GError *error = NULL;

	if (soup_message_io_run_until_finish (cad->cistream->priv->msg,
					      cad->cancellable, &error)) {
		G_INPUT_STREAM_CLASS (soup_client_input_stream_parent_class)->
			close_async (G_INPUT_STREAM (cad->cistream),
				     cad->priority,
				     cad->cancellable,
				     base_stream_closed,
				     cad);
		return FALSE;
	} else if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		g_simple_async_result_take_error (cad->result, error);
		g_simple_async_result_complete_in_idle (cad->result);
		close_async_data_free (cad);
		return FALSE;
	}

	return TRUE;
}

static void
soup_client_input_stream_close_async (GInputStream        *stream,
				      gint                 priority,
				      GCancellable        *cancellable,
				      GAsyncReadyCallback  callback,
				      gpointer             user_data)
{
	CloseAsyncData *cad;
	GSource *source;

	cad = g_slice_new (CloseAsyncData);
	cad->cistream = SOUP_CLIENT_INPUT_STREAM (stream);
	cad->result = g_simple_async_result_new (G_OBJECT (stream),
						 callback, user_data,
						 soup_client_input_stream_close_async);
	cad->priority = priority;
	cad->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

	source = soup_message_io_get_source (cad->cistream->priv->msg,
					     cancellable,
					     close_async_ready, cad);
	g_source_set_priority (source, priority);
	g_source_attach (source, g_main_context_get_thread_default ());
	g_source_unref (source);
}

static gboolean
soup_client_input_stream_close_finish (GInputStream  *stream,
				       GAsyncResult  *result,
				       GError       **error)
{
	GSimpleAsyncResult *simple = G_SIMPLE_ASYNC_RESULT (result);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
soup_client_input_stream_class_init (SoupClientInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupClientInputStreamPrivate));

	object_class->set_property = set_property;
	object_class->get_property = get_property;

	input_stream_class->read_fn = soup_client_input_stream_read_fn;
	input_stream_class->close_fn = soup_client_input_stream_close_fn;
	input_stream_class->close_async = soup_client_input_stream_close_async;
	input_stream_class->close_finish = soup_client_input_stream_close_finish;

	signals[EOF] =
		g_signal_new ("eof",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      _soup_marshal_NONE__NONE,
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

GInputStream *
soup_client_input_stream_new (GInputStream *base_stream,
			      SoupMessage  *msg)
{
	return g_object_new (SOUP_TYPE_CLIENT_INPUT_STREAM,
			     "base-stream", base_stream,
			     "message", msg,
			     NULL);
}
