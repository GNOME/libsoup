/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http2-output-stream.c
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-http2-output-stream.h"
#include "soup.h"
#include "soup-message-private.h"

static void soup_http2_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupHTTP2OutputStream, soup_http2_output_stream, SOUP_TYPE_FILTER_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
						soup_http2_output_stream_pollable_init))

enum {
	CLOSE,
	WRITE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_CHANNEL,
	PROP_STREAM_ID
};

struct _SoupHTTP2OutputStreamPrivate {
	SoupHTTP2Channel *chan;

	GMutex mutex;
	GCond cond;
	gboolean writable;
	GError *error;
	GSList *sources;
};
#define SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP2_OUTPUT_STREAM, SoupHTTP2OutputStreamPrivate))

static void
soup_http2_output_stream_init (SoupHTTP2OutputStream *stream)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);

	g_mutex_init (&priv->mutex);
	g_cond_init (&priv->cond);
}

static void
soup_http2_output_stream_finalize (GObject *object)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);

	g_clear_object (&priv->chan);
	g_mutex_clear (&priv->mutex);
	g_cond_clear (&priv->cond);
	g_clear_error (&priv->error);
	g_assert (priv->sources == NULL);

	G_OBJECT_CLASS (soup_http2_output_stream_parent_class)->finalize (object);
}

static void
soup_http2_output_stream_set_property (GObject *object, guint prop_id,
				      const GValue *value, GParamSpec *pspec)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);

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
soup_http2_output_stream_get_property (GObject *object, guint prop_id,
				      GValue *value, GParamSpec *pspec)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);

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

static void
wakeup_unlocked (SoupHTTP2OutputStreamPrivate *priv)
{
	GSList *iter;

	g_cond_signal (&priv->cond);
	for (iter = priv->sources; iter; iter = iter->next)
		g_source_set_ready_time (iter->data, 0);
}

void
soup_http2_output_stream_set_writable (SoupHTTP2OutputStream *h2o,
				       gboolean writable)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (h2o);

	g_mutex_lock (&priv->mutex);
	priv->writable = writable;
	if (priv->writable)
		wakeup_unlocked (priv);
	g_mutex_unlock (&priv->mutex);
}

void
soup_http2_output_stream_push_error (SoupHTTP2OutputStream *h2o,
				     GError *error)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (h2o);

	g_mutex_lock (&priv->mutex);
	if (!priv->error)
		priv->error = error;
	else
		g_error_free (error);
	wakeup_unlocked (priv);
	g_mutex_lock (&priv->mutex);
}

static gssize
write_internal (SoupHTTP2OutputStream *h2o,
		guchar        *buffer,
		gsize          count,
		gboolean       blocking,
		GCancellable  *cancellable,
		GError       **error)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (h2o);
	GBytes *bytes;

	g_mutex_lock (&priv->mutex);

	if (priv->error) {
		g_propagate_error (error, priv->error);
		priv->error = NULL;
		g_mutex_unlock (&priv->mutex);
		return -1;
	}

	if (!priv->writable) {
		if (!blocking) {
			g_mutex_unlock (&priv->mutex);
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
					     _("Operation would block"));
			return -1;
		}

		while (!priv->writable && !priv->error)
			g_cond_wait (&priv->cond, &priv->mutex);
	}

	g_signal_emit (h2o, signals[WRITE], 0, buffer, (gulong) count);

	g_mutex_unlock (&priv->mutex);

	return count;
}

static void
write_cancelled (GCancellable *cancellable,
		 gpointer      user_data)
{
	SoupHTTP2OutputStream *h2o = SOUP_HTTP2_OUTPUT_STREAM (user_data);
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (h2o);

	g_mutex_lock (&priv->mutex);
	if (!priv->write_error) {
		g_cancellable_set_error_if_cancelled (cancellable, &priv->write_error);
		wakeup_unlocked (priv);
	}
	g_mutex_unlock (&priv->mutex);
}

static gssize
soup_http2_output_stream_write_fn (GOutputStream  *stream,
				   void           *buffer,
				   gsize           count,
				   GCancellable   *cancellable,
				   GError        **error)
{
	SoupHTTP2OutputStream *h2o = SOUP_HTTP2_OUTPUT_STREAM (stream);
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (stream);
	guint cancelled_id = 0;
	gssize nwrote;

	if (cancellable) {
		if (g_cancellable_set_error_if_cancelled (cancellable, error))
			return -1;

		cancelled_id = g_signal_connect (cancellable, "cancelled",
						 G_CALLBACK (write_cancelled), stream);
	}

	nwrote = write_internal (h2o, buffer, count, TRUE, cancellable, error);

	if (cancellable)
		g_signal_handler_disconnect (cancellable, cancelled_id);

	return nwrote;
}

static gssize
soup_http2_output_stream_write_nonblocking (GPollableOutputStream  *stream,
					    void                   *buffer,
					    gsize                   count,
					    GError                **error)
{
	SoupHTTP2OutputStream *h2o = SOUP_HTTP2_OUTPUT_STREAM (stream);
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (stream);

	return write_internal (h2o, buffer, count, FALSE, NULL, error);
}

static gboolean
soup_http2_output_stream_is_writable (GPollableOutputStream  *stream)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);

	return priv->writable;
}

/* We need to create our own GSource type, so that it can remove
 * itself from priv->sources when it's destroyed.
 */
typedef struct {
	GSource source;
	SoupHTTP2OutputStream *h2o;
} SoupHTTP2OutputStreamSource;

static gboolean
http2_output_stream_source_dispatch (GSource     *source,
				     GSourceFunc  callback,
				     gpointer     user_data)
{
	return callback (user_data);
}

static void
http2_output_stream_source_finalize (GSource *source)
{
	SoupHTTP2OutputStreamSource *hosource = (SoupHTTP2OutputStreamSource *)source;
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (hosource->h2o);

	g_mutex_lock (&priv->mutex);
	priv->sources = g_slist_remove (priv->sources, source);
	g_mutex_unlock (&priv->mutex);
	g_object_unref (hosource->h2o);
}

static gboolean
http2_output_stream_source_closure_callback (gpointer data)
{
	GClosure *closure = data;
	GValue result_value = G_VALUE_INIT;

	g_value_init (&result_value, G_TYPE_BOOLEAN);
	g_closure_invoke (closure, &result_value, 0, NULL, NULL);
	return g_value_get_boolean (&result_value);
}

static GSourceFuncs http2_output_stream_source_funcs = {
	NULL,
	NULL,
	http2_output_stream_source_dispatch,
	http2_output_stream_source_finalize,
	(GSourceFunc) http2_output_stream_source_closure_callback,
	(GSourceDummyMarshal) g_cclosure_marshal_generic
};

GSource *
soup_http2_output_stream_create_source (GPollableOutputStream *stream,
					GCancellable          *cancellable)
{
	SoupHTTP2OutputStreamPrivate *priv = SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (object);
	GSource *base_source, *source;

	base_source = g_source_new (&http2_output_stream_source_funcs,
			       sizeof (SoupHTTP2OutputStreamSource));
	g_source_set_name (base_source, "SoupHTTP2OutputStreamSource");
	((SoupHTTP2OutputStreamSource *)base_source)->h2o = g_object_ref (stream);

	g_mutex_lock (&priv->mutex);
	if (priv->writable)
		g_source_set_ready_time (base_source, 0);
	priv->sources = g_slist_prepend (priv->sources, base_source);
	g_mutex_unlock (&priv->mutex);

	source = g_pollable_source_new (stream, base_source, cancellable);
	g_source_unref (base_source);

	return source;
}

static gboolean
soup_http2_output_stream_close_fn (GOutputStream  *stream,
				   GCancellable   *cancellable,
				   GError        **error)
{
	g_signal_emit (stream, signals[CLOSE], 0);
	return TRUE;
}

static void
soup_http2_output_stream_close_async (GOutputStream       *stream,
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
soup_http2_output_stream_close_finish (GOutputStream  *stream,
				       GAsyncResult   *result,
				       GError        **error)
{
	return g_task_propagate_boolean (G_TASK (result), error);
}

static void
soup_http2_output_stream_class_init (SoupHTTP2OutputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (stream_class);

	g_type_class_add_private (stream_class, sizeof (SoupHTTP2OutputStreamPrivate));

	object_class->finalize = soup_http2_output_stream_finalize;
	object_class->set_property = soup_http2_output_stream_set_property;
	object_class->get_property = soup_http2_output_stream_get_property;

	output_stream_class->write_fn = soup_http2_output_stream_write_fn;
	output_stream_class->close_fn = soup_http2_output_stream_close_fn;
	output_stream_class->close_async = soup_http2_output_stream_close_async;
	output_stream_class->close_finish = soup_http2_output_stream_close_finish;

	signals[CLOSE] =
		g_signal_new ("close",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);
	signals[WRITE] =
		g_signal_new ("write",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_ULONG);

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
soup_http2_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface,
					gpointer interface_data)
{
	pollable_interface->is_writable = soup_http2_output_stream_is_writable;
	pollable_interface->create_source = soup_http2_output_stream_create_source;
	pollable_interface->write_nonblocking = soup_http2_output_stream_write_nonblocking;
}

GOutputStream *
soup_http2_output_stream_new (SoupHTTP2Connection *connection,
			      guint32 stream_id)
{
	return g_object_new (SOUP_TYPE_HTTP2_OUTPUT_STREAM,
			     "connection", connection,
			     "stream-id", stream_id,
			     NULL);
}

guint32
soup_http2_output_stream_get_stream_id (SoupHTTP2OutputStream *h2o)
{
	return SOUP_HTTP2_OUTPUT_STREAM_GET_PRIVATE (h2o)->stream_id;
}
