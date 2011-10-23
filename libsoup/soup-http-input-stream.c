/* soup-input-stream.c, based on gsocketinputstream.c
 *
 * Copyright (C) 2006-2007, 2010 Red Hat, Inc.
 * Copyright (C) 2010 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <config.h>

#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#include "soup-http-input-stream.h"
#include "soup-session.h"

G_DEFINE_TYPE (SoupHTTPInputStream, soup_http_input_stream, G_TYPE_INPUT_STREAM)

typedef void (*SoupHTTPInputStreamCallback)(GInputStream *);

typedef struct {
	SoupSession *session;
	GMainContext *async_context;
	SoupMessage *msg;
	gboolean got_headers, finished;
	goffset offset;

	GCancellable *cancellable;
	GSource *cancel_watch;
	SoupHTTPInputStreamCallback got_headers_cb;
	SoupHTTPInputStreamCallback got_chunk_cb;
	SoupHTTPInputStreamCallback finished_cb;
	SoupHTTPInputStreamCallback cancelled_cb;

	GQueue *leftover_queue;

	guchar *caller_buffer;
	gsize caller_bufsize, caller_nread;
	GAsyncReadyCallback outstanding_callback;
	GSimpleAsyncResult *result;
} SoupHTTPInputStreamPrivate;
#define SOUP_HTTP_INPUT_STREAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP_INPUT_STREAM, SoupHTTPInputStreamPrivate))


static gssize   soup_http_input_stream_read (GInputStream         *stream,
					     void                 *buffer,
					     gsize count,
					     GCancellable         *cancellable,
					     GError              **error);
static gboolean soup_http_input_stream_close (GInputStream         *stream,
					      GCancellable         *cancellable,
					      GError              **error);
static void     soup_http_input_stream_read_async (GInputStream         *stream,
						   void                 *buffer,
						   gsize count,
						   int io_priority,
						   GCancellable         *cancellable,
						   GAsyncReadyCallback callback,
						   gpointer data);
static gssize   soup_http_input_stream_read_finish (GInputStream         *stream,
						    GAsyncResult         *result,
						    GError              **error);
static void     soup_http_input_stream_close_async (GInputStream         *stream,
						    int io_priority,
						    GCancellable         *cancellable,
						    GAsyncReadyCallback callback,
						    gpointer data);
static gboolean soup_http_input_stream_close_finish (GInputStream         *stream,
						     GAsyncResult         *result,
						     GError              **error);

static void soup_http_input_stream_got_headers (SoupMessage *msg, gpointer stream);
static void soup_http_input_stream_got_chunk (SoupMessage *msg, SoupBuffer *chunk, gpointer stream);
static void soup_http_input_stream_restarted (SoupMessage *msg, gpointer stream);
static void soup_http_input_stream_finished (SoupMessage *msg, gpointer stream);

static void
soup_http_input_stream_finalize (GObject *object)
{
	SoupHTTPInputStream *stream = SOUP_HTTP_INPUT_STREAM (object);
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	g_object_unref (priv->session);

	g_signal_handlers_disconnect_by_func (priv->msg, G_CALLBACK (soup_http_input_stream_got_headers), stream);
	g_signal_handlers_disconnect_by_func (priv->msg, G_CALLBACK (soup_http_input_stream_got_chunk), stream);
	g_signal_handlers_disconnect_by_func (priv->msg, G_CALLBACK (soup_http_input_stream_restarted), stream);
	g_signal_handlers_disconnect_by_func (priv->msg, G_CALLBACK (soup_http_input_stream_finished), stream);
	g_object_unref (priv->msg);

	g_queue_foreach (priv->leftover_queue, (GFunc) soup_buffer_free, NULL);
	g_queue_free (priv->leftover_queue);

	if (G_OBJECT_CLASS (soup_http_input_stream_parent_class)->finalize)
		(*G_OBJECT_CLASS (soup_http_input_stream_parent_class)->finalize)(object);
}

static void
soup_http_input_stream_class_init (SoupHTTPInputStreamClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
	GInputStreamClass *stream_class = G_INPUT_STREAM_CLASS (klass);

	g_type_class_add_private (klass, sizeof (SoupHTTPInputStreamPrivate));

	gobject_class->finalize = soup_http_input_stream_finalize;

	stream_class->read_fn = soup_http_input_stream_read;
	stream_class->close_fn = soup_http_input_stream_close;
	stream_class->read_async = soup_http_input_stream_read_async;
	stream_class->read_finish = soup_http_input_stream_read_finish;
	stream_class->close_async = soup_http_input_stream_close_async;
	stream_class->close_finish = soup_http_input_stream_close_finish;
}

static void
soup_http_input_stream_init (SoupHTTPInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->leftover_queue = g_queue_new ();
}

static void
soup_http_input_stream_queue_message (SoupHTTPInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->got_headers = priv->finished = FALSE;

	/* Add an extra ref since soup_session_queue_message steals one */
	g_object_ref (priv->msg);
	soup_session_queue_message (priv->session, priv->msg, NULL, NULL);
}

/**
 * soup_http_input_stream_new:
 * @session: the #SoupSession to use
 * @msg: the #SoupMessage whose response will be streamed
 *
 * Prepares to send @msg over @session, and returns a #GInputStream
 * that can be used to read the response.
 *
 * @msg may not be sent until the first read call; if you need to look
 * at the status code or response headers before reading the body, you
 * can use soup_http_input_stream_send() or soup_http_input_stream_send_async()
 * to force the message to be sent and the response headers read.
 *
 * If @msg gets a non-2xx result, the first read (or send) will return
 * an error with type %SOUP_HTTP_INPUT_STREAM_HTTP_ERROR.
 *
 * Internally, #SoupHTTPInputStream is implemented using asynchronous I/O,
 * so if you are using the synchronous API (eg,
 * g_input_stream_read()), you should create a new #GMainContext and
 * set it as the %SOUP_SESSION_ASYNC_CONTEXT property on @session. (If
 * you don't, then synchronous #GInputStream calls will cause the main
 * loop to be run recursively.) The async #GInputStream API works fine
 * with %SOUP_SESSION_ASYNC_CONTEXT either set or unset.
 *
 * Returns: a new #GInputStream.
 **/
GInputStream *
soup_http_input_stream_new (SoupSession *session, SoupMessage *msg)
{
	SoupHTTPInputStream *stream;
	SoupHTTPInputStreamPrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	stream = g_object_new (SOUP_TYPE_HTTP_INPUT_STREAM, NULL);
	priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->session = g_object_ref (session);
	priv->async_context = soup_session_get_async_context (session);
	priv->msg = g_object_ref (msg);

	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (soup_http_input_stream_got_headers), stream);
	g_signal_connect (msg, "got_chunk",
			  G_CALLBACK (soup_http_input_stream_got_chunk), stream);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (soup_http_input_stream_restarted), stream);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (soup_http_input_stream_finished), stream);

	soup_http_input_stream_queue_message (stream);
	return (GInputStream *)stream;
}

static void
soup_http_input_stream_got_headers (SoupMessage *msg, gpointer stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	/* If the message is expected to be restarted then we read the
	 * whole message first and hope it does get restarted, but
	 * if it doesn't, then we stream the body belatedly.
	 */
	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED ||
	    msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED ||
	    soup_session_would_redirect (priv->session, msg))
		return;

	priv->got_headers = TRUE;
	if (!priv->caller_buffer) {
		/* Not ready to read the body yet */
		soup_session_pause_message (priv->session, msg);
	}

	if (priv->got_headers_cb)
		priv->got_headers_cb (stream);
}

static void
soup_http_input_stream_got_chunk (SoupMessage *msg, SoupBuffer *chunk_buffer,
				  gpointer stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	const gchar *chunk = chunk_buffer->data;
	gsize chunk_size = chunk_buffer->length;

	/* Copy what we can into priv->caller_buffer */
	if (priv->caller_bufsize > priv->caller_nread && priv->leftover_queue->length == 0) {
		gsize nread = MIN (chunk_size, priv->caller_bufsize - priv->caller_nread);

		memcpy (priv->caller_buffer + priv->caller_nread, chunk, nread);
		priv->caller_nread += nread;
		priv->offset += nread;
		chunk += nread;
		chunk_size -= nread;
	}

	if (chunk_size > 0) {
		if (priv->leftover_queue->length > 0) {
			g_queue_push_tail (priv->leftover_queue, soup_buffer_copy (chunk_buffer));
		} else {
			g_queue_push_head (priv->leftover_queue,
					   soup_buffer_new_subbuffer (chunk_buffer,
								      chunk_buffer->length - chunk_size,
								      chunk_size));
		}
	}

	if (priv->got_headers) {
		soup_session_pause_message (priv->session, msg);
		if (priv->got_chunk_cb)
			priv->got_chunk_cb (stream);
	}
}

static void
soup_http_input_stream_restarted (SoupMessage *msg, gpointer stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	GList *q;

	/* Throw away any pending read data */
	for (q = priv->leftover_queue->head; q; q = q->next)
		soup_buffer_free (q->data);
	g_queue_clear (priv->leftover_queue);
}

static void
soup_http_input_stream_finished (SoupMessage *msg, gpointer stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->got_headers = TRUE;
	priv->finished = TRUE;

	if (priv->finished_cb)
		priv->finished_cb (stream);
}

static gboolean
soup_http_input_stream_cancelled (GIOChannel *chan, GIOCondition condition,
					 gpointer stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->cancel_watch = NULL;

	soup_session_pause_message (priv->session, priv->msg);
	if (priv->cancelled_cb)
		priv->cancelled_cb (stream);

	return FALSE;
}

static void
soup_http_input_stream_prepare_for_io (GInputStream *stream,
				       GCancellable *cancellable,
				       guchar       *buffer,
				       gsize count)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	int cancel_fd;

	priv->cancellable = cancellable;
	cancel_fd = g_cancellable_get_fd (cancellable);
	if (cancel_fd != -1) {
		GIOChannel *chan = g_io_channel_unix_new (cancel_fd);
		priv->cancel_watch = soup_add_io_watch (priv->async_context, chan,
							G_IO_IN | G_IO_ERR | G_IO_HUP,
							soup_http_input_stream_cancelled,
							stream);
		g_io_channel_unref (chan);
	}

	priv->caller_buffer = buffer;
	priv->caller_bufsize = count;
	priv->caller_nread = 0;

	if (priv->got_headers)
		soup_session_unpause_message (priv->session, priv->msg);
}

static void
soup_http_input_stream_done_io (GInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	if (priv->cancel_watch) {
		g_source_destroy (priv->cancel_watch);
		priv->cancel_watch = NULL;
		g_cancellable_release_fd (priv->cancellable);
	}
	priv->cancellable = NULL;

	priv->caller_buffer = NULL;
	priv->caller_bufsize = 0;
}

static gboolean
set_error_if_http_failed (SoupMessage *msg, GError **error)
{
	if (SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code)) {
		g_set_error_literal (error, SOUP_HTTP_ERROR,
				     msg->status_code, msg->reason_phrase);
		return TRUE;
	}
	return FALSE;
}

static gsize
read_from_leftover (SoupHTTPInputStreamPrivate *priv,
		    gpointer buffer, gsize bufsize)
{
	gsize nread;
	SoupBuffer *soup_buffer = (SoupBuffer *) g_queue_peek_head (priv->leftover_queue);
	gboolean fits_in_buffer = soup_buffer->length <= bufsize;

	nread = fits_in_buffer ? soup_buffer->length : bufsize;
	memcpy (buffer, soup_buffer->data, nread);

	g_queue_pop_head (priv->leftover_queue);
	if (!fits_in_buffer)
		g_queue_push_head (priv->leftover_queue,
				   soup_buffer_new_subbuffer (soup_buffer, nread, soup_buffer->length - nread));
	soup_buffer_free (soup_buffer);

	priv->offset += nread;
	return nread;
}

/* This does the work of soup_http_input_stream_send(), assuming that the
 * GInputStream pending flag has already been set. It is also used by
 * soup_http_input_stream_send_async() in some circumstances.
 */
static gboolean
soup_http_input_stream_send_internal (GInputStream  *stream,
				      GCancellable  *cancellable,
				      GError       **error)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	soup_http_input_stream_prepare_for_io (stream, cancellable, NULL, 0);
	while (!priv->finished && !priv->got_headers &&
	       !g_cancellable_is_cancelled (cancellable))
		g_main_context_iteration (priv->async_context, TRUE);
	soup_http_input_stream_done_io (stream);

	if (g_cancellable_set_error_if_cancelled (cancellable, error))
		return FALSE;
	else if (set_error_if_http_failed (priv->msg, error))
		return FALSE;
	return TRUE;
}

static void
send_sync_finished (GInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	priv->got_headers_cb = NULL;
	priv->finished_cb = NULL;

	/* Wake up the main context iteration */
	soup_add_completion (priv->async_context, NULL, NULL);
}

/**
 * soup_http_input_stream_send:
 * @httpstream: a #SoupHTTPInputStream
 * @cancellable: optional #GCancellable object, %NULL to ignore.
 * @error: location to store the error occuring, or %NULL to ignore
 *
 * Synchronously sends the HTTP request associated with @stream, and
 * reads the response headers. Call this after soup_http_input_stream_new()
 * and before the first g_input_stream_read() if you want to check the
 * HTTP status code before you start reading.
 *
 * Return value: %TRUE if msg has a successful (2xx) status, %FALSE if
 * not.
 **/
gboolean
soup_http_input_stream_send (SoupHTTPInputStream  *httpstream,
			     GCancellable         *cancellable,
			     GError              **error)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (httpstream);
	GInputStream *istream = (GInputStream *)httpstream;
	gboolean result;

	g_return_val_if_fail (SOUP_IS_HTTP_INPUT_STREAM (httpstream), FALSE);

	if (!g_input_stream_set_pending (istream, error))
		return FALSE;

	priv->got_headers_cb = send_sync_finished;
	priv->finished_cb = send_sync_finished;

	result = soup_http_input_stream_send_internal (istream, cancellable, error);
	g_input_stream_clear_pending (istream);

	return result;
}

static gssize
soup_http_input_stream_read (GInputStream  *stream,
			     void          *buffer,
			     gsize          count,
			     GCancellable  *cancellable,
			     GError       **error)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	/* If there is data leftover from a previous read, return it. */
	if (priv->leftover_queue->length)
		return read_from_leftover (priv, buffer, count);

	if (priv->finished)
		return 0;

	/* No leftover data, accept one chunk from the network */
	soup_http_input_stream_prepare_for_io (stream, cancellable, buffer, count);
	while (!priv->finished && priv->caller_nread == 0 &&
	       !g_cancellable_is_cancelled (cancellable))
		g_main_context_iteration (priv->async_context, TRUE);
	soup_http_input_stream_done_io (stream);

	if (priv->caller_nread > 0)
		return priv->caller_nread;

	if (g_cancellable_set_error_if_cancelled (cancellable, error))
		return -1;
	else if (set_error_if_http_failed (priv->msg, error))
		return -1;
	else
		return 0;
}

static gboolean
soup_http_input_stream_close (GInputStream  *stream,
			      GCancellable  *cancellable,
			      GError       **error)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	if (!priv->finished) {
		soup_session_unpause_message (priv->session, priv->msg);
		soup_session_cancel_message (priv->session, priv->msg, SOUP_STATUS_CANCELLED);
	}

	return TRUE;
}

static void
wrapper_callback (GObject *source_object, GAsyncResult *res,
		  gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source_object);
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	g_input_stream_clear_pending (stream);
	if (priv->outstanding_callback)
		(*priv->outstanding_callback) (source_object, res, user_data);
	priv->outstanding_callback = NULL;
	g_object_unref (stream);
}

static void
send_async_finished (GInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	GSimpleAsyncResult *result;
	GError *error = NULL;

	if (!g_cancellable_set_error_if_cancelled (priv->cancellable, &error))
		set_error_if_http_failed (priv->msg, &error);

	priv->got_headers_cb = NULL;
	priv->finished_cb = NULL;
	soup_http_input_stream_done_io (stream);

	result = priv->result;
	priv->result = NULL;

	g_simple_async_result_set_op_res_gboolean (result, error == NULL);
	if (error)
		g_simple_async_result_take_error (result, error);
	g_simple_async_result_complete (result);
	g_object_unref (result);
}

static void
soup_http_input_stream_send_async_internal (GInputStream        *stream,
					    int                  io_priority,
					    GCancellable        *cancellable,
					    GAsyncReadyCallback  callback,
					    gpointer             user_data)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);

	g_return_if_fail (priv->async_context == g_main_context_get_thread_default ());

	g_object_ref (stream);
	priv->outstanding_callback = callback;

	priv->got_headers_cb = send_async_finished;
	priv->finished_cb = send_async_finished;

	soup_http_input_stream_prepare_for_io (stream, cancellable, NULL, 0);
	priv->result = g_simple_async_result_new (G_OBJECT (stream),
						  wrapper_callback, user_data,
						  soup_http_input_stream_send_async);
}

/**
 * soup_http_input_stream_send_async:
 * @httpstream: a #SoupHTTPInputStream
 * @io_priority: the io priority of the request.
 * @cancellable: optional #GCancellable object, %NULL to ignore.
 * @callback: callback to call when the request is satisfied
 * @user_data: the data to pass to callback function
 *
 * Asynchronously sends the HTTP request associated with @stream, and
 * reads the response headers. Call this after soup_http_input_stream_new()
 * and before the first g_input_stream_read_async() if you want to
 * check the HTTP status code before you start reading.
 **/
void
soup_http_input_stream_send_async (SoupHTTPInputStream *httpstream,
				   int                  io_priority,
				   GCancellable        *cancellable,
				   GAsyncReadyCallback  callback,
				   gpointer             user_data)
{
	GInputStream *istream = (GInputStream *)httpstream;
	GError *error = NULL;

	g_return_if_fail (SOUP_IS_HTTP_INPUT_STREAM (httpstream));

	if (!g_input_stream_set_pending (istream, &error)) {
		g_simple_async_report_take_gerror_in_idle (G_OBJECT (httpstream),
							   callback,
							   user_data,
							   error);
		return;
	}
	soup_http_input_stream_send_async_internal (istream, io_priority, cancellable,
						    callback, user_data);
}

/**
 * soup_http_input_stream_send_finish:
 * @httpstream: a #SoupHTTPInputStream
 * @result: a #GAsyncResult.
 * @error: a #GError location to store the error occuring, or %NULL to
 * ignore.
 *
 * Finishes a soup_http_input_stream_send_async() operation.
 *
 * Return value: %TRUE if the message was sent successfully and
 * received a successful status code, %FALSE if not.
 **/
gboolean
soup_http_input_stream_send_finish (SoupHTTPInputStream  *httpstream,
				    GAsyncResult         *result,
				    GError              **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), FALSE);
	simple = G_SIMPLE_ASYNC_RESULT (result);

	g_return_val_if_fail (g_simple_async_result_get_source_tag (simple) == soup_http_input_stream_send_async, FALSE);

	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;

	return g_simple_async_result_get_op_res_gboolean (simple);
}

static void
read_async_done (GInputStream *stream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	GSimpleAsyncResult *result;
	GError *error = NULL;

	result = priv->result;
	priv->result = NULL;

	if (g_cancellable_set_error_if_cancelled (priv->cancellable, &error) ||
	    set_error_if_http_failed (priv->msg, &error))
		g_simple_async_result_take_error (result, error);
	else
		g_simple_async_result_set_op_res_gssize (result, priv->caller_nread);

	priv->got_chunk_cb = NULL;
	priv->finished_cb = NULL;
	priv->cancelled_cb = NULL;
	soup_http_input_stream_done_io (stream);

	g_simple_async_result_complete (result);
	g_object_unref (result);
}

static void
soup_http_input_stream_read_async (GInputStream        *stream,
				   void                *buffer,
				   gsize                count,
				   int                  io_priority,
				   GCancellable        *cancellable,
				   GAsyncReadyCallback  callback,
				   gpointer             user_data)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (stream);
	GSimpleAsyncResult *result;

	g_return_if_fail (priv->async_context == g_main_context_get_thread_default ());

	result = g_simple_async_result_new (G_OBJECT (stream),
					    callback, user_data,
					    soup_http_input_stream_read_async);

	if (priv->leftover_queue->length) {
		gsize nread = read_from_leftover (priv, buffer, count);
		g_simple_async_result_set_op_res_gssize (result, nread);
		g_simple_async_result_complete_in_idle (result);
		g_object_unref (result);
		return;
	}

	if (priv->finished) {
		g_simple_async_result_set_op_res_gssize (result, 0);
		g_simple_async_result_complete_in_idle (result);
		g_object_unref (result);
		return;
	}

	priv->result = result;

	priv->got_chunk_cb = read_async_done;
	priv->finished_cb = read_async_done;
	priv->cancelled_cb = read_async_done;
	soup_http_input_stream_prepare_for_io (stream, cancellable, buffer, count);
}

static gssize
soup_http_input_stream_read_finish (GInputStream  *stream,
				    GAsyncResult  *result,
				    GError       **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (G_IS_SIMPLE_ASYNC_RESULT (result), -1);
	simple = G_SIMPLE_ASYNC_RESULT (result);
	g_return_val_if_fail (g_simple_async_result_get_source_tag (simple) == soup_http_input_stream_read_async, -1);

	return g_simple_async_result_get_op_res_gssize (simple);
}

static void
soup_http_input_stream_close_async (GInputStream        *stream,
				    int                  io_priority,
				    GCancellable        *cancellable,
				    GAsyncReadyCallback  callback,
				    gpointer             user_data)
{
	GSimpleAsyncResult *result;
	gboolean success;
	GError *error = NULL;

	result = g_simple_async_result_new (G_OBJECT (stream),
					    callback, user_data,
					    soup_http_input_stream_close_async);
	success = soup_http_input_stream_close (stream, cancellable, &error);
	g_simple_async_result_set_op_res_gboolean (result, success);
	if (error)
		g_simple_async_result_take_error (result, error);

	g_simple_async_result_complete_in_idle (result);
	g_object_unref (result);
}

static gboolean
soup_http_input_stream_close_finish (GInputStream  *stream,
				     GAsyncResult  *result,
				     GError       **error)
{
	/* Failures handled in generic close_finish code */
	return TRUE;
}

SoupMessage *
soup_http_input_stream_get_message (SoupHTTPInputStream *httpstream)
{
	SoupHTTPInputStreamPrivate *priv = SOUP_HTTP_INPUT_STREAM_GET_PRIVATE (httpstream);
	return priv->msg ? g_object_ref (priv->msg) : NULL;
}
