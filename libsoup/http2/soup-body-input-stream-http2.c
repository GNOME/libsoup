/* GIO - GLib Input, Output and Streaming Library
 * 
 * Copyright (C) 2006-2007 Red Hat, Inc.
 * Copyright 2021 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Christian Kellner <gicmo@gnome.org> 
 */

#include "config.h"

#include "soup-body-input-stream-http2.h"
#include <glib/gi18n-lib.h>

/*
 * SoupBodyInputStreamHttp2
 * @short_description: Streaming input operations on memory chunks
 *
 * [type@BodyInputStreamHttp2] is a class for using arbitrary
 * memory chunks as input for GIO streaming input operations.
 *
 * It differs from #GMemoryInputStream in that it frees older chunks
 * after they have been read, returns #G_IO_ERROR_WOULDBLOCK at the end
 * of data until soup_body_input_stream_http2_complete() is called, and implements
 * g_pollable_input_stream_is_readable().
 */

struct _SoupBodyInputStreamHttp2 {
        GInputStream parent_instance;
};

typedef struct {
        GQueue *chunks;
        gsize start_offset;
        gsize len;
        gsize pos;
        gboolean completed;
        GCancellable *need_more_data_cancellable;
} SoupBodyInputStreamHttp2Private;

static void soup_body_input_stream_http2_pollable_iface_init (GPollableInputStreamInterface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupBodyInputStreamHttp2, soup_body_input_stream_http2, G_TYPE_INPUT_STREAM,
                               G_ADD_PRIVATE (SoupBodyInputStreamHttp2)
                               G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
                                                      soup_body_input_stream_http2_pollable_iface_init);)

enum {
        NEED_MORE_DATA,
        READ_DATA,
        LAST_SIGNAL
};

static guint signals [LAST_SIGNAL] = { 0 };

/**
 * soup_body_input_stream_http2_new:
 *
 * Creates a new empty [type@BodyInputStreamHttp2].
 *
 * Returns: a new #GInputStream
 */
GInputStream *
soup_body_input_stream_http2_new (void)
{
        return G_INPUT_STREAM (g_object_new (SOUP_TYPE_BODY_INPUT_STREAM_HTTP2, NULL));
}

gsize
soup_body_input_stream_http2_get_buffer_size (SoupBodyInputStreamHttp2 *stream)
{
        SoupBodyInputStreamHttp2Private *priv;

        g_return_val_if_fail (SOUP_IS_BODY_INPUT_STREAM_HTTP2 (stream), 0);

        priv = soup_body_input_stream_http2_get_instance_private (stream);

        g_assert (priv->len >= priv->pos);
        return priv->len - priv->pos;
}

void
soup_body_input_stream_http2_add_data (SoupBodyInputStreamHttp2 *stream,
                                       const guint8             *data,
                                       gsize                     size)
{
        SoupBodyInputStreamHttp2Private *priv;

        g_return_if_fail (SOUP_IS_BODY_INPUT_STREAM_HTTP2 (stream));
        g_return_if_fail (data != NULL);

        priv = soup_body_input_stream_http2_get_instance_private (stream);

        g_queue_push_tail (priv->chunks, g_bytes_new (data, size));
        priv->len += size;
        if (priv->need_more_data_cancellable) {
                g_cancellable_cancel (priv->need_more_data_cancellable);
                g_clear_object (&priv->need_more_data_cancellable);
        }
}

gboolean
soup_body_input_stream_http2_is_blocked (SoupBodyInputStreamHttp2 *stream)
{
        SoupBodyInputStreamHttp2Private *priv;

        g_return_val_if_fail (SOUP_IS_BODY_INPUT_STREAM_HTTP2 (stream), FALSE);

        priv = soup_body_input_stream_http2_get_instance_private (stream);
        return priv->need_more_data_cancellable != NULL;
}

static gboolean
have_more_data_coming (SoupBodyInputStreamHttp2 *stream)
{
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (stream);

        return !priv->completed || priv->pos < priv->len;
}

static gssize
soup_body_input_stream_http2_read_real (GInputStream  *stream,
                                        gboolean       blocking,
                                        void          *buffer,
                                        gsize          read_count,
                                        GCancellable  *cancellable,
                                        GError       **error)
{
        SoupBodyInputStreamHttp2 *memory_stream;
        SoupBodyInputStreamHttp2Private *priv;
        GList *l;
        GBytes *chunk;
        gsize len;
        gsize offset, start, rest, size;
        gsize count;

        memory_stream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        priv = soup_body_input_stream_http2_get_instance_private (memory_stream);

        /* We have a list of chunked bytes that we continually read from.
         * Once a chunk is fully read it is removed from our list and we
         * keep the offset of where the chunks start.
         */

        count = MIN (read_count, priv->len - priv->pos);

        offset = priv->start_offset;
        for (l = g_queue_peek_head_link(priv->chunks); l; l = l->next) {
                chunk = (GBytes *)l->data;
                len = g_bytes_get_size (chunk);

                if (offset + len > priv->pos)
                        break;

                offset += len;
        }

        priv->start_offset = offset;
        start = priv->pos - offset;
        rest = count;

        while (l && rest > 0) {
                GList *next = l->next;

                const guint8 *chunk_data;
                chunk = (GBytes *)l->data;

                chunk_data = g_bytes_get_data (chunk, &len);

                size = MIN (rest, len - start);

                memcpy ((guint8 *)buffer + (count - rest), chunk_data + start, size);
                rest -= size;

                /* Remove fully read chunk from list, note that we are always near the start of the list */
                if (start + size == len) {
                        priv->start_offset += len;
                        g_queue_delete_link (priv->chunks, l);
                        g_bytes_unref (chunk);
                }

                start = 0;
                l = next;
        }

        gsize bytes_read = count - rest;
        priv->pos += bytes_read;

        if (bytes_read > 0)
                g_signal_emit (memory_stream, signals[READ_DATA], 0, (guint64)bytes_read);

        /* When doing blocking reads we must always request more data.
         * Even when doing non-blocking, a read consuming data may trigger a new WINDOW_UPDATE. */
        if (have_more_data_coming (memory_stream) && bytes_read == 0) {
                GError *read_error = NULL;
                g_signal_emit (memory_stream, signals[NEED_MORE_DATA], 0,
                        blocking, cancellable, &read_error);

                if (read_error) {
                        g_propagate_error (error, read_error);
                        return -1;
                }

                if (blocking) {
                        return soup_body_input_stream_http2_read_real (
                                stream, blocking, buffer, read_count, cancellable, error
                        );
                }
        }

        return count;
}

static gssize
soup_body_input_stream_http2_read (GInputStream  *stream,
                                   void          *buffer,
                                   gsize          count,
                                   GCancellable  *cancellable,
                                   GError       **error)
{
        return soup_body_input_stream_http2_read_real (stream, TRUE, buffer, count, cancellable, error);
}

static gssize
soup_body_input_stream_http2_read_nonblocking (GPollableInputStream  *stream,
                                               void                  *buffer,
                                               gsize                  count,
                                               GError               **error)
{
        SoupBodyInputStreamHttp2 *memory_stream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        GError *inner_error = NULL;

        gsize read = soup_body_input_stream_http2_read_real (G_INPUT_STREAM (stream), FALSE, buffer, count, NULL, &inner_error);

        if (read == 0 && have_more_data_coming (memory_stream) && !inner_error) {
                g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK, _("Operation would block"));
                return -1;
        }

        if (inner_error)
                g_propagate_error (error, inner_error);

        return read;
}

void
soup_body_input_stream_http2_complete (SoupBodyInputStreamHttp2 *stream)
{
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (stream);
        priv->completed = TRUE;
        if (priv->need_more_data_cancellable) {
                g_cancellable_cancel (priv->need_more_data_cancellable);
                g_clear_object (&priv->need_more_data_cancellable);
        }
}

static gssize
soup_body_input_stream_http2_skip (GInputStream  *stream,
                                   gsize          count,
                                   GCancellable  *cancellable,
                                   GError       **error)
{
        SoupBodyInputStreamHttp2 *memory_stream;
        SoupBodyInputStreamHttp2Private *priv;

        memory_stream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        priv = soup_body_input_stream_http2_get_instance_private (memory_stream);

        count = MIN (count, priv->len - priv->pos);
        priv->pos += count;
        if (count)
                g_signal_emit (memory_stream, signals[READ_DATA], 0, (guint64)count);

        /* Remove all skipped chunks */
        gsize offset = priv->start_offset;
        for (GList *l = g_queue_peek_head_link(priv->chunks); l; l = l->next) {
                GBytes *chunk = (GBytes *)l->data;
                gsize chunk_len = g_bytes_get_size (chunk);

                if (offset + chunk_len <= priv->pos) {
                        g_queue_delete_link (priv->chunks, l);
                        g_bytes_unref (chunk);
                        offset += chunk_len;
                }
                break;
        }
        priv->start_offset = offset;

        return count;
}

static gboolean
soup_body_input_stream_http2_close (GInputStream  *stream,
                                    GCancellable  *cancellable,
                                    GError       **error)
{
        return TRUE;
}

static void
soup_body_input_stream_http2_skip_async (GInputStream *stream,
                                     gsize count,
                                     int io_priority,
                                     GCancellable *cancellable,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
        GTask *task;
        gssize nskipped;
        GError *error = NULL;

        nskipped = G_INPUT_STREAM_GET_CLASS (stream)->skip (stream, count, cancellable, &error);
        task = g_task_new (stream, cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_body_input_stream_http2_skip_async);

        if (error)
                g_task_return_error (task, error);
        else
                g_task_return_int (task, nskipped);
        g_object_unref (task);
}

static gssize
soup_body_input_stream_http2_skip_finish (GInputStream  *stream,
                                          GAsyncResult  *result,
                                          GError       **error)
{
        g_return_val_if_fail (g_task_is_valid (result, stream), -1);

        return g_task_propagate_int (G_TASK (result), error);
}

static void
soup_body_input_stream_http2_close_async (GInputStream        *stream,
                                          int                  io_priority,
                                          GCancellable        *cancellable,
                                          GAsyncReadyCallback  callback,
                                          gpointer             user_data)
{
        GTask *task;

        task = g_task_new (stream, cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_body_input_stream_http2_close_async);
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
}

static gboolean
soup_body_input_stream_http2_close_finish (GInputStream  *stream,
                                           GAsyncResult  *result,
                                           GError       **error)
{
        return TRUE;
}

static gboolean
soup_body_input_stream_http2_is_readable (GPollableInputStream *stream)
{
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (SOUP_BODY_INPUT_STREAM_HTTP2 (stream));

        return priv->pos < priv->len || priv->completed;
}

static GSource *
soup_body_input_stream_http2_create_source (GPollableInputStream *stream,
                                            GCancellable         *cancellable)
{
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (SOUP_BODY_INPUT_STREAM_HTTP2 (stream));
        GSource *base_source, *pollable_source;

        if (priv->pos < priv->len) {
                base_source = g_timeout_source_new (0);
        } else {
                if (!priv->need_more_data_cancellable)
                        priv->need_more_data_cancellable = g_cancellable_new ();
                base_source = g_cancellable_source_new (priv->need_more_data_cancellable);
        }

        pollable_source = g_pollable_source_new_full (stream, base_source, cancellable);
        g_source_set_name (pollable_source, "SoupMemoryStreamSource");
        g_source_unref (base_source);

        return pollable_source;
}

static void
soup_body_input_stream_http2_dispose (GObject *object)
{
        SoupBodyInputStreamHttp2 *stream = SOUP_BODY_INPUT_STREAM_HTTP2 (object);
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (stream);

        priv->completed = TRUE;
        if (priv->need_more_data_cancellable) {
		g_cancellable_cancel (priv->need_more_data_cancellable);
                g_clear_object (&priv->need_more_data_cancellable);
        }

        G_OBJECT_CLASS (soup_body_input_stream_http2_parent_class)->dispose (object);
}

static void
soup_body_input_stream_http2_finalize (GObject *object)
{
        SoupBodyInputStreamHttp2 *stream = SOUP_BODY_INPUT_STREAM_HTTP2 (object);
        SoupBodyInputStreamHttp2Private *priv = soup_body_input_stream_http2_get_instance_private (stream);

        g_queue_free_full (priv->chunks, (GDestroyNotify)g_bytes_unref);

        G_OBJECT_CLASS (soup_body_input_stream_http2_parent_class)->finalize (object);
}

static void
soup_body_input_stream_http2_pollable_iface_init (GPollableInputStreamInterface *iface)
{
        iface->is_readable = soup_body_input_stream_http2_is_readable;
        iface->create_source = soup_body_input_stream_http2_create_source;
        iface->read_nonblocking = soup_body_input_stream_http2_read_nonblocking;
}

static void
soup_body_input_stream_http2_init (SoupBodyInputStreamHttp2 *stream)
{
        SoupBodyInputStreamHttp2Private *priv;

        priv = soup_body_input_stream_http2_get_instance_private (stream);
        priv->chunks = g_queue_new ();
}

static void
soup_body_input_stream_http2_class_init (SoupBodyInputStreamHttp2Class *klass)
{
        GObjectClass *object_class;
        GInputStreamClass *istream_class;

        object_class = G_OBJECT_CLASS (klass);
        object_class->finalize = soup_body_input_stream_http2_finalize;
        object_class->dispose = soup_body_input_stream_http2_dispose;

        istream_class = G_INPUT_STREAM_CLASS (klass);
        istream_class->read_fn = soup_body_input_stream_http2_read;
        istream_class->skip = soup_body_input_stream_http2_skip;
        istream_class->close_fn = soup_body_input_stream_http2_close;

        istream_class->skip_async = soup_body_input_stream_http2_skip_async;
        istream_class->skip_finish = soup_body_input_stream_http2_skip_finish;
        istream_class->close_async = soup_body_input_stream_http2_close_async;
        istream_class->close_finish = soup_body_input_stream_http2_close_finish;

        signals[NEED_MORE_DATA] =
                g_signal_new ("need-more-data",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_ERROR,
                              2, G_TYPE_BOOLEAN,
                              G_TYPE_CANCELLABLE);

        signals[READ_DATA] =
                g_signal_new ("read-data",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 1,
                              G_TYPE_UINT64);
}
