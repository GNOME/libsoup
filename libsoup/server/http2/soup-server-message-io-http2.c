/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-server-message-io-http1.c: HTTP message I/O
 *
 * Copyright (C) 2022, Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#include "soup-server-message-io-http2.h"
#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-filter-input-stream.h"
#include "soup-message-io-data.h"
#include "soup-message-headers-private.h"
#include "soup-server-message-private.h"
#include "soup-misc.h"

#include <nghttp2/nghttp2.h>

typedef enum {
        STATE_NONE,
        STATE_READ_HEADERS,
        STATE_READ_DATA,
        STATE_READ_DONE,
        STATE_WRITE_HEADERS,
        STATE_WRITE_DATA,
        STATE_WRITE_DONE,
} SoupHTTP2IOState;

typedef struct {
        SoupServerMessage *msg;
        guint32 stream_id;
        SoupHTTP2IOState state;
        GSource *unpause_source;
        gboolean paused;

        SoupMessageIOCompletionFn completion_cb;
        gpointer completion_data;

        char *scheme;
        char *authority;
        char *path;

        GBytes *write_chunk;
        goffset write_offset;
        goffset chunk_written;
} SoupMessageIOHTTP2;

typedef struct {
        SoupServerMessageIO iface;

        SoupServerConnection *conn;
        GIOStream *iostream;
        GInputStream *istream;
        GOutputStream *ostream;

        GSource *read_source;
        GSource *write_source;

        nghttp2_session *session;

        /* Owned by nghttp2 */
        guint8 *write_buffer;
        gssize write_buffer_size;
        gssize written_bytes;

        SoupMessageIOStartedFn started_cb;
        gpointer started_user_data;

        GHashTable *messages;
} SoupServerMessageIOHTTP2;

static void soup_server_message_io_http2_send_response (SoupServerMessageIOHTTP2 *io,
                                                        SoupMessageIOHTTP2       *msg_io);

static const char *
state_to_string (SoupHTTP2IOState state)
{
        switch (state) {
        case STATE_NONE:
                return "NONE";
        case STATE_READ_HEADERS:
                return "READ_HEADERS";
        case STATE_READ_DATA:
                return "READ_DATA";
        case STATE_READ_DONE:
                return "READ_DONE";
        case STATE_WRITE_HEADERS:
                return "WRITE_HEADERS";
        case STATE_WRITE_DATA:
                return "WRITE_DATA";
        case STATE_WRITE_DONE:
                return "WRITE_DONE";
        default:
                g_assert_not_reached ();
                return "";
        }
}

static void
advance_state_from (SoupMessageIOHTTP2 *msg_io,
                    SoupHTTP2IOState    from,
                    SoupHTTP2IOState    to)
{
        if (msg_io->state != from) {
                g_warning ("Unexpected state changed %s -> %s, expected to be from %s",
                           state_to_string (msg_io->state), state_to_string (to),
                           state_to_string (from));
        }

        /* State never goes backwards */
        if (to < msg_io->state) {
                g_warning ("Unexpected state changed %s -> %s, expected %s -> %s\n",
                           state_to_string (msg_io->state), state_to_string (to),
                           state_to_string (from), state_to_string (to));
                return;
        }

        msg_io->state = to;
}

static SoupMessageIOHTTP2 *
soup_message_io_http2_new (SoupServerMessage *msg)
{
        SoupMessageIOHTTP2 *msg_io;

        msg_io = g_new0 (SoupMessageIOHTTP2, 1);
        msg_io->msg = msg;

        return msg_io;
}

static void
soup_message_io_http2_free (SoupMessageIOHTTP2 *msg_io)
{
        if (msg_io->unpause_source) {
                g_source_destroy (msg_io->unpause_source);
                g_source_unref (msg_io->unpause_source);
        }
        g_clear_object (&msg_io->msg);
        g_free (msg_io->scheme);
        g_free (msg_io->authority);
        g_free (msg_io->path);
        g_clear_pointer (&msg_io->write_chunk, g_bytes_unref);
        g_free (msg_io);
}

static void
soup_server_message_io_http2_destroy (SoupServerMessageIO *iface)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;

        if (io->read_source) {
                g_source_destroy (io->read_source);
                g_source_unref (io->read_source);
        }
        if (io->write_source) {
                g_source_destroy (io->write_source);
                g_source_unref (io->write_source);
        }

        g_clear_object (&io->iostream);
        g_clear_pointer (&io->session, nghttp2_session_del);
        g_clear_pointer (&io->messages, g_hash_table_unref);

        g_free (io);
}

static void
soup_server_message_io_http2_finished (SoupServerMessageIO *iface,
                                       SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;
        SoupMessageIOHTTP2 *msg_io = NULL;
        SoupMessageIOCompletionFn completion_cb;
        gpointer completion_data;
        SoupMessageIOCompletion completion;

        g_hash_table_steal_extended (io->messages, msg, NULL, (gpointer *)&msg_io);
        completion = msg_io->state < STATE_WRITE_DONE ? SOUP_MESSAGE_IO_INTERRUPTED : SOUP_MESSAGE_IO_COMPLETE;

        completion_cb = msg_io->completion_cb;
        completion_data = msg_io->completion_data;

        g_object_ref (msg);
        soup_message_io_http2_free (msg_io);

        if (completion_cb)
                completion_cb (G_OBJECT (msg), completion, completion_data);

        g_object_unref (msg);
}

static GIOStream *
soup_server_message_io_http2_steal (SoupServerMessageIO *iface)
{
        g_assert_not_reached ();
        return NULL;
}

static void
soup_server_message_io_http2_read_request (SoupServerMessageIO      *iface,
                                           SoupServerMessage        *msg,
                                           SoupMessageIOCompletionFn completion_cb,
                                           gpointer                  user_data)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;
        SoupMessageIOHTTP2 *msg_io;

        msg_io = g_hash_table_lookup (io->messages, msg);
        g_assert (msg_io);

        msg_io->completion_cb = completion_cb;
        msg_io->completion_data = user_data;
}

static void
soup_server_message_io_http2_pause (SoupServerMessageIO *iface,
                                    SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;
        SoupMessageIOHTTP2 *msg_io;

        msg_io = g_hash_table_lookup (io->messages, msg);
        g_assert (msg_io);

        if (msg_io->paused)
                g_warn_if_reached ();

        if (msg_io->unpause_source) {
                g_source_destroy (msg_io->unpause_source);
                g_clear_pointer (&msg_io->unpause_source, g_source_unref);
        }

        msg_io->paused = TRUE;
}

typedef struct {
        SoupServerMessageIOHTTP2 *io;
        SoupMessageIOHTTP2 *msg_io;
} UnpauseSourceData;

static gboolean
io_unpause_internal (UnpauseSourceData *data)
{
        SoupMessageIOHTTP2 *msg_io = data->msg_io;

        g_clear_pointer (&msg_io->unpause_source, g_source_unref);
        if (msg_io->paused)
                return FALSE;

        if (!nghttp2_session_get_stream_user_data (data->io->session, msg_io->stream_id)) {
                soup_server_message_finish (msg_io->msg);
                return FALSE;
        }

        switch (msg_io->state) {
        case STATE_READ_DONE:
                soup_server_message_io_http2_send_response (data->io, msg_io);
                break;
        default:
                g_warn_if_reached ();
        }
        return FALSE;
}

static void
soup_server_message_io_http2_unpause (SoupServerMessageIO *iface,
                                      SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;
        SoupMessageIOHTTP2 *msg_io;

        msg_io = g_hash_table_lookup (io->messages, msg);
        g_assert (msg_io);

        if (!msg_io->paused)
                g_warn_if_reached ();

        msg_io->paused = FALSE;

        if (!msg_io->unpause_source) {
                UnpauseSourceData *data = g_new (UnpauseSourceData, 1);

                data->io = io;
                data->msg_io = msg_io;
                msg_io->unpause_source = soup_add_completion_reffed (g_main_context_get_thread_default (),
                                                                     (GSourceFunc)io_unpause_internal,
                                                                     data, g_free);
        }
}

static gboolean
soup_server_message_io_http2_is_paused (SoupServerMessageIO *iface,
                                        SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)iface;
        SoupMessageIOHTTP2 *msg_io;

        msg_io = g_hash_table_lookup (io->messages, msg);
        g_assert (msg_io);

        return msg_io->paused;
}

static const SoupServerMessageIOFuncs io_funcs = {
        soup_server_message_io_http2_destroy,
        soup_server_message_io_http2_finished,
        soup_server_message_io_http2_steal,
        soup_server_message_io_http2_read_request,
        soup_server_message_io_http2_pause,
        soup_server_message_io_http2_unpause,
        soup_server_message_io_http2_is_paused
};

static gboolean
io_write (SoupServerMessageIOHTTP2 *io,
          GError                  **error)
{
        /* We must write all of nghttp2's buffer before we ask for more */
        if (io->written_bytes == io->write_buffer_size)
                io->write_buffer = NULL;

        if (io->write_buffer == NULL) {
                io->written_bytes = 0;
                io->write_buffer_size = nghttp2_session_mem_send (io->session, (const guint8**)&io->write_buffer);
                if (io->write_buffer_size == 0) {
                        /* Done */
                        io->write_buffer = NULL;
                        return TRUE;
                }
        }

        gssize ret = g_pollable_stream_write (io->ostream,
                                              io->write_buffer + io->written_bytes,
                                              io->write_buffer_size - io->written_bytes,
                                              FALSE, NULL, error);
        if (ret < 0)
                return FALSE;

        io->written_bytes += ret;
        return TRUE;
}

static gboolean
io_write_ready (GObject                  *stream,
                SoupServerMessageIOHTTP2 *io)
{
        GError *error = NULL;

        while (nghttp2_session_want_write (io->session) && !error)
                io_write (io, &error);

        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_error_free (error);
                return G_SOURCE_CONTINUE;
        }

        g_clear_error (&error);
        g_clear_pointer (&io->write_source, g_source_unref);

        return G_SOURCE_REMOVE;
}

static void
io_try_write (SoupServerMessageIOHTTP2 *io)
{
        GError *error = NULL;

        if (io->write_source)
                return;

        while (nghttp2_session_want_write (io->session) && !error)
                io_write (io, &error);

        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error (&error);
                io->write_source = g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (io->ostream), NULL);
                g_source_set_name (io->write_source, "Soup server HTTP/2 write source");
                g_source_set_callback (io->write_source, (GSourceFunc)io_write_ready, io, NULL);
                g_source_attach (io->write_source, g_main_context_get_thread_default ());
        }

        g_clear_error (&error);
}

static gboolean
io_read (SoupServerMessageIOHTTP2 *io,
         GError                  **error)
{
        guint8 buffer[8192];
        gssize read;

        if ((read = g_pollable_stream_read (io->istream, buffer, sizeof (buffer), FALSE, NULL, error)) < 0)
                return FALSE;

        return nghttp2_session_mem_recv (io->session, buffer, read) != 0;
}

static gboolean
io_read_ready (GObject                  *stream,
               SoupServerMessageIOHTTP2 *io)
{
        gboolean progress = TRUE;
        GError *error = NULL;

        while (nghttp2_session_want_read (io->session) && progress)
                progress = io_read (io, &error);

        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_error_free (error);
                return G_SOURCE_CONTINUE;
        }

        g_clear_error (&error);

        return G_SOURCE_REMOVE;
}

static SoupMessageIOHTTP2 *
soup_server_message_io_http2_get_or_create_msg_io (SoupServerMessageIOHTTP2 *io,
                                                   int32_t                   stream_id)
{
        SoupMessageIOHTTP2 *msg_io;

        /* The initial message is created earlier to handle the TLS certificate.
         * If there's only one message without a stream id, that means it's the
         * initial message and should be used now.
         */
        if (g_hash_table_size (io->messages) == 1) {
                GList *values = g_hash_table_get_values (io->messages);

                msg_io = (SoupMessageIOHTTP2 *)values->data;
                g_list_free (values);

                if (msg_io->stream_id == 0) {
                        msg_io->stream_id = stream_id;
                        return msg_io;
                }
        }

        msg_io = soup_message_io_http2_new (soup_server_message_new (io->conn));
        msg_io->stream_id = stream_id;
        soup_server_message_set_http_version (msg_io->msg, SOUP_HTTP_2_0);
        g_hash_table_insert (io->messages, msg_io->msg, msg_io);

        return msg_io;
}

static int
on_begin_headers_callback (nghttp2_session     *session,
                           const nghttp2_frame *frame,
                           void                *user_data)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)user_data;
        SoupMessageIOHTTP2 *msg_io;

        if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
                return 0;

        msg_io = soup_server_message_io_http2_get_or_create_msg_io (io, frame->hd.stream_id);
        nghttp2_session_set_stream_user_data (session, frame->hd.stream_id, msg_io);

        if (!msg_io->completion_cb)
                io->started_cb (msg_io->msg, io->started_user_data);

        advance_state_from (msg_io, STATE_NONE, STATE_READ_HEADERS);

        return 0;
}

static int
on_header_callback (nghttp2_session     *session,
                    const nghttp2_frame *frame,
                    const uint8_t       *name,
                    size_t               namelen,
                    const uint8_t       *value,
                    size_t               valuelen,
                    uint8_t              flags,
                    void                *user_data)
{
        SoupMessageIOHTTP2 *msg_io;
        SoupServerMessage *msg;

        if (frame->hd.type != NGHTTP2_HEADERS)
                return 0;

        if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
                return 0;

        msg_io = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
        if (!msg_io)
                return 0;

        msg = msg_io->msg;
        if (name[0] == ':') {
                if (strcmp ((char *)name, ":method") == 0)
                        soup_server_message_set_method (msg, (char *)value);
                else if (strcmp ((char *)name, ":scheme") == 0)
                        msg_io->scheme = g_strndup ((char *)value, valuelen);
                else if (strcmp ((char *)name, ":authority") == 0)
                        msg_io->authority = g_strndup ((char *)value, valuelen);
                else if (strcmp ((char *)name, ":path") == 0)
                        msg_io->path = g_strndup ((char *)value, valuelen);
                else
                        g_debug ("Unknown header: %s = %s", name, value);
                return 0;
        }

        soup_message_headers_append_untrusted_data (soup_server_message_get_request_headers (msg),
                                                    (const char*)name, (const char*)value);
        return 0;
}

static int
on_data_chunk_recv_callback (nghttp2_session *session,
                             uint8_t          flags,
                             int32_t          stream_id,
                             const uint8_t   *data,
                             size_t           len,
                             void            *user_data)
{
        SoupMessageIOHTTP2 *msg_io;
        GBytes *bytes;

        msg_io = nghttp2_session_get_stream_user_data (session, stream_id);
        if (!msg_io)
                return NGHTTP2_ERR_CALLBACK_FAILURE;

        bytes = g_bytes_new (data, len);
        soup_message_body_got_chunk (soup_server_message_get_request_body (msg_io->msg), bytes);
        soup_server_message_got_chunk (msg_io->msg, bytes);
        g_bytes_unref (bytes);

        return 0;
}

static ssize_t
on_data_source_read_callback (nghttp2_session     *session,
                              int32_t              stream_id,
                              uint8_t             *buf,
                              size_t               length,
                              uint32_t            *data_flags,
                              nghttp2_data_source *source,
                              void                *user_data)
{
        SoupMessageIOHTTP2 *msg_io;
        gsize bytes_written = 0;
        SoupMessageBody *response_body = (SoupMessageBody *)source->ptr;

        msg_io = nghttp2_session_get_stream_user_data (session, stream_id);

        while (bytes_written < length && msg_io->write_offset < response_body->length) {
                gconstpointer data;
                gsize data_length;
                gsize bytes_to_write;

                if (!msg_io->write_chunk)
                        msg_io->write_chunk = soup_message_body_get_chunk (response_body, msg_io->write_offset);

                data = g_bytes_get_data (msg_io->write_chunk, &data_length);
                bytes_to_write = MIN (length - bytes_written, data_length - msg_io->chunk_written);
                memcpy (buf + bytes_written, (uint8_t *)data + msg_io->chunk_written, bytes_to_write);
                bytes_written += bytes_to_write;
                msg_io->chunk_written += bytes_to_write;
                msg_io->write_offset += bytes_to_write;
                soup_server_message_wrote_body_data (msg_io->msg, bytes_to_write);

                if (msg_io->chunk_written == data_length) {
                        soup_message_body_wrote_chunk (response_body, msg_io->write_chunk);
                        g_clear_pointer (&msg_io->write_chunk, g_bytes_unref);
                        soup_server_message_wrote_chunk (msg_io->msg);
                        msg_io->chunk_written = 0;
                }
        }

        if (msg_io->write_offset == response_body->length) {
                soup_server_message_wrote_body (msg_io->msg);
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }

        return bytes_written;
}

#define MAKE_NV(NAME, VALUE, VALUELEN)                                      \
        {                                                                   \
                (uint8_t *)NAME, (uint8_t *)VALUE, strlen (NAME), VALUELEN, \
                    NGHTTP2_NV_FLAG_NONE                                    \
        }

#define MAKE_NV2(NAME, VALUE)                                                     \
        {                                                                         \
                (uint8_t *)NAME, (uint8_t *)VALUE, strlen (NAME), strlen (VALUE), \
                    NGHTTP2_NV_FLAG_NONE                                          \
        }

#define MAKE_NV3(NAME, VALUE, FLAGS)                                              \
        {                                                                         \
                (uint8_t *)NAME, (uint8_t *)VALUE, strlen (NAME), strlen (VALUE), \
                    FLAGS                                                         \
        }

static void
soup_server_message_io_http2_send_response (SoupServerMessageIOHTTP2 *io,
                                            SoupMessageIOHTTP2       *msg_io)
{
        if (msg_io->paused)
                return;

        SoupServerMessage *msg = msg_io->msg;
        GArray *headers = g_array_new (FALSE, FALSE, sizeof (nghttp2_nv));
        guint status_code = soup_server_message_get_status (msg);
        if (status_code == 0) {
                status_code = SOUP_STATUS_INTERNAL_SERVER_ERROR;
                soup_server_message_set_status (msg, status_code, NULL);
        }
        char *status = g_strdup_printf ("%u", status_code);
        const nghttp2_nv status_nv = MAKE_NV2 (":status", status);
        g_array_append_val (headers, status_nv);

        SoupMessageHeaders *response_headers = soup_server_message_get_response_headers (msg);
        if (status_code == SOUP_STATUS_NO_CONTENT || SOUP_STATUS_IS_INFORMATIONAL (status_code)) {
                soup_message_headers_remove (response_headers, "Content-Length");
        } else if (!soup_message_headers_get_content_length (response_headers)) {
                SoupMessageBody *response_body;

                response_body = soup_server_message_get_response_body (msg);
                soup_message_headers_set_content_length (response_headers, response_body->length);
        }

        SoupMessageHeadersIter iter;
        const char *name, *value;
        soup_message_headers_iter_init (&iter, response_headers);
        while (soup_message_headers_iter_next (&iter, &name, &value)) {
                const nghttp2_nv nv = MAKE_NV2 (name, value);
                g_array_append_val (headers, nv);
        }

        advance_state_from (msg_io, STATE_READ_DONE, STATE_WRITE_HEADERS);

        nghttp2_data_provider data_provider;
        data_provider.source.ptr = soup_server_message_get_response_body (msg);
        data_provider.read_callback = on_data_source_read_callback;
        nghttp2_submit_response (io->session, msg_io->stream_id, (const nghttp2_nv *)headers->data, headers->len, &data_provider);
        io_try_write (io);
        g_array_free (headers, TRUE);
        g_free (status);
}

static int
on_frame_recv_callback (nghttp2_session     *session,
                        const nghttp2_frame *frame,
                        void                *user_data)
{
        SoupServerMessageIOHTTP2 *io = (SoupServerMessageIOHTTP2 *)user_data;
        SoupMessageIOHTTP2 *msg_io;

        msg_io = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
        if (!msg_io)
                return 0;

        switch (frame->hd.type) {
        case NGHTTP2_HEADERS: {
                char *uri_string;
                GUri *uri;

                uri_string = g_strdup_printf ("%s://%s%s", msg_io->scheme, msg_io->authority, msg_io->path);
                uri = g_uri_parse (uri_string, SOUP_HTTP_URI_FLAGS, NULL);
                g_free (uri_string);
                soup_server_message_set_uri (msg_io->msg, uri);
                g_uri_unref (uri);

                advance_state_from (msg_io, STATE_READ_HEADERS, STATE_READ_DATA);
                soup_server_message_got_headers (msg_io->msg);
                break;
        }
        case NGHTTP2_DATA:
                break;
        default:
                return 0;
        }

        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                advance_state_from (msg_io, STATE_READ_DATA, STATE_READ_DONE);
                soup_server_message_got_body (msg_io->msg);
                soup_server_message_io_http2_send_response (io, msg_io);
        }

        return 0;
}

static int
on_frame_send_callback (nghttp2_session     *session,
                        const nghttp2_frame *frame,
                        void                *user_data)
{
        SoupMessageIOHTTP2 *msg_io;

        msg_io = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);

        switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
                if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
                        advance_state_from (msg_io, STATE_WRITE_HEADERS, STATE_WRITE_DATA);
                        soup_server_message_wrote_headers (msg_io->msg);
                }
                break;
        case NGHTTP2_DATA:
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                        advance_state_from (msg_io, STATE_WRITE_DATA, STATE_WRITE_DONE);
                        soup_server_message_wrote_body (msg_io->msg);
                }
                break;
        default:
                break;
        }

        return 0;
}

static int
on_stream_close_callback (nghttp2_session *session,
                          int32_t          stream_id,
                          uint32_t         error_code,
                          void            *user_data)
{
        SoupMessageIOHTTP2 *msg_io;

        msg_io = nghttp2_session_get_stream_user_data (session, stream_id);
        if (!msg_io)
                return 0;

        if (!msg_io->paused)
                soup_server_message_finish (msg_io->msg);

        return 0;
}

static void
soup_server_message_io_http2_init (SoupServerMessageIOHTTP2 *io)
{
        nghttp2_session_callbacks *callbacks;

        nghttp2_session_callbacks_new (&callbacks);
        nghttp2_session_callbacks_set_on_begin_headers_callback (callbacks, on_begin_headers_callback);
        nghttp2_session_callbacks_set_on_header_callback (callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback (callbacks, on_data_chunk_recv_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_frame_send_callback (callbacks, on_frame_send_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback (callbacks, on_stream_close_callback);

        nghttp2_session_server_new (&io->session, callbacks, io);
        nghttp2_session_callbacks_del (callbacks);
}

SoupServerMessageIO *
soup_server_message_io_http2_new (SoupServerConnection  *conn,
                                  SoupServerMessage     *msg,
                                  SoupMessageIOStartedFn started_cb,
                                  gpointer               user_data)
{
        SoupServerMessageIOHTTP2 *io;

        io = g_new0 (SoupServerMessageIOHTTP2, 1);
        io->conn = conn;
        io->iostream = g_object_ref (soup_server_connection_get_iostream (io->conn));
        io->istream = g_io_stream_get_input_stream (io->iostream);
        io->ostream = g_io_stream_get_output_stream (io->iostream);

        io->started_cb = started_cb;
        io->started_user_data = user_data;

        soup_server_message_io_http2_init (io);

        io->read_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (io->istream), NULL);
        g_source_set_name (io->read_source, "Soup server HTTP/2 read source");
        g_source_set_callback (io->read_source, (GSourceFunc)io_read_ready, io, NULL);
        g_source_attach (io->read_source, g_main_context_get_thread_default ());

        io->iface.funcs = &io_funcs;

        io->messages = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)soup_message_io_http2_free);
        g_hash_table_insert (io->messages, msg, soup_message_io_http2_new (msg));
        soup_server_message_set_http_version (msg, SOUP_HTTP_2_0);

        const nghttp2_settings_entry settings[] = {
                { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
                { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 }
        };
        nghttp2_submit_settings (io->session, NGHTTP2_FLAG_NONE, settings, G_N_ELEMENTS (settings));
        io_try_write (io);

        return (SoupServerMessageIO *)io;
}