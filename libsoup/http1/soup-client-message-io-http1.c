/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-message-io.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#ifdef HAVE_SYSPROF
#include <sysprof-capture.h>
#endif

#include "soup-client-message-io-http1.h"
#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-client-input-stream.h"
#include "soup-connection.h"
#include "soup-session-private.h"
#include "soup-filter-input-stream.h"
#include "soup-logger-private.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-message-metrics-private.h"
#include "soup-message-queue-item.h"
#include "soup-misc.h"
#include "soup-uri-utils-private.h"

typedef struct {
        SoupMessageIOData base;

        SoupMessageQueueItem *item;

        gint64 response_header_bytes_received;
        SoupMessageMetrics *metrics;

        /* Request body logger */
        SoupLogger *logger;

#ifdef HAVE_SYSPROF
        gint64 begin_time_nsec;
#endif
} SoupMessageIOHTTP1;

typedef struct {
        SoupClientMessageIO iface;

        GIOStream *iostream;
        GInputStream *istream;
        GOutputStream *ostream;

        SoupMessageIOHTTP1 *msg_io;
        gboolean is_reusable;
        gboolean ever_used;
} SoupClientMessageIOHTTP1;

#define RESPONSE_BLOCK_SIZE 8192
#define HEADER_SIZE_LIMIT (100 * 1024)

static void
soup_message_io_http1_free (SoupMessageIOHTTP1 *msg_io)
{
        soup_message_io_data_cleanup (&msg_io->base);
        soup_message_queue_item_unref (msg_io->item);
        g_free (msg_io);
}

static void
soup_client_message_io_http1_destroy (SoupClientMessageIO *iface)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        g_clear_object (&io->iostream);
        g_clear_pointer (&io->msg_io, soup_message_io_http1_free);

        g_slice_free (SoupClientMessageIOHTTP1, io);
}

static int
soup_client_message_io_http1_get_priority (SoupClientMessageIOHTTP1 *io)
{
        if (!io->msg_io->item->task)
                return G_PRIORITY_DEFAULT;

        return g_task_get_priority (io->msg_io->item->task);
}

static void
soup_client_message_io_complete (SoupClientMessageIOHTTP1 *io,
                                 SoupMessage *msg,
                                 SoupMessageIOCompletion completion)
{
        SoupMessageIOCompletionFn completion_cb;
        gpointer completion_data;

        completion_cb = io->msg_io->base.completion_cb;
        completion_data = io->msg_io->base.completion_data;

        g_object_ref (msg);
        if (io->istream)
                g_signal_handlers_disconnect_by_data (io->istream, msg);
        if (io->msg_io->base.body_ostream)
                g_signal_handlers_disconnect_by_data (io->msg_io->base.body_ostream, msg);
        g_clear_pointer (&io->msg_io, soup_message_io_http1_free);
        if (completion_cb)
                completion_cb (G_OBJECT (msg), completion, completion_data);
        g_object_unref (msg);
}

static void
soup_client_message_io_http1_finished (SoupClientMessageIO *iface,
                                       SoupMessage         *msg)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        SoupMessageIOCompletion completion;

        if ((io->msg_io->base.read_state >= SOUP_MESSAGE_IO_STATE_FINISHING &&
             io->msg_io->base.write_state >= SOUP_MESSAGE_IO_STATE_FINISHING))
                completion = SOUP_MESSAGE_IO_COMPLETE;
        else
                completion = SOUP_MESSAGE_IO_INTERRUPTED;

        soup_client_message_io_complete (io, msg, completion);
}

static void
soup_client_message_io_http1_stolen (SoupClientMessageIO *iface)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        soup_client_message_io_complete (io, io->msg_io->item->msg, SOUP_MESSAGE_IO_STOLEN);
}

static void
request_body_stream_wrote_data_cb (SoupMessage *msg,
                                   const void  *buffer,
                                   guint        count,
                                   gboolean     is_metadata)
{
        SoupClientMessageIOHTTP1 *client_io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);

        if (client_io->msg_io->metrics) {
                client_io->msg_io->metrics->request_body_bytes_sent += count;
                if (!is_metadata)
                        client_io->msg_io->metrics->request_body_size += count;
        }

        if (!is_metadata) {
                if (client_io->msg_io->logger)
                        soup_logger_log_request_data (client_io->msg_io->logger, msg, (const char *)buffer, count);
                soup_message_wrote_body_data (msg, count);
        }
}

static void
request_body_stream_wrote_cb (GOutputStream *ostream,
                              GAsyncResult  *result,
                              SoupMessage   *msg)
{
        SoupClientMessageIOHTTP1 *io;
        gssize nwrote;
        GCancellable *async_wait;
        GError *error = NULL;

        nwrote = g_output_stream_splice_finish (ostream, result, &error);

        io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);
        if (!io || !io->msg_io || !io->msg_io->base.async_wait || io->msg_io->base.body_ostream != ostream) {
                g_clear_error (&error);
                g_object_unref (msg);
                return;
        }

        if (nwrote != -1)
                io->msg_io->base.write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;

        if (error)
                g_propagate_error (&io->msg_io->base.async_error, error);
        async_wait = io->msg_io->base.async_wait;
        io->msg_io->base.async_wait = NULL;
        g_cancellable_cancel (async_wait);
        g_object_unref (async_wait);

        g_object_unref (msg);
}

static void
closed_async (GObject      *source,
              GAsyncResult *result,
              gpointer      user_data)
{
        GOutputStream *body_ostream = G_OUTPUT_STREAM (source);
        SoupMessage *msg = user_data;
        SoupClientMessageIOHTTP1 *io;
        GCancellable *async_wait;

        io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);
        if (!io || !io->msg_io || !io->msg_io->base.async_wait || io->msg_io->base.body_ostream != body_ostream) {
                g_object_unref (msg);
                return;
        }

        g_output_stream_close_finish (body_ostream, result, &io->msg_io->base.async_error);
        g_clear_object (&io->msg_io->base.body_ostream);

        async_wait = io->msg_io->base.async_wait;
        io->msg_io->base.async_wait = NULL;
        g_cancellable_cancel (async_wait);
        g_object_unref (async_wait);

        g_object_unref (msg);
}

/*
 * There are two request/response formats: the basic request/response,
 * possibly with one or more unsolicited informational responses (such
 * as the WebDAV "102 Processing" response):
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BODY     / R:NOT_STARTED    ->  R:BODY     / W:NOT_STARTED
 *     [W:DONE     / R:HEADERS (1xx)  <-  R:DONE     / W:HEADERS (1xx) ...]
 *      W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 *     
 * and the "Expect: 100-continue" request/response, with the client
 * blocking halfway through its request, and then either continuing or
 * aborting, depending on the server response:
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BLOCKING / R:HEADERS        <-  R:BLOCKING / W:HEADERS
 *     [W:BODY     / R:BLOCKING       ->  R:BODY     / W:BLOCKING]
 *     [W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS]
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 */

static void
write_headers (SoupMessage  *msg,
               GString      *header,
               SoupEncoding *encoding)
{
        GUri *uri = soup_message_get_uri (msg);
        char *uri_string;
        SoupMessageHeadersIter iter;
        const char *name, *value;

        if (soup_message_get_method (msg) == SOUP_METHOD_CONNECT) {
                char *uri_host = soup_uri_get_host_for_headers (uri);

                /* CONNECT URI is hostname:port for tunnel destination */
                uri_string = g_strdup_printf ("%s:%d", uri_host, g_uri_get_port (uri));
                g_free (uri_host);
        } else {
                SoupConnection *conn = soup_message_get_connection (msg);
                gboolean proxy = soup_connection_is_via_proxy (conn);

                g_object_unref (conn);

                /* Proxy expects full URI to destination. Otherwise
                 * just the path.
                 */
                if (proxy)
                        uri_string = g_uri_to_string (uri);
                else if (soup_message_get_is_options_ping (msg))
                        uri_string = g_strdup ("*");
                else
                        uri_string = soup_uri_get_path_and_query (uri);

                if (proxy && g_uri_get_fragment (uri)) {
                        /* Strip fragment */
                        char *fragment = strchr (uri_string, '#');
                        if (fragment)
                                *fragment = '\0';
                }
        }

        g_string_append_printf (header, "%s %s HTTP/1.%d\r\n",
                                soup_message_get_method (msg), uri_string,
                                (soup_message_get_http_version (msg) == SOUP_HTTP_1_0) ? 0 : 1);
        g_free (uri_string);

        *encoding = soup_message_headers_get_encoding (soup_message_get_request_headers (msg));

        soup_message_headers_iter_init (&iter, soup_message_get_request_headers (msg));
        while (soup_message_headers_iter_next (&iter, &name, &value))
                g_string_append_printf (header, "%s: %s\r\n", name, value);
        g_string_append (header, "\r\n");
}

/* Attempts to push forward the writing side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not writable, write is complete, etc).
 */
static gboolean
io_write (SoupClientMessageIOHTTP1 *client_io,
          gboolean                  blocking,
          GCancellable             *cancellable,
          GError                  **error)
{
        SoupMessageIOData *io = &client_io->msg_io->base;
        SoupMessage *msg = client_io->msg_io->item->msg;
        SoupSessionFeature *logger;
        gssize nwrote;

        if (io->async_error) {
                g_propagate_error (error, io->async_error);
                io->async_error = NULL;
                return FALSE;
        } else if (io->async_wait) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_WOULD_BLOCK,
                                     _("Operation would block"));
                return FALSE;
        }

        switch (io->write_state) {
        case SOUP_MESSAGE_IO_STATE_HEADERS:
                if (!io->write_buf->len)
                        write_headers (msg, io->write_buf, &io->write_encoding);

                while (io->written < io->write_buf->len) {
                        nwrote = g_pollable_stream_write (client_io->ostream,
                                                          io->write_buf->str + io->written,
                                                          io->write_buf->len - io->written,
                                                          blocking,
                                                          cancellable, error);
                        if (nwrote == -1)
                                return FALSE;
                        io->written += nwrote;
                        if (client_io->msg_io->metrics)
                                client_io->msg_io->metrics->request_header_bytes_sent += nwrote;
                }

                io->written = 0;
                g_string_truncate (io->write_buf, 0);

                if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH)
                        io->write_length = soup_message_headers_get_content_length (soup_message_get_request_headers (msg));

                if (soup_message_headers_get_expectations (soup_message_get_request_headers (msg)) & SOUP_EXPECTATION_CONTINUE) {
                        /* Need to wait for the Continue response */
                        io->write_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
                        io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
                } else
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_START;

                soup_message_wrote_headers (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                io->body_ostream = soup_body_output_stream_new (client_io->ostream,
                                                                io->write_encoding,
                                                                io->write_length);
                io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
                logger = soup_session_get_feature_for_message (client_io->msg_io->item->session,
                                                               SOUP_TYPE_LOGGER, msg);
                client_io->msg_io->logger = logger ? SOUP_LOGGER (logger) : NULL;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY:
                if (!io->write_length &&
                    io->write_encoding != SOUP_ENCODING_EOF &&
                    io->write_encoding != SOUP_ENCODING_CHUNKED) {
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                        break;
                }

                if (soup_message_get_request_body_stream (msg)) {
                        g_signal_connect_object (io->body_ostream,
                                                 "wrote-data",
                                                 G_CALLBACK (request_body_stream_wrote_data_cb),
                                                 msg, G_CONNECT_SWAPPED);
                        if (blocking) {
                                nwrote = g_output_stream_splice (io->body_ostream,
                                                                 soup_message_get_request_body_stream (msg),
                                                                 G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
                                                                 cancellable,
                                                                 error);
                                if (nwrote == -1)
                                        return FALSE;
                                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                                break;
                        } else {
                                io->async_wait = g_cancellable_new ();
                                g_output_stream_splice_async (io->body_ostream,
                                                              soup_message_get_request_body_stream (msg),
                                                              G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE,
                                                              soup_client_message_io_http1_get_priority (client_io),
                                                              cancellable,
                                                              (GAsyncReadyCallback)request_body_stream_wrote_cb,
                                                              g_object_ref (msg));
                                return FALSE;
                        }
                } else
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_FLUSH:
                if (io->body_ostream) {
                        if (blocking || io->write_encoding != SOUP_ENCODING_CHUNKED) {
                                if (!g_output_stream_close (io->body_ostream, cancellable, error))
                                        return FALSE;
                                g_clear_object (&io->body_ostream);
                        } else {
                                io->async_wait = g_cancellable_new ();
                                g_output_stream_close_async (io->body_ostream,
                                                             soup_client_message_io_http1_get_priority (client_io),
                                                             cancellable,
                                                             closed_async, g_object_ref (msg));
                        }
                }

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_DONE:
                io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                soup_message_wrote_body (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_FINISHING:
                io->write_state = SOUP_MESSAGE_IO_STATE_DONE;
                io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
                break;

        default:
                g_return_val_if_reached (FALSE);
        }

        return TRUE;
}

static gboolean
parse_headers (SoupMessage  *msg,
               char         *headers,
               guint         headers_len,
               SoupEncoding *encoding,
               GError      **error)
{
        SoupHTTPVersion version;
        char *reason_phrase;
        SoupStatus status;

        soup_message_set_reason_phrase (msg, NULL);

        if (!soup_headers_parse_response (headers, headers_len,
                                          soup_message_get_response_headers (msg),
                                          &version,
                                          &status,
                                          &reason_phrase)) {
                g_set_error_literal (error, SOUP_SESSION_ERROR,
                                     SOUP_SESSION_ERROR_PARSING,
                                     _("Could not parse HTTP response"));
                return FALSE;
        }

        soup_message_set_status (msg, status, reason_phrase);
        g_free (reason_phrase);

        if (version < soup_message_get_http_version (msg))
                soup_message_set_http_version (msg, version);

        if ((soup_message_get_method (msg) == SOUP_METHOD_HEAD ||
             soup_message_get_status (msg)  == SOUP_STATUS_NO_CONTENT ||
             soup_message_get_status (msg)  == SOUP_STATUS_NOT_MODIFIED ||
             SOUP_STATUS_IS_INFORMATIONAL (soup_message_get_status (msg))) ||
            (soup_message_get_method (msg) == SOUP_METHOD_CONNECT &&
             SOUP_STATUS_IS_SUCCESSFUL (soup_message_get_status (msg))))
                *encoding = SOUP_ENCODING_NONE;
        else
                *encoding = soup_message_headers_get_encoding (soup_message_get_response_headers (msg));

        if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
                g_set_error_literal (error, SOUP_SESSION_ERROR,
                                     SOUP_SESSION_ERROR_ENCODING,
                                     _("Unrecognized HTTP response encoding"));
                return FALSE;
        }

        return TRUE;
}

static void
response_network_stream_read_data_cb (SoupMessage *msg,
                                      guint        count)
{
        SoupClientMessageIOHTTP1 *client_io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);

        if (client_io->msg_io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY_START) {
                client_io->msg_io->response_header_bytes_received += count;
                if (client_io->msg_io->metrics)
                        client_io->msg_io->metrics->response_header_bytes_received += count;
                return;
        }

        if (client_io->msg_io->metrics)
                client_io->msg_io->metrics->response_body_bytes_received += count;

        soup_message_got_body_data (msg, count);
}

/* Attempts to push forward the reading side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not readable, read is complete, etc).
 */
static gboolean
io_read (SoupClientMessageIOHTTP1 *client_io,
         gboolean                  blocking,
         GCancellable             *cancellable,
         GError                  **error)
{
        SoupMessageIOData *io = &client_io->msg_io->base;
        SoupMessage *msg = client_io->msg_io->item->msg;
        gboolean succeeded;
        gboolean is_first_read;
        gushort extra_bytes;
        gsize response_body_bytes_received = 0;

        switch (io->read_state) {
        case SOUP_MESSAGE_IO_STATE_HEADERS:
                is_first_read = io->read_header_buf->len == 0 &&
                        soup_message_get_status (msg) == SOUP_STATUS_NONE;

                succeeded = soup_message_io_data_read_headers (io, SOUP_FILTER_INPUT_STREAM (client_io->istream),
                                                               blocking, cancellable, &extra_bytes, error);
                if (is_first_read && io->read_header_buf->len > 0)
                        soup_message_set_metrics_timestamp (msg, SOUP_MESSAGE_METRICS_RESPONSE_START);
                if (!succeeded)
                        return FALSE;

                /* Adjust the header and body bytes received, since we might
                 * have read part of the body already that is queued by the stream.
                 */
                if (client_io->msg_io->response_header_bytes_received > io->read_header_buf->len + extra_bytes) {
                        response_body_bytes_received = client_io->msg_io->response_header_bytes_received - io->read_header_buf->len - extra_bytes;
                        if (client_io->msg_io->metrics) {
                                client_io->msg_io->metrics->response_body_bytes_received = response_body_bytes_received;
                                client_io->msg_io->metrics->response_header_bytes_received -= response_body_bytes_received;
                        }
                }
                client_io->msg_io->response_header_bytes_received = 0;

                succeeded = parse_headers (msg,
                                           (char *)io->read_header_buf->data,
                                           io->read_header_buf->len,
                                           &io->read_encoding,
                                           error);
                g_byte_array_set_size (io->read_header_buf, 0);

                if (!succeeded) {
                        /* Either we couldn't parse the headers, or they
                         * indicated something that would mean we wouldn't
                         * be able to parse the body. (Eg, unknown
                         * Transfer-Encoding.). Skip the rest of the
                         * reading, and make sure the connection gets
                         * closed when we're done.
                         */
                        soup_message_headers_append_common (soup_message_get_request_headers (msg),
                                                            SOUP_HEADER_CONNECTION, "close");
                        soup_message_set_metrics_timestamp (msg, SOUP_MESSAGE_METRICS_RESPONSE_END);
                        io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                        break;
                }

                if (SOUP_STATUS_IS_INFORMATIONAL (soup_message_get_status (msg))) {
                        if (soup_message_get_status (msg) == SOUP_STATUS_CONTINUE &&
                            io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING) {
                                /* Pause the reader, unpause the writer */
                                io->read_state =
                                        SOUP_MESSAGE_IO_STATE_BLOCKING;
                                io->write_state =
                                        SOUP_MESSAGE_IO_STATE_BODY_START;
                        } else {
                                /* Just stay in HEADERS */
                                io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
                        }

                        /* Informational responses have no bodies, so
                         * bail out here rather than parsing encoding, etc
                         */
                        soup_message_got_informational (msg);

                        /* If this was "101 Switching Protocols", then
                         * the session may have stolen the connection...
                         */
                        if (client_io != (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg))
                                return FALSE;

                        soup_message_cleanup_response (msg);
                        break;
                } else {
                        io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;

                        /* If the client was waiting for a Continue
                         * but got something else, then it's done
                         * writing.
                         */
                        if (io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
                                io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                }

                if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
                        io->read_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));

                        if (!soup_message_is_keepalive (msg)) {
                                /* Some servers suck and send
                                 * incorrect Content-Length values, so
                                 * allow EOF termination in this case
                                 * (iff the message is too short) too.
                                 */
                                io->read_encoding = SOUP_ENCODING_EOF;
                        }
                } else
                        io->read_length = -1;

                soup_message_got_headers (msg);

                if (response_body_bytes_received > 0)
                        soup_message_got_body_data (msg, response_body_bytes_received);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                if (!io->body_istream) {
                        GInputStream *body_istream = soup_body_input_stream_new (client_io->istream,
                                                                                 io->read_encoding,
                                                                                 io->read_length);

                        io->body_istream = soup_session_setup_message_body_input_stream (client_io->msg_io->item->session,
                                                                                         msg, body_istream,
                                                                                         SOUP_STAGE_MESSAGE_BODY);
                        g_object_unref (body_istream);
                }

                if (!soup_message_try_sniff_content (msg, io->body_istream, blocking, cancellable, error))
                        return FALSE;

                io->read_state = SOUP_MESSAGE_IO_STATE_BODY;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY: {
                guchar buf[RESPONSE_BLOCK_SIZE];
                gssize nread;

                nread = g_pollable_stream_read (io->body_istream,
                                                buf,
                                                RESPONSE_BLOCK_SIZE,
                                                blocking,
                                                cancellable, error);
                if (nread == -1)
                        return FALSE;

                if (nread == 0)
                        io->read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;

                if (client_io->msg_io->metrics)
                        client_io->msg_io->metrics->response_body_size += nread;

                break;
        }

        case SOUP_MESSAGE_IO_STATE_BODY_DONE:
                io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                soup_message_set_metrics_timestamp (msg, SOUP_MESSAGE_METRICS_RESPONSE_END);
                client_io->is_reusable = soup_message_is_keepalive (msg);
                client_io->ever_used = TRUE;
                soup_message_got_body (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_FINISHING:
                io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
                break;

        default:
                g_return_val_if_reached (FALSE);
        }

        return TRUE;
}

static gboolean
request_is_restartable (SoupMessage *msg, GError *error)
{
        SoupClientMessageIOHTTP1 *client_io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);
        SoupMessageIOData *io;

        if (!client_io || !client_io->msg_io)
                return FALSE;

        io = &client_io->msg_io->base;

        return (io->read_state <= SOUP_MESSAGE_IO_STATE_HEADERS &&
                io->read_header_buf->len == 0 &&
                client_io->ever_used &&
                !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT) &&
                !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) &&
                !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
                error->domain != G_TLS_ERROR &&
                SOUP_METHOD_IS_IDEMPOTENT (soup_message_get_method (msg)));
}

static gboolean
io_run_until (SoupClientMessageIOHTTP1 *client_io,
              gboolean                  blocking,
              SoupMessageIOState        read_state,
              SoupMessageIOState        write_state,
              GCancellable             *cancellable,
              GError                  **error)
{
        SoupMessageIOData *io;
        SoupMessage *msg;
        gboolean progress = TRUE, done;
        GError *my_error = NULL;

        g_assert (client_io); // Silence clang static analysis
        io = &client_io->msg_io->base;

        if (g_cancellable_set_error_if_cancelled (cancellable, error))
                return FALSE;
        else if (!io) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_CANCELLED,
                                     _("Operation was cancelled"));
                return FALSE;
        }

        msg = client_io->msg_io->item->msg;
        g_object_ref (msg);

        while (progress && (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg) == client_io &&
               !io->paused && !io->async_wait &&
               (io->read_state < read_state || io->write_state < write_state)) {

                if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->read_state))
                        progress = io_read (client_io, blocking, cancellable, &my_error);
                else if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->write_state))
                        progress = io_write (client_io, blocking, cancellable, &my_error);
                else
                        progress = FALSE;
        }

        if (my_error) {
                g_propagate_error (error, my_error);
                g_object_unref (msg);
                return FALSE;
        } else if ((SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg) != client_io) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_CANCELLED,
                                     _("Operation was cancelled"));
                g_object_unref (msg);
                return FALSE;
        } else if (!io->async_wait &&
                   g_cancellable_set_error_if_cancelled (cancellable, error)) {
                g_object_unref (msg);
                return FALSE;
        }

        done = (io->read_state >= read_state &&
                io->write_state >= write_state);

        if (!blocking && !done) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_WOULD_BLOCK,
                                     _("Operation would block"));
                g_object_unref (msg);
                return FALSE;
        }

#ifdef HAVE_SYSPROF
        /* Allow profiling of network requests. */
        if (io->read_state == SOUP_MESSAGE_IO_STATE_DONE &&
            io->write_state == SOUP_MESSAGE_IO_STATE_DONE) {
                GUri *uri = soup_message_get_uri (msg);
                char *uri_str = g_uri_to_string_partial (uri, G_URI_HIDE_PASSWORD);
                const gchar *last_modified = soup_message_headers_get_one_common (soup_message_get_response_headers (msg), SOUP_HEADER_LAST_MODIFIED);
                const gchar *etag = soup_message_headers_get_one_common (soup_message_get_response_headers (msg), SOUP_HEADER_ETAG);
                const gchar *if_modified_since = soup_message_headers_get_one_common (soup_message_get_request_headers (msg), SOUP_HEADER_IF_MODIFIED_SINCE);
                const gchar *if_none_match = soup_message_headers_get_one_common (soup_message_get_request_headers (msg), SOUP_HEADER_IF_NONE_MATCH);

                /* FIXME: Expand and generalise sysprof support:
                 * https://gitlab.gnome.org/GNOME/sysprof/-/issues/43 */
                sysprof_collector_mark_printf (client_io->msg_io->begin_time_nsec,
                                               SYSPROF_CAPTURE_CURRENT_TIME - client_io->msg_io->begin_time_nsec,
                                               "libsoup", "message",
                                               "%s request/response to %s: "
                                               "read %" G_GOFFSET_FORMAT "B, "
                                               "wrote %" G_GOFFSET_FORMAT "B, "
                                               "If-Modified-Since: %s, "
                                               "If-None-Match: %s, "
                                               "Last-Modified: %s, "
                                               "ETag: %s",
                                               soup_message_get_tls_peer_certificate (msg) ? "HTTPS" : "HTTP",
                                               uri_str, io->read_length, io->write_length,
                                               (if_modified_since != NULL) ? if_modified_since : "(unset)",
                                               (if_none_match != NULL) ? if_none_match : "(unset)",
                                               (last_modified != NULL) ? last_modified : "(unset)",
                                               (etag != NULL) ? etag : "(unset)");
                g_free (uri_str);
        }
#endif  /* HAVE_SYSPROF */

        g_object_unref (msg);
        return done;
}

static void
soup_message_io_finish (SoupMessage  *msg,
                        GError       *error)
{
        if (request_is_restartable (msg, error)) {
                SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg);

                /* Connection got closed, but we can safely try again. */
                io->msg_io->item->state = SOUP_MESSAGE_RESTARTING;
        } else if (error) {
                soup_message_set_metrics_timestamp (msg, SOUP_MESSAGE_METRICS_RESPONSE_END);
        }

        soup_message_io_finished (msg);
}

static void soup_client_message_io_http1_run (SoupClientMessageIO *iface, SoupMessage *msg, gboolean blocking);

static gboolean
io_run_ready (SoupMessage *msg, gpointer user_data)
{
        soup_client_message_io_http1_run (soup_message_get_io_data (msg), msg, FALSE);
        return FALSE;
}

static void
soup_client_message_io_http1_run (SoupClientMessageIO *iface,
                                  SoupMessage         *msg,
                                  gboolean             blocking)
{
        SoupClientMessageIOHTTP1 *client_io = (SoupClientMessageIOHTTP1 *)iface;
        SoupMessageIOData *io = &client_io->msg_io->base;
        GError *error = NULL;

        if (io->io_source) {
                g_source_destroy (io->io_source);
                g_source_unref (io->io_source);
                io->io_source = NULL;
        }

        g_object_ref (msg);

        if (io_run_until (client_io, blocking,
                          SOUP_MESSAGE_IO_STATE_DONE,
                          SOUP_MESSAGE_IO_STATE_DONE,
                          client_io->msg_io->item->cancellable, &error)) {
                soup_message_io_finished (msg);
        } else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error (&error);
                io->io_source = soup_message_io_data_get_source (io, G_OBJECT (msg),
                                                                 client_io->istream,
                                                                 client_io->ostream,
                                                                 client_io->msg_io->item->cancellable,
                                                                 (SoupMessageIOSourceFunc)io_run_ready,
                                                                 NULL);
                g_source_set_priority (io->io_source,
                                       soup_client_message_io_http1_get_priority (client_io));
                g_source_attach (io->io_source, g_main_context_get_thread_default ());
        } else {
                if ((SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg) == client_io) {
                        g_assert (!client_io->msg_io->item->error);
                        client_io->msg_io->item->error = g_steal_pointer (&error);
                        soup_message_io_finish (msg, client_io->msg_io->item->error);
                }
                g_clear_error (&error);

        }

        g_object_unref (msg);
}

static gboolean
soup_client_message_io_http1_run_until_read (SoupClientMessageIO *iface,
                                             SoupMessage         *msg,
                                             GCancellable        *cancellable,
                                             GError             **error)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        if (io_run_until (io, TRUE,
                          SOUP_MESSAGE_IO_STATE_BODY,
                          SOUP_MESSAGE_IO_STATE_ANY,
                          cancellable, error))
                return TRUE;

        if ((SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg) == io)
                soup_message_io_finish (msg, *error);

        return FALSE;
}

static void io_run_until_read_async (SoupClientMessageIOHTTP1 *io, GTask *task);

static gboolean
io_run_until_read_ready (SoupMessage *msg,
                         gpointer     user_data)
{
        GTask *task = user_data;

        io_run_until_read_async ((SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg), task);
        return FALSE;
}

static void
io_run_until_read_async (SoupClientMessageIOHTTP1 *client_io,
                         GTask                    *task)
{
        SoupMessageIOData *io = &client_io->msg_io->base;
        SoupMessage *msg = client_io->msg_io->item->msg;
        GError *error = NULL;

        if (io->io_source) {
                g_source_destroy (io->io_source);
                g_source_unref (io->io_source);
                io->io_source = NULL;
        }

        if (io_run_until (client_io, FALSE,
                          SOUP_MESSAGE_IO_STATE_BODY,
                          SOUP_MESSAGE_IO_STATE_ANY,
                          g_task_get_cancellable (task),
                          &error)) {
                g_task_return_boolean (task, TRUE);
                g_object_unref (task);
                return;
        }

        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_error_free (error);
                io->io_source = soup_message_io_data_get_source (io, G_OBJECT (msg),
                                                                 client_io->istream,
                                                                 client_io->ostream,
                                                                 g_task_get_cancellable (task),
                                                                 (SoupMessageIOSourceFunc)io_run_until_read_ready,
                                                                 task);
                g_source_set_priority (io->io_source, g_task_get_priority (task));
                g_source_attach (io->io_source, g_main_context_get_thread_default ());
                return;
        }

        if ((SoupClientMessageIOHTTP1 *)soup_message_get_io_data (msg) == client_io)
                soup_message_io_finish (msg, error);

        g_task_return_error (task, error);
        g_object_unref (task);
}

static void
soup_client_message_io_http1_run_until_read_async (SoupClientMessageIO *iface,
                                                   SoupMessage         *msg,
                                                   int                  io_priority,
                                                   GCancellable        *cancellable,
                                                   GAsyncReadyCallback  callback,
                                                   gpointer             user_data)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        GTask *task;

        task = g_task_new (msg, cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_client_message_io_http1_run_until_read_async);
        g_task_set_priority (task, io_priority);
        io_run_until_read_async (io, task);
}

static gboolean
soup_client_message_io_http1_close_async (SoupClientMessageIO *io,
                                          SoupConnection      *conn,
                                          GAsyncReadyCallback  callback)
{
        return FALSE;
}

static gboolean
soup_client_message_io_http1_skip (SoupClientMessageIO *iface,
                                   SoupMessage         *msg,
                                   gboolean             blocking,
                                   GCancellable        *cancellable,
                                   GError             **error)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        gboolean success;

        g_object_ref (msg);

        if (io && io->msg_io) {
                if (io->msg_io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY_DONE)
                        io->msg_io->base.read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
        }

        success = io_run_until (io, blocking,
                                SOUP_MESSAGE_IO_STATE_DONE,
                                SOUP_MESSAGE_IO_STATE_DONE,
                                cancellable, error);

        g_object_unref (msg);
        return success;
}

static void
client_stream_eof (SoupClientInputStream    *stream,
                   SoupClientMessageIOHTTP1 *io)
{
        if (io && io->msg_io && io->msg_io->base.read_state == SOUP_MESSAGE_IO_STATE_BODY)
                io->msg_io->base.read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
}

static GInputStream *
soup_client_message_io_http1_get_response_stream (SoupClientMessageIO *iface,
                                                  SoupMessage         *msg,
                                                  GError             **error)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        GInputStream *client_stream;

        g_assert (io->msg_io && io->msg_io->item->msg == msg);

        client_stream = soup_client_input_stream_new (io->msg_io->base.body_istream, msg);
        g_signal_connect (client_stream, "eof",
                          G_CALLBACK (client_stream_eof), io);

        return client_stream;
}

static void
soup_client_message_io_http1_send_item (SoupClientMessageIO       *iface,
                                        SoupMessageQueueItem      *item,
                                        SoupMessageIOCompletionFn  completion_cb,
                                        gpointer                   user_data)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        SoupMessageIOHTTP1 *msg_io;

        msg_io = g_new0 (SoupMessageIOHTTP1, 1);
        msg_io->item = soup_message_queue_item_ref (item);
        msg_io->base.completion_cb = completion_cb;
        msg_io->base.completion_data = user_data;

        msg_io->base.read_header_buf = g_byte_array_new ();
        msg_io->base.write_buf = g_string_new (NULL);

        msg_io->base.read_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
        msg_io->base.write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
        msg_io->metrics = soup_message_get_metrics (msg_io->item->msg);
        g_signal_connect_object (io->istream, "read-data",
                                 G_CALLBACK (response_network_stream_read_data_cb),
                                 msg_io->item->msg, G_CONNECT_SWAPPED);

#ifdef HAVE_SYSPROF
        msg_io->begin_time_nsec = SYSPROF_CAPTURE_CURRENT_TIME;
#endif
        if (io->msg_io)
                g_warn_if_reached ();

        io->msg_io = msg_io;
        io->is_reusable = FALSE;
}

static void
soup_client_message_io_http1_pause (SoupClientMessageIO *iface,
                                    SoupMessage         *msg)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->item->msg == msg);
        g_assert (io->msg_io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY);

        soup_message_io_data_pause (&io->msg_io->base);
}

static void
soup_client_message_io_http1_unpause (SoupClientMessageIO *iface,
                                      SoupMessage         *msg)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->item->msg == msg);
        g_assert (io->msg_io->base.read_state < SOUP_MESSAGE_IO_STATE_BODY);

        io->msg_io->base.paused = FALSE;
}

static gboolean
soup_client_message_io_http1_is_paused (SoupClientMessageIO *iface,
                                        SoupMessage         *msg)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->item->msg == msg);

        return io->msg_io->base.paused;
}

static gboolean
soup_client_message_io_http1_is_open (SoupClientMessageIO *iface)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;
        char buffer[1];
        GError *error = NULL;

        /* This is tricky. The goal is to check if the socket is readable. If
         * so, that means either the server has disconnected or it's broken (it
         * should not send any data while the connection is in idle state). But
         * we can't just check the readability of the SoupSocket because there
         * could be non-application layer TLS data that is readable, but which
         * we don't want to consider. So instead, just read and see if the read
         * succeeds. This is OK to do here because if the read does succeed, we
         * just disconnect and ignore the data anyway.
         */
        g_pollable_input_stream_read_nonblocking (G_POLLABLE_INPUT_STREAM (io->istream),
                                                  &buffer, sizeof (buffer),
	                                          NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error (&error);
		return FALSE;
        }

        g_error_free (error);

        return TRUE;
}

static gboolean
soup_client_message_io_http1_in_progress (SoupClientMessageIO *iface,
                                          SoupMessage         *msg)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        return io->msg_io != NULL;
}

static gboolean
soup_client_message_io_http1_is_reusable (SoupClientMessageIO *iface)
{
        SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        return io->is_reusable;
}

static GCancellable *
soup_client_message_io_http1_get_cancellable (SoupClientMessageIO *iface,
                                          SoupMessage         *msg)
{
	SoupClientMessageIOHTTP1 *io = (SoupClientMessageIOHTTP1 *)iface;

        return io->msg_io ? io->msg_io->item->cancellable : NULL;
}

static const SoupClientMessageIOFuncs io_funcs = {
        soup_client_message_io_http1_destroy,
        soup_client_message_io_http1_finished,
        soup_client_message_io_http1_stolen,
        soup_client_message_io_http1_send_item,
        soup_client_message_io_http1_get_response_stream,
        soup_client_message_io_http1_pause,
        soup_client_message_io_http1_unpause,
        soup_client_message_io_http1_is_paused,
        soup_client_message_io_http1_run,
        soup_client_message_io_http1_run_until_read,
        soup_client_message_io_http1_run_until_read_async,
        soup_client_message_io_http1_close_async,
        soup_client_message_io_http1_skip,
        soup_client_message_io_http1_is_open,
        soup_client_message_io_http1_in_progress,
        soup_client_message_io_http1_is_reusable,
        soup_client_message_io_http1_get_cancellable
};

SoupClientMessageIO *
soup_client_message_io_http1_new (SoupConnection *conn)
{
        SoupClientMessageIOHTTP1 *io;

        io = g_slice_new0 (SoupClientMessageIOHTTP1);
        io->iostream = g_object_ref (soup_connection_get_iostream (conn));
        io->istream = g_io_stream_get_input_stream (io->iostream);
        io->ostream = g_io_stream_get_output_stream (io->iostream);
        io->is_reusable = TRUE;

        io->iface.funcs = &io_funcs;

        return (SoupClientMessageIO *)io;
}
