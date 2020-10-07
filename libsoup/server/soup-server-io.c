/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server-io.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-filter-input-stream.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-socket-private.h"

#define RESPONSE_BLOCK_SIZE 8192
#define HEADER_SIZE_LIMIT (64 * 1024)

static void
closed_async (GObject      *source,
              GAsyncResult *result,
              gpointer      user_data)
{
        GOutputStream *body_ostream = G_OUTPUT_STREAM (source);
        SoupMessage *msg = user_data;
        SoupMessageIOData *io;
        GCancellable *async_wait;

        io = soup_message_get_io_data (msg);
        if (!io || !io->async_wait || io->body_ostream != body_ostream) {
                g_object_unref (msg);
                return;
        }

        g_output_stream_close_finish (body_ostream, result, &io->async_error);
        g_clear_object (&io->body_ostream);

        async_wait = io->async_wait;
        io->async_wait = NULL;
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
handle_partial_get (SoupMessage *msg)
{
        SoupRange *ranges;
        int nranges;
        GBytes *full_response;
        guint status;

        /* Make sure the message is set up right for us to return a
         * partial response; it has to be a GET, the status must be
         * 200 OK (and in particular, NOT already 206 Partial
         * Content), and the SoupServer must have already filled in
         * the response body
         */
        if (msg->method != SOUP_METHOD_GET ||
            msg->status_code != SOUP_STATUS_OK ||
            soup_message_headers_get_encoding (msg->response_headers) !=
            SOUP_ENCODING_CONTENT_LENGTH ||
            msg->response_body->length == 0 ||
            !soup_message_body_get_accumulate (msg->response_body))
                return;

        /* Oh, and there has to have been a valid Range header on the
         * request, of course.
         */
        status = soup_message_headers_get_ranges_internal (msg->request_headers,
                                                           msg->response_body->length,
                                                           TRUE,
                                                           &ranges, &nranges);
        if (status == SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
                soup_message_set_status (msg, status);
                soup_message_body_truncate (msg->response_body);
                return;
        } else if (status != SOUP_STATUS_PARTIAL_CONTENT)
                return;

        full_response = soup_message_body_flatten (msg->response_body);
        if (!full_response) {
                soup_message_headers_free_ranges (msg->request_headers, ranges);
                return;
        }

        soup_message_set_status (msg, SOUP_STATUS_PARTIAL_CONTENT);
        soup_message_body_truncate (msg->response_body);

        if (nranges == 1) {
                GBytes *range_buf;

                /* Single range, so just set Content-Range and fix the body. */

                soup_message_headers_set_content_range (msg->response_headers,
                                                        ranges[0].start,
                                                        ranges[0].end,
                                                        g_bytes_get_size (full_response));
                range_buf = g_bytes_new_from_bytes (full_response,
                                                    ranges[0].start,
                                                    ranges[0].end - ranges[0].start + 1);
                soup_message_body_append_bytes (msg->response_body, range_buf);
                g_bytes_unref (range_buf);
        } else {
                SoupMultipart *multipart;
                SoupMessageHeaders *part_headers;
                GBytes *part_body;
                GBytes *body = NULL;
                const char *content_type;
                int i;

                /* Multiple ranges, so build a multipart/byteranges response
                 * to replace msg->response_body with.
                 */

                multipart = soup_multipart_new ("multipart/byteranges");
                content_type = soup_message_headers_get_one (msg->response_headers,
                                                             "Content-Type");
                for (i = 0; i < nranges; i++) {
                        part_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
                        if (content_type) {
                                soup_message_headers_append (part_headers,
                                                             "Content-Type",
                                                             content_type);
                        }
                        soup_message_headers_set_content_range (part_headers,
                                                                ranges[i].start,
                                                                ranges[i].end,
                                                                g_bytes_get_size (full_response));
                        part_body = g_bytes_new_from_bytes (full_response,
                                                            ranges[i].start,
                                                            ranges[i].end - ranges[i].start + 1);
                        soup_multipart_append_part (multipart, part_headers,
                                                    part_body);
                        soup_message_headers_free (part_headers);
                        g_bytes_unref (part_body);
                }

                soup_multipart_to_message (multipart, msg->response_headers, &body);
                soup_message_body_append_bytes (msg->response_body, body);
                g_bytes_unref (body);
                soup_multipart_free (multipart);
        }

        g_bytes_unref (full_response);
        soup_message_headers_free_ranges (msg->request_headers, ranges);
}

static void
write_headers (SoupMessage  *msg,
               GString      *headers,
               SoupEncoding *encoding)
{
        SoupEncoding claimed_encoding;
        SoupMessageHeadersIter iter;
        const char *name, *value;

        if (msg->status_code == 0)
                soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);

        handle_partial_get (msg);

        g_string_append_printf (headers, "HTTP/1.%c %d %s\r\n",
                                soup_message_get_http_version (msg) == SOUP_HTTP_1_0 ? '0' : '1',
                                msg->status_code, msg->reason_phrase);

        claimed_encoding = soup_message_headers_get_encoding (msg->response_headers);
        if ((msg->method == SOUP_METHOD_HEAD ||
             msg->status_code  == SOUP_STATUS_NO_CONTENT ||
             msg->status_code  == SOUP_STATUS_NOT_MODIFIED ||
             SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) ||
            (msg->method == SOUP_METHOD_CONNECT &&
             SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)))
                *encoding = SOUP_ENCODING_NONE;
        else
                *encoding = claimed_encoding;

        if (claimed_encoding == SOUP_ENCODING_CONTENT_LENGTH &&
            !soup_message_headers_get_content_length (msg->response_headers)) {
                soup_message_headers_set_content_length (msg->response_headers,
                                                         msg->response_body->length);
        }

        soup_message_headers_iter_init (&iter, msg->response_headers);
        while (soup_message_headers_iter_next (&iter, &name, &value))
                g_string_append_printf (headers, "%s: %s\r\n", name, value);
        g_string_append (headers, "\r\n");
}

/* Attempts to push forward the writing side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not writable, write is complete, etc).
 */
static gboolean
io_write (SoupMessage  *msg,
          GCancellable *cancellable,
          GError      **error)
{
        SoupMessageIOData *io = soup_message_get_io_data (msg);
        GBytes *chunk;
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
                if (io->read_state == SOUP_MESSAGE_IO_STATE_BLOCKING && msg->status_code == 0) {
                        /* Client requested "Expect: 100-continue", and
                         * server did not set an error.
                         */
                        soup_message_set_status (msg, SOUP_STATUS_CONTINUE);
                }

                if (!io->write_buf->len)
                        write_headers (msg, io->write_buf, &io->write_encoding);

                while (io->written < io->write_buf->len) {
                        nwrote = g_pollable_stream_write (io->ostream,
                                                          io->write_buf->str + io->written,
                                                          io->write_buf->len - io->written,
                                                          FALSE,
                                                          cancellable, error);
                        if (nwrote == -1)
                                return FALSE;
                        io->written += nwrote;
                }

                io->written = 0;
                g_string_truncate (io->write_buf, 0);

                if (SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
                        if (msg->status_code == SOUP_STATUS_CONTINUE) {
                                /* Stop and wait for the body now */
                                io->write_state =
                                        SOUP_MESSAGE_IO_STATE_BLOCKING;
                                io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;
                        } else {
                                /* We just wrote a 1xx response
                                 * header, so stay in STATE_HEADERS.
                                 * (The caller will pause us from the
                                 * wrote_informational callback if he
                                 * is not ready to send the final
                                 * response.)
                                 */
                        }

                        soup_message_wrote_informational (msg);

                        /* If this was "101 Switching Protocols", then
                         * the server probably stole the connection...
                         */
                        if (io != soup_message_get_io_data (msg))
                                return FALSE;

                        soup_message_cleanup_response (msg);
                        break;
                }

                if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH)
                        io->write_length = soup_message_headers_get_content_length (msg->response_headers);

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_START;
                /* If the client was waiting for a Continue
                 * but we sent something else, then they're
                 * now done writing.
                 */
                if (io->read_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
                        io->read_state = SOUP_MESSAGE_IO_STATE_DONE;

                soup_message_wrote_headers (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                io->body_ostream = soup_body_output_stream_new (io->ostream,
                                                                io->write_encoding,
                                                                io->write_length);
                io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY:
                if (!io->write_length &&
                    io->write_encoding != SOUP_ENCODING_EOF &&
                    io->write_encoding != SOUP_ENCODING_CHUNKED) {
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                        break;
                }

                if (!io->write_chunk) {
                        io->write_chunk = soup_message_body_get_chunk (msg->response_body, io->write_body_offset);
                        if (!io->write_chunk) {
                                soup_message_io_pause (msg);
                                return FALSE;
                        }
                        if (!g_bytes_get_size (io->write_chunk)) {
                                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                                break;
                        }
                }

                nwrote = g_pollable_stream_write (io->body_ostream,
                                                  (guchar*)g_bytes_get_data (io->write_chunk, NULL) + io->written,
                                                  g_bytes_get_size (io->write_chunk) - io->written,
                                                  FALSE,
                                                  cancellable, error);
                if (nwrote == -1)
                        return FALSE;

                chunk = g_bytes_new_from_bytes (io->write_chunk, io->written, nwrote);
                io->written += nwrote;
                if (io->write_length)
                        io->write_length -= nwrote;

                if (io->written == g_bytes_get_size (io->write_chunk))
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DATA;

                soup_message_wrote_body_data (msg, chunk);
                g_bytes_unref (chunk);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_DATA:
                io->written = 0;
                if (g_bytes_get_size (io->write_chunk) == 0) {
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                        break;
                }

                soup_message_body_wrote_chunk (msg->response_body, io->write_chunk);
                io->write_body_offset += g_bytes_get_size (io->write_chunk);
                g_clear_pointer (&io->write_chunk, g_bytes_unref);

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
                soup_message_wrote_chunk (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_FLUSH:
                if (io->body_ostream) {
                        if (io->write_encoding != SOUP_ENCODING_CHUNKED) {
                                if (!g_output_stream_close (io->body_ostream, cancellable, error))
                                        return FALSE;
                                g_clear_object (&io->body_ostream);
                        } else {
                                io->async_wait = g_cancellable_new ();
                                g_main_context_push_thread_default (io->async_context);
                                g_output_stream_close_async (io->body_ostream,
                                                             G_PRIORITY_DEFAULT, cancellable,
                                                             closed_async, g_object_ref (msg));
                                g_main_context_pop_thread_default (io->async_context);
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

                break;

        default:
                g_return_val_if_reached (FALSE);
        }

        return TRUE;
}

static SoupURI *
parse_connect_authority (const char *req_path)
{
        SoupURI *uri;
        char *fake_uri;

        fake_uri = g_strdup_printf ("http://%s", req_path);
        uri = soup_uri_new (fake_uri);
        g_free (fake_uri);

        if (uri->user || uri->password ||
            uri->query || uri->fragment ||
            !uri->host ||
            (uri->port == 0) ||
            (strcmp (uri->path, "/") != 0)) {
                soup_uri_free (uri);
                return NULL;
        }

        return uri;
}

static guint
parse_headers (SoupMessage  *msg,
               char         *headers,
               guint         headers_len,
               SoupEncoding *encoding,
               SoupSocket   *sock,
               GError      **error)
{
        char *req_method, *req_path, *url;
        SoupHTTPVersion version;
        const char *req_host;
        guint status;
        SoupURI *uri;

        status = soup_headers_parse_request (headers, headers_len,
                                             msg->request_headers,
                                             &req_method,
                                             &req_path,
                                             &version);
        if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
                if (status == SOUP_STATUS_MALFORMED) {
                        g_set_error_literal (error, SOUP_REQUEST_ERROR,
                                             SOUP_REQUEST_ERROR_PARSING,
                                             _("Could not parse HTTP request"));
                }
                return status;
        }

        g_object_set (G_OBJECT (msg),
                      SOUP_MESSAGE_METHOD, req_method,
                      SOUP_MESSAGE_HTTP_VERSION, version,
                      NULL);
        g_free (req_method);

        /* Handle request body encoding */
        *encoding = soup_message_headers_get_encoding (msg->request_headers);
        if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
                if (soup_message_headers_get_list (msg->request_headers, "Transfer-Encoding"))
                        return SOUP_STATUS_NOT_IMPLEMENTED;
                else
                        return SOUP_STATUS_BAD_REQUEST;
        }

        /* Generate correct context for request */
        req_host = soup_message_headers_get_one (msg->request_headers, "Host");
        if (req_host && strchr (req_host, '/')) {
                g_free (req_path);
                return SOUP_STATUS_BAD_REQUEST;
        }

        if (!strcmp (req_path, "*") && req_host) {
                /* Eg, "OPTIONS * HTTP/1.1" */
                url = g_strdup_printf ("%s://%s",
                                       soup_socket_is_ssl (sock) ? "https" : "http",
                                       req_host);
                uri = soup_uri_new (url);
                if (uri)
                        soup_uri_set_path (uri, "*");
                g_free (url);
        } else if (msg->method == SOUP_METHOD_CONNECT) {
                /* Authority */
                uri = parse_connect_authority (req_path);
        } else if (*req_path != '/') {
                /* Absolute URI */
                uri = soup_uri_new (req_path);
        } else if (req_host) {
                url = g_strdup_printf ("%s://%s%s",
                                       soup_socket_is_ssl (sock) ? "https" : "http",
                                       req_host, req_path);
                uri = soup_uri_new (url);
                g_free (url);
        } else if (soup_message_get_http_version (msg) == SOUP_HTTP_1_0) {
                /* No Host header, no AbsoluteUri */
                GInetSocketAddress *addr = soup_socket_get_local_address (sock);
                GInetAddress *inet_addr = g_inet_socket_address_get_address (addr);
                char *local_ip = g_inet_address_to_string (inet_addr);

                uri = soup_uri_new (NULL);
                soup_uri_set_scheme (uri, soup_socket_is_ssl (sock) ?
                                     SOUP_URI_SCHEME_HTTPS :
                                     SOUP_URI_SCHEME_HTTP);
                soup_uri_set_host (uri, local_ip);
                soup_uri_set_port (uri, g_inet_socket_address_get_port (addr));
                soup_uri_set_path (uri, req_path);
                g_free (local_ip);
        } else
                uri = NULL;

        g_free (req_path);

        if (!uri || !uri->host) {
                if (uri)
                        soup_uri_free (uri);
                return SOUP_STATUS_BAD_REQUEST;
        }

        soup_message_set_uri (msg, uri);
        soup_uri_free (uri);

        return SOUP_STATUS_OK;
}

/* Attempts to push forward the reading side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not readable, read is complete, etc).
 */
static gboolean
io_read (SoupMessage  *msg,
         GCancellable *cancellable,
         GError      **error)
{
        SoupMessageIOData *io = soup_message_get_io_data (msg);
        gssize nread;
        guint status;

        switch (io->read_state) {
        case SOUP_MESSAGE_IO_STATE_HEADERS:
                if (!soup_message_io_read_headers (msg, io->istream, io->read_header_buf, FALSE, cancellable, error))
                        return FALSE;

                status = parse_headers (msg,
                                        (char *)io->read_header_buf->data,
                                        io->read_header_buf->len,
                                        &io->read_encoding,
                                        io->sock,
                                        error);
                g_byte_array_set_size (io->read_header_buf, 0);

                if (status != SOUP_STATUS_OK) {
                        /* Either we couldn't parse the headers, or they
                         * indicated something that would mean we wouldn't
                         * be able to parse the body. (Eg, unknown
                         * Transfer-Encoding.). Skip the rest of the
                         * reading, and make sure the connection gets
                         * closed when we're done.
                         */
                        soup_message_set_status (msg, status);
                        soup_message_headers_append (msg->request_headers,
                                                     "Connection", "close");
                        io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                        break;
                }

                if (soup_message_headers_get_expectations (msg->request_headers) & SOUP_EXPECTATION_CONTINUE) {
                        /* We must return a status code and response
                         * headers to the client; either an error to
                         * be set by a got-headers handler below, or
                         * else %SOUP_STATUS_CONTINUE otherwise.
                         */
                        io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
                        io->read_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
                } else
                        io->read_state = SOUP_MESSAGE_IO_STATE_BODY_START;

                if (io->read_encoding == SOUP_ENCODING_CONTENT_LENGTH)
                        io->read_length = soup_message_headers_get_content_length (msg->request_headers);
                else
                        io->read_length = -1;

                soup_message_got_headers (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                if (!io->body_istream) {
                        io->body_istream = soup_body_input_stream_new (G_INPUT_STREAM (io->istream),
                                                                       io->read_encoding,
                                                                       io->read_length);

                }

                io->read_state = SOUP_MESSAGE_IO_STATE_BODY;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY: {
                guchar buf[RESPONSE_BLOCK_SIZE];

                nread = g_pollable_stream_read (io->body_istream,
                                                buf,
                                                RESPONSE_BLOCK_SIZE,
                                                FALSE,
                                                cancellable, error);
                if (nread > 0) {
                        if (msg->request_body) {
                                GBytes *bytes = g_bytes_new (buf, nread);
                                soup_message_body_got_chunk (msg->request_body, bytes);
                                soup_message_got_chunk (msg, bytes);
                                g_bytes_unref (bytes);
                        }
                        break;
                }

                if (nread == -1)
                        return FALSE;

                /* else nread == 0 */
                io->read_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
                break;
        }

        case SOUP_MESSAGE_IO_STATE_BODY_DONE:
                io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                soup_message_got_body (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_FINISHING:
                io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
                io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
                break;

        default:
                g_return_val_if_reached (FALSE);
        }

        return TRUE;
}

static gboolean
io_run_until (SoupMessage       *msg,
              SoupMessageIOState read_state,
              SoupMessageIOState write_state,
              GCancellable      *cancellable,
              GError           **error)
{
        SoupMessageIOData *io = soup_message_get_io_data (msg);
        gboolean progress = TRUE, done;
        GError *my_error = NULL;

        if (g_cancellable_set_error_if_cancelled (cancellable, error))
                return FALSE;
        else if (!io) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_CANCELLED,
                                     _("Operation was cancelled"));
                return FALSE;
        }

        g_object_ref (msg);

        while (progress && soup_message_get_io_data (msg) == io && !io->paused && !io->async_wait &&
               (io->read_state < read_state || io->write_state < write_state)) {

                if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->read_state))
                        progress = io_read (msg, cancellable, &my_error);
                else if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->write_state))
                        progress = io_write (msg, cancellable, &my_error);
                else
                        progress = FALSE;
        }

        if (my_error) {
                g_propagate_error (error, my_error);
                g_object_unref (msg);
                return FALSE;
        } else if (soup_message_get_io_data (msg) != io) {
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

        if (!done) {
                g_set_error_literal (error, G_IO_ERROR,
                                     G_IO_ERROR_WOULD_BLOCK,
                                     _("Operation would block"));
                g_object_unref (msg);
                return FALSE;
        }

        g_object_unref (msg);
        return done;
}

static void io_run (SoupMessage *msg);

static gboolean
io_run_ready (SoupMessage *msg,
              gpointer     user_data)
{
        io_run (msg);
        return FALSE;
}

static void
io_run (SoupMessage *msg)
{
        SoupMessageIOData *io = soup_message_get_io_data (msg);
        GError *error = NULL;
        GCancellable *cancellable;

        if (io->io_source) {
                g_source_destroy (io->io_source);
                g_source_unref (io->io_source);
                io->io_source = NULL;
        }

        g_object_ref (msg);
        cancellable = io->cancellable ? g_object_ref (io->cancellable) : NULL;

        if (io_run_until (msg,
                          SOUP_MESSAGE_IO_STATE_DONE,
                          SOUP_MESSAGE_IO_STATE_DONE,
                          cancellable, &error)) {
                soup_message_io_finished (msg);
        } else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error (&error);
                io->io_source = soup_message_io_get_source (msg, NULL, io_run_ready, msg);
                g_source_attach (io->io_source, io->async_context);
        } else {
                if (soup_message_get_io_data (msg) == io) {
			if (!SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code) &&
			    !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
                                soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
                        }
                        soup_message_io_finished (msg);
                }
                g_error_free (error);

        }

        g_object_unref (msg);
        g_clear_object (&cancellable);
}

void
soup_message_read_request (SoupMessage               *msg,
                           SoupSocket                *sock,
                           SoupMessageCompletionFn    completion_cb,
                           gpointer                   user_data)
{
        SoupMessageIOData *io;

        io = g_slice_new0 (SoupMessageIOData);
        io->completion_cb = completion_cb;
        io->completion_data = user_data;

        io->sock = sock;
        io->iostream = g_object_ref (soup_socket_get_iostream (io->sock));
        io->istream = SOUP_FILTER_INPUT_STREAM (g_io_stream_get_input_stream (io->iostream));
        io->ostream = g_io_stream_get_output_stream (io->iostream);
        io->async_context = g_main_context_ref_thread_default ();

        io->read_header_buf = g_byte_array_new ();
        io->write_buf = g_string_new (NULL);

        io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
        io->write_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;

        soup_message_set_io_data (msg, io);

        io_run (msg);
}
