/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-server-message-io-http1.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#include "soup-server-message-io-http1.h"
#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-filter-input-stream.h"
#include "soup-message-io-data.h"
#include "soup-message-headers-private.h"
#include "soup-server-message-private.h"
#include "soup-misc.h"

typedef struct {
        SoupMessageIOData base;

        SoupServerMessage *msg;

        GBytes  *write_chunk;
	goffset  write_body_offset;

        GSource *unpause_source;

	GMainContext *async_context;
} SoupMessageIOHTTP1;

typedef struct {
        SoupServerMessageIO iface;

        GIOStream *iostream;
        GInputStream *istream;
        GOutputStream *ostream;

        SoupMessageIOStartedFn started_cb;
        gpointer started_user_data;

        gboolean in_io_run;

        SoupMessageIOHTTP1 *msg_io;
} SoupServerMessageIOHTTP1;

#define RESPONSE_BLOCK_SIZE 8192
#define HEADER_SIZE_LIMIT (100 * 1024)

static gboolean io_run_ready (SoupServerMessage *msg,
                              gpointer           user_data);
static void io_run (SoupServerMessageIOHTTP1 *server_io);

static SoupMessageIOHTTP1 *
soup_message_io_http1_new (SoupServerMessage *msg)
{
        SoupMessageIOHTTP1 *msg_io;

        msg_io = g_new0 (SoupMessageIOHTTP1, 1);
        msg_io->msg = msg;
        msg_io->base.read_header_buf = g_byte_array_new ();
        msg_io->base.write_buf = g_string_new (NULL);
        msg_io->base.read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
        msg_io->base.write_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
        msg_io->async_context = g_main_context_ref_thread_default ();

        return msg_io;
}

static void
soup_message_io_http1_free (SoupMessageIOHTTP1 *msg_io)
{
        soup_message_io_data_cleanup (&msg_io->base);

        if (msg_io->unpause_source) {
                g_source_destroy (msg_io->unpause_source);
                g_source_unref (msg_io->unpause_source);
                msg_io->unpause_source = NULL;
        }

        g_clear_object (&msg_io->msg);
        g_clear_pointer (&msg_io->async_context, g_main_context_unref);
        g_clear_pointer (&msg_io->write_chunk, g_bytes_unref);

        g_free (msg_io);
}

static void
soup_server_message_io_http1_destroy (SoupServerMessageIO *iface)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;

        g_clear_object (&io->iostream);
        g_clear_pointer (&io->msg_io, soup_message_io_http1_free);

        g_slice_free (SoupServerMessageIOHTTP1, io);
}

static void
soup_server_message_io_http1_finished (SoupServerMessageIO *iface,
                                       SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;
        SoupMessageIOCompletionFn completion_cb;
        gpointer completion_data;
        SoupMessageIOCompletion completion;
        SoupServerConnection *conn;

	completion_cb = io->msg_io->base.completion_cb;
        completion_data = io->msg_io->base.completion_data;

        if ((io->msg_io->base.read_state >= SOUP_MESSAGE_IO_STATE_FINISHING &&
             io->msg_io->base.write_state >= SOUP_MESSAGE_IO_STATE_FINISHING))
                completion = SOUP_MESSAGE_IO_COMPLETE;
        else
		completion = SOUP_MESSAGE_IO_INTERRUPTED;

        g_object_ref (msg);
        g_clear_pointer (&io->msg_io, soup_message_io_http1_free);
        conn = soup_server_message_get_connection (msg);
	if (completion_cb) {
                completion_cb (G_OBJECT (msg), completion, completion_data);
                if (soup_server_connection_is_connected (conn)) {
                        io->msg_io = soup_message_io_http1_new (soup_server_message_new (conn));
                        io->msg_io->base.io_source = soup_message_io_data_get_source (&io->msg_io->base,
                                                                                      G_OBJECT (io->msg_io->msg),
                                                                                      io->istream,
                                                                                      io->ostream,
                                                                                      NULL,
                                                                                      (SoupMessageIOSourceFunc)io_run_ready,
                                                                                      NULL);
                        g_source_attach (io->msg_io->base.io_source, io->msg_io->async_context);
                }
        } else {
                soup_server_connection_disconnect (conn);
        }
        g_object_unref (msg);
}

static GIOStream *
soup_server_message_io_http1_steal (SoupServerMessageIO *iface)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;
        SoupServerMessage *msg;
        SoupMessageIOCompletionFn completion_cb;
	gpointer completion_data;
	GIOStream *iostream;

        if (!io->iostream)
                return NULL;

        iostream = g_object_ref (io->iostream);
        completion_cb = io->msg_io->base.completion_cb;
	completion_data = io->msg_io->base.completion_data;

        msg = io->msg_io->msg;
        g_object_ref (msg);
        g_clear_pointer (&io->msg_io, soup_message_io_http1_free);
        if (completion_cb)
                completion_cb (G_OBJECT (msg), SOUP_MESSAGE_IO_STOLEN, completion_data);
        g_object_unref (msg);

	return iostream;
}

static void
closed_async (GObject      *source,
              GAsyncResult *result,
              gpointer      user_data)
{
        GOutputStream *body_ostream = G_OUTPUT_STREAM (source);
        SoupServerMessage *msg = user_data;
        SoupServerMessageIOHTTP1 *io;
        GCancellable *async_wait;

        io = (SoupServerMessageIOHTTP1 *)soup_server_message_get_io_data (msg);
        if (!io || !io->msg_io || !io->msg_io->base.async_wait || io->msg_io->base.body_ostream != body_ostream) {
                g_object_unref (msg);
                return;
        }

        g_output_stream_close_finish (body_ostream, result, &io->msg_io->base.async_error);
        g_clear_object (&io->msg_io->base.body_ostream);

        async_wait = g_steal_pointer (&io->msg_io->base.async_wait);
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
handle_partial_get (SoupServerMessage *msg)
{
        SoupRange *ranges;
        int nranges;
        GBytes *full_response;
        guint status;
	SoupMessageHeaders *request_headers;
	SoupMessageHeaders *response_headers;
	SoupMessageBody *response_body;

	request_headers = soup_server_message_get_request_headers (msg);
	response_headers = soup_server_message_get_response_headers (msg);
	response_body = soup_server_message_get_response_body (msg);

        /* Make sure the message is set up right for us to return a
         * partial response; it has to be a GET, the status must be
         * 200 OK (and in particular, NOT already 206 Partial
         * Content), and the SoupServer must have already filled in
         * the response body
         */
        if (soup_server_message_get_method (msg) != SOUP_METHOD_GET ||
            soup_server_message_get_status (msg) != SOUP_STATUS_OK ||
            soup_message_headers_get_encoding (response_headers) !=
            SOUP_ENCODING_CONTENT_LENGTH ||
            response_body->length == 0 ||
            !soup_message_body_get_accumulate (response_body))
                return;

        /* Oh, and there has to have been a valid Range header on the
         * request, of course.
         */
        status = soup_message_headers_get_ranges_internal (request_headers,
                                                           response_body->length,
                                                           TRUE,
                                                           &ranges, &nranges);
        if (status == SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
                soup_server_message_set_status (msg, status, NULL);
                soup_message_body_truncate (response_body);
                return;
        } else if (status != SOUP_STATUS_PARTIAL_CONTENT)
                return;

        full_response = soup_message_body_flatten (response_body);
        if (!full_response) {
                soup_message_headers_free_ranges (request_headers, ranges);
                return;
        }

        soup_server_message_set_status (msg, SOUP_STATUS_PARTIAL_CONTENT, NULL);
        soup_message_body_truncate (response_body);

        if (nranges == 1) {
                GBytes *range_buf;

                /* Single range, so just set Content-Range and fix the body. */

                soup_message_headers_set_content_range (response_headers,
                                                        ranges[0].start,
                                                        ranges[0].end,
                                                        g_bytes_get_size (full_response));
                range_buf = g_bytes_new_from_bytes (full_response,
                                                    ranges[0].start,
                                                    ranges[0].end - ranges[0].start + 1);
                soup_message_body_append_bytes (response_body, range_buf);
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
                content_type = soup_message_headers_get_one_common (response_headers, SOUP_HEADER_CONTENT_TYPE);
                for (i = 0; i < nranges; i++) {
                        part_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
                        if (content_type) {
                                soup_message_headers_append_common (part_headers,
                                                                    SOUP_HEADER_CONTENT_TYPE,
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
                        soup_message_headers_unref (part_headers);
                        g_bytes_unref (part_body);
                }

                soup_multipart_to_message (multipart, response_headers, &body);
                soup_message_body_append_bytes (response_body, body);
                g_bytes_unref (body);
                soup_multipart_free (multipart);
        }

        g_bytes_unref (full_response);
        soup_message_headers_free_ranges (request_headers, ranges);
}

static void
write_headers (SoupServerMessage  *msg,
               GString            *headers,
               SoupEncoding       *encoding)
{
        SoupEncoding claimed_encoding;
        SoupMessageHeadersIter iter;
        const char *name, *value;
	guint status_code;
	const char *reason_phrase;
	const char *method;
	SoupMessageHeaders *response_headers;

        if (soup_server_message_get_status (msg) == 0)
                soup_server_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);

        handle_partial_get (msg);

	status_code = soup_server_message_get_status (msg);
        reason_phrase = soup_server_message_get_reason_phrase (msg);

        g_string_append_printf (headers, "HTTP/1.%c %d %s\r\n",
				soup_server_message_get_http_version (msg) == SOUP_HTTP_1_0 ? '0' : '1',
				status_code, reason_phrase);

	method = soup_server_message_get_method (msg);
	response_headers = soup_server_message_get_response_headers (msg);
        claimed_encoding = soup_message_headers_get_encoding (response_headers);
        if ((method == SOUP_METHOD_HEAD ||
             status_code  == SOUP_STATUS_NO_CONTENT ||
             status_code  == SOUP_STATUS_NOT_MODIFIED ||
             SOUP_STATUS_IS_INFORMATIONAL (status_code)) ||
            (method == SOUP_METHOD_CONNECT &&
             SOUP_STATUS_IS_SUCCESSFUL (status_code)))
                *encoding = SOUP_ENCODING_NONE;
        else
                *encoding = claimed_encoding;

        /* Per rfc 7230:
         * A server MUST NOT send a Content-Length header field in any response
         * with a status code of 1xx (Informational) or 204 (No Content).
         */

        if (status_code  == SOUP_STATUS_NO_CONTENT ||
            SOUP_STATUS_IS_INFORMATIONAL (status_code)) {
                soup_message_headers_remove (response_headers, "Content-Length");
        } else if (claimed_encoding == SOUP_ENCODING_CONTENT_LENGTH &&
            !soup_message_headers_get_content_length (response_headers)) {
                SoupMessageBody *response_body;

                response_body = soup_server_message_get_response_body (msg);
                soup_message_headers_set_content_length (response_headers,
                                                         response_body->length);
        }

        soup_message_headers_iter_init (&iter, response_headers);
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
io_write (SoupServerMessageIOHTTP1 *server_io,
          GError                  **error)
{
        SoupServerMessage *msg = server_io->msg_io->msg;
	SoupMessageIOData *io = &server_io->msg_io->base;
        GBytes *chunk;
        gssize nwrote;
	guint status_code;

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
		status_code = soup_server_message_get_status (msg);
                if (io->read_state == SOUP_MESSAGE_IO_STATE_BLOCKING && status_code == 0) {
                        /* Client requested "Expect: 100-continue", and
                         * server did not set an error.
                         */
                        soup_server_message_set_status (msg, SOUP_STATUS_CONTINUE, NULL);
                }

                if (!io->write_buf->len)
                        write_headers (msg, io->write_buf, &io->write_encoding);

                while (io->written < io->write_buf->len) {
                        nwrote = g_pollable_stream_write (server_io->ostream,
                                                          io->write_buf->str + io->written,
                                                          io->write_buf->len - io->written,
                                                          FALSE,
                                                          NULL, error);
                        if (nwrote == -1)
                                return FALSE;
                        io->written += nwrote;
                }

                io->written = 0;
                g_string_truncate (io->write_buf, 0);

		status_code = soup_server_message_get_status (msg);
                if (SOUP_STATUS_IS_INFORMATIONAL (status_code)) {
                        if (status_code == SOUP_STATUS_CONTINUE) {
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

                        soup_server_message_wrote_informational (msg);

                        /* If this was "101 Switching Protocols", then
                         * the server probably stole the connection...
                         */
                        if ((SoupServerMessageIO *)server_io != soup_server_message_get_io_data (msg))
                                return FALSE;

                        soup_server_message_cleanup_response (msg);
                        break;
                }

                if (io->write_encoding == SOUP_ENCODING_CONTENT_LENGTH)
                        io->write_length = soup_message_headers_get_content_length (soup_server_message_get_response_headers (msg));

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_START;
                /* If the client was waiting for a Continue
                 * but we sent something else, then they're
                 * now done writing.
                 */
                if (io->read_state == SOUP_MESSAGE_IO_STATE_BLOCKING)
                        io->read_state = SOUP_MESSAGE_IO_STATE_DONE;

                soup_server_message_wrote_headers (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                io->body_ostream = soup_body_output_stream_new (server_io->ostream,
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

                if (!server_io->msg_io->write_chunk) {
                        server_io->msg_io->write_chunk = soup_message_body_get_chunk (soup_server_message_get_response_body (msg),
                                                                                      server_io->msg_io->write_body_offset);
                        if (!server_io->msg_io->write_chunk) {
                                soup_server_message_pause (msg);
                                return FALSE;
                        }
                        if (!g_bytes_get_size (server_io->msg_io->write_chunk)) {
                                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                                break;
                        }
                }

                nwrote = g_pollable_stream_write (io->body_ostream,
                                                  (guchar*)g_bytes_get_data (server_io->msg_io->write_chunk, NULL) + io->written,
                                                  g_bytes_get_size (server_io->msg_io->write_chunk) - io->written,
                                                  FALSE,
                                                  NULL, error);
                if (nwrote == -1)
                        return FALSE;

                chunk = g_bytes_new_from_bytes (server_io->msg_io->write_chunk, io->written, nwrote);
                io->written += nwrote;
                if (io->write_length)
                        io->write_length -= nwrote;

                if (io->written == g_bytes_get_size (server_io->msg_io->write_chunk))
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DATA;

                soup_server_message_wrote_body_data (msg, g_bytes_get_size (chunk));
                g_bytes_unref (chunk);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_DATA:
                io->written = 0;
                if (g_bytes_get_size (server_io->msg_io->write_chunk) == 0) {
                        io->write_state = SOUP_MESSAGE_IO_STATE_BODY_FLUSH;
                        break;
                }

                soup_message_body_wrote_chunk (soup_server_message_get_response_body (msg),
					       server_io->msg_io->write_chunk);
                server_io->msg_io->write_body_offset += g_bytes_get_size (server_io->msg_io->write_chunk);
                g_clear_pointer (&server_io->msg_io->write_chunk, g_bytes_unref);

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY;
                soup_server_message_wrote_chunk (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_FLUSH:
                if (io->body_ostream) {
                        if (io->write_encoding != SOUP_ENCODING_CHUNKED) {
                                if (!g_output_stream_close (io->body_ostream, NULL, error))
                                        return FALSE;
                                g_clear_object (&io->body_ostream);
                        } else {
                                io->async_wait = g_cancellable_new ();
                                g_main_context_push_thread_default (server_io->msg_io->async_context);
                                g_output_stream_close_async (io->body_ostream,
                                                             G_PRIORITY_DEFAULT, NULL,
                                                             closed_async, g_object_ref (msg));
                                g_main_context_pop_thread_default (server_io->msg_io->async_context);
                        }
                }

                io->write_state = SOUP_MESSAGE_IO_STATE_BODY_DONE;
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_DONE:
                io->write_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                soup_server_message_wrote_body (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_FINISHING:
                io->write_state = SOUP_MESSAGE_IO_STATE_DONE;

                break;

        default:
                g_return_val_if_reached (FALSE);
        }

        return TRUE;
}

static GUri *
parse_connect_authority (const char *req_path)
{
	GUri *uri;
	char *fake_uri;

	fake_uri = g_strdup_printf ("http://%s", req_path);
	uri = g_uri_parse (fake_uri, SOUP_HTTP_URI_FLAGS, NULL);
	g_free (fake_uri);

        if (!uri)
                return NULL;

        if (g_uri_get_user (uri) ||
            g_uri_get_password (uri) ||
            g_uri_get_query (uri) ||
            g_uri_get_fragment (uri) ||
            !g_uri_get_host (uri) ||
            g_uri_get_port (uri) <= 0 ||
            strcmp (g_uri_get_path (uri), "/") != 0) {
                g_uri_unref (uri);
                return NULL;
        }

	return uri;
}

static guint
parse_headers (SoupServerMessage *msg,
               char              *headers,
               guint              headers_len,
               SoupEncoding      *encoding,
               GError           **error)
{
        char *req_method, *req_path, *url;
        SoupHTTPVersion version;
	SoupServerConnection *conn;
        const char *req_host;
        guint status;
        GUri *uri;
	SoupMessageHeaders *request_headers;

	request_headers = soup_server_message_get_request_headers (msg);

        status = soup_headers_parse_request (headers, headers_len,
                                             request_headers,
                                             &req_method,
                                             &req_path,
                                             &version);
        if (!SOUP_STATUS_IS_SUCCESSFUL (status))
                return status;

	soup_server_message_set_method (msg, req_method);
	soup_server_message_set_http_version (msg, version);
        g_free (req_method);

        /* Handle request body encoding */
        *encoding = soup_message_headers_get_encoding (request_headers);
        if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
                g_free (req_path);
                if (soup_message_headers_get_list_common (request_headers, SOUP_HEADER_TRANSFER_ENCODING))
                        return SOUP_STATUS_NOT_IMPLEMENTED;
                else
                        return SOUP_STATUS_BAD_REQUEST;
        }

        /* Generate correct context for request */
        req_host = soup_message_headers_get_one_common (request_headers, SOUP_HEADER_HOST);
        if (req_host && strchr (req_host, '/')) {
                g_free (req_path);
                return SOUP_STATUS_BAD_REQUEST;
        }

	conn = soup_server_message_get_connection (msg);

	if (!strcmp (req_path, "*") && req_host) {
		/* Eg, "OPTIONS * HTTP/1.1" */
		url = g_strdup_printf ("%s://%s/",
				       soup_server_connection_is_ssl (conn) ? "https" : "http",
				       req_host);
		uri = g_uri_parse (url, SOUP_HTTP_URI_FLAGS, NULL);
                soup_server_message_set_options_ping (msg, TRUE);
		g_free (url);
	} else if (soup_server_message_get_method (msg) == SOUP_METHOD_CONNECT) {
		/* Authority */
		uri = parse_connect_authority (req_path);
	} else if (*req_path != '/') {
		/* Absolute URI */
		uri = g_uri_parse (req_path, SOUP_HTTP_URI_FLAGS, NULL);
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s%s",
				       soup_server_connection_is_ssl (conn) ? "https" : "http",
				       req_host, req_path);
		uri = g_uri_parse (url, SOUP_HTTP_URI_FLAGS, NULL);
		g_free (url);
	} else if (soup_server_message_get_http_version (msg) == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		GInetSocketAddress *addr = G_INET_SOCKET_ADDRESS (soup_server_connection_get_local_address (conn));
                GInetAddress *inet_addr = g_inet_socket_address_get_address (addr);
                char *local_ip = g_inet_address_to_string (inet_addr);
                int port = g_inet_socket_address_get_port (addr);
                if (port == 0)
                        port = -1;

                uri = g_uri_build (SOUP_HTTP_URI_FLAGS,
                                   soup_server_connection_is_ssl (conn) ? "https" : "http",
                                   NULL, local_ip, port, req_path, NULL, NULL);
		g_free (local_ip);
	} else
		uri = NULL;

	g_free (req_path);

	if (!uri || !g_uri_get_host (uri)) {
		if (uri)
			g_uri_unref (uri);
		return SOUP_STATUS_BAD_REQUEST;
	}

	soup_server_message_set_uri (msg, uri);
        g_uri_unref (uri);

        return SOUP_STATUS_OK;
}

/* Attempts to push forward the reading side of @msg's I/O. Returns
 * %TRUE if it manages to make some progress, and it is likely that
 * further progress can be made. Returns %FALSE if it has reached a
 * stopping point of some sort (need input from the application,
 * socket not readable, read is complete, etc).
 */
static gboolean
io_read (SoupServerMessageIOHTTP1 *server_io,
         GError                  **error)
{
        SoupServerMessage *msg = server_io->msg_io->msg;
	SoupMessageIOData *io = &server_io->msg_io->base;
        gssize nread;
        guint status;
	SoupMessageHeaders *request_headers;
        gboolean succeeded;
        gboolean is_first_read;

        switch (io->read_state) {
        case SOUP_MESSAGE_IO_STATE_HEADERS:
                is_first_read = io->read_header_buf->len == 0 && !soup_server_message_get_method (msg);

                succeeded = soup_message_io_data_read_headers (io, SOUP_FILTER_INPUT_STREAM (server_io->istream), FALSE, NULL, NULL, error);
                if (is_first_read && io->read_header_buf->len > 0 && !io->completion_cb)
                        server_io->started_cb (msg, server_io->started_user_data);

                if (!succeeded) {
                        if (g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT))
                                soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
                        return FALSE;
		}

                status = parse_headers (msg,
                                        (char *)io->read_header_buf->data,
                                        io->read_header_buf->len,
                                        &io->read_encoding,
                                        error);
                g_byte_array_set_size (io->read_header_buf, 0);

		request_headers = soup_server_message_get_request_headers (msg);

                if (status != SOUP_STATUS_OK) {
                        /* Either we couldn't parse the headers, or they
                         * indicated something that would mean we wouldn't
                         * be able to parse the body. (Eg, unknown
                         * Transfer-Encoding.). Skip the rest of the
                         * reading, and make sure the connection gets
                         * closed when we're done.
                         */
                        soup_server_message_set_status (msg, status, NULL);
                        soup_message_headers_append_common (request_headers, SOUP_HEADER_CONNECTION, "close");
                        io->read_state = SOUP_MESSAGE_IO_STATE_FINISHING;
                        break;
                }

                if (soup_message_headers_get_expectations (request_headers) & SOUP_EXPECTATION_CONTINUE) {
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
                        io->read_length = soup_message_headers_get_content_length (request_headers);
                else
                        io->read_length = -1;

                soup_server_message_got_headers (msg);
                break;

        case SOUP_MESSAGE_IO_STATE_BODY_START:
                if (!io->body_istream) {
                        io->body_istream = soup_body_input_stream_new (server_io->istream,
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
                                                NULL, error);
                if (nread > 0) {
			SoupMessageBody *request_body;

			request_body = soup_server_message_get_request_body (msg);
                        if (request_body) {
                                GBytes *bytes = g_bytes_new (buf, nread);
                                soup_message_body_got_chunk (request_body, bytes);
                                soup_server_message_got_chunk (msg, bytes);
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
                soup_server_message_got_body (msg);
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
io_run_until (SoupServerMessageIOHTTP1 *server_io,
              SoupMessageIOState        read_state,
              SoupMessageIOState        write_state,
              GError                  **error)
{
        SoupServerMessage *msg = server_io->msg_io->msg;
	SoupMessageIOData *io = &server_io->msg_io->base;
        gboolean progress = TRUE, done;
        GError *my_error = NULL;

        if (!io)
                return FALSE;

        g_object_ref (msg);

        while (progress && soup_server_message_get_io_data (msg) == (SoupServerMessageIO *)server_io && !io->paused && !io->async_wait &&
               (io->read_state < read_state || io->write_state < write_state)) {

                if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->read_state))
                        progress = io_read (server_io, &my_error);
                else if (SOUP_MESSAGE_IO_STATE_ACTIVE (io->write_state))
                        progress = io_write (server_io, &my_error);
                else
                        progress = FALSE;
        }

        if (my_error) {
                g_propagate_error (error, my_error);
                g_object_unref (msg);
                return FALSE;
        }

	if (soup_server_message_get_io_data (msg) != (SoupServerMessageIO *)server_io) {
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

static gboolean
io_run_ready (SoupServerMessage *msg,
              gpointer           user_data)
{
        io_run ((SoupServerMessageIOHTTP1 *)soup_server_message_get_io_data (msg));
        return FALSE;
}

static void
io_run (SoupServerMessageIOHTTP1 *server_io)
{
        SoupServerMessage *msg = server_io->msg_io->msg;
	SoupMessageIOData *io = &server_io->msg_io->base;
        gboolean success;
        GError *error = NULL;

        g_assert (!server_io->in_io_run);
        server_io->in_io_run = TRUE;

        if (io->io_source) {
                g_source_destroy (io->io_source);
                g_source_unref (io->io_source);
                io->io_source = NULL;
        }

        g_object_ref (msg);
        success = io_run_until (server_io,
                                SOUP_MESSAGE_IO_STATE_DONE,
                                SOUP_MESSAGE_IO_STATE_DONE,
                                &error);

        if (soup_server_message_get_io_data (msg) != (SoupServerMessageIO *)server_io) {
                g_object_unref (msg);
                g_clear_error (&error);

                return;
        }

        server_io->in_io_run = FALSE;

        if (success) {
                soup_server_message_finish (msg);
        } else if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                g_clear_error (&error);
                io->io_source = soup_message_io_data_get_source (io, G_OBJECT (msg),
                                                                 server_io->istream,
                                                                 server_io->ostream,
                                                                 NULL,
								 (SoupMessageIOSourceFunc)io_run_ready,
								 NULL);
                g_source_attach (io->io_source, server_io->msg_io->async_context);
        } else if (soup_server_message_get_io_data (msg) == (SoupServerMessageIO *)server_io) {
		soup_server_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, error ? error->message : NULL);
		soup_server_message_finish (msg);
	}
	g_object_unref (msg);
	g_clear_error (&error);
}

static void
soup_server_message_io_http1_read_request (SoupServerMessageIO      *iface,
                                           SoupServerMessage        *msg,
                                           SoupMessageIOCompletionFn completion_cb,
                                           gpointer                  user_data)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;
        SoupMessageIOHTTP1 *msg_io = io->msg_io;

        g_assert (msg_io->msg == msg);

        msg_io->base.completion_cb = completion_cb;
        msg_io->base.completion_data = user_data;

        if (!io->in_io_run)
                io_run (io);
}

static void
soup_server_message_io_http1_pause (SoupServerMessageIO *iface,
                                    SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->msg == msg);

	if (io->msg_io->unpause_source) {
                g_source_destroy (io->msg_io->unpause_source);
                g_clear_pointer (&io->msg_io->unpause_source, g_source_unref);
	}

	soup_message_io_data_pause (&io->msg_io->base);
}

static gboolean
io_unpause_internal (SoupServerMessageIOHTTP1 *io)
{
	g_assert (io != NULL && io->msg_io != NULL);

	g_clear_pointer (&io->msg_io->unpause_source, g_source_unref);
	soup_message_io_data_unpause (&io->msg_io->base);
        if (io->msg_io->base.io_source)
		return FALSE;

        io_run (io);
	return FALSE;
}

static void
soup_server_message_io_http1_unpause (SoupServerMessageIO *iface,
                                      SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->msg == msg);

        if (!io->msg_io->unpause_source) {
	        io->msg_io->unpause_source = soup_add_completion_reffed (io->msg_io->async_context,
                                                                         (GSourceFunc)io_unpause_internal,
                                                                         io, NULL);
        }
}

static gboolean
soup_server_message_io_http1_is_paused (SoupServerMessageIO *iface,
                                        SoupServerMessage   *msg)
{
        SoupServerMessageIOHTTP1 *io = (SoupServerMessageIOHTTP1 *)iface;

        g_assert (io->msg_io && io->msg_io->msg == msg);

	return io->msg_io->base.paused;
}

static const SoupServerMessageIOFuncs io_funcs = {
        soup_server_message_io_http1_destroy,
        soup_server_message_io_http1_finished,
        soup_server_message_io_http1_steal,
        soup_server_message_io_http1_read_request,
        soup_server_message_io_http1_pause,
        soup_server_message_io_http1_unpause,
        soup_server_message_io_http1_is_paused
};

SoupServerMessageIO *
soup_server_message_io_http1_new (SoupServerConnection  *conn,
                                  SoupServerMessage     *msg,
                                  SoupMessageIOStartedFn started_cb,
                                  gpointer               user_data)
{
        SoupServerMessageIOHTTP1 *io;

        io = g_slice_new0 (SoupServerMessageIOHTTP1);
        io->iostream = g_object_ref (soup_server_connection_get_iostream (conn));
        io->istream = g_io_stream_get_input_stream (io->iostream);
        io->ostream = g_io_stream_get_output_stream (io->iostream);

        io->started_cb = started_cb;
        io->started_user_data = user_data;

        io->iface.funcs = &io_funcs;

        io->msg_io = soup_message_io_http1_new (msg);

        return (SoupServerMessageIO *)io;
}
