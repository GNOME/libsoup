/*
 * Copyright 2021 Igalia S.L.
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "test-utils.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-server-message-private.h"
#include "soup-body-input-stream-http2.h"
#include <gio/gnetworking.h>

static GUri *base_uri;

typedef struct {
        SoupSession *session;
} Test;

#define LARGE_N_CHARS 24
#define LARGE_CHARS_REPEAT 1024

// This just needs to be larger than our default window size in soup-connection.c
#define REALLY_LARGE_BUFFER_SIZE 62914600

static void
setup_session (Test *test, gconstpointer data)
{
        test->session = soup_test_session_new (NULL);
}

static void
teardown_session (Test *test, gconstpointer data)
{
        soup_test_session_abort_unref (test->session);
}

static void
do_basic_async_test (Test *test, gconstpointer data)
{
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_1_1);

        response = soup_test_session_async_send (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_2_0);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");

        g_bytes_unref (response);
        g_object_unref (msg);
}

static void
do_basic_sync_test (Test *test, gconstpointer data)
{
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_1_1);

        response = soup_session_send_and_read (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_2_0);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");

        g_bytes_unref (response);
        g_object_unref (msg);
}

static void
do_no_content_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/no-content", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        response = soup_test_session_async_send (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpuint (soup_message_get_status (msg), ==, 204);
        g_assert_cmpuint (g_bytes_get_size (response), ==, 0);

        g_uri_unref (uri);
        g_bytes_unref (response);
        g_object_unref (msg);
}

static void
do_large_test (Test *test, gconstpointer data)
{
        gboolean async = GPOINTER_TO_INT (data);
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/large", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);

        /* This is both large and read in chunks */
        if (async)
                response = soup_test_session_async_send (test->session, msg, NULL, &error);
        else
                response = soup_session_send_and_read (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpuint (g_bytes_get_size (response), ==, (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1);

        g_uri_unref (uri);
        g_bytes_unref (response);
        g_object_unref (msg);
}

static GBytes *
read_stream_to_bytes_sync (GInputStream *stream)
{
        GOutputStream *out = g_memory_output_stream_new_resizable ();
        GError *error = NULL;

        gssize read = g_output_stream_splice (out, stream,  G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                              NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpint (read, >=, 0);

        GBytes *bytes = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (out));
        g_object_unref (out);
        return bytes;
}

static void
on_send_complete (GObject *source, GAsyncResult *res, gpointer user_data)
{
        SoupSession *sess = SOUP_SESSION (source);
        GError *error = NULL;
        GInputStream *stream;
        GBytes **bytes_out = user_data;

        stream = soup_session_send_finish (sess, res, &error);

        g_assert_no_error (error);
        g_assert_nonnull (stream);

        *bytes_out = read_stream_to_bytes_sync (stream);
        g_object_unref (stream);
}

static void
do_multi_message_async_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();
        GUri *uri1, *uri2;
        SoupMessage *msg1, *msg2;
        GBytes *response1 = NULL;
        GBytes *response2 = NULL;

        uri1 = g_uri_parse_relative (base_uri, "echo_query?body%201", SOUP_HTTP_URI_FLAGS, NULL);
        msg1 = soup_message_new_from_uri (SOUP_METHOD_GET, uri1);
        soup_message_set_http_version (msg1, SOUP_HTTP_2_0);

        uri2 = g_uri_parse_relative (base_uri, "echo_query?body%202", SOUP_HTTP_URI_FLAGS, NULL);
        msg2 = soup_message_new_from_uri (SOUP_METHOD_GET, uri2);
        soup_message_set_http_version (msg2, SOUP_HTTP_2_0);
        soup_session_send_async (test->session, msg1, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response1);
        soup_session_send_async (test->session, msg2, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response2);

        while (!response1 || !response2) {
                g_main_context_iteration (async_context, TRUE);
        }

        g_assert_cmpuint (soup_message_get_http_version (msg1), ==, SOUP_HTTP_2_0);
        g_assert_cmpuint (soup_message_get_http_version (msg2), ==, SOUP_HTTP_2_0);

        g_assert_cmpstr (g_bytes_get_data (response1, NULL), ==, "body%201");
        g_assert_cmpstr (g_bytes_get_data (response2, NULL), ==, "body%202");

        g_bytes_unref (response1);
        g_bytes_unref (response2);
        g_object_unref (msg1);
        g_object_unref (msg2);
        g_uri_unref (uri1);
        g_uri_unref (uri2);
        g_main_context_unref (async_context);
}


static void
on_send_and_read_cancelled_complete (SoupSession  *session,
                                     GAsyncResult *result,
                                     gboolean     *done)
{
        GError *error = NULL;
        GBytes *response = soup_session_send_and_read_finish (session, result, &error);

        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
        g_assert_null (response);
        g_error_free (error);
        *done = TRUE;
}

static void
on_send_and_read_complete (SoupSession  *session,
                           GAsyncResult *result,
                           gboolean     *done)
{
        GError *error = NULL;
        GBytes *response = soup_session_send_and_read_finish (session, result, &error);

        g_assert_no_error (error);
        g_assert_nonnull (response);
        g_bytes_unref (response);
        *done = TRUE;
}

static void
do_cancellation_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GMainContext *async_context = g_main_context_ref_thread_default ();
        GCancellable *cancellable = g_cancellable_new ();
        gboolean done = FALSE;

        uri = g_uri_parse_relative (base_uri, "/large", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, cancellable,
                                          (GAsyncReadyCallback)on_send_and_read_cancelled_complete, &done);

        /* Cancel right after getting the headers */
        g_signal_connect_swapped (msg, "got-headers", G_CALLBACK (g_cancellable_cancel), cancellable);

        while (!done)
                g_main_context_iteration (async_context, FALSE);

        g_object_unref (msg);

        done = FALSE;
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)on_send_and_read_complete, &done);

        while (!done)
                g_main_context_iteration (async_context, FALSE);

        g_uri_unref (uri);
        g_object_unref (msg);
        g_object_unref (cancellable);
        g_main_context_unref (async_context);
}

static void
do_one_cancel_after_send_request_test (SoupSession *session,
                                       gboolean     reuse_cancellable,
                                       gboolean     cancelled_by_session)
{
        SoupMessage *msg;
        GCancellable *cancellable;
        GInputStream *istream;
        GOutputStream *ostream;
        guint flags = SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH;
        GBytes *body;
        GError *error = NULL;

        if (cancelled_by_session)
                flags |= SOUP_TEST_REQUEST_CANCEL_BY_SESSION;

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        cancellable = g_cancellable_new ();
        istream = soup_test_request_send (session, msg, cancellable, flags, &error);
        g_assert_no_error (error);
        g_assert_nonnull (istream);

        /* If we use a new cancellable to read the stream
         * it shouldn't fail with cancelled error.
         */
        if (!reuse_cancellable) {
                g_object_unref (cancellable);
                cancellable = g_cancellable_new ();
        }
        ostream = g_memory_output_stream_new_resizable ();
        g_output_stream_splice (ostream, istream,
                                G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                cancellable, &error);

        if (reuse_cancellable || cancelled_by_session) {
                g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
                g_clear_error (&error);
        } else {
                g_assert_no_error (error);
                body = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream));
                g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "Hello world");
                g_bytes_unref (body);
        }

        g_object_unref (cancellable);
        g_object_unref (ostream);
        g_object_unref (istream);
        g_object_unref (msg);
}

static void
do_cancellation_after_send_test (Test *test, gconstpointer data)
{
        do_one_cancel_after_send_request_test (test->session, TRUE, FALSE);
        do_one_cancel_after_send_request_test (test->session, FALSE, FALSE);
        do_one_cancel_after_send_request_test (test->session, FALSE, TRUE);
}

static void
do_post_sync_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GInputStream *response;
        GBytes *bytes = g_bytes_new_static ("body 1", sizeof ("body 1"));
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);

        response = soup_session_send (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_nonnull (response);

        GBytes *response_bytes = read_stream_to_bytes_sync (response);
        g_assert_cmpstr (g_bytes_get_data (response_bytes, NULL), ==, "body 1");

        g_bytes_unref (response_bytes);
        g_object_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_post_large_sync_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GInputStream *response;
        guint large_size = 1000000;
        char *large_data;
        unsigned int i;
        GError *error = NULL;

        large_data = g_malloc (large_size);
        for (i = 0; i < large_size; i++)
                large_data[i] = i & 0xFF;
        GBytes *bytes = g_bytes_new_take (large_data, large_size);

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);

        response = soup_session_send (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_nonnull (response);

        GBytes *response_bytes = read_stream_to_bytes_sync (response);
        g_assert_true (g_bytes_equal (bytes, response_bytes));

        g_bytes_unref (response_bytes);
        g_object_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_post_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response = NULL;
        GMainContext *async_context = g_main_context_ref_thread_default ();
        GBytes *bytes = g_bytes_new_static ("body 1", sizeof ("body 1"));

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);

        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response)
                g_main_context_iteration (async_context, TRUE);

        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "body 1");

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_main_context_unref (async_context);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_post_large_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response = NULL;
        GMainContext *async_context = g_main_context_ref_thread_default ();
        guint large_size = 1000000;
        char *large_data;
        unsigned int i;

        large_data = g_malloc (large_size);
        for (i = 0; i < large_size; i++)
                large_data[i] = i & 0xFF;
        GBytes *bytes = g_bytes_new_take (large_data, large_size);

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);

        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response)
                g_main_context_iteration (async_context, TRUE);

        g_assert_true (g_bytes_equal (bytes, response));

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_main_context_unref (async_context);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_post_blocked_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response = NULL;
        GMainContext *async_context = g_main_context_ref_thread_default ();

        GInputStream *in_stream = soup_body_input_stream_http2_new ();
        soup_body_input_stream_http2_add_data (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream), (guint8*)"Part 1 -", 8);

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body (msg, "text/plain", in_stream, 8 + 8);

        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response) {
                // Let it iterate for a bit waiting on blocked data
                if (soup_body_input_stream_http2_is_blocked (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream))) {
                        soup_body_input_stream_http2_add_data (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream), (guint8*)" Part 2", 8);
                        soup_body_input_stream_http2_complete (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream));
                }
                g_main_context_iteration (async_context, TRUE);
        }

        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Part 1 - Part 2");

        g_bytes_unref (response);
        g_object_unref (in_stream);
        g_main_context_unref (async_context);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_post_file_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response = NULL;
        GMainContext *async_context = g_main_context_ref_thread_default ();

        GFile *in_file = g_file_new_for_path (g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL));
        GFileInputStream *in_stream = g_file_read (in_file, NULL, NULL);
        g_assert_nonnull (in_stream);

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body (msg, "application/x-x509-ca-cert", G_INPUT_STREAM (in_stream), -1);

        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response)
                g_main_context_iteration (async_context, TRUE);

        g_assert_true (g_str_has_prefix (g_bytes_get_data (response, NULL), "-----BEGIN CERTIFICATE-----"));

        g_bytes_unref (response);
        g_object_unref (in_stream);
        g_object_unref (in_file);
        g_main_context_unref (async_context);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static gboolean
on_delayed_auth (SoupAuth *auth)
{
        g_test_message ("Authenticating");
        soup_auth_authenticate (auth, "username", "password");
        return G_SOURCE_REMOVE;
}

static gboolean
on_authenticate (SoupMessage *msg, SoupAuth *auth, gboolean retrying, gpointer user_data)
{
        g_test_message ("Authenticate request");
        /* Force it to pause the message by delaying auth */
        g_timeout_add (500, (GSourceFunc)on_delayed_auth, auth);
        return TRUE;
}

static void
do_paused_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/auth", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_signal_connect (msg, "authenticate", G_CALLBACK (on_authenticate), NULL);
        response = soup_test_session_async_send (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Authenticated");

        g_bytes_unref (response);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
on_send_for_buffer_test (GObject *object, GAsyncResult *result, gpointer user_data)
{
        SoupSession *session = SOUP_SESSION (object);
        GError *error = NULL;
        GInputStream **stream_out = user_data;

        *stream_out = soup_session_send_finish (session, result, &error);

        g_assert_no_error (error);
        g_assert_nonnull (*stream_out);
}

static SoupBodyInputStreamHttp2 *
get_body_stream_from_response (GInputStream *stream)
{
       return SOUP_BODY_INPUT_STREAM_HTTP2 (g_filter_input_stream_get_base_stream (G_FILTER_INPUT_STREAM (stream))); 
}

static void
read_until_end_for_buffer_test (GObject *object, GAsyncResult *result, gpointer user_data)
{
        gboolean *finished = user_data;
	gssize nread;
        static char buffer[10240];

	nread = g_input_stream_read_finish (G_INPUT_STREAM (object), result, NULL);
        if (nread > 0) {
                g_input_stream_read_async (G_INPUT_STREAM (object), buffer, sizeof (buffer), G_PRIORITY_DEFAULT, NULL, read_until_end_for_buffer_test, user_data);
                return;
        }

        g_assert_cmpint (nread, ==, 0);
        *finished = TRUE;
}

static void
on_read_for_buffer_test (GObject *object, GAsyncResult *result, gpointer user_data)
{
	gssize *nread = user_data;

	*nread = g_input_stream_read_finish (G_INPUT_STREAM (object), result, NULL);
        g_assert_cmpint (*nread, >, 0);
}

static void
do_flow_control_buffer_sizes (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *large_msg;
        SoupMessage *small_msg;
        GBytes *small_response;
        GInputStream *response_stream = NULL;
        static char buffer[1024] = { 0 };
        gssize read_bytes = 0;
        gsize buffer_size = 0;
        gboolean finished = FALSE;

        uri = g_uri_parse_relative (base_uri, "/larger-than-window", SOUP_HTTP_URI_FLAGS, NULL);
        large_msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_uri_unref (uri);
        soup_session_send_async (test->session, large_msg, G_PRIORITY_DEFAULT, NULL, on_send_for_buffer_test, &response_stream);
        while (!response_stream)
                g_main_context_iteration (g_main_context_default(), TRUE);

        g_input_stream_read_async (response_stream, buffer, sizeof (buffer), G_PRIORITY_DEFAULT, NULL, on_read_for_buffer_test, &read_bytes);
        while (read_bytes == 0)
                g_main_context_iteration (g_main_context_default(), TRUE);


        buffer_size = soup_body_input_stream_http2_get_buffer_size (get_body_stream_from_response (response_stream));
        // We have not already buffered the whole response.
        g_assert_cmpint (buffer_size, <, REALLY_LARGE_BUFFER_SIZE);

        uri = g_uri_parse_relative (base_uri, "/large", SOUP_HTTP_URI_FLAGS, NULL);
        small_msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_uri_unref (uri);
        small_response = soup_session_send_and_read (test->session, small_msg, NULL, NULL);
        g_assert_nonnull(small_response);
        g_bytes_unref (small_response);
        g_object_unref (small_msg);

        // The buffer could grow a little but shouldn't buffer the whole thing still.
        buffer_size = soup_body_input_stream_http2_get_buffer_size (get_body_stream_from_response (response_stream));
        g_assert_cmpint (buffer_size, <, REALLY_LARGE_BUFFER_SIZE);

        g_input_stream_read_async (response_stream, buffer, sizeof (buffer), G_PRIORITY_DEFAULT, NULL, read_until_end_for_buffer_test, &finished);
        while (!finished)
                g_main_context_iteration (g_main_context_default(), TRUE);

        // Entire buffer was read.
        g_assert_cmpint (0, ==, soup_body_input_stream_http2_get_buffer_size (get_body_stream_from_response (response_stream)));

        g_object_unref (large_msg);
        g_object_unref (response_stream);
}

typedef struct {
        int connection;
        int stream;
} WindowSize;

static void
flow_control_message_network_event (SoupMessage        *msg,
                                    GSocketClientEvent  event,
                                    GIOStream          *connection,
                                    WindowSize         *window_size)
{
        SoupConnection *conn;

        if (event != G_SOCKET_CLIENT_RESOLVING)
                return;

        conn = soup_message_get_connection (msg);
        g_assert_nonnull (conn);
        if (window_size->connection != -1)
                soup_connection_set_http2_initial_window_size (conn, window_size->connection);
        if (window_size->stream != -1)
                soup_connection_set_http2_initial_stream_window_size (conn, window_size->stream);
}

static void
do_flow_control_large_test (Test *test, gconstpointer data)
{
        gboolean async = GPOINTER_TO_INT (data);
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;
        WindowSize window_size = { (LARGE_N_CHARS * LARGE_CHARS_REPEAT) / 2 , (LARGE_N_CHARS * LARGE_CHARS_REPEAT) / 2 };

        uri = g_uri_parse_relative (base_uri, "/large", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (flow_control_message_network_event),
                          &window_size);

        if (async)
                response = soup_test_session_async_send (test->session, msg, NULL, &error);
        else
                response = soup_session_send_and_read (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpuint (g_bytes_get_size (response), ==, (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1);

        g_uri_unref (uri);
        g_bytes_unref (response);
        g_object_unref (msg);
}

static void
do_flow_control_multi_message_async_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg1, *msg2;
        GBytes *response1 = NULL;
        GBytes *response2 = NULL;
        WindowSize window_size = { (LARGE_N_CHARS * LARGE_CHARS_REPEAT), (LARGE_N_CHARS * LARGE_CHARS_REPEAT) / 2 };

        uri = g_uri_parse_relative (base_uri, "/large", SOUP_HTTP_URI_FLAGS, NULL);
        msg1 = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_signal_connect (msg1, "network-event",
                          G_CALLBACK (flow_control_message_network_event),
                          &window_size);
        msg2 = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        soup_session_send_async (test->session, msg1, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response1);
        soup_session_send_async (test->session, msg2, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response2);

        while (!response1 || !response2)
                g_main_context_iteration (NULL, TRUE);

        g_assert_cmpuint (g_bytes_get_size (response1), ==, (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1);
        g_assert_cmpuint (g_bytes_get_size (response2), ==, (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1);

        g_uri_unref (uri);
        g_bytes_unref (response1);
        g_bytes_unref (response2);
        g_object_unref (msg1);
        g_object_unref (msg2);
}

static SoupConnection *last_connection;

static void
on_send_ready (GObject *source, GAsyncResult *res, gpointer user_data)
{
        SoupSession *sess = SOUP_SESSION (source);
        SoupMessage *msg = soup_session_get_async_result_message (sess, res);
        guint *complete_count = user_data;
        SoupConnection *conn;
        GError *error = NULL;
        GInputStream *stream;

        stream = soup_session_send_finish (sess, res, &error);
        g_assert_no_error (error);
        g_assert_nonnull (stream);

        g_assert_nonnull (msg);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_2_0);
        conn = soup_message_get_connection (msg);
        if (last_connection)
                g_assert_true (last_connection == conn);
        else
                last_connection = conn;

        GBytes *result = read_stream_to_bytes_sync (stream);
        g_object_unref (stream);
        g_assert_nonnull (result);
        g_assert_cmpstr (g_bytes_get_data (result, NULL), ==, "Hello world");
        g_bytes_unref (result);

        g_test_message ("Conn (%u) = %p", *complete_count, conn);

        *complete_count += 1;
}

static void
do_connections_test (Test *test, gconstpointer data)
{
        GMainContext *async_context;
        guint complete_count = 0;
        GUri *uri;

#ifdef __SANITIZE_ADDRESS__
        g_test_skip ("Flakey on asan GitLab runner");
        return;
#endif

        async_context = g_main_context_ref_thread_default ();

        uri = g_uri_parse_relative (base_uri, "/slow", SOUP_HTTP_URI_FLAGS, NULL);
#define N_TESTS 100

        for (unsigned int i = 0; i < N_TESTS; ++i) {
                SoupMessage *msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
                soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_ready, &complete_count);
                g_object_unref (msg);
        }

        while (complete_count != N_TESTS) {
                g_main_context_iteration (async_context, TRUE);
        }

        /* After no messages reference the connection it should be IDLE and reusable */
        g_assert_cmpuint (soup_connection_get_state (last_connection), ==, SOUP_CONNECTION_IDLE);
        SoupMessage *msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_ready, &complete_count);
        g_object_unref (msg);

        while (complete_count != N_TESTS + 1)
                g_main_context_iteration (async_context, TRUE);

        g_uri_unref (uri);
        g_main_context_unref (async_context);
}

static void
do_misdirected_request_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/misdirected_request", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        response = soup_test_session_async_send (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Success!");

        g_bytes_unref (response);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
log_printer (SoupLogger *logger,
             SoupLoggerLogLevel level,
             char direction,
             const char *data,
             gpointer user_data)
{
        gboolean *has_logged_body = user_data;

        // We are testing that the request body is logged
        // which is backend specific for now
        if (direction == '>' && g_strcmp0 (data, "Test") == 0)
                *has_logged_body = TRUE;
}

static void
do_logging_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;
        GBytes *bytes = g_bytes_new_static ("Test", sizeof ("Test"));
        gboolean has_logged_body = FALSE;

        SoupLogger *logger = soup_logger_new (SOUP_LOGGER_LOG_BODY);
        soup_logger_set_printer (logger, log_printer, &has_logged_body, NULL);
        soup_session_add_feature (test->session, SOUP_SESSION_FEATURE (logger));
        g_clear_object (&logger);

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);

        response = soup_test_session_async_send (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Test");
        g_assert_true (has_logged_body);

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
msg_got_body_data_cb (SoupMessage *msg,
                      guint        chunk_size,
                      guint64     *response_body_bytes_received)
{
        *response_body_bytes_received += chunk_size;
}

static void
do_metrics_size_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;
        guint64 response_body_bytes_received = 0;
        GBytes *bytes = g_bytes_new_static ("Test", sizeof ("Test"));

        uri = g_uri_parse_relative (base_uri, "/echo_post", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_POST, uri);
        g_signal_connect (msg, "got-body-data",
                          G_CALLBACK (msg_got_body_data_cb),
                          &response_body_bytes_received);
        soup_message_set_request_body_from_bytes (msg, "text/plain", bytes);
        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);

        response = soup_test_session_async_send (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Test");

        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);
        g_assert_nonnull (metrics);

        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, g_bytes_get_size (bytes));
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), >, soup_message_metrics_get_request_body_size (metrics));

        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), ==, g_bytes_get_size (response));
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), >, soup_message_metrics_get_response_body_size (metrics));
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, response_body_bytes_received);

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
metrics_test_network_event_cb (SoupMessage       *msg,
                               GSocketClientEvent event,
                               GIOStream         *connection,
                               guint             *network_event_called)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);

        switch (event) {
        case G_SOCKET_CLIENT_RESOLVING:
                g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), >, 0);
                break;
        case G_SOCKET_CLIENT_RESOLVED:
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >=, soup_message_metrics_get_dns_start (metrics));
                break;
        case G_SOCKET_CLIENT_CONNECTING:
                g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >=, soup_message_metrics_get_dns_end (metrics));
                break;
        case G_SOCKET_CLIENT_TLS_HANDSHAKING:
                g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >=, soup_message_metrics_get_connect_start (metrics));
                break;
        case G_SOCKET_CLIENT_COMPLETE:
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >=, soup_message_metrics_get_connect_start (metrics));
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >=, soup_message_metrics_get_tls_start (metrics));
                break;
        default:
                return;
        }

        *network_event_called += 1;
}

static void
metrics_test_message_starting_cb (SoupMessage *msg,
                                  gboolean    *starting_called)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >=, soup_message_metrics_get_fetch_start (metrics));

        *starting_called = TRUE;
}

static void
metrics_test_status_changed_cb (SoupMessage *msg,
                                GParamSpec  *pspec,
                                gboolean    *status_changed_called)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >=, soup_message_metrics_get_request_start (metrics));

        *status_changed_called = TRUE;
}

static void
metrics_test_got_body_cb (SoupMessage *msg,
                          gboolean    *got_body_called)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >=, soup_message_metrics_get_response_start (metrics));

        *got_body_called = TRUE;
}

static void
do_one_metrics_time_test (SoupSession *session,
                          gboolean     is_new_connection)
{
        SoupMessage *msg;
        GBytes *body;
        SoupMessageMetrics *metrics;
        gboolean starting_called = FALSE;
        gboolean status_changed_called = FALSE;
        gboolean got_body_called = FALSE;
        guint network_event_called = 0;

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        g_signal_connect (msg, "starting",
                          G_CALLBACK (metrics_test_message_starting_cb),
                          &starting_called);
        g_signal_connect (msg, "notify::status-code",
                          G_CALLBACK (metrics_test_status_changed_cb),
                          &status_changed_called);
        g_signal_connect (msg, "got-body",
                          G_CALLBACK (metrics_test_got_body_cb),
                          &got_body_called);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (metrics_test_network_event_cb),
                          &network_event_called);
        body = soup_session_send_and_read (session, msg, NULL, NULL);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_bytes_unref (body);

        g_assert_true (starting_called);
        g_assert_true (status_changed_called);
        g_assert_true (got_body_called);
        if (is_new_connection)
                g_assert_cmpuint (network_event_called, ==, 5);
        else
                g_assert_cmpuint (network_event_called, ==, 0);

        metrics = soup_message_get_metrics (msg);
        g_assert_nonnull (metrics);
        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);
        if (is_new_connection) {
                g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >, 0);
        } else {
                g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), ==, 0);
        }
        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >, 0);
        g_object_unref (msg);
}

static void
do_metrics_time_test (Test *test, gconstpointer data)
{
        do_one_metrics_time_test (test->session, TRUE);
        do_one_metrics_time_test (test->session, FALSE);
}

static void
on_preconnect_ready (SoupSession     *session,
                     GAsyncResult    *result,
                     SoupConnection **conn)
{
        SoupMessage *msg = soup_session_get_async_result_message (session, result);
        GError *error = NULL;

        *conn = soup_message_get_connection (msg);
        soup_session_preconnect_finish (session, result, &error);
        g_assert_no_error (error);
}

static void
do_preconnect_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();
        SoupMessage *msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        GError *error = NULL;
        SoupConnection *conn = NULL;
        guint32 connection_id;

        soup_session_preconnect_async (test->session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)on_preconnect_ready,
                                       &conn);

        while (!conn)
                g_main_context_iteration (async_context, FALSE);

        connection_id = soup_message_get_connection_id (msg);
        g_assert_cmpuint (soup_connection_get_state (conn), ==, SOUP_CONNECTION_IDLE);
        g_object_unref (msg);

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        GBytes *response = soup_test_session_async_send (test->session, msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");
        g_assert_cmpuint (soup_message_get_connection_id (msg), ==, connection_id);

        g_bytes_unref (response);
        g_object_unref (msg);
        g_main_context_unref (async_context);
}

static void
do_invalid_header_test (Test *test, gconstpointer data)
{
        static const char *invalid_headers[] = { "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade" };
        guint i;

        for (i = 0; i < G_N_ELEMENTS (invalid_headers); i++) {
                SoupMessage *msg;
                SoupMessageHeaders *request_headers;
                GBytes *body;
                GError *error = NULL;

                msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
                request_headers = soup_message_get_request_headers (msg);
                soup_message_headers_append (request_headers, invalid_headers[i], "Value");
                body = soup_test_session_async_send (test->session, msg, NULL, &error);
                g_assert_no_error (error);
                g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "Hello world");
                g_bytes_unref (body);
                g_object_unref (msg);
        }
}

static void
do_invalid_header_received_test (Test *test, gconstpointer data)
{
        gboolean async = GPOINTER_TO_INT (data);
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/invalid-header", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);

        if (async)
                response = soup_test_session_async_send (test->session, msg, NULL, &error);
        else
                response = soup_session_send_and_read (test->session, msg, NULL, &error);

        g_assert_null (response);
        g_error_matches (error, G_IO_ERROR, G_IO_ERROR_FAILED);
        g_assert_cmpstr (error->message, ==, "HTTP/2 Error: PROTOCOL_ERROR");
        g_clear_error (&error);
        g_uri_unref (uri);
        g_object_unref (msg);
}

#ifdef HAVE_NGHTTP2_OPTION_SET_NO_RFC9113_LEADING_AND_TRAILING_WS_VALIDATION
static void
do_invalid_header_rfc9113_received_test (Test *test, gconstpointer data)
{
        gboolean async = GPOINTER_TO_INT (data);
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/invalid-header-rfc9113", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);

        if (async)
                response = soup_test_session_async_send (test->session, msg, NULL, &error);
        else
                response = soup_session_send_and_read (test->session, msg, NULL, &error);

        g_assert_nonnull (response);
        g_assert_no_error (error);
        g_bytes_unref (response);
        g_object_unref (msg);
        g_uri_unref (uri);
}
#endif

static void
content_sniffed (SoupMessage *msg,
                 const char  *content_type,
                 GHashTable  *params,
                 char       **sniffed_type)
{
        g_object_set_data (G_OBJECT (msg), "content-sniffed", GINT_TO_POINTER (TRUE));
        *sniffed_type = g_strdup (content_type);
}

static void
got_headers (SoupMessage *msg)
{
        soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
                          "content-sniffed got emitted before got-headers");

        g_object_set_data (G_OBJECT (msg), "got-headers", GINT_TO_POINTER (TRUE));
}

static void
sniffer_test_send_ready_cb (SoupSession   *session,
                            GAsyncResult  *result,
                            GInputStream **stream)
{
        GError *error = NULL;

        *stream = soup_session_send_finish (session, result, &error);
        g_assert_no_error (error);
        g_assert_nonnull (*stream);
}

static void
do_one_sniffer_test (SoupSession  *session,
                     const char   *path,
                     gsize         expected_size,
                     const char   *expected_type,
                     gboolean      should_sniff,
                     GMainContext *async_context)
{
        GUri *uri;
        SoupMessage *msg;
        GInputStream *stream = NULL;
        GBytes *bytes;
        char *sniffed_type = NULL;

        uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        g_object_connect (msg,
                          "signal::got-headers", got_headers, NULL,
                          "signal::content-sniffed", content_sniffed, &sniffed_type,
                          NULL);
        if (async_context) {
                soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                         (GAsyncReadyCallback)sniffer_test_send_ready_cb,
                                         &stream);

                while (!stream)
                        g_main_context_iteration (async_context, TRUE);
        } else {
                GError *error = NULL;

                stream = soup_session_send (session, msg, NULL, &error);
                g_assert_no_error (error);
                g_assert_nonnull (stream);
        }

        if (should_sniff) {
                soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") != NULL,
                                  "content-sniffed did not get emitted");
                g_assert_cmpstr (sniffed_type, ==, expected_type);
        } else {
                soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
                                  "content-sniffed got emitted without a sniffer");
                g_assert_null (sniffed_type);
        }

        bytes = read_stream_to_bytes_sync (stream);
        g_assert_cmpuint (g_bytes_get_size (bytes), ==, expected_size);

        g_free (sniffed_type);
        g_object_unref (stream);
        g_bytes_unref (bytes);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_sniffer_async_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();
        gboolean should_content_sniff = GPOINTER_TO_INT (data);

        if (should_content_sniff)
                soup_session_add_feature_by_type (test->session, SOUP_TYPE_CONTENT_SNIFFER);

        do_one_sniffer_test (test->session, "/", 11, "text/plain", should_content_sniff, async_context);
        do_one_sniffer_test (test->session, "/large", (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1, "text/plain", should_content_sniff, async_context);
        do_one_sniffer_test (test->session, "/no-content", 0, "text/plain", should_content_sniff, async_context);
        do_one_sniffer_test (test->session, "/no-content-but-has-content-type", 0, "text/javascript", should_content_sniff, async_context);
        do_one_sniffer_test (test->session, "/empty-but-has-content-type", 0, "text/javascript", should_content_sniff, async_context);

        g_main_context_unref (async_context);
}

static void
do_sniffer_sync_test (Test *test, gconstpointer data)
{
        gboolean should_content_sniff = GPOINTER_TO_INT (data);

        if (should_content_sniff)
                soup_session_add_feature_by_type (test->session, SOUP_TYPE_CONTENT_SNIFFER);

        do_one_sniffer_test (test->session, "/", 11, "text/plain", should_content_sniff, NULL);
        do_one_sniffer_test (test->session, "/large", (LARGE_N_CHARS * LARGE_CHARS_REPEAT) + 1, "text/plain", should_content_sniff, NULL);
        do_one_sniffer_test (test->session, "/no-content", 0, "text/plain", should_content_sniff, NULL);
        do_one_sniffer_test (test->session, "/no-content-but-has-content-type", 0, "text/javascript", should_content_sniff, NULL);
        do_one_sniffer_test (test->session, "/empty-but-has-content-type", 0, "text/javascript", should_content_sniff, NULL);

}

static void
do_timeout_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GBytes *response;
        GError *error = NULL;

        soup_session_set_timeout (test->session, 2);

        uri = g_uri_parse_relative (base_uri, "/timeout", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        response = soup_test_session_async_send (test->session, msg, NULL, &error);
        g_assert_null (response);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT);
        g_clear_error (&error);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_connection_closed_test (Test *test, gconstpointer data)
{
        GUri *uri;
        SoupMessage *msg;
        GInputStream *stream;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, "/close", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
        stream = soup_session_send (test->session, msg, NULL, &error);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT);
        g_clear_error (&error);
        g_clear_object (&stream);
        g_object_unref (msg);
        g_uri_unref (uri);
}

static void
do_broken_pseudo_header_test (Test *test, gconstpointer data)
{
	char *path;
	SoupMessage *msg;
	GUri *uri;
	GBytes *body = NULL;
	GError *error = NULL;

	uri = g_uri_parse_relative (base_uri, "/ag", SOUP_HTTP_URI_FLAGS, NULL);

	/* an ugly cheat to construct a broken URI, which can be sent from other libs */
	path = (char *) g_uri_get_path (uri);
	path[1] = '%';

	msg = soup_message_new_from_uri (SOUP_METHOD_GET, uri);
	body = soup_test_session_async_send (test->session, msg, NULL, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT);
	g_assert_null (body);
	g_clear_error (&error);
	g_object_unref (msg);
	g_uri_unref (uri);
}

static gboolean
unpause_message (SoupServerMessage *msg)
{
        soup_server_message_unpause (msg);
        g_object_unref (msg);
        return FALSE;
}

static void
server_handler (SoupServer        *server,
                SoupServerMessage *msg,
                const char        *path,
                GHashTable        *query,
                gpointer           user_data)
{
        g_assert_cmpuint (soup_server_message_get_http_version (msg), ==, SOUP_HTTP_2_0);

        if (strcmp (path, "/") == 0 || strcmp (path, "/slow") == 0 || strcmp (path, "/timeout") == 0) {
                gboolean is_slow = path[1] == 's';
                gboolean is_timeout = path[1] == 't';

                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC,
                                                  "Hello world", 11);
                if (is_slow || is_timeout) {
                        GSource *timeout;

                        soup_server_message_pause (msg);
                        timeout = soup_add_timeout (g_main_context_get_thread_default (),
                                                    is_timeout ? 4000 : 1000,
                                                    (GSourceFunc)unpause_message, g_object_ref (msg));
                        g_source_unref (timeout);
                }
        } else if (strcmp (path, "/no-content") == 0) {
                soup_server_message_set_status (msg, SOUP_STATUS_NO_CONTENT, NULL);
        } else if (strcmp (path, "/no-content-but-has-content-type") == 0) {
                soup_message_headers_set_content_type (soup_server_message_get_response_headers (msg), "text/javascript", NULL);
                soup_server_message_set_status (msg, SOUP_STATUS_NO_CONTENT, NULL);
        } else if (strcmp (path, "/empty-but-has-content-type") == 0) {
                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                soup_server_message_set_response (msg, "text/javascript",
                                                  SOUP_MEMORY_STATIC,
                                                  NULL, 0);
        } else if (strcmp (path, "/large") == 0) {
                int i, j;
                SoupMessageBody *response_body;
                char letter = 'A';

                /* Send increasing letters just to aid debugging */
                response_body = soup_server_message_get_response_body (msg);
                for (i = 0; i < LARGE_N_CHARS; i++, letter++) {
                        GString *chunk = g_string_new (NULL);
                        GBytes *bytes;

                        for (j = 0; j < LARGE_CHARS_REPEAT; j++)
                                chunk = g_string_append_c (chunk, letter);

                        bytes = g_string_free_to_bytes (chunk);
                        soup_message_body_append_bytes (response_body, bytes);
                        g_bytes_unref (bytes);
                }
                soup_message_body_append (response_body, SOUP_MEMORY_STATIC, "\0", 1);

                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        } else if (strcmp (path, "/larger-than-window") == 0) {
                char *big_data = g_malloc0 (REALLY_LARGE_BUFFER_SIZE);
                GBytes *bytes = g_bytes_new_take (big_data, REALLY_LARGE_BUFFER_SIZE);

                SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
                soup_message_body_append_bytes (response_body, bytes);
                g_bytes_unref (bytes);

                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        } else if (strcmp (path, "/echo_query") == 0) {
                const char *query_str = g_uri_get_query (soup_server_message_get_uri (msg));

                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC,
                                                  query_str, strlen (query_str));
        } else if (strcmp (path, "/echo_post") == 0) {
                SoupMessageBody *request_body;

                request_body = soup_server_message_get_request_body (msg);
                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_COPY,
                                                  request_body->data,
                                                  request_body->length);
        } else if (strcmp (path, "/misdirected_request") == 0) {
                static SoupServerConnection *conn = NULL;

                if (!conn) {
                        conn = soup_server_message_get_connection (msg);
                        soup_server_message_set_status (msg, SOUP_STATUS_MISDIRECTED_REQUEST, NULL);
                } else {
                        /* Message is retried on a different connection */
                        g_assert_false (conn == soup_server_message_get_connection (msg));
                        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                        soup_server_message_set_response (msg, "text/plain",
                                                          SOUP_MEMORY_STATIC,
                                                          "Success!", 8);
                }
        } else if (strcmp (path, "/auth") == 0) {
                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC,
                                                  "Authenticated", 13);
        } else if (strcmp (path, "/invalid-header") == 0) {
                SoupMessageHeaders *response_headers;

                response_headers = soup_server_message_get_response_headers (msg);
                /* Use soup_message_headers_append_common to skip the validation check. */
                soup_message_headers_append_common (response_headers, SOUP_HEADER_CONTENT_TYPE, "\r");
                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        } else if (strcmp (path, "/invalid-header-rfc9113") == 0) {
                SoupMessageHeaders *response_headers;

                response_headers = soup_server_message_get_response_headers (msg);
                soup_message_headers_append (response_headers, "Invalid-Header-Value", "foo ");
                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC,
                                                  "Success!", 8);
                soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        } else if (strcmp (path, "/close") == 0) {
                SoupServerConnection *conn;
                int fd;

                conn = soup_server_message_get_connection (msg);
                fd = g_socket_get_fd (soup_server_connection_get_socket (conn));
#ifdef G_OS_WIN32
                shutdown (fd, SD_SEND);
#else
                shutdown (fd, SHUT_WR);
#endif

                soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC,
                                                  "Success!", 8);
        }
}

static gboolean
server_basic_auth_callback (SoupAuthDomain    *auth_domain,
                            SoupServerMessage *msg,
                            const char        *username,
                            const char        *password,
                            gpointer           data)
{
        if (strcmp (username, "username") != 0)
                return FALSE;

        return strcmp (password, "password") == 0;
}

int
main (int argc, char **argv)
{
        SoupServer *server;
        SoupAuthDomain *auth;
	int ret;

	test_init (argc, argv, NULL);

        if (!tls_available)
                return 0;

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD | SOUP_TEST_SERVER_HTTP2);
        auth = soup_auth_domain_basic_new ("realm", "http2-test",
                                           "auth-callback", server_basic_auth_callback,
                                           NULL);
        soup_auth_domain_add_path (auth, "/auth");
        soup_server_add_auth_domain (server, auth);
        g_object_unref (auth);

        soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
        base_uri = soup_test_server_get_uri (server, "https", "127.0.0.1");

        g_test_add ("/http2/basic/async", Test, NULL,
                    setup_session,
                    do_basic_async_test,
                    teardown_session);
        g_test_add ("/http2/basic/sync", Test, NULL,
                    setup_session,
                    do_basic_sync_test,
                    teardown_session);
        g_test_add ("/http2/no_content/async", Test, NULL,
                    setup_session,
                    do_no_content_async_test,
                    teardown_session);
        g_test_add ("/http2/large/async", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_large_test,
                    teardown_session);
        g_test_add ("/http2/large/sync", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_large_test,
                    teardown_session);
        g_test_add ("/http2/multiplexing/async", Test, NULL,
                    setup_session,
                    do_multi_message_async_test,
                    teardown_session);
        g_test_add ("/http2/post/async", Test, NULL,
                    setup_session,
                    do_post_async_test,
                    teardown_session);
        g_test_add ("/http2/post/sync", Test, NULL,
                    setup_session,
                    do_post_sync_test,
                    teardown_session);
        g_test_add ("/http2/post/large/sync", Test, NULL,
                    setup_session,
                    do_post_large_sync_test,
                    teardown_session);
        g_test_add ("/http2/post/large/async", Test, NULL,
                    setup_session,
                    do_post_large_async_test,
                    teardown_session);
        g_test_add ("/http2/post/blocked/async", Test, NULL,
                    setup_session,
                    do_post_blocked_async_test,
                    teardown_session);
        g_test_add ("/http2/post/file/async", Test, NULL,
                    setup_session,
                    do_post_file_async_test,
                    teardown_session);
        g_test_add ("/http2/paused/async", Test, NULL,
                    setup_session,
                    do_paused_async_test,
                    teardown_session);
        g_test_add ("/http2/flow-control/large/async", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_flow_control_large_test,
                    teardown_session);
        g_test_add ("/http2/flow-control/large/sync", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_flow_control_large_test,
                    teardown_session);
        g_test_add ("/http2/flow-control/multiplex/async", Test, NULL,
                    setup_session,
                    do_flow_control_multi_message_async_test,
                    teardown_session);
        g_test_add ("/http2/flow-control/buffer-size", Test, NULL,
                    setup_session,
                    do_flow_control_buffer_sizes,
                    teardown_session);
        g_test_add ("/http2/connections", Test, NULL,
                    setup_session,
                    do_connections_test,
                    teardown_session);
        g_test_add ("/http2/misdirected_request", Test, NULL,
                    setup_session,
                    do_misdirected_request_test,
                    teardown_session);
        g_test_add ("/http2/logging", Test, NULL,
                    setup_session,
                    do_logging_test,
                    teardown_session);
        g_test_add ("/http2/metrics/size", Test, NULL,
                    setup_session,
                    do_metrics_size_test,
                    teardown_session);
        g_test_add ("/http2/metrics/time", Test, NULL,
                    setup_session,
                    do_metrics_time_test,
                    teardown_session);
        g_test_add ("/http2/preconnect", Test, NULL,
                    setup_session,
                    do_preconnect_test,
                    teardown_session);
        g_test_add ("/http2/cancellation", Test, NULL,
                    setup_session,
                    do_cancellation_test,
                    teardown_session);
        g_test_add ("/http2/cancellation-after-send", Test, NULL,
                    setup_session,
                    do_cancellation_after_send_test,
                    teardown_session);
        g_test_add ("/http2/invalid-header", Test, NULL,
                    setup_session,
                    do_invalid_header_test,
                    teardown_session);
        g_test_add ("/http2/invalid-header-received/async", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_invalid_header_received_test,
                    teardown_session);
        g_test_add ("/http2/invalid-header-received/sync", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_invalid_header_received_test,
                    teardown_session);
#ifdef HAVE_NGHTTP2_OPTION_SET_NO_RFC9113_LEADING_AND_TRAILING_WS_VALIDATION
        g_test_add ("/http2/invalid-header-rfc9113-received/async", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_invalid_header_rfc9113_received_test,
                    teardown_session);
        g_test_add ("/http2/invalid-header-rfc9113-received/sync", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_invalid_header_rfc9113_received_test,
                    teardown_session);
#endif
        g_test_add ("/http2/sniffer/with-sniffer/async", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_sniffer_async_test,
                    teardown_session);
        g_test_add ("/http2/sniffer/no-sniffer/async", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_sniffer_async_test,
                    teardown_session);
        g_test_add ("/http2/sniffer/with-sniffer/sync", Test, GINT_TO_POINTER (TRUE),
                    setup_session,
                    do_sniffer_sync_test,
                    teardown_session);
        g_test_add ("/http2/sniffer/no-sniffer/sync", Test, GINT_TO_POINTER (FALSE),
                    setup_session,
                    do_sniffer_sync_test,
                    teardown_session);
        g_test_add ("/http2/timeout", Test, NULL,
                    setup_session,
                    do_timeout_test,
                    teardown_session);
        g_test_add ("/http2/connection-closed", Test, NULL,
                    setup_session,
                    do_connection_closed_test,
                    teardown_session);
        g_test_add ("/http2/broken-pseudo-header", Test, NULL,
                    setup_session,
                    do_broken_pseudo_header_test,
                    teardown_session);

	ret = g_test_run ();

        g_uri_unref (base_uri);
        soup_test_server_quit_unref (server);

        test_cleanup ();

	return ret;
}
