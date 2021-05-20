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
#include "soup-body-input-stream-http2.h"

typedef struct {
        SoupSession *session;
        SoupMessage *msg;
} Test;

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
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/");
        GError *error = NULL;
        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");

        g_bytes_unref (response);
        g_object_unref (test->msg);
}

static void
do_basic_sync_test (Test *test, gconstpointer data)
{
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/");
        GError *error = NULL;

        GBytes *response = soup_session_send_and_read (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");

        g_bytes_unref (response);
        g_object_unref (test->msg);
}

static void
do_no_content_async_test (Test *test, gconstpointer data)
{
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/no-content");
        GError *error = NULL;

        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpuint (soup_message_get_status (test->msg), ==, 204);
        g_assert_cmpuint (g_bytes_get_size (response), ==, 0);

        g_bytes_unref (response);
        g_object_unref (test->msg);
}

static void
do_large_async_test (Test *test, gconstpointer data)
{
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/large");
        GError *error = NULL;

        /* This is both large and read in chunks */
        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        /* Size hardcoded to match http2-server.py's response */
        g_assert_cmpuint (g_bytes_get_size (response), ==, (1024 * 24) + 1);

        g_bytes_unref (response);
        g_object_unref (test->msg);
}

static GBytes *
read_stream_to_bytes_sync (GInputStream *stream)
{
        GOutputStream *out = g_memory_output_stream_new_resizable ();
        GError *error = NULL;

        gssize read = g_output_stream_splice (out, stream,  G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE | G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                              NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpint (read, >, 0);

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

        SoupMessage *msg1 = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/echo_query?body%201");
        soup_message_set_http_version (msg1, SOUP_HTTP_2_0);

        SoupMessage *msg2 = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/echo_query?body%202");
        soup_message_set_http_version (msg2, SOUP_HTTP_2_0);

        GBytes *response1 = NULL;
        GBytes *response2 = NULL;
        soup_session_send_async (test->session, msg1, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response1);
        soup_session_send_async (test->session, msg2, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response2);

        while (!response1 || !response2) {
                g_main_context_iteration (async_context, TRUE);
        }

        g_assert_cmpuint (soup_message_get_http_version (msg1), ==, SOUP_HTTP_2_0);
        g_assert_cmpuint (soup_message_get_http_version (msg2), ==, SOUP_HTTP_2_0);

        g_assert_cmpstr (g_bytes_get_data (response1, NULL), ==, "body%201");
        g_assert_cmpstr (g_bytes_get_data (response2, NULL), ==, "body%202");

        while (g_main_context_pending (async_context))
                g_main_context_iteration (async_context, FALSE);

        g_bytes_unref (response1);
        g_bytes_unref (response2);
        g_object_unref (msg1);
        g_object_unref (msg2);
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
        SoupMessage *msg;
        GMainContext *async_context = g_main_context_ref_thread_default ();
        GCancellable *cancellable = g_cancellable_new ();
        gboolean done = FALSE;

        msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/large");
        soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, cancellable,
                                          (GAsyncReadyCallback)on_send_and_read_cancelled_complete, &done);

        /* Just iterate until a partial read is happening */
        for (guint i = 100000; i; i--)
                g_main_context_iteration (async_context, FALSE);

        /* Then cancel everything */
        g_cancellable_cancel (cancellable);

        while (!done)
                g_main_context_iteration (async_context, FALSE);

        g_object_unref (msg);

        done = FALSE;
        msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/large");
        soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)on_send_and_read_complete, &done);

        while (!done)
                g_main_context_iteration (async_context, FALSE);

        g_object_unref (msg);
        g_object_unref (cancellable);
        g_main_context_unref (async_context);
}

static void
do_post_sync_test (Test *test, gconstpointer data)
{
        GBytes *bytes = g_bytes_new_static ("body 1", sizeof ("body 1"));
        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body_from_bytes (test->msg, "text/plain", bytes);

        GError *error = NULL;
        GInputStream *response = soup_session_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_nonnull (response);

        GBytes *response_bytes = read_stream_to_bytes_sync (response);
        g_assert_cmpstr (g_bytes_get_data (response_bytes, NULL), ==, "body 1");

        g_bytes_unref (response_bytes);
        g_object_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (test->msg);

}

static void
do_post_async_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();

        GBytes *bytes = g_bytes_new_static ("body 1", sizeof ("body 1"));
        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body_from_bytes (test->msg, "text/plain", bytes);

        GBytes *response = NULL;
        soup_session_send_async (test->session, test->msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response) {
                g_main_context_iteration (async_context, TRUE);
        }

        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "body 1");

        while (g_main_context_pending (async_context))
                g_main_context_iteration (async_context, FALSE);

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_main_context_unref (async_context);
        g_object_unref (test->msg);
}

static void
do_post_blocked_async_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();

        GInputStream *parent_stream = g_memory_input_stream_new ();
        GInputStream *in_stream = soup_body_input_stream_http2_new (G_POLLABLE_INPUT_STREAM (parent_stream));
        soup_body_input_stream_http2_add_data (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream), (guint8*)"Part 1 -", 8);

        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body (test->msg, "text/plain", in_stream, 8 + 8);

        GBytes *response = NULL;
        soup_session_send_async (test->session, test->msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        int iteration_count = 20;
        while (!response) {
                // Let it iterate for a bit waiting on blocked data
                if (iteration_count-- == 0) {
                        soup_body_input_stream_http2_add_data (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream), (guint8*)" Part 2", 8);
                        soup_body_input_stream_http2_complete (SOUP_BODY_INPUT_STREAM_HTTP2 (in_stream));
                }
                g_main_context_iteration (async_context, TRUE);
        }

        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Part 1 - Part 2");

        while (g_main_context_pending (async_context))
                g_main_context_iteration (async_context, FALSE);

        g_bytes_unref (response);
        g_object_unref (parent_stream);
        g_object_unref (in_stream);
        g_main_context_unref (async_context);
        g_object_unref (test->msg);
}

static void
do_post_file_async_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();

        GFile *in_file = g_file_new_for_path (g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL));
        GFileInputStream *in_stream = g_file_read (in_file, NULL, NULL);
        g_assert_nonnull (in_stream);

        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body (test->msg, "application/x-x509-ca-cert", G_INPUT_STREAM (in_stream), -1);

        GBytes *response = NULL;
        soup_session_send_async (test->session, test->msg, G_PRIORITY_DEFAULT, NULL, on_send_complete, &response);

        while (!response)
                g_main_context_iteration (async_context, TRUE);

        g_assert_true (g_str_has_prefix (g_bytes_get_data (response, NULL), "-----BEGIN CERTIFICATE-----"));

        while (g_main_context_pending (async_context))
                g_main_context_iteration (async_context, FALSE);

        g_bytes_unref (response);
        g_object_unref (in_stream);
        g_object_unref (in_file);
        g_main_context_unref (async_context);
        g_object_unref (test->msg);
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

        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/auth");
        g_signal_connect (test->msg, "authenticate", G_CALLBACK (on_authenticate), NULL);

        GError *error = NULL;
        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Authenticated");

        g_bytes_unref (response);
        g_object_unref (test->msg);
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

        GBytes *result = read_stream_to_bytes_sync (stream);
        g_object_unref (stream);
        g_assert_nonnull (result);
        g_assert_cmpstr (g_bytes_get_data (result, NULL), ==, "Hello world");
        g_bytes_unref (result);

        g_assert_nonnull (msg);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_2_0);
        conn = soup_message_get_connection (msg);

        if (last_connection)
                g_assert (last_connection == conn);
        else
                last_connection = conn;
        
        g_test_message ("Conn (%u) = %p", *complete_count, conn);

        *complete_count += 1;
}

static void
do_connections_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();
        guint complete_count = 0;

#define N_TESTS 100

        for (uint i = 0; i < N_TESTS; ++i) {
                SoupMessage *msg = soup_message_new ("GET", "https://127.0.0.1:5000/slow");
                soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_ready, &complete_count);
                g_object_unref (msg);
        }

        while (complete_count != N_TESTS) {
                g_main_context_iteration (async_context, TRUE);
        }

        // After no messages reference the connection we should still be able to re-use the same connection
        SoupMessage *msg = soup_message_new ("GET", "https://127.0.0.1:5000/slow");
        soup_session_send_async (test->session, msg, G_PRIORITY_DEFAULT, NULL, on_send_ready, &complete_count);
        g_object_unref (msg);

        while (g_main_context_pending (async_context))
                g_main_context_iteration (async_context, FALSE);

        g_main_context_unref (async_context);
}

static void
do_misdirected_request_test (Test *test, gconstpointer data)
{
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/misdirected_request");
        GError *error = NULL;

        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Success!");

        g_bytes_unref (response);
        g_object_unref (test->msg);
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
        gboolean has_logged_body = FALSE;

        SoupLogger *logger = soup_logger_new (SOUP_LOGGER_LOG_BODY);
        soup_logger_set_printer (logger, log_printer, &has_logged_body, NULL);
        soup_session_add_feature (test->session, SOUP_SESSION_FEATURE (logger));

        GBytes *bytes = g_bytes_new_static ("Test", sizeof ("Test"));
        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body_from_bytes (test->msg, "text/plain", bytes);
        GError *error = NULL;

        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Test");
        g_assert_true (has_logged_body);

        g_bytes_unref (response);
        g_object_unref (test->msg);
}

static void
do_metrics_test (Test *test, gconstpointer data)
{
        GBytes *bytes = g_bytes_new_static ("Test", sizeof ("Test"));
        test->msg = soup_message_new (SOUP_METHOD_POST, "https://127.0.0.1:5000/echo_post");
        soup_message_set_request_body_from_bytes (test->msg, "text/plain", bytes);
        soup_message_add_flags (test->msg, SOUP_MESSAGE_COLLECT_METRICS);

        GError *error = NULL;
        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Test");

        SoupMessageMetrics *metrics = soup_message_get_metrics (test->msg);
        g_assert_nonnull (metrics);

        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, g_bytes_get_size (bytes));
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), >, soup_message_metrics_get_request_body_size (metrics));

        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), ==, g_bytes_get_size (response));
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), >, soup_message_metrics_get_response_body_size (metrics));

        g_bytes_unref (response);
        g_bytes_unref (bytes);
        g_object_unref (test->msg);
}

static void
on_preconnect_ready (SoupSession *session, GAsyncResult *res, gboolean *has_preconnected)
{
        GError *error = NULL;

        soup_session_preconnect_finish (session, res, &error);
        g_assert_no_error (error);

        *has_preconnected = TRUE;
}

static void
do_preconnect_test (Test *test, gconstpointer data)
{
        GMainContext *async_context = g_main_context_ref_thread_default ();
        test->msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/");
        gboolean has_preconnected = FALSE;
        GError *error = NULL;
        guint32 connection_id;

        soup_session_preconnect_async (test->session, test->msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)on_preconnect_ready, &has_preconnected);

        while (!has_preconnected)
                g_main_context_iteration (async_context, FALSE);

        connection_id = soup_message_get_connection_id (test->msg);

        GBytes *response = soup_test_session_async_send (test->session, test->msg, NULL, &error);

        g_assert_no_error (error);
        g_assert_cmpstr (g_bytes_get_data (response, NULL), ==, "Hello world");
        g_assert_cmpuint (soup_message_get_connection_id (test->msg), ==, connection_id);

        g_bytes_unref (response);
        g_object_unref (test->msg);
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

                msg = soup_message_new (SOUP_METHOD_GET, "https://127.0.0.1:5000/");
                request_headers = soup_message_get_request_headers (msg);
                soup_message_headers_append (request_headers, invalid_headers[i], "Value");
                body = soup_test_session_async_send (test->session, msg, NULL, &error);
                g_assert_no_error (error);
                g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "Hello world");
                g_bytes_unref (body);
                g_object_unref (msg);
        }
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

        if (!quart_init ()) {
                test_cleanup ();
                return 1;
        }

        g_setenv ("SOUP_ENABLE_HTTP2", "1", TRUE);

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
        g_test_add ("/http2/large/async", Test, NULL,
                    setup_session,
                    do_large_async_test,
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
        g_test_add ("/http2/metrics", Test, NULL,
                    setup_session,
                    do_metrics_test,
                    teardown_session);
        g_test_add ("/http2/preconnect", Test, NULL,
                    setup_session,
                    do_preconnect_test,
                    teardown_session);
        g_test_add ("/http2/cancellation", Test, NULL,
                    setup_session,
                    do_cancellation_test,
                    teardown_session);
        g_test_add ("/http2/invalid-header", Test, NULL,
                    setup_session,
                    do_invalid_header_test,
                    teardown_session);



	ret = g_test_run ();

        test_cleanup ();

	return ret;
}
