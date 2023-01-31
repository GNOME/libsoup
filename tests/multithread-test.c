/*
 * Copyright 2022 Igalia S.L.
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

static GUri *base_uri;

typedef enum {
        BASIC_SYNC = 1 << 0,
        BASIC_SSL = 1 << 1,
        BASIC_PROXY = 1 << 2,
        BASIC_HTTP2 = 1 << 3,
        BASIC_MAX_CONNS = 1 << 4,
        BASIC_NO_MAIN_THREAD = 1 << 5
} BasicTestFlags;

typedef struct {
        SoupSession *session;
        BasicTestFlags flags;
} Test;

#define HTTPS_SERVER "https://127.0.0.1:47525"
#define HTTP_PROXY   "http://127.0.0.1:47526"

static void
test_setup (Test *test, gconstpointer data)
{
        test->flags = GPOINTER_TO_UINT (data);
        if (test->flags & BASIC_MAX_CONNS)
                test->session = soup_test_session_new ("max-conns", 1, NULL);
        else
                test->session = soup_test_session_new (NULL);
}

static void
test_teardown (Test *test, gconstpointer data)
{
        soup_test_session_abort_unref (test->session);
        while (g_main_context_pending (NULL))
                g_main_context_iteration (NULL, FALSE);
}

static void
msg_signal_check_context (SoupMessage  *msg,
                          GMainContext *context)
{
        g_assert_true (g_object_get_data (G_OBJECT (msg), "thread-context") == context);
}

static void
connect_message_signals_to_check_context (SoupMessage  *msg,
                                          GMainContext *context)
{
        g_object_set_data (G_OBJECT (msg), "thread-context", context);
        g_signal_connect (msg, "starting", G_CALLBACK (msg_signal_check_context), context);
        g_signal_connect (msg, "wrote-headers", G_CALLBACK (msg_signal_check_context), context);
        g_signal_connect (msg, "wrote-body", G_CALLBACK (msg_signal_check_context), context);
        g_signal_connect (msg, "got-headers", G_CALLBACK (msg_signal_check_context), context);
        g_signal_connect (msg, "got-body", G_CALLBACK (msg_signal_check_context), context);
        g_signal_connect (msg, "finished", G_CALLBACK (msg_signal_check_context), context);
}

static void
msg_signal_check_thread (SoupMessage *msg,
                         GThread     *thread)
{
        g_assert_true (g_object_get_data (G_OBJECT (msg), "thread-id") == thread);
}

static void
connect_message_signals_to_check_thread (SoupMessage *msg,
                                         GThread     *thread)
{
        g_object_set_data (G_OBJECT (msg), "thread-id", thread);
        g_signal_connect (msg, "starting", G_CALLBACK (msg_signal_check_thread), thread);
        g_signal_connect (msg, "wrote-headers", G_CALLBACK (msg_signal_check_thread), thread);
        g_signal_connect (msg, "wrote-body", G_CALLBACK (msg_signal_check_thread), thread);
        g_signal_connect (msg, "got-headers", G_CALLBACK (msg_signal_check_thread), thread);
        g_signal_connect (msg, "got-body", G_CALLBACK (msg_signal_check_thread), thread);
        g_signal_connect (msg, "finished", G_CALLBACK (msg_signal_check_thread), thread);
}

static void
message_send_and_read_ready_cb (SoupSession  *session,
                                GAsyncResult *result,
                                GMainLoop    *loop)
{
        GBytes *body;
        GBytes *index = soup_test_get_index ();
        GError *error = NULL;

        if (loop)
                g_assert_true (g_main_loop_get_context (loop) == g_main_context_get_thread_default ());

        body = soup_session_send_and_read_finish (session, result, &error);
        g_assert_no_error (error);
        g_assert_nonnull (body);
        g_assert_cmpmem (g_bytes_get_data (body, NULL), g_bytes_get_size (body), g_bytes_get_data (index, NULL), g_bytes_get_size (index));
        g_bytes_unref (body);

        if (loop)
                g_main_loop_quit (loop);
}

static void
task_async_function (GTask        *task,
                     GObject      *source,
                     Test         *test,
                     GCancellable *cancellable)
{
        GMainContext *context;
        GMainLoop *loop;
        SoupMessage *msg;

        context = g_main_context_new ();
        g_main_context_push_thread_default (context);

        loop = g_main_loop_new (context, FALSE);

        if (test->flags & BASIC_SSL)
                msg = soup_message_new ("GET", HTTPS_SERVER);
        else
                msg = soup_message_new_from_uri ("GET", base_uri);
        if (test->flags & BASIC_HTTP2)
                soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        connect_message_signals_to_check_context (msg, context);
        soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)message_send_and_read_ready_cb,
                                          loop);
        g_object_unref (msg);

        g_main_loop_run (loop);
        g_main_loop_unref (loop);

        g_task_return_boolean (task, TRUE);

        g_main_context_pop_thread_default (context);
        g_main_context_unref (context);
}

static void
task_sync_function (GTask        *task,
                    GObject      *source,
                    Test         *test,
                    GCancellable *cancellable)
{
        SoupMessage *msg;
        GBytes *body;
        GBytes *index = soup_test_get_index ();
        GError *error = NULL;

        if (test->flags & BASIC_SSL)
                msg = soup_message_new ("GET", HTTPS_SERVER);
        else
                msg = soup_message_new_from_uri ("GET", base_uri);
        if (test->flags & BASIC_HTTP2)
                soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        connect_message_signals_to_check_thread (msg, g_thread_self ());
        body = soup_session_send_and_read (test->session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_nonnull (body);
        g_assert_cmpmem (g_bytes_get_data (body, NULL), g_bytes_get_size (body), g_bytes_get_data (index, NULL), g_bytes_get_size (index));
        g_bytes_unref (body);
        g_object_unref (msg);

        g_task_return_boolean (task, TRUE);
}

static void
task_finished_cb (GObject      *source,
                  GAsyncResult *result,
                  guint        *finished_count)
{
        g_assert_true (g_task_propagate_boolean (G_TASK (result), NULL));
        g_atomic_int_inc (finished_count);
}

static void
message_finished_cb (SoupMessage *msg,
                     guint       *finished_count)
{
        g_atomic_int_inc (finished_count);
}

static void
do_multithread_basic_test (Test         *test,
                           gconstpointer data)
{
        SoupMessage *msg = NULL;
        guint n_msgs = 6;
        guint n_main_thread_msgs;
        guint i;
        guint finished_count = 0;

        if (test->flags & BASIC_PROXY) {
                GProxyResolver *resolver;

                resolver = g_simple_proxy_resolver_new (HTTP_PROXY, NULL);
                soup_session_set_proxy_resolver (test->session, resolver);
                g_object_unref (resolver);
        }

        n_main_thread_msgs = test->flags & BASIC_NO_MAIN_THREAD ? 0 : 1;

        if (n_main_thread_msgs) {
                if (test->flags & BASIC_SSL)
                        msg = soup_message_new ("GET", HTTPS_SERVER);
                else
                        msg = soup_message_new_from_uri ("GET", base_uri);
                if (test->flags & BASIC_HTTP2)
                        soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
                if (test->flags & BASIC_SYNC)
                        connect_message_signals_to_check_thread (msg, g_thread_self ());
                else
                        connect_message_signals_to_check_context (msg, g_main_context_get_thread_default ());
                g_signal_connect (msg, "finished",
                                  G_CALLBACK (message_finished_cb),
                                  &finished_count);
                soup_session_send_and_read_async (test->session, msg, G_PRIORITY_DEFAULT, NULL,
                                                  (GAsyncReadyCallback)message_send_and_read_ready_cb,
                                                  NULL);
        }

        for (i = 0; i < n_msgs - n_main_thread_msgs; i++) {
                GTask *task;

                task = g_task_new (NULL, NULL, (GAsyncReadyCallback)task_finished_cb, &finished_count);
                g_task_set_task_data (task, test, NULL);
                g_task_run_in_thread (task, (GTaskThreadFunc)(test->flags & BASIC_SYNC ? task_sync_function : task_async_function));
                g_object_unref (task);
        }

        while (g_atomic_int_get (&finished_count) != n_msgs)
                g_main_context_iteration (NULL, TRUE);

        g_clear_object (&msg);

        while (g_main_context_pending (NULL))
                g_main_context_iteration (NULL, FALSE);
}

static void
do_multithread_basic_proxy_test (Test         *test,
                                 gconstpointer data)
{
        SOUP_TEST_SKIP_IF_NO_APACHE;

        do_multithread_basic_test (test, data);
}

static void
do_multithread_basic_ssl_test (Test         *test,
                               gconstpointer data)
{
        SOUP_TEST_SKIP_IF_NO_TLS;
        SOUP_TEST_SKIP_IF_NO_APACHE;

        do_multithread_basic_test (test, data);
}

static void
connections_test_msg_starting (SoupMessage     *msg,
                               SoupConnection **conn)
{
        *conn = g_object_ref (soup_message_get_connection (msg));
}

static void
connections_test_task_async_function (GTask        *task,
                                      GObject      *source,
                                      Test         *test,
                                      GCancellable *cancellable)
{
        GMainContext *context;
        SoupMessage *msg;
        GBytes *body;
        SoupConnection *conn = NULL;

        context = g_main_context_new ();
        g_main_context_push_thread_default (context);

        if (test->flags & BASIC_SSL)
                msg = soup_message_new ("GET", HTTPS_SERVER);
        else
                msg = soup_message_new_from_uri ("GET", base_uri);
        if (test->flags & BASIC_HTTP2)
                soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        g_signal_connect (msg, "starting",
                          G_CALLBACK (connections_test_msg_starting),
                          &conn);
        body = soup_test_session_async_send (test->session, msg, NULL, NULL);
        g_bytes_unref (body);
        g_object_unref (msg);

        g_task_return_pointer (task, conn, g_object_unref);

        g_main_context_pop_thread_default (context);
        g_main_context_unref (context);
}

static void
connections_test_task_sync_function (GTask        *task,
                                     GObject      *source,
                                     Test         *test,
                                     GCancellable *cancellable)
{
        SoupMessage *msg;
        GBytes *body;
        SoupConnection *conn = NULL;

        if (test->flags & BASIC_SSL)
                msg = soup_message_new ("GET", HTTPS_SERVER);
        else
                msg = soup_message_new_from_uri ("GET", base_uri);
        if (test->flags & BASIC_HTTP2)
                soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        g_signal_connect (msg, "starting",
                          G_CALLBACK (connections_test_msg_starting),
                          &conn);
        body = soup_session_send_and_read (test->session, msg, NULL, NULL);
        g_bytes_unref (body);
        g_object_unref (msg);

        g_task_return_pointer (task, conn, g_object_unref);
}

static void
do_multithread_connections_test (Test         *test,
                                 gconstpointer data)
{
        SoupMessage *msg;
        SoupConnection *conn = NULL;
        SoupConnection *thread_conn;
        GBytes *body;
        GTask *task;

        if (test->flags & BASIC_SSL)
                msg = soup_message_new ("GET", HTTPS_SERVER);
        else
                msg = soup_message_new_from_uri ("GET", base_uri);
        if (test->flags & BASIC_HTTP2)
                soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        g_signal_connect (msg, "starting",
                          G_CALLBACK (connections_test_msg_starting),
                          &conn);
        body = soup_test_session_async_send (test->session, msg, NULL, NULL);
        g_bytes_unref (body);

        g_assert_nonnull (conn);
        g_assert_cmpuint (soup_connection_get_state (conn), ==, SOUP_CONNECTION_IDLE);

        /* An idle connection can be reused by another thread */
        task = g_task_new (NULL, NULL, NULL, NULL);
        g_task_set_task_data (task, test, NULL);
        g_task_run_in_thread_sync (task, (GTaskThreadFunc)(test->flags & BASIC_SYNC ? connections_test_task_sync_function : connections_test_task_async_function));
        thread_conn = g_task_propagate_pointer (task, NULL);
        g_object_unref (task);
        g_assert_true (conn == thread_conn);
        g_object_unref (thread_conn);

        g_object_unref (conn);
        g_object_unref (msg);
}

static void
do_multithread_connections_http2_test (Test         *test,
                                       gconstpointer data)
{
        SOUP_TEST_SKIP_IF_NO_TLS;
        SOUP_TEST_SKIP_IF_NO_APACHE;

        do_multithread_connections_test (test, data);
}

static void
do_multithread_no_main_context_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *body;
        GBytes *index = soup_test_get_index ();
        guint i;

        SOUP_TEST_SKIP_IF_NO_TLS;
        SOUP_TEST_SKIP_IF_NO_APACHE;

        session = soup_test_session_new (NULL);

        for (i = 0; i < 2; i++) {
                msg = soup_message_new ("GET", HTTPS_SERVER);
                if (i > 0)
                        soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
                body = soup_session_send_and_read (session, msg, NULL, NULL);
                g_assert_nonnull (body);
                g_assert_cmpmem (g_bytes_get_data (body, NULL), g_bytes_get_size (body), g_bytes_get_data (index, NULL), g_bytes_get_size (index));
                g_bytes_unref (body);
                g_object_unref (msg);
        }

        soup_test_session_abort_unref (session);
}

static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg,
                 const char        *path,
                 GHashTable        *query,
                 gpointer           data)
{
        GBytes *index = soup_test_get_index ();

        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_server_message_set_response (msg, "text/plain",
                                          SOUP_MEMORY_STATIC,
                                          g_bytes_get_data (index, NULL),
                                          g_bytes_get_size (index));
}

int
main (int argc, char **argv)
{
        int ret;
        SoupServer *server;

        test_init (argc, argv, NULL);
        apache_init ();

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
        soup_server_add_handler (server, NULL, server_callback, "http", NULL);
        base_uri = soup_test_server_get_uri (server, "http", NULL);

        g_test_add ("/multithread/basic/async", Test,
                    GUINT_TO_POINTER (0),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/basic/sync", Test,
                    GUINT_TO_POINTER (BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/basic-ssl/async", Test,
                    GUINT_TO_POINTER (BASIC_SSL),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-ssl/sync", Test,
                    GUINT_TO_POINTER (BASIC_SSL | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-proxy/async", Test,
                    GUINT_TO_POINTER (BASIC_PROXY),
                    test_setup,
                    do_multithread_basic_proxy_test,
                    test_teardown);
        g_test_add ("/multithread/basic-proxy/sync", Test,
                    GUINT_TO_POINTER (BASIC_PROXY | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_proxy_test,
                    test_teardown);
        g_test_add ("/multithread/basic-no-main-thread/async", Test,
                    GUINT_TO_POINTER (BASIC_NO_MAIN_THREAD),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/basic-no-main-thread/sync", Test,
                    GUINT_TO_POINTER (BASIC_NO_MAIN_THREAD | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/basic-ssl-proxy/async", Test,
                    GUINT_TO_POINTER (BASIC_SSL | BASIC_PROXY),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-ssl-proxy/sync", Test,
                    GUINT_TO_POINTER (BASIC_SSL | BASIC_PROXY | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-http2/async", Test,
                    GUINT_TO_POINTER (BASIC_HTTP2 | BASIC_SSL),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-http2/sync", Test,
                    GUINT_TO_POINTER (BASIC_HTTP2 | BASIC_SSL | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-no-main-thread-http2/async", Test,
                    GUINT_TO_POINTER (BASIC_NO_MAIN_THREAD | BASIC_HTTP2 | BASIC_SSL),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-no-main-thread-http2/sync", Test,
                    GUINT_TO_POINTER (BASIC_NO_MAIN_THREAD | BASIC_HTTP2 | BASIC_SSL | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_ssl_test,
                    test_teardown);
        g_test_add ("/multithread/basic-max-conns/async", Test,
                    GUINT_TO_POINTER (BASIC_MAX_CONNS),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/basic-max-conns/sync", Test,
                    GUINT_TO_POINTER (BASIC_MAX_CONNS | BASIC_SYNC),
                    test_setup,
                    do_multithread_basic_test,
                    test_teardown);
        g_test_add ("/multithread/connections/async", Test,
                    GUINT_TO_POINTER (0),
                    test_setup,
                    do_multithread_connections_test,
                    test_teardown);
        g_test_add ("/multithread/connections/sync", Test,
                    GUINT_TO_POINTER (BASIC_SYNC),
                    test_setup,
                    do_multithread_connections_test,
                    test_teardown);
        g_test_add ("/multithread/connections-http2/async", Test,
                    GUINT_TO_POINTER (BASIC_HTTP2 | BASIC_SSL),
                    test_setup,
                    do_multithread_connections_http2_test,
                    test_teardown);
        g_test_add ("/multithread/connections-http2/sync", Test,
                    GUINT_TO_POINTER (BASIC_HTTP2 | BASIC_SSL | BASIC_SYNC),
                    test_setup,
                    do_multithread_connections_http2_test,
                    test_teardown);
        g_test_add_func ("/multithread/no-main-context",
                         do_multithread_no_main_context_test);

        ret = g_test_run ();

        g_uri_unref (base_uri);
        soup_test_server_quit_unref (server);
        test_cleanup ();

        return ret;
}
