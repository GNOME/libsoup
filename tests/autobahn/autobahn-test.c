/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-autobahn-test-client.c
 *
 * Copyright (C) 2021 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "test-utils.h"

#include <libsoup/soup.h>

#define TEST_QUICK_THRESHOLD 310

static char *address = "ws://localhost:9001";
static char *agent = "libsoup";

static unsigned long int AUTOBAHN_TEST_TIMEOUT = 60;

typedef void (*ConnectionFunc) (SoupWebsocketConnection *socket_connection,
                                gint type,
                                GBytes *message,
                                gpointer data);

typedef struct {
        ConnectionFunc method;
        gpointer data;
        gboolean done;
} ConnectionContext;

typedef struct {
        SoupSession *session;
        unsigned int num_test_case;
        char *path;
} TestBundle;

static void
test_bundle_free (TestBundle *bundle)
{
        g_free (bundle->path);
        g_free (bundle);
}

static void
on_message_received (SoupWebsocketConnection *socket_connection,
                     gint type, GBytes *message,
                     gpointer data)
{
        ConnectionContext *ctx = (ConnectionContext *)data;

        g_test_message ("Message received");

        if (ctx && ctx->method)
                ctx->method (socket_connection, type, message, ctx->data);
}

static void
on_connection_closed (SoupWebsocketConnection *socket_connection,
                      gpointer data)
{
        ConnectionContext *ctx = (ConnectionContext *)data;

        g_test_message ("Connection closed");

        g_object_unref (socket_connection);

        ctx->done = TRUE;
}

static void
on_connect (GObject *session,
            GAsyncResult *res,
            gpointer user_data)
{
        ConnectionContext *ctx = user_data;
        GError *error = NULL;
        SoupWebsocketConnection *socket_connection = soup_session_websocket_connect_finish (SOUP_SESSION (session), res, &error);
        if (!socket_connection) {
                g_test_message ("Connection failed: %s", error->message);
                g_error_free (error);
                ctx->done = TRUE;
                return;
        }

        /* The performance tests increase the size of the payload up to 16 MB, let's disable
        the limit to see what happens. */
        soup_websocket_connection_set_max_incoming_payload_size (socket_connection, 0);

        g_test_message ("Connected");
        g_signal_connect (socket_connection, "message", G_CALLBACK (on_message_received), ctx);
        g_signal_connect (socket_connection, "closed", G_CALLBACK (on_connection_closed), ctx);
}

static void
connect_and_run (SoupSession *session, char *path, ConnectionFunc method, gpointer data)
{
        char *uri = g_strconcat (address, path, NULL);
        SoupMessage *message = soup_message_new (SOUP_METHOD_GET, uri);
        ConnectionContext *ctx = g_new0 (ConnectionContext, 1);
        GMainContext *async_context = g_main_context_ref_thread_default ();

        ctx->method = method;
        ctx->data = data;
        ctx->done = FALSE;

        g_test_message ("Connecting to %s", uri);
        soup_session_websocket_connect_async (session, message, NULL, NULL, G_PRIORITY_DEFAULT, NULL, on_connect, ctx);

        time_t now = time(NULL);
        const time_t threshold = now + AUTOBAHN_TEST_TIMEOUT;

        while (!ctx->done) {
                g_main_context_iteration (async_context, TRUE);
                now = time(NULL);
                if (now > threshold) {
                        debug_printf (1, "Test timeout: %s\n", uri);
                        break;
                }
        }

        g_object_unref (message);
        g_free (uri);
        if (ctx->done)
                g_free (ctx);
        g_main_context_unref (async_context);
}

static void
test_case_message_received (SoupWebsocketConnection *socket_connection,
                            gint type,
                            GBytes *message,
                            gpointer data)
{
        /* Cannot send messages if we're not in an open state. */
        if (soup_websocket_connection_get_state (socket_connection) != SOUP_WEBSOCKET_STATE_OPEN)
                return;

        g_test_message ("Sending message");

        soup_websocket_connection_send_message (socket_connection, type, message);
}

static void
test_case (gconstpointer data)
{
        TestBundle *bundle = (TestBundle *)data;

        connect_and_run (bundle->session, bundle->path, test_case_message_received, bundle);
}

static void
update_reports (SoupSession *session)
{
        char *path = g_strdup_printf ("/updateReports?agent=%s", agent);
        g_test_message ("Updating reports...");
        connect_and_run (session, path, NULL, NULL);
        g_free (path);
}

static gboolean
autobahn_server (const char *action, guint64 *num_cases_out)
{
        GSubprocessLauncher *launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDOUT_PIPE);
        GSubprocess *proc;
        GError *error = NULL;
        char *build_dir;
        char *autobahn_script;

        autobahn_script = g_test_build_filename (G_TEST_DIST, "autobahn", "autobahn-server.sh", NULL);
        build_dir = g_test_build_filename (G_TEST_BUILT, "autobahn", NULL);

        if (!g_file_test (autobahn_script, G_FILE_TEST_EXISTS))
            autobahn_script = g_build_filename("tests", "autobahn", "autobahn-server.sh", NULL);

        if (!g_file_test (build_dir, G_FILE_TEST_IS_DIR))
            build_dir = g_path_get_dirname (g_test_build_filename (G_TEST_BUILT, "autobahn", NULL));

        autobahn_script = g_canonicalize_filename (autobahn_script, NULL);

        g_subprocess_launcher_set_cwd (launcher, build_dir);
        proc = g_subprocess_launcher_spawn (launcher, &error, autobahn_script, action, NULL);

        g_free (autobahn_script);
        g_free (build_dir);
        g_object_unref (launcher);

        if (error) {
                debug_printf (1, "Error running autobahn script: %s\n", error->message);
                g_error_free (error);
                return FALSE;
        }

        /* We are done if we are stopping the server */
        if (strcmp (action, "--start"))
                return TRUE;

        GDataInputStream *stdout = g_data_input_stream_new  (g_subprocess_get_stdout_pipe (proc));
        GRegex *re = g_regex_new ("Ok, will run (\\d+) test cases", 0, 0, NULL);
        char *line = NULL;
        gboolean ret = FALSE;

        /* Read the process output until we know its listening successfully */
        while (TRUE) {
                line = g_data_input_stream_read_line_utf8 (stdout, NULL, NULL, NULL);
                if (!line)
                        goto done;

                GMatchInfo *match;
                if (g_regex_match (re, line, 0, &match)) {
                        char *matched_number = g_match_info_fetch (match, 1);
                        *num_cases_out = g_ascii_strtoull (matched_number, NULL, 10);

                        ret = TRUE;
                        g_free (matched_number);
                        g_match_info_unref (match);
                        goto done;
                }

                g_clear_pointer (&line, g_free);
        }

done:
        g_free (line);
        g_object_unref (stdout);
        g_object_unref (proc);
        g_regex_unref (re);

        return ret;
}

static gboolean
should_run_test (int i)
{
        return g_test_slow () || i < TEST_QUICK_THRESHOLD;
}

static
void prepare_test (SoupSession *session, int i)
{
        char *test_path = g_strdup_printf ("/autobahn/%u", i);

        TestBundle *bundle = g_new0 (TestBundle, 1);
        bundle->session = session;
        bundle->num_test_case = i;
        bundle->path = g_strdup_printf ("/runCase?case=%u&agent=%s", i, agent);

        g_test_add_data_func_full (test_path, bundle, test_case, (GDestroyNotify) test_bundle_free);

        g_free (test_path);
}

int main (int argc, char *argv[])
{
        int ret = 0;
        guint64 num_case = 1, num_cases;
        SoupSession *session;
        const char *num_cases_env, *num_case_env, *timeout_env;

        test_init (argc, argv, NULL);

        if (!autobahn_server ("--start", &num_cases))
                exit (1);

        if ((num_cases_env = g_getenv ("AUTOBAHN_NUM_CASES")))
                num_cases = atol (num_cases_env);

        if ((num_case_env = g_getenv ("AUTOBAHN_NUM_CASE"))) {
                num_case = atol (num_case_env);
                num_cases = num_case;
        }

        if ((timeout_env = g_getenv ("AUTOBAHN_TEST_TIMEOUT")))
                AUTOBAHN_TEST_TIMEOUT = atol (timeout_env);

        session = soup_session_new ();
        soup_session_add_feature_by_type (session, SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER);

        for (int i = num_case; i <= num_cases; i++) {
                if (should_run_test (i))
                        prepare_test (session, i);
                else
                        g_test_skip ("Ran in quick mode");
        }

        ret = g_test_run ();

        update_reports (session);

        g_object_unref (session);

        autobahn_server ("--stop", NULL);
        test_cleanup ();

        return ret;
}
