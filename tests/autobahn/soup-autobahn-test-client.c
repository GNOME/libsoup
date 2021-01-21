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

#include <stdio.h>
#include <libsoup/soup.h>

GMainLoop *loop;
static char *address = "ws://localhost:9001";
static char *agent = "libsoup";
static unsigned int total_num_cases = 0;
gboolean running_tests = FALSE;

typedef void (*ConnectionFunc) (SoupWebsocketConnection *socket_connection,
                                gint type,
                                GBytes *message,
                                gpointer data);

typedef struct {
    ConnectionFunc method;
    gpointer data;
} ConnectionContext;

static void run_case (SoupSession *session, const unsigned int test_case);

static gboolean option_run_all = FALSE;
static int option_run_test = -1;
static gboolean option_number_of_tests = FALSE;
static gboolean option_update_report = FALSE;
static gboolean option_debug = FALSE;

static GOptionEntry entries[] =
{
    { "run-all",         'a', 0, G_OPTION_ARG_NONE, &option_run_all,         "Run all tests", NULL },
    { "test",            't', 0, G_OPTION_ARG_INT,  &option_run_test,        "Run TEST only", "TEST" },
    { "number-of-tests", 'n', 0, G_OPTION_ARG_NONE, &option_number_of_tests, "Queries the Autobahn server for the number of test cases", NULL },
    { "update-report",   'r', 0, G_OPTION_ARG_NONE, &option_update_report,   "Requests the Autobahn server to update the report for tests", NULL },
    { "debug",           'd', 0, G_OPTION_ARG_NONE, &option_debug,           "Enables extra debug output", NULL },
    { NULL }
};

static void
on_message_received (SoupWebsocketConnection *socket_connection,
                     gint type, GBytes *message,
                     gpointer data)
{
    ConnectionContext *ctx = (ConnectionContext*) data;

    if (option_debug)
        fprintf (stderr, "<- ");

    if (ctx && ctx->method)
        ctx->method (socket_connection, type, message, ctx->data);
}

static void
on_connection_closed (SoupWebsocketConnection *socket_connection,
                      gpointer data)
{
    ConnectionContext *ctx = (ConnectionContext*) data;

    if (option_debug)
        fprintf (stderr, "\nConnection closed\n");

    if (running_tests)
        fprintf (stderr, " DONE\n");

    g_free (ctx);

    g_object_unref (socket_connection);
    g_main_loop_quit (loop);
}

static void
on_connect (GObject *session,
            GAsyncResult *res,
            gpointer ctx)
{
    SoupWebsocketConnection *socket_connection = soup_session_websocket_connect_finish (SOUP_SESSION(session), res, NULL);
    if (!socket_connection) {
        g_free (ctx);
        return;
    }

    /* The performance tests increase the size of the payload up to 16 MB, let's disable
       the limit to see what happens. */
    soup_websocket_connection_set_max_incoming_payload_size (socket_connection, 0);

    g_signal_connect (socket_connection, "message", G_CALLBACK(on_message_received), ctx);
    g_signal_connect (socket_connection, "closed", G_CALLBACK(on_connection_closed), ctx);
}

static void
connect_and_run (SoupSession *session, char *path, ConnectionFunc method, gpointer data)
{
    char *uri = g_strconcat (address, path, NULL);
    SoupMessage *message = soup_message_new (SOUP_METHOD_GET, uri);
    ConnectionContext *ctx  = g_new0 (ConnectionContext, 1);

    ctx->method = method;
    ctx->data = data;

    if (option_debug)
        fprintf (stderr, "About to connect to %s\n", uri);
    soup_session_websocket_connect_async (session, message, NULL, NULL, G_PRIORITY_DEFAULT, NULL, on_connect, ctx);

    g_object_unref (message);
    g_free (uri);

    g_main_loop_run (loop);
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

    if (option_debug)
        fprintf (stderr, "-> ");

    soup_websocket_connection_send_message (socket_connection, type, message);
}

static void
run_case (SoupSession *session, const unsigned int test_case)
{
    char *path = g_strdup_printf ("/runCase?case=%u&agent=%s", test_case, agent);

    running_tests = TRUE;
    fprintf (stderr, "Running test case %u:", test_case);
    connect_and_run (session, path, test_case_message_received, GUINT_TO_POINTER (test_case));
    g_free (path);
}

static void
run_all_cases (SoupSession *session)
{
    int i;
    for (i = 0; i < total_num_cases; i++)
        run_case (session, i + 1);
}

static void
got_case_count (SoupWebsocketConnection *socket_connection,
                gint type,
                GBytes *message,
                gpointer data)
{
    total_num_cases = g_ascii_strtoull (g_bytes_get_data (message, NULL), NULL, 10);

    fprintf (stderr, "Total number of cases: %u\n", total_num_cases);
}

static void
get_case_count (SoupSession *session)
{
    connect_and_run (session, "/getCaseCount", got_case_count, NULL);
}

static void
update_reports (SoupSession *session)
{
    char *path = g_strdup_printf ("/updateReports?agent=%s", agent);
    fprintf (stderr, "Updating reports..\n");
    connect_and_run (session, path, NULL, NULL);
    g_free (path);
}

int main (int argc, char* argv[])
{
    GOptionContext *context;
    GError *error = NULL;
    SoupSession *session;

    context = g_option_context_new ("- libsoup test runner for Autobahn WebSocket client tests.");
    g_option_context_add_main_entries (context, entries, NULL);

    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_warning ("Option parsing failed: %s\n", error->message);
        g_error_free (error);
        g_option_context_free (context);
        exit (1);
    }
    g_option_context_free (context);

    if (option_run_test >= 0 || option_number_of_tests)
        option_run_all = FALSE;

    session = soup_session_new ();
    soup_session_add_feature_by_type (session, SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER);
    loop = g_main_loop_new (g_main_context_default (), FALSE);

    if (!(option_run_all || option_number_of_tests || option_update_report || option_run_test > 0))
        option_run_all = TRUE;

    if (option_run_all || option_number_of_tests)
        get_case_count (session);

    if (option_run_test >= 0)
        run_case (session, option_run_test);
    else if (option_run_all)
        run_all_cases (session);

    if (option_update_report)
        update_reports (session);

    g_object_unref (session);

    return 0;
}
