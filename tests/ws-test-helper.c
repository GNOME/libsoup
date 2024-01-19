/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2024 Axis Communications AB, SWEDEN.
 */
/*

To use this WebSocket test helper with valgrind, follow these steps.

1. Start a ws server in a separate terminal

    docker run -it --rm \
            -p 9001:9001 \
            crossbario/autobahn-testsuite \
            wstest --mode echoserver --wsuri=ws://127.0.0.1:9001

2. Build this helper

    meson setup _build
    meson compile -C _build tests/ws-test-helper

3. Run this helper with valgrind in yet another terminal

    G_MESSAGES_DEBUG=all valgrind --leak-check=full --suppressions=tests/libsoup.supp _build/tests/ws-test-helper

4. In a third terminal, drop packets to and from the ws server:

    # Change ACTION to "--delete" and re-run to undo the effects of this
    ACTION=--append ; IP=127.0.0.1 ; PORT=9001
    sudo iptables \
        --table filter \
        $ACTION INPUT \
        --protocol tcp \
        --destination $IP \
        --destination-port $PORT \
        --jump DROP
    sudo iptables \
        --table filter \
        $ACTION OUTPUT \
        --protocol tcp \
        --source $IP \
        --source-port $PORT \
        --jump DROP

5. After waiting a few seconds you will see output similar to this:

    ==867041== Using Valgrind-3.19.0 and LibVEX; rerun with -h for copyright info
    ** Message: 15:56:37.721: Connecting to ws://127.0.0.1:9001
    ** Message: 15:56:38.415: Connected
    (process:867041): libsoup-DEBUG: 15:56:41.308: ping libsoup-keepalive-1
    (process:867041): libsoup-DEBUG: 15:56:41.318: received keepalive pong
    ...
    (process:867041): libsoup-DEBUG: 15:58:23.306: ping libsoup-keepalive-35
    (process:867041): libsoup-DEBUG: 15:58:23.307: expected pong never arrived; connection probably lost
    ** Message: 15:58:23.311: Error: Did not receive keepalive pong within 3 seconds
    (process:867041): libsoup-DEBUG: 15:58:23.312: requesting close due to error
    ** Message: 15:58:28.319: Closed
    ==867041== LEAK SUMMARY:
    ==867041==    definitely lost: 0 bytes in 0 blocks
    ==867041==    indirectly lost: 0 bytes in 0 blocks
    ==867041==      possibly lost: 0 bytes in 0 blocks
    ==867041== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 3 from 3)

 */

#include <glib-unix.h>
#include <libsoup/soup.h>

typedef struct {
        SoupWebsocketConnection *connection;
        gboolean closed;
} AppState;

static gboolean
on_sigint (AppState *app_state)
{
        soup_websocket_connection_close (app_state->connection, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL);

        return G_SOURCE_CONTINUE;
}

static void
on_error (SoupWebsocketConnection *connection,
          GError *err,
          AppState *app_state)
{
        g_message ("Error: %s", err->message);
}

static void
on_closed (SoupWebsocketConnection *connection,
           AppState *app_state)
{
        app_state->closed = TRUE;
        g_message ("Closed");
}

static void
on_connect (GObject *session,
            GAsyncResult *res,
            AppState *app_state)
{
        GError *error = NULL;
        app_state->connection = soup_session_websocket_connect_finish (SOUP_SESSION (session), res, &error);
        if (!app_state->connection) {
                g_message ("Connection failed: %s", error->message);
                g_error_free (error);
                app_state->closed = TRUE;
                return;
        }

        g_message ("Connected");

        g_signal_connect (app_state->connection, "error", G_CALLBACK (on_error), app_state);
        g_signal_connect (app_state->connection, "closed", G_CALLBACK (on_closed), app_state);

        soup_websocket_connection_set_keepalive_interval (app_state->connection, 3);
        soup_websocket_connection_set_keepalive_pong_timeout (app_state->connection, 3);
}

int
main (int argc, char *argv[])
{
        AppState *app_state = g_new0 (AppState, 1);

        // Connect
        char *uri = "ws://127.0.0.1:9001";
        SoupSession *session = soup_session_new ();
        soup_session_add_feature_by_type (session, SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER);
        SoupMessage *message = soup_message_new (SOUP_METHOD_GET, uri);
        g_message ("Connecting to %s", uri);
        soup_session_websocket_connect_async (
            session,
            message,
            NULL, NULL,
            G_PRIORITY_DEFAULT, NULL,
            (GAsyncReadyCallback)on_connect, app_state);

        // Setup a SIGINT handler for clean and valgrind friendly shutdown.
        GMainContext *async_context = g_main_context_ref_thread_default ();
        GSource *sigint_source = g_unix_signal_source_new (SIGINT);
        g_source_set_callback (sigint_source, (GSourceFunc)on_sigint, app_state, NULL);
        g_source_attach (sigint_source, async_context);

        // Run the main loop.
        while (!app_state->closed) {
                g_main_context_iteration (async_context, TRUE);
        }

        // Properly free stuff so valgrind can give relevant leak reports.
        g_source_destroy (sigint_source);
        g_source_unref (sigint_source);
        g_main_context_unref (async_context);
        if (app_state->connection) {
                g_signal_handlers_disconnect_by_func (app_state->connection, on_closed, app_state);
                g_signal_handlers_disconnect_by_func (app_state->connection, on_error, app_state);
                g_object_unref (app_state->connection);
        }
        g_object_unref (message);
        g_object_unref (session);
        g_free (app_state);

        return 0;
}
