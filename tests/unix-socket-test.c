/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"

#include <gio/gunixsocketaddress.h>

static SoupServer *server;

static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg,
                 const char        *path,
                 GHashTable        *query,
                 gpointer           data)
{
        const char *method;

        method = soup_server_message_get_method (msg);
        if (method != SOUP_METHOD_GET) {
                soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
                return;
        }

        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_server_message_set_response (msg, "application/json",
                                          SOUP_MEMORY_STATIC, "{\"count\":42}", 12);
}

static void
do_load_uri_test (void)
{
        SoupSession *session;
        GSocketAddress *address;
        SoupMessage *msg;
        GBytes *body;
        const char *content_type;
        char *json;
        GSocketAddress *remote_address;
        GError *error = NULL;

        address = g_unix_socket_address_new (soup_test_server_get_unix_path (server));
        session = soup_test_session_new ("remote-connectable", address, NULL);
        g_object_unref (address);

        msg = soup_message_new (SOUP_METHOD_GET, "http://localhost/foo");
        body = soup_session_send_and_read (session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_nonnull (body);

        remote_address = soup_message_get_remote_address (msg);
        g_assert_nonnull (remote_address);
        g_assert_true (G_IS_UNIX_SOCKET_ADDRESS (remote_address));
        g_assert_cmpstr (g_unix_socket_address_get_path (G_UNIX_SOCKET_ADDRESS (remote_address)), ==, soup_test_server_get_unix_path (server));

        content_type = soup_message_headers_get_one (soup_message_get_response_headers (msg), "Content-Type");
        g_assert_cmpstr (content_type, ==, "application/json");
        g_object_unref (msg);

        json = g_strndup (g_bytes_get_data (body, NULL), g_bytes_get_size (body));
        g_assert_cmpstr (json, ==, "{\"count\":42}");
        g_free (json);
        g_bytes_unref (body);

        soup_test_session_abort_unref (session);
}

int
main (int argc,
      char *argv[])
{
        int ret;

        test_init (argc, argv, NULL);

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD | SOUP_TEST_SERVER_UNIX_SOCKET);
        soup_server_add_handler (server, NULL,
                                 server_callback, NULL, NULL);

        g_test_add_func ("/unix-socket/load-uri", do_load_uri_test);

        ret = g_test_run ();

        soup_test_server_quit_unref (server);

        test_cleanup ();
        return ret;
}
