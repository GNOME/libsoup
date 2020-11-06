/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2010 Igalia S.L.
 */

#include "test-utils.h"
#include "soup-message-private.h"

static SoupSession *session;
static SoupURI *base_uri;

typedef struct {
        SoupSession *session;
        GInputStream *stream;
        GBytes *bytes;
        int nwrote;
} PutTestData;

typedef enum {
        BYTES  = 1 << 0,
        RESTART = 1 << 1,
        ASYNC = 1 << 2,
        LARGE = 1 << 3,
        EMPTY = 1 << 4
} RequestTestFlags;

static void
wrote_body_data (SoupMessage *msg,
		 guint        count,
                 PutTestData *ptd)
{
        debug_printf (2, "  wrote_body_data, %u bytes\n", count);
        ptd->nwrote += count;
}

static GChecksum *
setup_request_body (PutTestData     *ptd,
                    RequestTestFlags flags)
{
        GChecksum *check;

        ptd->nwrote = 0;
        check = g_checksum_new (G_CHECKSUM_MD5);
        if (flags & LARGE) {
                static const unsigned int large_size = 1000000;
                char *large_data;
                unsigned int i;

                large_data = g_malloc (large_size);
                for (i = 0; i < large_size; i++)
                        large_data[i] = i & 0xFF;
                ptd->bytes = g_bytes_new_take (large_data, large_size);
                g_checksum_update (check, (guchar *)large_data, large_size);
        } else if (flags & EMPTY) {
                ptd->bytes = g_bytes_new_static (NULL, 0);
        } else {
                static const char *data = "one two three";

                ptd->bytes = g_bytes_new_static (data, strlen (data));
                g_checksum_update (check, (guchar *)data, strlen (data));
        }
        ptd->stream = flags & BYTES ? NULL : g_memory_input_stream_new_from_bytes (ptd->bytes);

        return check;
}

static void
restarted (SoupMessage *msg,
           PutTestData *ptd)
{
        debug_printf (2, "  --restarting--\n");

        ptd->nwrote = 0;

        /* FIXME: The 302 redirect will turn it into a GET request */
        soup_message_set_method (msg, SOUP_METHOD_PUT);

        if (ptd->stream) {
                g_object_unref (ptd->stream);
                ptd->stream = g_memory_input_stream_new_from_bytes (ptd->bytes);
                soup_message_set_request_body (msg, "text/plain", ptd->stream, -1);
        } else {
                soup_message_set_request_body_from_bytes (msg, "text/plain", ptd->bytes);
        }
}

static void
do_request_test (gconstpointer data)
{
        RequestTestFlags flags = GPOINTER_TO_UINT (data);
        SoupURI *uri;
        PutTestData ptd;
        SoupMessage *msg;
        const char *client_md5, *server_md5;
        GChecksum *check;

        if (flags & RESTART)
                uri = soup_uri_new_with_base (base_uri, "/redirect");
        else
                uri = soup_uri_copy (base_uri);

        ptd.session = session;
        check = setup_request_body (&ptd, flags);
        client_md5 = g_checksum_get_string (check);

        msg = soup_message_new_from_uri ("PUT", uri);
        if (flags & BYTES)
                soup_message_set_request_body_from_bytes (msg, flags & EMPTY ? NULL : "text/plain", ptd.bytes);
        else
                soup_message_set_request_body (msg, "text/plain", ptd.stream, -1);

        if (flags & RESTART) {
                g_signal_connect (msg, "restarted",
                                  G_CALLBACK (restarted), &ptd);
        }

        g_signal_connect (msg, "wrote-body-data",
                          G_CALLBACK (wrote_body_data), &ptd);

        if (flags & ASYNC)
                soup_test_session_async_send (session, msg);
        else
                soup_test_session_send_message (session, msg);
        soup_test_assert_message_status (msg, SOUP_STATUS_CREATED);
        g_assert_cmpint (g_bytes_get_size (ptd.bytes), ==, ptd.nwrote);

        server_md5 = soup_message_headers_get_one (soup_message_get_response_headers (msg),
                                                   "Content-MD5");
        g_assert_cmpstr (client_md5, ==, server_md5);

        g_bytes_unref (ptd.bytes);
        g_clear_object (&ptd.stream);
        g_object_unref (msg);
        g_checksum_free (check);

        soup_uri_free (uri);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
                 const char        *path,
		 GHashTable        *query,
                 gpointer           data)
{
        SoupMessageBody *md5_body;
        char *md5;

        if (g_str_has_prefix (path, "/redirect")) {
                soup_server_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
                return;
        }

        if (soup_server_message_get_method (msg) == SOUP_METHOD_PUT) {
                soup_server_message_set_status (msg, SOUP_STATUS_CREATED, NULL);
                md5_body = soup_server_message_get_request_body (msg);
        } else {
                soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
                return;
        }

        md5 = g_compute_checksum_for_data (G_CHECKSUM_MD5,
                                           (guchar *)md5_body->data,
                                           md5_body->length);
        soup_message_headers_append (soup_server_message_get_response_headers (msg),
                                     "Content-MD5", md5);
        g_free (md5);
}

int
main (int argc, char **argv)
{
        GMainLoop *loop;
        SoupServer *server;
        int ret;

        test_init (argc, argv, NULL);

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
        soup_server_add_handler (server, NULL,
                                 server_callback, NULL, NULL);

        loop = g_main_loop_new (NULL, TRUE);

        base_uri = soup_test_server_get_uri (server, "http", NULL);
        session = soup_test_session_new (NULL);

        g_test_add_data_func ("/request-body/sync/stream", GINT_TO_POINTER (0), do_request_test);
        g_test_add_data_func ("/request-body/sync/bytes", GINT_TO_POINTER (BYTES), do_request_test);
        g_test_add_data_func ("/request-body/sync/restart-stream", GINT_TO_POINTER (RESTART), do_request_test);
        g_test_add_data_func ("/request-body/sync/restart-bytes", GINT_TO_POINTER (RESTART | BYTES), do_request_test);
        g_test_add_data_func ("/request-body/sync/large", GINT_TO_POINTER (BYTES | LARGE), do_request_test);
        g_test_add_data_func ("/request-body/sync/empty", GINT_TO_POINTER (BYTES | EMPTY), do_request_test);
        g_test_add_data_func ("/request-body/async/stream", GINT_TO_POINTER (ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/bytes", GINT_TO_POINTER (BYTES | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/restart-stream", GINT_TO_POINTER (RESTART | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/restart-bytes", GINT_TO_POINTER (RESTART | ASYNC | BYTES), do_request_test);
        g_test_add_data_func ("/request-body/async/large", GINT_TO_POINTER (BYTES | LARGE | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/empty", GINT_TO_POINTER (BYTES | EMPTY | ASYNC), do_request_test);

        ret = g_test_run ();

        soup_test_session_abort_unref (session);

        soup_uri_free (base_uri);

        g_main_loop_unref (loop);
        soup_test_server_quit_unref (server);

        test_cleanup ();
        return ret;
}
