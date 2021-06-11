/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2010 Igalia S.L.
 */

#include "test-utils.h"
#include "soup-message-private.h"

static SoupSession *session;
static GUri *base_uri;

typedef struct {
        SoupSession *session;
        GInputStream *stream;
        GBytes *bytes;
        const char *content_type;
        int nwrote;
} PutTestData;

typedef enum {
        BYTES  = 1 << 0,
        RESTART = 1 << 1,
        ASYNC = 1 << 2,
        LARGE = 1 << 3,
        EMPTY = 1 << 4,
        NO_CONTENT_TYPE = 1 << 5,
	NULL_STREAM = 1 << 6,
} RequestTestFlags;

static void
wrote_body_data (SoupMessage *msg,
                 guint        count,
                 PutTestData *ptd)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        debug_printf (2, "  wrote_body_data, %u bytes\n", count);
        ptd->nwrote += count;

        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), >=, ptd->nwrote);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, ptd->nwrote);
}

static void
wrote_body (SoupMessage *msg,
            PutTestData *ptd)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), >=, ptd->nwrote);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, ptd->nwrote);
}

static GChecksum *
setup_request_body (PutTestData     *ptd,
                    RequestTestFlags flags)
{
        GChecksum *check;

        ptd->nwrote = 0;
        check = g_checksum_new (G_CHECKSUM_MD5);
	if (flags & NULL_STREAM) {
		ptd->bytes = NULL;
		ptd->stream = NULL;
		ptd->content_type = NULL;

		return check;
	}

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
        ptd->content_type = flags & NO_CONTENT_TYPE ? NULL : "text/plain";

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
                soup_message_set_request_body (msg, ptd->content_type, ptd->stream, -1);
        } else if (ptd->bytes) {
                soup_message_set_request_body_from_bytes (msg, ptd->content_type, ptd->bytes);
        }
}

static void
do_request_test (gconstpointer data)
{
        RequestTestFlags flags = GPOINTER_TO_UINT (data);
        GUri *uri;
        PutTestData ptd;
        SoupMessage *msg;
        SoupMessageHeaders *request_headers;
        const char *client_md5, *server_md5;
        GChecksum *check;
        SoupMessageMetrics *metrics;

        if (flags & RESTART)
                uri = g_uri_parse_relative (base_uri, "/redirect", SOUP_HTTP_URI_FLAGS, NULL);
        else
                uri = g_uri_ref (base_uri);

        ptd.session = session;
        check = setup_request_body (&ptd, flags);
        client_md5 = g_checksum_get_string (check);

        msg = soup_message_new_from_uri ("PUT", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        request_headers = soup_message_get_request_headers (msg);
        if (flags & BYTES) {
                soup_message_set_request_body_from_bytes (msg, ptd.content_type, ptd.bytes);
                g_assert_cmpuint (soup_message_headers_get_content_length (request_headers), ==, g_bytes_get_size (ptd.bytes));
                g_assert_true (soup_message_headers_get_encoding (request_headers) == SOUP_ENCODING_CONTENT_LENGTH);
        } else if (!(flags & NULL_STREAM)) {
                soup_message_set_request_body (msg, ptd.content_type, ptd.stream, -1);
                g_assert_cmpuint (soup_message_headers_get_content_length (request_headers), ==, 0);
                g_assert_true (soup_message_headers_get_encoding (request_headers) == SOUP_ENCODING_CHUNKED);
        }
        g_assert_cmpstr (soup_message_headers_get_one (request_headers, "Content-Type"), ==, ptd.content_type);

        if (flags & RESTART) {
                g_signal_connect (msg, "restarted",
                                  G_CALLBACK (restarted), &ptd);
        }

        g_signal_connect (msg, "wrote-body-data",
                          G_CALLBACK (wrote_body_data), &ptd);
        g_signal_connect (msg, "wrote-body",
                          G_CALLBACK (wrote_body), &ptd);

        if (flags & ASYNC) {
                GBytes *body;

                body = soup_test_session_async_send (session, msg, NULL, NULL);
                g_assert_nonnull (body);
                g_bytes_unref (body);
        } else
                soup_test_session_send_message (session, msg);
        soup_test_assert_message_status (msg, SOUP_STATUS_CREATED);

        metrics = soup_message_get_metrics (msg);
	if (flags & NULL_STREAM) {
		g_assert_cmpint (ptd.nwrote, ==, 0);
		g_assert_cmpstr (soup_message_headers_get_one (request_headers, "Content-Length"), ==, "0");
                g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
	} else {
		g_assert_cmpint (g_bytes_get_size (ptd.bytes), ==, ptd.nwrote);
                if (flags & BYTES) {
                        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, ptd.nwrote);
                } else {
                        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), >, ptd.nwrote);
                }
                g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, ptd.nwrote);
	}

        server_md5 = soup_message_headers_get_one (soup_message_get_response_headers (msg),
                                                   "Content-MD5");
        g_assert_cmpstr (client_md5, ==, server_md5);

	g_clear_pointer (&ptd.bytes, g_bytes_unref);
        g_clear_object (&ptd.stream);
        g_object_unref (msg);
        g_checksum_free (check);
        g_uri_unref (uri);
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
        g_test_add_data_func ("/request-body/sync/no-content-type-stream", GINT_TO_POINTER (NO_CONTENT_TYPE), do_request_test);
        g_test_add_data_func ("/request-body/sync/no-content-type-bytes", GINT_TO_POINTER (BYTES | NO_CONTENT_TYPE), do_request_test);
	g_test_add_data_func ("/request-body/sync/null", GINT_TO_POINTER (NULL_STREAM), do_request_test);
        g_test_add_data_func ("/request-body/async/stream", GINT_TO_POINTER (ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/bytes", GINT_TO_POINTER (BYTES | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/restart-stream", GINT_TO_POINTER (RESTART | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/restart-bytes", GINT_TO_POINTER (RESTART | ASYNC | BYTES), do_request_test);
        g_test_add_data_func ("/request-body/async/large", GINT_TO_POINTER (BYTES | LARGE | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/empty", GINT_TO_POINTER (BYTES | EMPTY | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/no-content-type-stream", GINT_TO_POINTER (NO_CONTENT_TYPE | ASYNC), do_request_test);
        g_test_add_data_func ("/request-body/async/no-content-type-bytes", GINT_TO_POINTER (BYTES | NO_CONTENT_TYPE | ASYNC), do_request_test);
	g_test_add_data_func ("/request-body/async/null", GINT_TO_POINTER (NULL_STREAM | ASYNC), do_request_test);

        ret = g_test_run ();

        soup_test_session_abort_unref (session);

        g_uri_unref (base_uri);

        g_main_loop_unref (loop);
        soup_test_server_quit_unref (server);

        test_cleanup ();
        return ret;
}
