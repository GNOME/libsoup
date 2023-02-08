/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

#define RESPONSE_CHUNK_SIZE 1024

GBytes *full_response;
char *full_response_md5;

static void
write_next_chunk (SoupServerMessage *msg,
		  gpointer           user_data)
{
	gsize *offset = user_data;
	gsize chunk_length;
	SoupMessageBody *response_body;

	response_body = soup_server_message_get_response_body (msg);

	chunk_length = MIN (RESPONSE_CHUNK_SIZE, g_bytes_get_size (full_response) - *offset);
	if (chunk_length > 0) {
		debug_printf (2, "  writing chunk\n");
                GBytes *chunk = g_bytes_new_from_bytes (full_response, *offset, chunk_length);
                soup_message_body_append_bytes (response_body, chunk);
                g_bytes_unref (chunk);
		*offset += chunk_length;
	} else {
		debug_printf (2, "  done\n");
		/* This is only actually needed in the chunked and eof
		 * cases, but it's harmless in the content-length
		 * case.
		 */
		soup_message_body_complete (response_body);
	}
}

static void
free_offset (SoupServerMessage *msg,
	     gpointer           offset)
{
	g_free (offset);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	gsize *offset;
	SoupMessageHeaders *response_headers;

	response_headers = soup_server_message_get_response_headers (msg);
	if (!strcmp (path, "/chunked")) {
		soup_message_headers_set_encoding (response_headers,
						   SOUP_ENCODING_CHUNKED);
	} else if (!strcmp (path, "/content-length")) {
		soup_message_headers_set_encoding (response_headers,
						   SOUP_ENCODING_CONTENT_LENGTH);
		soup_message_headers_set_content_length (response_headers,
							 g_bytes_get_size (full_response));
	} else if (!strcmp (path, "/eof")) {
		soup_message_headers_set_encoding (response_headers,
						   SOUP_ENCODING_EOF);
	} else {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		return;
	}
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

	offset = g_new0 (gsize, 1);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (write_next_chunk), offset);
	g_signal_connect (msg, "wrote-chunk",
			  G_CALLBACK (write_next_chunk), offset);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (free_offset), offset);
}

static void
msg_wrote_headers_cb (SoupMessage        *msg,
                      SoupMessageMetrics *metrics)
{
        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
}

static void
msg_got_headers_cb (SoupMessage        *msg,
                    SoupMessageMetrics *metrics)
{
        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), >, 0);
}

static void
msg_got_body_data_cb (SoupMessage *msg,
                      guint        chunk_size,
                      guint64     *response_body_bytes_received)
{
        *response_body_bytes_received += chunk_size;
}

static void
msg_got_body_cb (SoupMessage        *msg,
                 SoupMessageMetrics *metrics)
{
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), >, 0);
}

static void
do_request (SoupSession *session, GUri *base_uri, char *path)
{
	GUri *uri;
	SoupMessage *msg;
	GBytes *body;
	char *md5;
        SoupMessageMetrics *metrics;
        guint64 response_body_bytes_received = 0;

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        metrics = soup_message_get_metrics (msg);
        g_assert_nonnull (metrics);
        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), ==, 0);

        g_signal_connect (msg, "wrote-headers",
                          G_CALLBACK (msg_wrote_headers_cb),
                          metrics);
        g_signal_connect (msg, "got-headers",
                          G_CALLBACK (msg_got_headers_cb),
                          metrics);
        g_signal_connect (msg, "got-body-data",
                          G_CALLBACK (msg_got_body_data_cb),
                          &response_body_bytes_received);
        g_signal_connect (msg, "got-body",
                          G_CALLBACK (msg_got_body_cb),
                          metrics);

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpint (g_bytes_get_size (body), ==, g_bytes_get_size (full_response));
        g_assert_cmpint (soup_message_metrics_get_response_body_size (metrics), ==, g_bytes_get_size (body));
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, response_body_bytes_received);
        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), >, 0);
        if (g_str_equal (path, "chunked")) {
                g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), >, soup_message_metrics_get_response_body_size (metrics));
        } else {
                g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, soup_message_metrics_get_response_body_size (metrics));
        }
        if (g_str_equal (path, "content-length")) {
                goffset content_length;

                content_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));
                g_assert_cmpuint (content_length, ==, response_body_bytes_received);
        }

	md5 = g_compute_checksum_for_data (G_CHECKSUM_MD5,
					   (guchar *)g_bytes_get_data (body, NULL),
					   g_bytes_get_size (body));
	g_assert_cmpstr (md5, ==, full_response_md5);
	g_free (md5);

	g_bytes_unref (body);
	g_object_unref (msg);
}

static void
do_chunked_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;

	session = soup_test_session_new (NULL);
	do_request (session, base_uri, "chunked");
	soup_test_session_abort_unref (session);
}

static void
do_content_length_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;

	session = soup_test_session_new (NULL);
	do_request (session, base_uri, "content-length");
	soup_test_session_abort_unref (session);
}

static void
do_eof_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;

	g_test_bug ("572153");

	session = soup_test_session_new (NULL);
	do_request (session, base_uri, "eof");
	soup_test_session_abort_unref (session);
}

static void
do_skip (SoupSession *session,
         GUri        *base_uri,
         const char  *path)
{
        GUri *uri;
        SoupMessage *msg;
        GInputStream *stream;
        SoupMessageMetrics *metrics;
        guint64 body_size = 0;
        guint64 response_body_bytes_received = 0;
        GError *error = NULL;

        uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        g_signal_connect (msg, "got-body-data",
                          G_CALLBACK (msg_got_body_data_cb),
                          &response_body_bytes_received);

        stream = soup_test_request_send (session, msg, NULL, 0, &error);
        g_assert_no_error (error);
        while (TRUE) {
                gssize skipped;

                skipped = g_input_stream_skip (stream, 4096, NULL, &error);
                g_assert_no_error (error);
                if (skipped == 0)
                        break;

                body_size += skipped;
        }
        g_object_unref (stream);

        metrics = soup_message_get_metrics (msg);
        g_assert_cmpint (body_size, ==, g_bytes_get_size (full_response));
        g_assert_cmpint (soup_message_metrics_get_response_body_size (metrics), ==, body_size);
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, response_body_bytes_received);
        if (g_str_equal (path, "chunked")) {
                g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), >, soup_message_metrics_get_response_body_size (metrics));
        } else {
                g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, soup_message_metrics_get_response_body_size (metrics));
        }
        if (g_str_equal (path, "content-length")) {
                goffset content_length;

                content_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));
                g_assert_cmpuint (content_length, ==, response_body_bytes_received);
        }

        g_object_unref (msg);
}

static void
do_skip_test (gconstpointer data)
{
        GUri *base_uri = (GUri *)data;
        SoupSession *session;

        session = soup_test_session_new (NULL);
        do_skip (session, base_uri, "chunked");
        do_skip (session, base_uri, "content-length");
        do_skip (session, base_uri, "eof");
        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	GUri *base_uri;
	int ret;

	test_init (argc, argv, NULL);

	full_response = soup_test_get_index ();
	full_response_md5 = g_compute_checksum_for_bytes (G_CHECKSUM_MD5, full_response);

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);

	loop = g_main_loop_new (NULL, TRUE);

	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add_data_func ("/streaming/chunked", base_uri, do_chunked_test);
	g_test_add_data_func ("/streaming/content-length", base_uri, do_content_length_test);
	g_test_add_data_func ("/streaming/eof", base_uri, do_eof_test);
        g_test_add_data_func ("/streaming/skip", base_uri, do_skip_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	g_main_loop_unref (loop);

	g_free (full_response_md5);
	soup_test_server_quit_unref (server);
	test_cleanup ();

	return ret;
}
