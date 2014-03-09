/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

#define RESPONSE_CHUNK_SIZE 1024

SoupBuffer *full_response;
char *full_response_md5;

static void
write_next_chunk (SoupMessage *msg, gpointer user_data)
{
	gsize *offset = user_data;
	gsize chunk_length;

	chunk_length = MIN (RESPONSE_CHUNK_SIZE, full_response->length - *offset);
	if (chunk_length > 0) {
		debug_printf (2, "  writing chunk\n");
		soup_message_body_append (msg->response_body,
					  SOUP_MEMORY_STATIC,
					  full_response->data + *offset,
					  chunk_length);
		*offset += chunk_length;
	} else {
		debug_printf (2, "  done\n");
		/* This is only actually needed in the chunked and eof
		 * cases, but it's harmless in the content-length
		 * case.
		 */
		soup_message_body_complete (msg->response_body);
	}
}

static void
free_offset (SoupMessage *msg, gpointer offset)
{
	g_free (offset);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	gsize *offset;

	if (!strcmp (path, "/chunked")) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_CHUNKED);
	} else if (!strcmp (path, "/content-length")) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_CONTENT_LENGTH);
		soup_message_headers_set_content_length (msg->response_headers,
							 full_response->length);
	} else if (!strcmp (path, "/eof")) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_EOF);
	} else {
		soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	}
	soup_message_set_status (msg, SOUP_STATUS_OK);

	offset = g_new0 (gsize, 1);
	g_signal_connect (msg, "wrote_headers",
			  G_CALLBACK (write_next_chunk), offset);
	g_signal_connect (msg, "wrote_chunk",
			  G_CALLBACK (write_next_chunk), offset);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (free_offset), offset);
}

static void
do_request (SoupSession *session, SoupURI *base_uri, char *path)
{
	SoupURI *uri;
	SoupMessage *msg;
	char *md5;

	uri = soup_uri_new_with_base (base_uri, path);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpint (msg->response_body->length, ==, full_response->length);

	md5 = g_compute_checksum_for_data (G_CHECKSUM_MD5,
					   (guchar *)msg->response_body->data,
					   msg->response_body->length);
	g_assert_cmpstr (md5, ==, full_response_md5);
	g_free (md5);

	g_object_unref (msg);
}

static void
do_chunked_test (gconstpointer data)
{
	SoupURI *base_uri = (SoupURI *)data;
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_request (session, base_uri, "chunked");
	soup_test_session_abort_unref (session);
}

static void
do_content_length_test (gconstpointer data)
{
	SoupURI *base_uri = (SoupURI *)data;
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_request (session, base_uri, "content-length");
	soup_test_session_abort_unref (session);
}

static void
do_eof_test (gconstpointer data)
{
	SoupURI *base_uri = (SoupURI *)data;
	SoupSession *session;

	g_test_bug ("572153");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_request (session, base_uri, "eof");
	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	SoupURI *base_uri;
	int ret;

	test_init (argc, argv, NULL);

	full_response = soup_test_get_index ();
	full_response_md5 = g_compute_checksum_for_data (G_CHECKSUM_MD5,
							 (guchar *)full_response->data,
							 full_response->length);

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);

	loop = g_main_loop_new (NULL, TRUE);

	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add_data_func ("/streaming/chunked", base_uri, do_chunked_test);
	g_test_add_data_func ("/streaming/content-length", base_uri, do_content_length_test);
	g_test_add_data_func ("/streaming/eof", base_uri, do_eof_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	g_main_loop_unref (loop);

	g_free (full_response_md5);
	soup_test_server_quit_unref (server);
	test_cleanup ();

	return ret;
}
