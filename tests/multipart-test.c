/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2011 Collabora Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test-utils.h"

#ifndef G_OS_WIN32
#include <unistd.h>
#endif

#define READ_BUFFER_SIZE 8192

typedef enum {
	NO_MULTIPART,
	SYNC_MULTIPART,
	ASYNC_MULTIPART,
	ASYNC_MULTIPART_SMALL_READS
} MultipartMode;

char *buffer;
SoupSession *session;
char *base_uri_string;
SoupURI *base_uri;
SoupMultipartInputStream *multipart;
unsigned passes;


/* This payload contains 4 different responses.
 *
 * First, a text/html response with a Content-Length (31);
 * Second, a response lacking Content-Type with Content-Length (11);
 * Third, a text/css response with no Content-Length;
 * Fourth, same as the third, but with different content;
 */
const char *payload = \
	"--cut-here\r\n" \
	"Content-Type: text/html\n"
	"Content-Length: 30\r\n" \
	"\r\n" \
	"<html><body>Hey!</body></html>" \
	"\r\n--cut-here\r\n" \
	"Content-Length: 10\r\n" \
	"\r\n" \
	"soup rocks" \
	"\r\n--cut-here\r\n" \
	"Content-Type: text/css\r\n" \
	"\r\n" \
	".soup { before: rocks; }" \
	"\r\n--cut-here\n" /* Tests boundary ending in a single \n. */ \
	"Content-Type: text/css\r\n" \
	"\r\n" \
	"#soup { background-color: black; }" \
        "\r\n--cut-here--";

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	soup_message_headers_append (msg->response_headers,
				     "Content-Type", "multipart/x-mixed-replace; boundary=cut-here");

	soup_message_body_append (msg->response_body,
				  SOUP_MEMORY_STATIC,
				  payload,
				  strlen (payload));

	soup_message_body_complete (msg->response_body);
}

static void
content_sniffed (SoupMessage *msg, char *content_type, GHashTable *params, int *sniffed_count)
{
	*sniffed_count = *sniffed_count + 1;
	debug_printf (2, "  content-sniffed -> %s\n", content_type);
}

static void
check_is_next (gboolean is_next)
{
	soup_test_assert (is_next,
			  "expected a header, but there are no more headers");
}

static void
got_headers (SoupMessage *msg, int *headers_count)
{
	SoupMessageHeadersIter iter;
	gboolean is_next;
	const char* name, *value;

	*headers_count = *headers_count + 1;

	soup_message_headers_iter_init (&iter, msg->response_headers);

	is_next = soup_message_headers_iter_next (&iter, &name, &value);
	check_is_next (is_next);

	if (g_str_equal (name, "Date")) {
		is_next = soup_message_headers_iter_next (&iter, &name, &value);
		check_is_next (is_next);
	}

	g_assert_cmpstr (name, ==, "Content-Type");
	g_assert_cmpstr (value, ==, "multipart/x-mixed-replace; boundary=cut-here");
}

static void
read_cb (GObject *source, GAsyncResult *asyncResult, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	GInputStream *stream = G_INPUT_STREAM (source);
	GError *error = NULL;
	gssize bytes_read;

	bytes_read = g_input_stream_read_finish (stream, asyncResult, &error);
	g_assert_no_error (error);
	if (error) {
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	}

	if (!bytes_read) {
		g_input_stream_close (stream, NULL, &error);
		g_assert_no_error (error);
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	}

	g_input_stream_read_async (stream, buffer, READ_BUFFER_SIZE,
				   G_PRIORITY_DEFAULT, NULL,
				   read_cb, data);
}

static void
no_multipart_handling_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	SoupRequest *request = SOUP_REQUEST (source);
	GError *error = NULL;
	GInputStream* in;

	in = soup_request_send_finish (request, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	g_input_stream_read_async (in, buffer, READ_BUFFER_SIZE,
				   G_PRIORITY_DEFAULT, NULL,
				   read_cb, data);
}

static void
multipart_close_part_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	GInputStream *in = G_INPUT_STREAM (source);
	GError *error = NULL;

	g_input_stream_close_finish (in, res, &error);
	g_assert_no_error (error);
}

static void multipart_next_part_cb (GObject *source,
				    GAsyncResult *res,
				    gpointer data);

static void
check_read (gsize nread, unsigned passes)
{
	switch (passes) {
	case 0:
		g_assert_cmpint (nread, ==, 30);
		break;
	case 1:
		g_assert_cmpint (nread, ==, 10);
		break;
	case 2:
		g_assert_cmpint (nread, ==, 24);
		break;
	case 3:
		g_assert_cmpint (nread, ==, 34);
		break;
	default:
		soup_test_assert (FALSE, "unexpected read of size: %d", (int)nread);
		break;
	}
}

static void
multipart_read_cb (GObject *source, GAsyncResult *asyncResult, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	GInputStream *in = G_INPUT_STREAM (source);
	GError *error = NULL;
	static gssize bytes_read_for_part = 0;
	gssize bytes_read;

	bytes_read = g_input_stream_read_finish (in, asyncResult, &error);
	g_assert_no_error (error);
	if (error) {
		g_input_stream_close_async (in, G_PRIORITY_DEFAULT, NULL,
					    multipart_close_part_cb, NULL);
		g_object_unref (in);

		g_main_loop_quit (loop);
		return;
	}

	/* Read 0 bytes - try to start reading another part. */
	if (!bytes_read) {
		check_read (bytes_read_for_part, passes);
		bytes_read_for_part = 0;
		passes++;

		g_input_stream_close_async (in, G_PRIORITY_DEFAULT, NULL,
					    multipart_close_part_cb, NULL);
		g_object_unref (in);

		soup_multipart_input_stream_next_part_async (multipart, G_PRIORITY_DEFAULT, NULL,
							     multipart_next_part_cb, data);
		return;
	}

	bytes_read_for_part += bytes_read;
	g_input_stream_read_async (in, buffer, READ_BUFFER_SIZE,
				   G_PRIORITY_DEFAULT, NULL,
				   multipart_read_cb, data);
}

static void
check_headers (SoupMultipartInputStream* multipart, unsigned passes)
{
	SoupMessageHeaders *headers;
	SoupMessageHeadersIter iter;
	gboolean is_next;
	const char *name, *value;

	headers = soup_multipart_input_stream_get_headers (multipart);
	soup_message_headers_iter_init (&iter, headers);

	switch (passes) {
	case 0:
		is_next = soup_message_headers_iter_next (&iter, &name, &value);
		check_is_next (is_next);

		g_assert_cmpstr (name, ==, "Content-Type");
		g_assert_cmpstr (value, ==, "text/html");

		is_next = soup_message_headers_iter_next (&iter, &name, &value);
		check_is_next (is_next);

		g_assert_cmpstr (name, ==, "Content-Length");
		g_assert_cmpstr (value, ==, "30");

		break;
	case 1:
		is_next = soup_message_headers_iter_next (&iter, &name, &value);
		check_is_next (is_next);

		g_assert_cmpstr (name, ==, "Content-Length");
		g_assert_cmpstr (value, ==, "10");

		break;
	case 2:
	case 3:
		is_next = soup_message_headers_iter_next (&iter, &name, &value);
		check_is_next (is_next);

		g_assert_cmpstr (name, ==, "Content-Type");
		g_assert_cmpstr (value, ==, "text/css");

		break;
	default:
		soup_test_assert (FALSE, "unexpected part received");
		break;
	}
}

static void
multipart_next_part_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	GError *error = NULL;
	GInputStream *in;
	gsize read_size = READ_BUFFER_SIZE;

	g_assert (SOUP_MULTIPART_INPUT_STREAM (source) == multipart);

	in = soup_multipart_input_stream_next_part_finish (multipart, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_clear_error (&error);
		g_object_unref (multipart);
		g_main_loop_quit (loop);
		return;
	}

	if (!in) {
		g_assert_cmpint (passes, ==, 4);
		g_object_unref (multipart);
		g_main_loop_quit (loop);
		return;
	}

	check_headers (multipart, passes);

	if (g_object_get_data (G_OBJECT (multipart), "multipart-small-reads"))
		read_size = 4;

	g_input_stream_read_async (in, buffer, read_size,
				   G_PRIORITY_DEFAULT, NULL,
				   multipart_read_cb, data);
}

static void
multipart_handling_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	SoupRequest *request = SOUP_REQUEST (source);
	GError *error = NULL;
	GInputStream *in;
	SoupMessage *message;

	in = soup_request_send_finish (request, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	message = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	multipart = soup_multipart_input_stream_new (message, in);
	g_object_unref (message);
	g_object_unref (in);

	if (g_object_get_data (source, "multipart-small-reads"))
		g_object_set_data (G_OBJECT (multipart), "multipart-small-reads", GINT_TO_POINTER(1));

	soup_multipart_input_stream_next_part_async (multipart, G_PRIORITY_DEFAULT, NULL,
						     multipart_next_part_cb, data);
}

static void
sync_multipart_handling_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	SoupRequest *request = SOUP_REQUEST (source);
	GError *error = NULL;
	GInputStream *in;
	SoupMessage *message;
	char buffer[READ_BUFFER_SIZE];
	gsize bytes_read;

	in = soup_request_send_finish (request, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	message = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	multipart = soup_multipart_input_stream_new (message, in);
	g_object_unref (message);
	g_object_unref (in);

	while (TRUE) {
		in = soup_multipart_input_stream_next_part (multipart, NULL, &error);
		g_assert_no_error (error);
		if (error) {
			g_clear_error (&error);
			break;
		}

		if (!in)
			break;

		check_headers (multipart, passes);

		g_input_stream_read_all (in, (void*)buffer, sizeof (buffer), &bytes_read, NULL, &error);
		g_assert_no_error (error);
		if (error) {
			g_clear_error (&error);
			g_object_unref (in);
			break;
		}

		check_read (bytes_read, passes);

		passes++;
		g_object_unref (in);
	}

	g_assert_cmpint (passes, ==, 4);

	g_main_loop_quit (loop);
	g_object_unref (multipart);
}

static void
test_multipart (gconstpointer data)
{
	int headers_expected = 1, sniffed_expected = 1;
	MultipartMode multipart_mode = GPOINTER_TO_INT (data);
	SoupRequest* request;
	SoupMessage *msg;
	GMainLoop *loop;
	int headers_count = 0;
	int sniffed_count = 0;
	GHashTable *params;
	const char *content_type;
	gboolean message_is_multipart = FALSE;
	GError* error = NULL;

	request = soup_session_request (session, base_uri_string, &error);
	g_assert_no_error (error);
	if (error)
		return;

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	/* This is used to track the number of parts. */
	passes = 0;

	/* Force the server to close the connection. */
	soup_message_headers_append (msg->request_headers,
				     "Connection", "close");

	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), &headers_count);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (content_sniffed), &sniffed_count);

	loop = g_main_loop_new (NULL, TRUE);

	if (multipart_mode == ASYNC_MULTIPART)
		soup_request_send_async (request, NULL, multipart_handling_cb, loop);
	else if (multipart_mode == ASYNC_MULTIPART_SMALL_READS) {
		g_object_set_data (G_OBJECT (request), "multipart-small-reads", GINT_TO_POINTER(1));
		soup_request_send_async (request, NULL, multipart_handling_cb, loop);
	} else if (multipart_mode == SYNC_MULTIPART)
		soup_request_send_async (request, NULL, sync_multipart_handling_cb, loop);
	else
		soup_request_send_async (request, NULL, no_multipart_handling_cb, loop);

	g_main_loop_run (loop);

	content_type = soup_message_headers_get_content_type (msg->response_headers, &params);

	if (content_type &&
	    g_str_has_prefix (content_type, "multipart/") &&
	    g_hash_table_lookup (params, "boundary")) {
		message_is_multipart = TRUE;
	}
	g_clear_pointer (&params, g_hash_table_unref);

	g_assert_true (message_is_multipart);
	g_assert_cmpint (headers_count, ==, headers_expected);
	g_assert_cmpint (sniffed_count, ==, sniffed_expected);

	g_object_unref (msg);
	g_object_unref (request);
	g_main_loop_unref (loop);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	int ret;

	test_init (argc, argv, NULL);

	buffer = g_malloc (READ_BUFFER_SIZE);

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);
	base_uri_string = soup_uri_to_string (base_uri, FALSE);

	/* FIXME: I had to raise the number of connections allowed here, otherwise I
	 * was hitting the limit, which indicates some connections are not dying.
	 */
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 "use-thread-context", TRUE,
					 "max-conns", 20,
					 "max-conns-per-host", 20,
					 NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	g_test_add_data_func ("/multipart/no", GINT_TO_POINTER (NO_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/sync", GINT_TO_POINTER (SYNC_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/async", GINT_TO_POINTER (ASYNC_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/async-small-reads", GINT_TO_POINTER (ASYNC_MULTIPART_SMALL_READS), test_multipart);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	g_free (base_uri_string);
	g_free (buffer);

	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
