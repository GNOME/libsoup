/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
GUri *base_uri;
SoupMultipartInputStream *multipart;
unsigned passes;
GMainLoop *loop;


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
	"\r\n--cut-here\r\n"; /* Tests missing termination .*/

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	SoupMessageHeaders *response_headers;
	SoupMessageBody *response_body;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

	response_headers = soup_server_message_get_response_headers (msg);
	soup_message_headers_append (response_headers,
				     "Content-Type", "multipart/x-mixed-replace; boundary=cut-here");

	response_body = soup_server_message_get_response_body (msg);
	soup_message_body_append (response_body,
				  SOUP_MEMORY_STATIC,
				  payload,
				  strlen (payload));

	soup_message_body_complete (response_body);
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

	soup_message_headers_iter_init (&iter, soup_message_get_response_headers (msg));

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
				   read_cb, NULL);
}

static void
no_multipart_handling_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	SoupSession *session = SOUP_SESSION (source);
	GError *error = NULL;
	GInputStream* in;

	in = soup_session_send_finish (session, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	g_input_stream_read_async (in, buffer, READ_BUFFER_SIZE,
				   G_PRIORITY_DEFAULT, NULL,
				   read_cb, NULL);
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
							     multipart_next_part_cb, NULL);
		return;
	}

	bytes_read_for_part += bytes_read;
	g_input_stream_read_async (in, buffer, READ_BUFFER_SIZE,
				   G_PRIORITY_DEFAULT, NULL,
				   multipart_read_cb, NULL);
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
	GError *error = NULL;
	GInputStream *in;
	gsize read_size = READ_BUFFER_SIZE;

	g_assert_true (SOUP_MULTIPART_INPUT_STREAM (source) == multipart);

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
	SoupMessage *message;
	SoupSession *session = SOUP_SESSION (source);
	GError *error = NULL;
	GInputStream *in;

	in = soup_session_send_finish (session, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	message = soup_session_get_async_result_message (session, res);
	multipart = soup_multipart_input_stream_new (message, in);
	g_object_unref (in);

	if (g_object_get_data (G_OBJECT (message), "multipart-small-reads"))
		g_object_set_data (G_OBJECT (multipart), "multipart-small-reads", GINT_TO_POINTER(1));

	soup_multipart_input_stream_next_part_async (multipart, G_PRIORITY_DEFAULT, NULL,
						     multipart_next_part_cb, NULL);
}

static void
sync_multipart_handling_cb (GObject *source, GAsyncResult *res, gpointer data)
{
	SoupMessage *message;
	SoupSession *session = SOUP_SESSION (source);
	GError *error = NULL;
	GInputStream *in;
	char buffer[READ_BUFFER_SIZE];
	gsize bytes_read;

	in = soup_session_send_finish (session, res, &error);
	g_assert_no_error (error);
	if (error) {
		g_main_loop_quit (loop);
		return;
	}

	message = soup_session_get_async_result_message (session, res);
	multipart = soup_multipart_input_stream_new (message, in);
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
	SoupMessage *msg;
	int headers_count = 0;
	int sniffed_count = 0;
	GHashTable *params;
	const char *content_type;
	gboolean message_is_multipart = FALSE;

	msg = soup_message_new ("GET", base_uri_string);

	/* This is used to track the number of parts. */
	passes = 0;

	/* Force the server to close the connection. */
	soup_message_headers_append (soup_message_get_request_headers (msg),
				     "Connection", "close");

	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), &headers_count);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (content_sniffed), &sniffed_count);

	loop = g_main_loop_new (NULL, TRUE);

	if (multipart_mode == ASYNC_MULTIPART)
		soup_session_send_async (session, msg, 0, NULL, multipart_handling_cb, NULL);
	else if (multipart_mode == ASYNC_MULTIPART_SMALL_READS) {
		g_object_set_data (G_OBJECT (msg), "multipart-small-reads", GINT_TO_POINTER(1));
		soup_session_send_async (session, msg, 0, NULL, multipart_handling_cb, NULL);
	} else if (multipart_mode == SYNC_MULTIPART)
		soup_session_send_async (session, msg, 0, NULL, sync_multipart_handling_cb, NULL);
	else
		soup_session_send_async (session, msg, 0, NULL, no_multipart_handling_cb, NULL);

	g_main_loop_run (loop);

	content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (msg), &params);

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
	g_main_loop_unref (loop);
	loop = NULL;
}

static void
test_multipart_bounds_good (void)
{
	#define TEXT "line1\r\nline2"
	SoupMultipart *multipart;
	SoupMessageHeaders *headers, *set_headers = NULL;
	GBytes *bytes, *set_bytes = NULL;
	const char *raw_data = "--123\r\nContent-Type: text/plain;\r\n\r\n" TEXT "\r\n--123--\r\n";
	gboolean success;

	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_message_headers_append (headers, "Content-Type", "multipart/mixed; boundary=\"123\"");

	bytes = g_bytes_new (raw_data, strlen (raw_data));

	multipart = soup_multipart_new_from_message (headers, bytes);

	g_assert_nonnull (multipart);
	g_assert_cmpint (soup_multipart_get_length (multipart), ==, 1);
	success = soup_multipart_get_part (multipart, 0, &set_headers, &set_bytes);
	g_assert_true (success);
	g_assert_nonnull (set_headers);
	g_assert_nonnull (set_bytes);
	g_assert_cmpint (strlen (TEXT), ==, g_bytes_get_size (set_bytes));
	g_assert_cmpstr ("text/plain", ==, soup_message_headers_get_content_type (set_headers, NULL));
	g_assert_cmpmem (TEXT, strlen (TEXT), g_bytes_get_data (set_bytes, NULL), g_bytes_get_size (set_bytes));

	soup_message_headers_unref (headers);
	g_bytes_unref (bytes);

	soup_multipart_free (multipart);

	#undef TEXT
}

static void
test_multipart_bounds_bad (void)
{
	SoupMultipart *multipart;
	SoupMessageHeaders *headers;
	GBytes *bytes;
	const char *raw_data = "--123\r\nContent-Type: text/plain;\r\nline1\r\nline2\r\n--123--\r\n";

	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_message_headers_append (headers, "Content-Type", "multipart/mixed; boundary=\"123\"");

	bytes = g_bytes_new (raw_data, strlen (raw_data));

	/* it did read out of raw_data/bytes bounds */
	multipart = soup_multipart_new_from_message (headers, bytes);
	g_assert_null (multipart);

	soup_message_headers_unref (headers);
	g_bytes_unref (bytes);
}

static void
test_multipart_bounds_bad_2 (void)
{
	SoupMultipart *multipart;
	SoupMessageHeaders *headers;
	GBytes *bytes;
	const char *raw_data = "\n--123\r\nline\r\n--123--\r";

	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_message_headers_append (headers, "Content-Type", "multipart/mixed; boundary=\"123\"");

	bytes = g_bytes_new (raw_data, strlen (raw_data));

	multipart = soup_multipart_new_from_message (headers, bytes);
	g_assert_nonnull (multipart);

	soup_multipart_free (multipart);
	soup_message_headers_unref (headers);
	g_bytes_unref (bytes);
}

static void
test_multipart_too_large (void)
{
	const char *raw_body =
		"-------------------\r\n"
		"-\n"
		"Cont\"\r\n"
		"Content-Tynt----e:n\x8erQK\r\n"
		"Content-Disposition:   name=  form-; name=\"file\"; filename=\"ype:i/  -d; ----\xae\r\n"
		"Content-Typimag\x01/png--\\\n"
		"\r\n"
		"---:\n\r\n"
		"\r\n"
		"-------------------------------------\r\n"
		"---------\r\n"
		"----------------------";
	GBytes *body;
	GHashTable *params;
	SoupMessageHeaders *headers;
	SoupMultipart *multipart;

	params = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (params, (gpointer) "boundary", (gpointer) "-----------------");
	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
	soup_message_headers_set_content_type (headers, "multipart/form-data", params);
	g_hash_table_unref (params);

	body = g_bytes_new_static (raw_body, strlen (raw_body));
	multipart = soup_multipart_new_from_message (headers, body);
	soup_message_headers_unref (headers);
	g_bytes_unref (body);

	g_assert_nonnull (multipart);
	g_assert_cmpint (soup_multipart_get_length (multipart), ==, 1);
	g_assert_true (soup_multipart_get_part (multipart, 0, &headers, &body));
	g_assert_cmpint (g_bytes_get_size (body), ==, 0);
	soup_multipart_free (multipart);
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
	base_uri_string = g_uri_to_string (base_uri);

	/* FIXME: I had to raise the number of connections allowed here, otherwise I
	 * was hitting the limit, which indicates some connections are not dying.
	 */
	session = soup_test_session_new ("max-conns", 20,
					 "max-conns-per-host", 20,
					 NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	g_test_add_data_func ("/multipart/no", GINT_TO_POINTER (NO_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/sync", GINT_TO_POINTER (SYNC_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/async", GINT_TO_POINTER (ASYNC_MULTIPART), test_multipart);
	g_test_add_data_func ("/multipart/async-small-reads", GINT_TO_POINTER (ASYNC_MULTIPART_SMALL_READS), test_multipart);
	g_test_add_func ("/multipart/bounds-good", test_multipart_bounds_good);
	g_test_add_func ("/multipart/bounds-bad", test_multipart_bounds_bad);
	g_test_add_func ("/multipart/bounds-bad-2", test_multipart_bounds_bad_2);
	g_test_add_func ("/multipart/too-large", test_multipart_too_large);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	g_free (base_uri_string);
	g_free (buffer);

	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
