/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva <gns@gnome.org>.
 */

#include "test-utils.h"

SoupSession *session;
SoupURI *base_uri;
SoupMessageBody *chunk_data;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	GError *error = NULL;
	char *query_key;
	SoupBuffer *response = NULL;
	gsize offset;
	gboolean empty_response = FALSE;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (query) {
		query_key = g_hash_table_lookup (query, "chunked");
		if (query_key && g_str_equal (query_key, "yes")) {
			soup_message_headers_set_encoding (msg->response_headers,
							   SOUP_ENCODING_CHUNKED);
		}

		query_key = g_hash_table_lookup (query, "empty_response");
		if (query_key && g_str_equal (query_key, "yes"))
			empty_response = TRUE;
	}

	if (!strcmp (path, "/mbox")) {
		if (!empty_response) {
			response = soup_test_load_resource ("mbox", &error);
			g_assert_no_error (error);
		}

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/nosniff/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (msg->response_headers,
					     "X-Content-Type-Options", "nosniff");

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "no/sniffing-allowed");
	}

	if (g_str_has_prefix (path, "/text_or_binary/") || g_str_has_prefix (path, "/apache_bug/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/unknown/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "UNKNOWN/unknown");
	}

	if (g_str_has_prefix (path, "/type/")) {
		char **components = g_strsplit (path, "/", 4);
		char *ptr;

		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		/* Hack to allow passing type in the URI */
		ptr = g_strrstr (components[2], "_");
		*ptr = '/';

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", components[2]);
		g_strfreev (components);
	}

	if (g_str_has_prefix (path, "/multiple_headers/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/xml");
		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (response) {
		for (offset = 0; offset < response->length; offset += 500) {
			soup_message_body_append (msg->response_body,
						  SOUP_MEMORY_COPY,
						  response->data + offset,
						  MIN (500, response->length - offset));
		}

		soup_buffer_free (response);
	}

	soup_message_body_complete (msg->response_body);
}

static gboolean
unpause_msg (gpointer data)
{
	SoupMessage *msg = (SoupMessage*)data;
	debug_printf (2, "  unpause\n");
	soup_session_unpause_message (session, msg);
	return FALSE;
}


static void
content_sniffed (SoupMessage *msg, char *content_type, GHashTable *params, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	debug_printf (2, "  content-sniffed -> %s\n", content_type);

	soup_test_assert (g_object_get_data (G_OBJECT (msg), "got-chunk") == NULL,
			  "got-chunk got emitted before content-sniffed");

	g_object_set_data (G_OBJECT (msg), "content-sniffed", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		debug_printf (2, "  pause\n");
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_headers (SoupMessage *msg, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	debug_printf (2, "  got-headers\n");

	soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
			  "content-sniffed got emitted before got-headers");

	g_object_set_data (G_OBJECT (msg), "got-headers", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		debug_printf (2, "  pause\n");
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_chunk (SoupMessage *msg, SoupBuffer *chunk, gpointer data)
{
	gboolean should_accumulate = GPOINTER_TO_INT (data);

	debug_printf (2, "  got-chunk\n");

	g_object_set_data (G_OBJECT (msg), "got-chunk", GINT_TO_POINTER (TRUE));

	if (!should_accumulate) {
		if (!chunk_data)
			chunk_data = soup_message_body_new ();
		soup_message_body_append_buffer (chunk_data, chunk);
	}
}

static void
do_signals_test (gboolean should_content_sniff,
		 gboolean should_pause,
		 gboolean should_accumulate,
		 gboolean chunked_encoding,
		 gboolean empty_response)
{
	SoupURI *uri = soup_uri_new_with_base (base_uri, "/mbox");
	SoupMessage *msg = soup_message_new_from_uri ("GET", uri);
	SoupBuffer *expected;
	GError *error = NULL;
	SoupBuffer *body = NULL;

	debug_printf (1, "do_signals_test(%ssniff, %spause, %saccumulate, %schunked, %sempty)\n",
		      should_content_sniff ? "" : "!",
		      should_pause ? "" : "!",
		      should_accumulate ? "" : "!",
		      chunked_encoding ? "" : "!",
		      empty_response ? "" : "!");

	if (chunked_encoding)
		soup_uri_set_query (uri, "chunked=yes");

	if (empty_response) {
		if (uri->query) {
			char *tmp = uri->query;
			uri->query = g_strdup_printf ("%s&empty_response=yes", tmp);
			g_free (tmp);
		} else
			soup_uri_set_query (uri, "empty_response=yes");
	}

	soup_message_set_uri (msg, uri);

	soup_message_body_set_accumulate (msg->response_body, should_accumulate);

	g_object_connect (msg,
			  "signal::got-headers", got_headers, GINT_TO_POINTER (should_pause),
			  "signal::got-chunk", got_chunk, GINT_TO_POINTER (should_accumulate),
			  "signal::content_sniffed", content_sniffed, GINT_TO_POINTER (should_pause),
			  NULL);

	soup_session_send_message (session, msg);

	if (should_content_sniff) {
		soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") != NULL,
				  "content-sniffed did not get emitted");
	} else {
		soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
				  "content-sniffed got emitted without a sniffer");
	}

	if (empty_response)
		expected = soup_buffer_new (SOUP_MEMORY_STATIC, "", 0);
	else {
		expected = soup_test_load_resource ("mbox", &error);
		g_assert_no_error (error);
	}

	if (!should_accumulate && chunk_data)
		body = soup_message_body_flatten (chunk_data);
	else if (msg->response_body)
		body = soup_message_body_flatten (msg->response_body);

	if (body) {
		soup_assert_cmpmem (body->data, body->length,
				    expected->data, expected->length);
	}

	soup_buffer_free (expected);
	if (body)
		soup_buffer_free (body);
	if (chunk_data) {
		soup_message_body_free (chunk_data);
		chunk_data = NULL;
	}

	soup_uri_free (uri);
	g_object_unref (msg);
}

static void
do_signals_tests (gconstpointer data)
{
	gboolean should_content_sniff = GPOINTER_TO_INT (data);

	if (!should_content_sniff)
		soup_session_remove_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	do_signals_test (should_content_sniff,
			 FALSE, FALSE, FALSE, FALSE);
	do_signals_test (should_content_sniff,
			 FALSE, FALSE, TRUE, FALSE);
	do_signals_test (should_content_sniff,
			 FALSE, TRUE, FALSE, FALSE);
	do_signals_test (should_content_sniff,
			 FALSE, TRUE, TRUE, FALSE);

	do_signals_test (should_content_sniff,
			 TRUE, TRUE, FALSE, FALSE);
	do_signals_test (should_content_sniff,
			 TRUE, TRUE, TRUE, FALSE);
	do_signals_test (should_content_sniff,
			 TRUE, FALSE, FALSE, FALSE);
	do_signals_test (should_content_sniff,
			 TRUE, FALSE, TRUE, FALSE);

	/* FIXME g_test_bug ("587907") */
	do_signals_test (should_content_sniff,
			 TRUE, TRUE, FALSE, TRUE);
	do_signals_test (should_content_sniff,
			 TRUE, TRUE, TRUE, TRUE);

	if (!should_content_sniff)
		soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);
}

static void
sniffing_content_sniffed (SoupMessage *msg, const char *content_type,
			  GHashTable *params, gpointer data)
{
	char **sniffed_type = (char **)data;
	GString *full_header;
	GHashTableIter iter;
	gpointer key, value;

	full_header = g_string_new (content_type);

	g_hash_table_iter_init (&iter, params);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		if (full_header->len)
			g_string_append (full_header, "; ");
		soup_header_g_string_append_param (full_header,
						   (const char *) key,
						   (const char *) value);
	}

	*sniffed_type = g_string_free (full_header, FALSE);
}

static void
test_sniffing (const char *path, const char *expected_type)
{
	SoupURI *uri;
	SoupMessage *msg;
	SoupRequest *req;
	GInputStream *stream;
	char *sniffed_type = NULL;
	const char *req_sniffed_type;
	GError *error = NULL;

	uri = soup_uri_new_with_base (base_uri, path);
	msg = soup_message_new_from_uri ("GET", uri);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	soup_session_send_message (session, msg);
	g_assert_cmpstr (sniffed_type, ==, expected_type);
	g_free (sniffed_type);
	g_object_unref (msg);

	req = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (req, NULL, 0, &error);
	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);
		g_object_unref (stream);
	}
	g_assert_no_error (error);
	g_clear_error (&error);

	req_sniffed_type = soup_request_get_content_type (req);
	g_assert_cmpstr (req_sniffed_type, ==, expected_type);
	g_object_unref (req);

	soup_uri_free (uri);
}

static void
do_sniffing_test (gconstpointer data)
{
	const char *path_and_result = data;
	char **parts;

	parts = g_strsplit (path_and_result, " => ", -1);
	g_assert (parts && parts[0] && parts[1] && !parts[2]);

	test_sniffing (parts[0], parts[1]);
	g_strfreev (parts);
}

static void
test_disabled (gconstpointer data)
{
	const char *path = data;
	SoupURI *uri;
	SoupMessage *msg;
	SoupRequest *req;
	GInputStream *stream;
	char *sniffed_type = NULL;
	const char *sniffed_content_type;
	GError *error = NULL;

	g_test_bug ("574773");

	uri = soup_uri_new_with_base (base_uri, path);

	msg = soup_message_new_from_uri ("GET", uri);
	g_assert_false (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));
	soup_message_disable_feature (msg, SOUP_TYPE_CONTENT_SNIFFER);
	g_assert_true (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	soup_session_send_message (session, msg);

	g_assert_null (sniffed_type);
	g_object_unref (msg);

	req = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	g_assert_false (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));
	soup_message_disable_feature (msg, SOUP_TYPE_CONTENT_SNIFFER);
	g_assert_true (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));
	g_object_unref (msg);
	stream = soup_test_request_send (req, NULL, 0, &error);
	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);
		g_object_unref (stream);
	}
	g_assert_no_error (error);

	sniffed_content_type = soup_request_get_content_type (req);
	g_assert_cmpstr (sniffed_content_type, ==, NULL);

	g_object_unref (req);

	soup_uri_free (uri);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	g_test_add_data_func ("/sniffing/signals/no-sniffer",
			      GINT_TO_POINTER (FALSE),
			      do_signals_tests);
	g_test_add_data_func ("/sniffing/signals/with-sniffer",
			      GINT_TO_POINTER (TRUE),
			      do_signals_tests);

	/* Test the apache bug sniffing path */
	g_test_add_data_func ("/sniffing/apache-bug/binary",
			      "/apache_bug/text_binary.txt => application/octet-stream",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/apache-bug/text",
			      "/apache_bug/text.txt => text/plain",
			      do_sniffing_test);

	/* X-Content-Type-Options: nosniff */
	g_test_add_data_func ("/sniffing/nosniff",
			      "nosniff/home.gif => no/sniffing-allowed",
			      do_sniffing_test);

	/* GIF is a 'safe' type */
	g_test_add_data_func ("/sniffing/type/gif",
			      "text_or_binary/home.gif => image/gif",
			      do_sniffing_test);

	/* With our current code, no sniffing is done using GIO, so
	 * the mbox will be identified as text/plain; should we change
	 * this?
	 */
	g_test_add_data_func ("/sniffing/type/mbox",
			      "text_or_binary/mbox => text/plain",
			      do_sniffing_test);

	/* HTML is considered unsafe for this algorithm, since it is
	 * scriptable, so going from text/plain to text/html is
	 * considered 'privilege escalation'
	 */
	g_test_add_data_func ("/sniffing/type/html-in-text-context",
			      "text_or_binary/test.html => text/plain",
			      do_sniffing_test);

	/* text/plain with binary content and unknown pattern should be
	 * application/octet-stream
	 */
	g_test_add_data_func ("/sniffing/type/text-binary",
			      "text_or_binary/text_binary.txt => application/octet-stream",
			      do_sniffing_test);

	/* text/html with binary content and scriptable pattern should be
	 * application/octet-stream to avoid 'privilege escalation'
	 */
	g_test_add_data_func ("/sniffing/type/html-binary",
			      "text_or_binary/html_binary.html => application/octet-stream",
			      do_sniffing_test);

	/* text/plain with binary content and non scriptable known pattern should
	 * be the given type
	 */
	g_test_add_data_func ("/sniffing/type/ps",
			      "text_or_binary/ps_binary.ps => application/postscript",
			      do_sniffing_test);

	/* Test the unknown sniffing path */
	g_test_add_data_func ("/sniffing/type/unknown-html",
			      "unknown/test.html => text/html",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/unknown-gif",
			      "unknown/home.gif => image/gif",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/unknown-mbox",
			      "unknown/mbox => text/plain",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/unknown-binary",
			      "unknown/text_binary.txt => application/octet-stream",
			      do_sniffing_test);
	/* FIXME g_test_bug ("715126") */
	g_test_add_data_func ("/sniffing/type/unknown-leading-space",
			      "unknown/leading_space.html => text/html",
			      do_sniffing_test);
	/* https://bugs.webkit.org/show_bug.cgi?id=173923 */
	g_test_add_data_func ("/sniffing/type/unknown-xml",
			      "unknown/misc.xml => text/xml",
			      do_sniffing_test);

	/* Test the XML sniffing path */
	g_test_add_data_func ("/sniffing/type/xml",
			      "type/text_xml/home.gif => text/xml",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/xml+xml",
			      "type/anice_type+xml/home.gif => anice/type+xml",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/application-xml",
			      "type/application_xml/home.gif => application/xml",
			      do_sniffing_test);

	/* Test the feed or html path */
	g_test_add_data_func ("/sniffing/type/html/html",
			      "type/text_html/test.html => text/html",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/html/rss",
			      "type/text_html/rss20.xml => application/rss+xml",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/html/atom",
			      "type/text_html/atom.xml => application/atom+xml",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/html/rdf",
			      "type/text_html/feed.rdf => application/rss+xml",
			      do_sniffing_test);

	/* Test the image sniffing path */
	g_test_add_data_func ("/sniffing/type/image/gif",
			      "type/image_png/home.gif => image/gif",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/image/png",
			      "type/image_gif/home.png => image/png",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/image/jpeg",
			      "type/image_png/home.jpg => image/jpeg",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/image/webp",
			      "type/image_png/tux.webp => image/webp",
			      do_sniffing_test);

	/* Test audio and video sniffing path */
	g_test_add_data_func ("/sniffing/type/audio/wav",
			      "type/audio_mpeg/test.wav => audio/wave",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/audio/aiff",
			      "type/audio_mpeg/test.aiff => audio/aiff",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/audio/ogg",
			      "type/audio_mpeg/test.ogg => application/ogg",
			      do_sniffing_test);
	g_test_add_data_func ("/sniffing/type/video/webm",
			      "type/video_theora/test.webm => video/webm",
			      do_sniffing_test);

	/* Test the MP4 sniffing path */
	g_test_add_data_func ("/sniffing/type/video/mp4",
			      "unknown/test.mp4 => video/mp4",
			      do_sniffing_test);

	/* The spec tells us to only use the last Content-Type header */
	g_test_add_data_func ("/sniffing/multiple-headers",
			      "multiple_headers/home.gif => image/gif",
			      do_sniffing_test);

	/* Test that we keep the parameters when sniffing */
	g_test_add_data_func ("/sniffing/parameters",
			      "type/text_html; charset=UTF-8/test.html => text/html; charset=UTF-8",
			      do_sniffing_test);

	/* Test that disabling the sniffer works correctly */
	g_test_add_data_func ("/sniffing/disabled",
			      "/text_or_binary/home.gif",
			      test_disabled);

	ret = g_test_run ();

	soup_uri_free (base_uri);

	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
