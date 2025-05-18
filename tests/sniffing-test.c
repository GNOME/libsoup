/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva <gns@gnome.org>.
 */

#include "test-utils.h"

SoupSession *session;
GUri *base_uri;

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	GError *error = NULL;
	char *query_key;
	GBytes *response = NULL;
	gsize offset;
	SoupMessageHeaders *response_headers;
	SoupMessageBody *response_body;
	gboolean empty_response = FALSE;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

	response_headers = soup_server_message_get_response_headers (msg);
	if (query) {
		query_key = g_hash_table_lookup (query, "chunked");
		if (query_key && g_str_equal (query_key, "yes")) {
			soup_message_headers_set_encoding (response_headers,
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

		soup_message_headers_append (response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/nosniff/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (response_headers,
					     "X-Content-Type-Options", "nosniff");

		soup_message_headers_append (response_headers,
					     "Content-Type", "no/sniffing-allowed");
	}

	if (g_str_has_prefix (path, "/text_or_binary/") || g_str_has_prefix (path, "/apache_bug/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (response_headers,
					     "Content-Type", "text/plain");
	}

	if (g_str_has_prefix (path, "/unknown/")) {
		if (!empty_response) {
			char *base_name = g_path_get_basename (path);

			response = soup_test_load_resource (base_name, &error);
			g_assert_no_error (error);
			g_free (base_name);
		}

		soup_message_headers_append (response_headers,
					     "Content-Type", "UNKNOWN/unknown");
	}

	if (g_str_has_prefix (path, "/type/")) {
		char **components = g_strsplit (path, "/", 4);

		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		/* Hack to allow passing type in the URI */
		char *ptr = g_strrstr (components[2], "_");
		*ptr = '/';

		soup_message_headers_append (response_headers,
					     "Content-Type", components[2]);
		g_strfreev (components);
	}

	if (g_str_has_prefix (path, "/multiple_headers/")) {
		char *base_name = g_path_get_basename (path);

		response = soup_test_load_resource (base_name, &error);
		g_assert_no_error (error);
		g_free (base_name);

		soup_message_headers_append (response_headers,
					     "Content-Type", "text/xml");
		soup_message_headers_append (response_headers,
					     "Content-Type", "text/plain");
	}

	response_body = soup_server_message_get_response_body (msg);
	if (response) {
                gsize response_size = g_bytes_get_size (response);
		for (offset = 0; offset < response_size; offset += 500) {
                        GBytes *chunk = g_bytes_new_from_bytes (response, offset, MIN (500, response_size - offset));
                        soup_message_body_append_bytes (response_body, chunk);
                        g_bytes_unref (chunk);
		}

		g_bytes_unref (response);
	}

	soup_message_body_complete (response_body);
}

static void
content_sniffed (SoupMessage *msg,
		 char        *content_type,
		 GHashTable  *params)
{
	debug_printf (2, "  content-sniffed -> %s\n", content_type);

	soup_test_assert (g_object_get_data (G_OBJECT (msg), "got-chunk") == NULL,
			  "got-chunk got emitted before content-sniffed");

	g_object_set_data (G_OBJECT (msg), "content-sniffed", GINT_TO_POINTER (TRUE));
}

static void
got_headers (SoupMessage *msg)
{
	debug_printf (2, "  got-headers\n");

	soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
			  "content-sniffed got emitted before got-headers");

	g_object_set_data (G_OBJECT (msg), "got-headers", GINT_TO_POINTER (TRUE));
}

static void
do_signals_test (gboolean should_content_sniff,
		 gboolean chunked_encoding,
		 gboolean empty_response)
{
	GUri *uri = g_uri_parse_relative (base_uri, "/mbox", SOUP_HTTP_URI_FLAGS, NULL);
	SoupMessage *msg = soup_message_new_from_uri ("GET", uri);
	GBytes *expected;
	GError *error = NULL;
	GBytes *body = NULL;

	debug_printf (1, "do_signals_test(%ssniff, %schunked, %sempty)\n",
		      should_content_sniff ? "" : "!",
		      chunked_encoding ? "" : "!",
		      empty_response ? "" : "!");

	if (chunked_encoding) {
		GUri *copy = soup_uri_copy (uri, SOUP_URI_QUERY, "chunked=yes", SOUP_URI_NONE);
		g_uri_unref (uri);
		uri = copy;

	}

	if (empty_response) {
		if (g_uri_get_query (uri)) {
			char *new_query = g_strdup_printf ("%s&empty_response=yes", g_uri_get_query (uri));
			GUri *copy = soup_uri_copy (uri, SOUP_URI_QUERY, new_query, SOUP_URI_NONE);
     			g_free (new_query);
			g_uri_unref (uri);
			uri = copy;
		} else {
			GUri *copy = soup_uri_copy (uri, SOUP_URI_QUERY, "empty_response=yes", SOUP_URI_NONE);
			g_uri_unref (uri);
			uri = copy;
		}
	}

	soup_message_set_uri (msg, uri);

	g_object_connect (msg,
			  "signal::got-headers", got_headers, NULL,
			  "signal::content_sniffed", content_sniffed, NULL,
			  NULL);

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	if (should_content_sniff) {
		soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") != NULL,
				  "content-sniffed did not get emitted");
	} else {
		soup_test_assert (g_object_get_data (G_OBJECT (msg), "content-sniffed") == NULL,
				  "content-sniffed got emitted without a sniffer");
	}

	if (empty_response)
		expected = g_bytes_new_static (NULL, 0);
	else {
		expected = soup_test_load_resource ("mbox", &error);
		g_assert_no_error (error);
	}

	if (body) {
                //g_message ("|||body (%zu): %s", g_bytes_get_size (body), (char*)g_bytes_get_data (body, NULL));
                //g_message ("|||expected (%zu): %s", g_bytes_get_size (expected), (char*)g_bytes_get_data (expected, NULL));
                g_assert_true (g_bytes_equal (body, expected));
        }

	g_bytes_unref (expected);
	g_bytes_unref (body);
	g_uri_unref (uri);
	g_object_unref (msg);
}

static void
do_signals_tests (gconstpointer data)
{
	gboolean should_content_sniff = GPOINTER_TO_INT (data);

	if (!should_content_sniff)
		soup_session_remove_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	do_signals_test (should_content_sniff,
			 FALSE, FALSE);
	do_signals_test (should_content_sniff,
			 TRUE, FALSE);
	do_signals_test (should_content_sniff,
			 FALSE, TRUE);
	do_signals_test (should_content_sniff,
			 TRUE, TRUE);

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
	GUri *uri;
	SoupMessage *msg;
	GBytes *body;
	char *sniffed_type = NULL;

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	body = soup_test_session_async_send (session, msg, NULL, NULL);
	g_assert_cmpstr (sniffed_type, ==, expected_type);
	g_free (sniffed_type);
	g_bytes_unref (body);
	g_object_unref (msg);
	g_uri_unref (uri);
}

static void
do_sniffing_test (gconstpointer data)
{
	const char *path_and_result = data;
	char **parts;

	parts = g_strsplit (path_and_result, " => ", -1);
	g_assert_true (parts && parts[0] && parts[1] && !parts[2]);

	test_sniffing (parts[0], parts[1]);
	g_strfreev (parts);
}

static void
test_disabled (gconstpointer data)
{
	const char *path = data;
	GUri *uri;
	SoupMessage *msg;
	GBytes *body;
	char *sniffed_type = NULL;

	g_test_bug ("574773");

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);

	msg = soup_message_new_from_uri ("GET", uri);
	g_assert_false (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));
	soup_message_disable_feature (msg, SOUP_TYPE_CONTENT_SNIFFER);
	g_assert_true (soup_message_is_feature_disabled (msg, SOUP_TYPE_CONTENT_SNIFFER));

	g_signal_connect (msg, "content-sniffed",
			  G_CALLBACK (sniffing_content_sniffed), &sniffed_type);

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	g_assert_null (sniffed_type);
	g_bytes_unref (body);
	g_object_unref (msg);
	g_uri_unref (uri);
}

static void
do_skip_whitespace_test (void)
{
        const gsize MARKUP_LENGTH = strlen ("<!--") + strlen ("-->");
        SoupContentSniffer *sniffer = soup_content_sniffer_new ();
        SoupMessage *msg = soup_message_new (SOUP_METHOD_GET, "http://example.org");
        const char *test_cases[] = {
                "",
                "<rdf:RDF",
                "<rdf:RDFxmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"",
                "<rdf:RDFxmlns=\"http://purl.org/rss/1.0/\"",
        };

        soup_message_headers_set_content_type (soup_message_get_response_headers (msg), "text/html", NULL);

        for (guint i = 0; i < G_N_ELEMENTS (test_cases); i++) {
                const char *trailing_data = test_cases[i];
                gsize leading_zeros = 512 - MARKUP_LENGTH - strlen (trailing_data);
                gsize testsize = MARKUP_LENGTH + leading_zeros + strlen (trailing_data);
                guint8 *data = g_malloc0 (testsize);
                guint8 *p = data;
                char *content_type;
                GBytes *buffer;

                // Format of <!--[0x00 * $leading_zeros]-->$trailing_data
                memcpy (p, "<!--", strlen ("<!--"));
                p += strlen ("<!--");
                p += leading_zeros;
                memcpy (p, "-->", strlen ("-->"));
                p += strlen ("-->");
                if (strlen (trailing_data))
                        memcpy (p, trailing_data, strlen (trailing_data));
                // Purposefully not NUL terminated.                

                buffer = g_bytes_new_take (g_steal_pointer (&data), testsize);
                content_type = soup_content_sniffer_sniff (sniffer, msg, buffer, NULL);

                g_free (content_type);
                g_bytes_unref (buffer);
        }

        g_object_unref (msg);
        g_object_unref (sniffer);
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

	session = soup_test_session_new (NULL);
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
	g_test_add_data_func ("/sniffing/type/unknown-empty",
			      "unknown/mbox?empty_response=yes => text/plain",
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

	g_test_add_func ("/sniffing/whitespace", do_skip_whitespace_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);

	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
