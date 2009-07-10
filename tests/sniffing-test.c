/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva <gns@gnome.org>.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libsoup/soup.h>

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
	char *chunked;
	char *contents;
	gsize length;
	gboolean use_chunked_encoding = FALSE;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (query) {
		chunked = g_hash_table_lookup (query, "chunked");
		if (chunked && g_str_equal (chunked, "yes")) {
			soup_message_headers_set_encoding (msg->response_headers,
							   SOUP_ENCODING_CHUNKED);
			use_chunked_encoding = TRUE;
		}
	}

	if (!strcmp (path, "/mbox")) {
		g_file_get_contents ("resources/mbox",
				     &contents, &length,
				     &error);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_TAKE,
					   contents,
					   length);
	}

	if (g_str_has_prefix (path, "/text_or_binary/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf ("resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_TAKE,
					   contents,
					   length);
	}

	if (g_str_has_prefix (path, "/unknown/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf ("resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_set_response (msg, "UNKNOWN/unknown",
					   SOUP_MEMORY_TAKE,
					   contents,
					   length);
	}

	if (g_str_has_prefix (path, "/type/")) {
		char **components = g_strsplit (path, "/", 4);
		char *ptr;

		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf ("resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		/* Hack to allow passing type in the URI */
		ptr = g_strrstr (components[2], "_");
		*ptr = '/';

		soup_message_set_response (msg, components[2],
					   SOUP_MEMORY_TAKE,
					   contents,
					   length);

		g_strfreev (components);
	}

	if (g_str_has_prefix (path, "/multiple_headers/")) {
		char *base_name = g_path_get_basename (path);
		char *file_name = g_strdup_printf ("resources/%s", base_name);

		g_file_get_contents (file_name,
				     &contents, &length,
				     &error);

		g_free (base_name);
		g_free (file_name);

		if (error) {
			g_error ("%s", error->message);
			g_error_free (error);
			exit (1);
		}

		soup_message_set_response (msg, "text/xml",
					   SOUP_MEMORY_TAKE,
					   contents,
					   length);

		soup_message_headers_append (msg->response_headers,
					     "Content-Type", "text/plain");
	}

	if (use_chunked_encoding)
		soup_message_body_complete (msg->response_body);
}

static gboolean
unpause_msg (gpointer data)
{
	SoupMessage *msg = (SoupMessage*)data;
	soup_session_unpause_message (session, msg);
	return FALSE;
}


static void
content_sniffed (SoupMessage *msg, char *content_type, GHashTable *params, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	if (g_object_get_data (G_OBJECT (msg), "got-chunk")) {
		debug_printf (1, "  got-chunk got emitted before content-sniffed\n");
		errors++;
	}

	g_object_set_data (G_OBJECT (msg), "content-sniffed", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_headers (SoupMessage *msg, gpointer data)
{
	gboolean should_pause = GPOINTER_TO_INT (data);

	if (g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed got emitted before got-headers\n");
		errors++;
	}

	g_object_set_data (G_OBJECT (msg), "got-headers", GINT_TO_POINTER (TRUE));

	if (should_pause) {
		soup_session_pause_message (session, msg);
		g_idle_add (unpause_msg, msg);
	}
}

static void
got_chunk (SoupMessage *msg, SoupBuffer *chunk, gpointer data)
{
	gboolean should_accumulate = GPOINTER_TO_INT (data);

	g_object_set_data (G_OBJECT (msg), "got-chunk", GINT_TO_POINTER (TRUE));

	if (!should_accumulate) {
		if (!chunk_data)
			chunk_data = soup_message_body_new ();
		soup_message_body_append_buffer (chunk_data, chunk);
	}
}

static void
finished (SoupSession *session, SoupMessage *msg, gpointer data)
{
	GMainLoop *loop = (GMainLoop*)data;
	g_main_loop_quit (loop);
}

static void
do_signals_test (gboolean should_content_sniff,
		 gboolean should_pause,
		 gboolean should_accumulate,
		 gboolean chunked_encoding)
{
	SoupURI *uri = soup_uri_new_with_base (base_uri, "/mbox");
	SoupMessage *msg = soup_message_new_from_uri ("GET", uri);
	GMainLoop *loop = g_main_loop_new (NULL, TRUE);
	char *contents;
	gsize length;
	GError *error = NULL;
	SoupBuffer *body;

	if (chunked_encoding)
		soup_uri_set_query (uri, "chunked=yes");

	soup_message_set_uri (msg, uri);

	soup_message_body_set_accumulate (msg->response_body, should_accumulate);

	g_object_connect (msg,
			  "signal::got-headers", got_headers, GINT_TO_POINTER (should_pause),
			  "signal::got-chunk", got_chunk, GINT_TO_POINTER (should_accumulate),
			  "signal::content_sniffed", content_sniffed, GINT_TO_POINTER (should_pause),
			  NULL);

	g_object_ref (msg);
	soup_session_queue_message (session, msg, finished, loop);

	g_main_loop_run (loop);

	if (!should_content_sniff &&
	    g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed got emitted without a sniffer\n");
		errors++;
	} else if (should_content_sniff &&
		   !g_object_get_data (G_OBJECT (msg), "content-sniffed")) {
		debug_printf (1, "  content-sniffed did not get emitted\n");
		errors++;
	}

	g_file_get_contents ("resources/mbox",
			     &contents, &length,
			     &error);

	if (error) {
		g_error ("%s", error->message);
		g_error_free (error);
		exit (1);
	}

	if (!should_accumulate) {
		body = soup_message_body_flatten (chunk_data);
		soup_message_body_free (chunk_data);
		chunk_data = NULL;
	} else
		body = soup_message_body_flatten (msg->response_body);

	if (body->length != length) {
		debug_printf (1, "  lengths do not match\n");
		errors++;
	}

	if (memcmp (body->data, contents, length)) {
		debug_printf (1, "  downloaded data does not match\n");
		errors++;
	}

	g_free (contents);
	soup_buffer_free (body);

	soup_uri_free (uri);
	g_object_unref (msg);
	g_main_loop_unref (loop);
}

static void
sniffing_content_sniffed (SoupMessage *msg, char *content_type, GHashTable *params, gpointer data)
{
	char *expected_type = (char*)data;

	if (strcmp (content_type, expected_type)) {
		debug_printf (1, "  sniffing failed! expected %s, got %s\n",
			      expected_type, content_type);
		errors++;
	}
}

static void
test_sniffing (const char *path, const char *expected_type)
{
	SoupURI *uri = soup_uri_new_with_base (base_uri, path);
	SoupMessage *msg = soup_message_new_from_uri ("GET", uri);
	GMainLoop *loop = g_main_loop_new (NULL, TRUE);

	g_object_connect (msg,
			  "signal::content_sniffed", sniffing_content_sniffed, expected_type,
			  NULL);

	g_object_ref (msg);

	soup_session_queue_message (session, msg, finished, loop);

	g_main_loop_run (loop);

	soup_uri_free (uri);
	g_object_unref (msg);
	g_main_loop_unref (loop);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupContentSniffer *sniffer;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	session = soup_session_async_new ();

	/* No sniffer, no content_sniffed should be emitted */
	do_signals_test (FALSE, FALSE, FALSE, FALSE);
	do_signals_test (FALSE, FALSE, FALSE, TRUE);
	do_signals_test (FALSE, FALSE, TRUE, FALSE);
	do_signals_test (FALSE, FALSE, TRUE, TRUE);

	do_signals_test (FALSE, TRUE, TRUE, FALSE);
	do_signals_test (FALSE, TRUE, TRUE, TRUE);
	do_signals_test (FALSE, TRUE, FALSE, FALSE);
	do_signals_test (FALSE, TRUE, FALSE, TRUE);

	sniffer = soup_content_sniffer_new ();
	soup_session_add_feature (session, (SoupSessionFeature*)sniffer);

	/* Now, with a sniffer, content_sniffed must be emitted after
	 * got-headers, and before got-chunk.
	 */
	do_signals_test (TRUE, FALSE, FALSE, FALSE);
	do_signals_test (TRUE, FALSE, FALSE, TRUE);
	do_signals_test (TRUE, FALSE, TRUE, FALSE);
	do_signals_test (TRUE, FALSE, TRUE, TRUE);

	do_signals_test (TRUE, TRUE, TRUE, FALSE);
	do_signals_test (TRUE, TRUE, TRUE, TRUE);
	do_signals_test (TRUE, TRUE, FALSE, FALSE);
	do_signals_test (TRUE, TRUE, FALSE, TRUE);

	/* Test the text_or_binary sniffing path */

	/* GIF is a 'safe' type */
	test_sniffing ("/text_or_binary/home.gif", "image/gif");

	/* With our current code, no sniffing is done using GIO, so
	 * the mbox will be identified as text/plain; should we change
	 * this?
	 */
	test_sniffing ("/text_or_binary/mbox", "text/plain");

	/* HTML is considered unsafe for this algorithm, since it is
	 * scriptable, so going from text/plain to text/html is
	 * considered 'privilege escalation'
	 */
	test_sniffing ("/text_or_binary/test.html", "text/plain");

	/* Test the unknown sniffing path */

	test_sniffing ("/unknown/test.html", "text/html");
	test_sniffing ("/unknown/home.gif", "image/gif");
	test_sniffing ("/unknown/mbox", "application/mbox");

	/* Test the XML sniffing path */

	test_sniffing ("/type/text_xml/home.gif", "text/xml");
	test_sniffing ("/type/anice_type+xml/home.gif", "anice/type+xml");
	test_sniffing ("/type/application_xml/home.gif", "application/xml");

	/* Test the image sniffing path */

	test_sniffing ("/type/image_png/home.gif", "image/gif");

	/* Test the feed or html path */

	test_sniffing ("/type/text_html/test.html", "text/html");
	test_sniffing ("/type/text_html/rss20.xml", "application/rss+xml");
	test_sniffing ("/type/text_html/atom.xml", "application/atom+xml");

	/* The spec tells us to only use the last Content-Type header */

	test_sniffing ("/multiple_headers/home.gif", "image/gif");

	soup_uri_free (base_uri);

	test_cleanup ();
	return errors != 0;
}
