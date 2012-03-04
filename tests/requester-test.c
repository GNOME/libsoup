/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LIBSOUP_USE_UNSTABLE_REQUEST_API
#include <libsoup/soup.h>
#include <libsoup/soup-requester.h>
#include <libsoup/soup-request-http.h>

#include "test-utils.h"

SoupServer *server;
GMainLoop *loop;
char buf[1024];

SoupBuffer *response, *auth_response;

#define REDIRECT_HTML_BODY "<html><body>Try again</body></html>\r\n"
#define AUTH_HTML_BODY "<html><body>Unauthorized</body></html>\r\n"

static void
get_index (void)
{
	char *contents;
	gsize length;
	GError *error = NULL;

	if (!g_file_get_contents (SRCDIR "/index.txt", &contents, &length, &error)) {
		fprintf (stderr, "Could not read index.txt: %s\n",
			 error->message);
		exit (1);
	}

	response = soup_buffer_new (SOUP_MEMORY_TAKE, contents, length);

	auth_response = soup_buffer_new (SOUP_MEMORY_STATIC,
					 AUTH_HTML_BODY,
					 strlen (AUTH_HTML_BODY));
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	gboolean chunked = FALSE;
	int i;

	if (strcmp (path, "/auth") == 0) {
		soup_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED);
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   AUTH_HTML_BODY,
					   strlen (AUTH_HTML_BODY));
		soup_message_headers_append (msg->response_headers,
					     "WWW-Authenticate",
					     "Basic: realm=\"requester-test\"");
		return;
	} else if (strcmp (path, "/foo") == 0) {
		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		/* Make the response HTML so if we sniff that instead of the
		 * real body, we'll notice.
		 */
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   REDIRECT_HTML_BODY,
					   strlen (REDIRECT_HTML_BODY));
		return;
	} else if (strcmp (path, "/chunked") == 0) {
		chunked = TRUE;
	} else if (strcmp (path, "/non-persistent") == 0) {
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (chunked) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_CHUNKED);

		for (i = 0; i < response->length; i += 8192) {
			SoupBuffer *tmp;

			tmp = soup_buffer_new_subbuffer (response, i,
							 MIN (8192, response->length - i));
			soup_message_body_append_buffer (msg->response_body, tmp);
			soup_buffer_free (tmp);
		}
		soup_message_body_complete (msg->response_body);
	} else
		soup_message_body_append_buffer (msg->response_body, response);
}

static void
stream_closed (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	GError *error = NULL;

	if (!g_input_stream_close_finish (stream, res, &error)) {
		debug_printf (1, "    close failed: %s", error->message);
		g_error_free (error);
		errors++;
	}
	g_main_loop_quit (loop);
	g_object_unref (stream);
}

static void
test_read_ready (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	GString *body = user_data;
	GError *error = NULL;
	gsize nread;

	nread = g_input_stream_read_finish (stream, res, &error);
	if (nread == -1) {
		debug_printf (1, "    read_async failed: %s", error->message);
		g_error_free (error);
		errors++;
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	} else if (nread == 0) {
		g_input_stream_close_async (stream,
					    G_PRIORITY_DEFAULT, NULL,
					    stream_closed, NULL);
		return;
	}

	g_string_append_len (body, buf, nread);
	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, body);
}

static void
auth_test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GString *body = user_data;
	GInputStream *stream;
	GError *error = NULL;
	SoupMessage *msg;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (!stream) {
		debug_printf (1, "    send_async failed: %s\n", error->message);
		errors++;
		g_main_loop_quit (loop);
		return;
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (source));
	if (msg->status_code != SOUP_STATUS_UNAUTHORIZED) {
		debug_printf (1, "    GET failed: %d %s\n", msg->status_code,
			      msg->reason_phrase);
		errors++;
		g_main_loop_quit (loop);
		return;
	}
	g_object_unref (msg);

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	if (g_strcmp0 (content_type, "text/html") != 0) {
		debug_printf (1, "    failed to sniff Content-Type: got %s\n",
			      content_type ? content_type : "(NULL)");
		errors++;
	}

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, body);
}

static void
test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GString *body = user_data;
	GInputStream *stream;
	GError *error = NULL;
	SoupMessage *msg;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (!stream) {
		debug_printf (1, "    send_async failed: %s\n", error->message);
		errors++;
		g_main_loop_quit (loop);
		return;
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (source));
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    GET failed: %d %s\n", msg->status_code,
			      msg->reason_phrase);
		errors++;
		g_main_loop_quit (loop);
		return;
	}
	g_object_unref (msg);

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	if (g_strcmp0 (content_type, "text/plain") != 0) {
		debug_printf (1, "    failed to sniff Content-Type: got %s\n",
			      content_type ? content_type : "(NULL)");
		errors++;
	}

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, body);
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket, gpointer user_data)
{
	SoupSocket **save_socket = user_data;

	*save_socket = g_object_ref (socket);
}

static void
do_one_test (SoupSession *session, SoupURI *uri,
	     GAsyncReadyCallback callback, SoupBuffer *expected_response,
	     gboolean persistent)
{
	SoupRequester *requester;
	SoupRequest *request;
	GString *body;
	guint started_id;
	SoupSocket *socket = NULL;

	requester = SOUP_REQUESTER (soup_session_get_feature (session, SOUP_TYPE_REQUESTER));

	body = g_string_new (NULL);
	request = soup_requester_request_uri (requester, uri, NULL);

	started_id = g_signal_connect (session, "request-started",
				       G_CALLBACK (request_started),
				       &socket);

	soup_request_send_async (request, NULL, callback, body);
	g_object_unref (request);

	loop = g_main_loop_new (soup_session_get_async_context (session), TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_signal_handler_disconnect (session, started_id);

	if (body->len != expected_response->length) {
		debug_printf (1, "    body length mismatch: expected %d, got %d\n",
			      (int)expected_response->length, (int)body->len);
		errors++;
	} else if (memcmp (body->str, expected_response->data,
			   expected_response->length) != 0) {
		debug_printf (1, "    body data mismatch\n");
		errors++;
	}

	if (persistent) {
		if (!soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket not still connected!\n");
			errors++;
		}
	} else {
		if (soup_socket_is_connected (socket)) {
			debug_printf (1, "    socket still connected!\n");
			errors++;
		}
	}
	g_object_unref (socket);

	g_string_free (body, TRUE);
}

static void
do_test_for_thread_and_context (SoupSession *session, const char *base_uri)
{
	SoupRequester *requester;
	SoupURI *uri;

	requester = soup_requester_new ();
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
	g_object_unref (requester);
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	debug_printf (1, "  basic test\n");
	uri = soup_uri_new (base_uri);
	do_one_test (session, uri, test_sent, response, TRUE);
	soup_uri_free (uri);

	debug_printf (1, "  chunked test\n");
	uri = soup_uri_new (base_uri);
	soup_uri_set_path (uri, "/chunked");
	do_one_test (session, uri, test_sent, response, TRUE);
	soup_uri_free (uri);

	debug_printf (1, "  auth test\n");
	uri = soup_uri_new (base_uri);
	soup_uri_set_path (uri, "/auth");
	do_one_test (session, uri, auth_test_sent, auth_response, TRUE);
	soup_uri_free (uri);

	debug_printf (1, "  non-persistent test\n");
	uri = soup_uri_new (base_uri);
	soup_uri_set_path (uri, "/non-persistent");
	do_one_test (session, uri, test_sent, response, FALSE);
	soup_uri_free (uri);
}

static void
do_simple_test (const char *uri)
{
	SoupSession *session;

	debug_printf (1, "Simple streaming test\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);
}

static gpointer
do_test_with_context (const char *uri)
{
	GMainContext *async_context;
	SoupSession *session;

	async_context = g_main_context_new ();
	g_main_context_push_thread_default (async_context);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_ASYNC_CONTEXT, async_context,
					 NULL);

	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);

	g_main_context_pop_thread_default (async_context);
	g_main_context_unref (async_context);
	return NULL;
}

static void
do_context_test (const char *uri)
{
	debug_printf (1, "Streaming with a non-default-context\n");
	do_test_with_context (uri);
}

static void
do_thread_test (const char *uri)
{
	GThread *thread;

	debug_printf (1, "Streaming in another thread\n");

	thread = g_thread_new ("do_test_with_context",
			       (GThreadFunc)do_test_with_context,
			       (gpointer)uri);
	g_thread_join (thread);
}

int
main (int argc, char **argv)
{
	char *uri;

	test_init (argc, argv, NULL);
	get_index ();

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	uri = g_strdup_printf ("http://127.0.0.1:%u/foo", soup_server_get_port (server));

	do_simple_test (uri);
	do_thread_test (uri);
	do_context_test (uri);

	g_free (uri);
	soup_buffer_free (response);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
