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

SoupBuffer *response;

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
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC, NULL, 0);
	soup_message_body_append_buffer (msg->response_body, response);
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
		debug_printf (1, "  read_async failed: %s", error->message);
		errors++;
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	} else if (nread == 0) {
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	}

	g_string_append_len (body, buf, nread);
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

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (!stream) {
		debug_printf (1, "  send_async failed: %s", error->message);
		errors++;
		g_main_loop_quit (loop);
		return;
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (source));
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "  GET failed: %d %s", msg->status_code,
			      msg->reason_phrase);
		errors++;
		g_main_loop_quit (loop);
		return;
	}
	g_object_unref (msg);

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, body);
}

static void
do_test_for_thread_and_context (SoupSession *session, const char *uri)
{
	SoupRequester *requester;
	SoupRequest *request;
	GString *body;

	requester = soup_requester_new ();
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
	g_object_unref (requester);

	body = g_string_new (NULL);

	request = soup_requester_request (requester, uri, NULL);
	soup_request_send_async (request, NULL, test_sent, body);
	g_object_unref (request);

	loop = g_main_loop_new (soup_session_get_async_context (session), TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	if (body->len != response->length) {
		debug_printf (1, "  body length mismatch: expected %d, got %d\n",
			      (int)response->length, (int)body->len);
		errors++;
	} else if (memcmp (body->str, response->data, response->length) != 0) {
		debug_printf (1, "  body data mismatch\n");
		errors++;
	}

	g_string_free (body, TRUE);
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

	thread = g_thread_create ((GThreadFunc)do_test_with_context,
				  (gpointer)uri, TRUE, NULL);
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
	uri = g_strdup_printf ("http://127.0.0.1:%u/", soup_server_get_port (server));

	do_simple_test (uri);
	do_thread_test (uri);
	do_context_test (uri);

	g_free (uri);
	soup_buffer_free (response);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
