/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia S.L.
 */

#include "test-utils.h"

SoupBuffer *index_buffer;

static void
get_index (void)
{
	char *contents;
	gsize length;
	GError *error = NULL;

	if (!g_file_get_contents (SRCDIR "/index.txt", &contents, &length, &error)) {
		g_printerr ("Could not read index.txt: %s\n",
			    error->message);
		exit (1);
	}

	index_buffer = soup_buffer_new (SOUP_MEMORY_TAKE, contents, length);
}

static void
register_gresource (void)
{
	GResource *resource;
	GError *error = NULL;

	resource = g_resource_load ("soup-tests.gresource", &error);
	if (!resource) {
		g_printerr ("Could not load resource soup-tests.gresource: %s\n",
			    error->message);
		exit (1);
	}
	g_resources_register (resource);
	g_resource_unref (resource);
}

static void
check_results (GString *body)
{
	if (body->len != index_buffer->length) {
		debug_printf (1, "    body length mismatch: expected %d, got %d\n",
			      (int)index_buffer->length, (int)body->len);
		errors++;
	} else if (memcmp (body->str, index_buffer->data, body->len) != 0) {
		debug_printf (1, "    body data mismatch\n");
		errors++;
	}
}

typedef struct {
	GString *body;
	char buffer[1024];
	GMainLoop *loop;
} AsyncRequestData;

static void
stream_closed (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GInputStream *in = G_INPUT_STREAM (source);
	AsyncRequestData *data = user_data;
	GError *error = NULL;

	if (!g_input_stream_close_finish (in, result, &error)) {
		debug_printf (1, "    close failed: %s\n", error->message);
		g_error_free (error);
		errors++;
	}
	g_main_loop_quit (data->loop);
	g_object_unref (in);
}

static void
test_read_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GInputStream *in = G_INPUT_STREAM (source);
	AsyncRequestData *data = user_data;
	gssize nread;
	GError *error = NULL;

	nread = g_input_stream_read_finish (in, result, &error);
	if (nread == -1) {
		debug_printf (1, "    g_input_stream_read failed: %s\n",
			      error->message);
		g_clear_error (&error);
		g_input_stream_close (in, NULL, NULL);
		g_object_unref (in);
		errors++;
		return;
	} else if (nread == 0) {
		g_input_stream_close_async (in, G_PRIORITY_DEFAULT, NULL,
					    stream_closed, data);
		return;
	}

	g_string_append_len (data->body, data->buffer, nread);
	g_input_stream_read_async (in, data->buffer, sizeof (data->buffer),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
async_request_sent (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GInputStream *in;
	AsyncRequestData *data = user_data;
	GError *error = NULL;

	in = soup_request_send_finish (SOUP_REQUEST (source), result, &error);
	if (!in) {
		debug_printf (1, "    soup_request_send_async failed: %s\n",
			      error->message);
		g_clear_error (&error);
		errors++;
		return;
	}

	g_input_stream_read_async (in, data->buffer, sizeof (data->buffer),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
do_async_request (SoupRequest *request)
{
	AsyncRequestData data;

	data.body = g_string_new (NULL);
	soup_request_send_async (request, NULL, async_request_sent, &data);

	data.loop = g_main_loop_new (soup_session_get_async_context (soup_request_get_session (request)), TRUE);
	g_main_loop_run (data.loop);
	g_main_loop_unref (data.loop);

	check_results (data.body);
	g_string_free (data.body, TRUE);
}

static void
do_sync_request (SoupRequest *request)
{
	GInputStream *in;
	GString *body;
	char buffer[1024];
	gssize nread;
	GError *error = NULL;

	in = soup_request_send (request, NULL, &error);
	if (!in) {
		debug_printf (1, "    soup_request_send failed: %s\n",
			      error->message);
		g_clear_error (&error);
		errors++;
		return;
	}

	body = g_string_new (NULL);
	do {
		nread = g_input_stream_read (in, buffer, sizeof (buffer),
					     NULL, &error);
		if (nread == -1) {
			debug_printf (1, "    g_input_stream_read failed: %s\n",
				      error->message);
			g_clear_error (&error);
			errors++;
			break;
		}
		g_string_append_len (body, buffer, nread);
	} while (nread > 0);

	if (!g_input_stream_close (in, NULL, &error)) {
		debug_printf (1, "    g_input_stream_close failed: %s\n",
			      error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (in);

	check_results (body);
	g_string_free (body, TRUE);
}

static void
do_request_file_test (SoupSession *session,
		      gboolean	   async)
{
	SoupRequest *request;
	GFile *index;
	char *uri_string;
	SoupURI *uri;

	index = g_file_new_for_path (SRCDIR "/index.txt");
	uri_string = g_file_get_uri (index);
	g_object_unref (index);

	uri = soup_uri_new (uri_string);
	g_free (uri_string);

	request = soup_session_request_uri (session, uri, NULL);
	if (async)
		do_async_request (request);
	else
		do_sync_request (request);
	g_object_unref (request);

	soup_uri_free (uri);
}

static void
do_request_data_test (SoupSession *session,
		      gboolean	   async)
{
	SoupRequest *request;
	gchar *base64;
	char *uri_string;
	SoupURI *uri;

	base64 = g_base64_encode ((const guchar *)index_buffer->data, index_buffer->length);
	uri_string = g_strdup_printf ("data:text/plain;charset=utf8;base64,%s", base64);
	g_free (base64);

	uri = soup_uri_new (uri_string);
	g_free (uri_string);

	request = soup_session_request_uri (session, uri, NULL);
	if (async)
		do_async_request (request);
	else
		do_sync_request (request);
	g_object_unref (request);

	soup_uri_free (uri);
}

static void
do_request_gresource_test (SoupSession *session,
			   gboolean     async)
{
	SoupRequest *request;
	SoupURI *uri;

	uri = soup_uri_new ("resource:///org/gnome/libsoup/tests/index.txt");
	request = soup_session_request_uri (session, uri, NULL);
	if (async)
		do_async_request (request);
	else
		do_sync_request (request);
	g_object_unref (request);

	soup_uri_free (uri);
}

int
main (int argc, char **argv)
{
	SoupSession *session;

	test_init (argc, argv, NULL);

	get_index ();
	register_gresource ();

	/* Sync tests */
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	do_request_file_test (session, FALSE);
	do_request_data_test (session, FALSE);
	do_request_gresource_test (session, FALSE);

	soup_test_session_abort_unref (session);

	/* Async tests */
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);

	do_request_file_test (session, TRUE);
	do_request_data_test (session, TRUE);
	do_request_gresource_test (session, TRUE);

	soup_test_session_abort_unref (session);

	test_cleanup ();
	return errors != 0;
}
