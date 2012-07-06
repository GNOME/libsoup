/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#include "test-utils.h"

static char *base_uri;

typedef struct {
	SoupServer *server;
	SoupMessage *msg;
	GSource *timeout;
} SlowData;

static void
request_failed (SoupMessage *msg, gpointer data)
{
	SlowData *sd = data;

	if (SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
		g_source_destroy (sd->timeout);
	g_free (sd);
}

static gboolean
add_body_chunk (gpointer data)
{
	SlowData *sd = data;

	soup_message_body_append (sd->msg->response_body,
				  SOUP_MEMORY_STATIC, "OK\r\n", 4);
	soup_message_body_complete (sd->msg->response_body);
	soup_server_unpause_message (sd->server, sd->msg);
	g_object_unref (sd->msg);

	return FALSE;
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SlowData *sd;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	if (!strcmp (path, "/fast")) {
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC, "OK\r\n", 4);
		return;
	}

	soup_message_headers_set_encoding (msg->response_headers,
					   SOUP_ENCODING_CHUNKED);
	g_object_ref (msg);
	soup_server_pause_message (server, msg);

	sd = g_new (SlowData, 1);
	sd->server = server;
	sd->msg = msg;
	sd->timeout = soup_add_timeout (
		soup_server_get_async_context (server),
		200, add_body_chunk, sd);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (request_failed), sd);
}

/* Test 1: An async session in another thread with its own
 * async_context can complete a request while the main thread's main
 * loop is stopped.
 */

static gboolean idle_start_test1_thread (gpointer loop);
static gpointer test1_thread (gpointer user_data);

static GCond test1_cond;
static GMutex test1_mutex;
static GMainLoop *test1_loop;

static void
do_test1 (int n, gboolean use_thread_context)
{
	debug_printf (1, "\nTest %d: blocking the main thread does not block other thread\n", n);
	if (use_thread_context)
		debug_printf (1, "(Using g_main_context_push_thread_default())\n");
	else
		debug_printf (1, "(Using SOUP_SESSION_ASYNC_CONTEXT)\n");

	test1_loop = g_main_loop_new (NULL, FALSE);
	g_idle_add (idle_start_test1_thread, GINT_TO_POINTER (use_thread_context));
	g_main_loop_run (test1_loop);
	g_main_loop_unref (test1_loop);
}

static gboolean
idle_start_test1_thread (gpointer use_thread_context)
{
	guint64 time;
	GThread *thread;

	g_mutex_lock (&test1_mutex);
	thread = g_thread_new ("test1_thread", test1_thread, use_thread_context);

	time = g_get_monotonic_time () + 5000000;
	if (g_cond_wait_until (&test1_cond, &test1_mutex, time))
		g_thread_join (thread);
	else {
		debug_printf (1, "  timeout!\n");
		g_thread_unref (thread);
		errors++;
	}

	g_mutex_unlock (&test1_mutex);
	g_main_loop_quit (test1_loop);
	return FALSE;
}

static void
test1_finished (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	g_main_loop_quit (loop);
}

static gpointer
test1_thread (gpointer use_thread_context)
{
	SoupSession *session;
	GMainContext *async_context;
	char *uri;
	SoupMessage *msg;
	GMainLoop *loop;

	/* Wait for main thread to be waiting on test1_cond */
	g_mutex_lock (&test1_mutex);
	g_mutex_unlock (&test1_mutex);

	async_context = g_main_context_new ();
	if (use_thread_context) {
		g_main_context_push_thread_default (async_context);
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 NULL);
	} else {
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_ASYNC_CONTEXT, async_context,
						 NULL);
	}
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	debug_printf (1, "  send_message\n");
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    unexpected status: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	debug_printf (1, "  queue_message\n");
	msg = soup_message_new ("GET", uri);
	loop = g_main_loop_new (async_context, FALSE);
	g_object_ref (msg);
	soup_session_queue_message (session, msg, test1_finished, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    unexpected status: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	g_free (uri);

	g_cond_signal (&test1_cond);

	if (use_thread_context)
		g_main_context_pop_thread_default (async_context);
	return NULL;
}

/* Test 2: An async session in the main thread with its own
 * async_context runs independently of the default main loop.
 */

static gboolean idle_test2_fail (gpointer user_data);

static void
do_test2 (int n, gboolean use_thread_context)
{
	guint idle;
	GMainContext *async_context;
	SoupSession *session;
	char *uri;
	SoupMessage *msg;

	debug_printf (1, "\nTest %d: a session with its own context is independent of the main loop.\n", n);
	if (use_thread_context)
		debug_printf (1, "(Using g_main_context_push_thread_default())\n");
	else
		debug_printf (1, "(Using SOUP_SESSION_ASYNC_CONTEXT)\n");

	idle = g_idle_add_full (G_PRIORITY_HIGH, idle_test2_fail, NULL, NULL);

	async_context = g_main_context_new ();
	if (use_thread_context) {
		g_main_context_push_thread_default (async_context);
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 NULL);
	} else {
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_ASYNC_CONTEXT, async_context,
						 NULL);
	}
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	debug_printf (1, "  send_message\n");
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    unexpected status: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	g_free (uri);

	g_source_remove (idle);

	if (use_thread_context)
		g_main_context_pop_thread_default (async_context);
}

static gboolean
idle_test2_fail (gpointer user_data)
{
	debug_printf (1, "  idle ran!\n");
	errors++;
	return FALSE;
}

static void
multi_request_started (SoupSession *session, SoupMessage *msg,
		       SoupSocket *socket, gpointer user_data)
{
	g_object_set_data (G_OBJECT (msg), "started", GUINT_TO_POINTER (TRUE));
}

static void
msg1_got_headers (SoupMessage *msg, gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
}

static void
multi_msg_finished (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_object_set_data (G_OBJECT (msg), "finished", GUINT_TO_POINTER (TRUE));
	g_main_loop_quit (loop);
}

static void
do_multicontext_test (int n)
{
	SoupSession *session;
	SoupMessage *msg1, *msg2;
	GMainContext *context1, *context2;
	GMainLoop *loop1, *loop2;

	debug_printf (1, "\nTest %d: Using multiple async contexts\n", n);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	g_signal_connect (session, "request-started",
			  G_CALLBACK (multi_request_started), NULL);

	context1 = g_main_context_new ();
	loop1 = g_main_loop_new (context1, FALSE);
	context2 = g_main_context_new ();
	loop2 = g_main_loop_new (context2, FALSE);

	g_main_context_push_thread_default (context1);
	msg1 = soup_message_new ("GET", base_uri);
	g_object_ref (msg1);
	soup_session_queue_message (session, msg1, multi_msg_finished, loop1);
	g_signal_connect (msg1, "got-headers",
			  G_CALLBACK (msg1_got_headers), loop1);
	g_object_set_data (G_OBJECT (msg1), "session", session);
	g_main_context_pop_thread_default (context1);

	g_main_context_push_thread_default (context2);
	msg2 = soup_message_new ("GET", base_uri);
	g_object_ref (msg2);
	soup_session_queue_message (session, msg2, multi_msg_finished, loop2);
	g_main_context_pop_thread_default (context2);

	g_main_context_push_thread_default (context1);
	g_main_loop_run (loop1);
	g_main_context_pop_thread_default (context1);

	if (!g_object_get_data (G_OBJECT (msg1), "started")) {
		debug_printf (1, "  msg1 not started??\n");
		errors++;
	}
	if (g_object_get_data (G_OBJECT (msg2), "started")) {
		debug_printf (1, "  msg2 started while loop1 was running!\n");
		errors++;
	}

	g_main_context_push_thread_default (context2);
	g_main_loop_run (loop2);
	g_main_context_pop_thread_default (context2);

	if (g_object_get_data (G_OBJECT (msg1), "finished")) {
		debug_printf (1, "  msg1 finished while loop2 was running!\n");
		errors++;
	}
	if (!g_object_get_data (G_OBJECT (msg2), "finished")) {
		debug_printf (1, "  msg2 not finished??\n");
		errors++;
	}

	g_main_context_push_thread_default (context1);
	g_main_loop_run (loop1);
	g_main_context_pop_thread_default (context1);

	if (!g_object_get_data (G_OBJECT (msg1), "finished")) {
		debug_printf (1, "  msg1 not finished??\n");
		errors++;
	}

	g_object_unref (msg1);
	g_object_unref (msg2);

	soup_test_session_abort_unref (session);

	g_main_loop_unref (loop1);
	g_main_loop_unref (loop2);
	g_main_context_unref (context1);
	g_main_context_unref (context2);
}

int
main (int argc, char **argv)
{
	SoupServer *server;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = g_strdup_printf ("http://127.0.0.1:%u/",
				    soup_server_get_port (server));

	do_test1 (1, FALSE);
	do_test1 (2, TRUE);
	do_test2 (3, FALSE);
	do_test2 (4, TRUE);
	do_multicontext_test (5);

	g_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
