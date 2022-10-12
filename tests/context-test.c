/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#include "test-utils.h"
#include "soup-misc.h"

static char *base_uri;

typedef struct {
	SoupServerMessage *msg;
	GSource *timeout;
} SlowData;

static void
request_finished (SoupServerMessage *msg,
		  gpointer           data)
{
	SlowData *sd = data;

	g_source_destroy (sd->timeout);
	g_source_unref (sd->timeout);
	g_free (sd);
}

static gboolean
add_body_chunk (gpointer data)
{
	SlowData *sd = data;
	SoupMessageBody *response_body;

	response_body = soup_server_message_get_response_body (sd->msg);
	soup_message_body_append (response_body,
				  SOUP_MEMORY_STATIC, "OK\r\n", 4);
	soup_message_body_complete (response_body);
	soup_server_message_unpause (sd->msg);
	g_object_unref (sd->msg);

	return FALSE;
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	SlowData *sd;
	SoupMessageHeaders *response_headers;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	if (!strcmp (path, "/fast")) {
		soup_server_message_set_response (msg, "text/plain",
						  SOUP_MEMORY_STATIC, "OK\r\n", 4);
		return;
	}

	response_headers = soup_server_message_get_response_headers (msg);
	soup_message_headers_set_encoding (response_headers,
					   SOUP_ENCODING_CHUNKED);
	g_object_ref (msg);
	soup_server_message_pause (msg);

	sd = g_new (SlowData, 1);
	sd->msg = msg;
	sd->timeout = soup_add_timeout (
		g_main_context_get_thread_default (),
		200, add_body_chunk, sd);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (request_finished), sd);
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
do_test1 (void)
{
        if (g_getenv ("ASAN_OPTIONS")) {
                g_test_skip ("Flaky timing with ASAN enabled");
                return;
        }

	test1_loop = g_main_loop_new (NULL, FALSE);
	g_idle_add (idle_start_test1_thread, NULL);
	g_main_loop_run (test1_loop);
	g_main_loop_unref (test1_loop);
}

static gboolean
idle_start_test1_thread (gpointer user_data)
{
	guint64 time;
	GThread *thread;

	g_mutex_lock (&test1_mutex);
	thread = g_thread_new ("test1_thread", test1_thread, NULL);

	time = g_get_monotonic_time () + 5000000;
	if (g_cond_wait_until (&test1_cond, &test1_mutex, time))
		g_thread_join (thread);
	else {
		soup_test_assert (FALSE, "timeout");
		g_thread_unref (thread);
	}

	g_mutex_unlock (&test1_mutex);
	g_main_loop_quit (test1_loop);
	return FALSE;
}

static void
message_send_cb (SoupSession  *session,
		 GAsyncResult *result,
		 GMainContext *async_context)
{
        GBytes *body;

	g_assert_true (async_context == g_main_context_get_thread_default ());
	body = soup_session_send_and_read_finish (session, result, NULL);
	g_clear_pointer (&body, g_bytes_unref);
}

static void
message_finished (SoupMessage *msg,
		GMainLoop   *loop)
{
	g_main_loop_quit (loop);
}

static gpointer
test1_thread (gpointer user_data)
{
	SoupSession *session;
	GMainContext *async_context;
	char *uri;
	SoupMessage *msg;
	GInputStream *stream;
	GMainLoop *loop;

	/* Wait for main thread to be waiting on test1_cond */
	g_mutex_lock (&test1_mutex);
	g_mutex_unlock (&test1_mutex);

        async_context = g_main_context_new ();
        g_main_context_push_thread_default (async_context);
        session = soup_test_session_new (NULL);
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	debug_printf (1, "  send_message\n");
	msg = soup_message_new ("GET", uri);
	stream = soup_session_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (stream);
	g_object_unref (msg);

	debug_printf (1, "  queue_message\n");
	msg = soup_message_new ("GET", uri);
	loop = g_main_loop_new (async_context, FALSE);
	g_signal_connect (msg, "finished", G_CALLBACK (message_finished), loop);
        soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)message_send_cb,
                                          async_context);
	g_main_loop_run (loop);
	/* We need one more iteration, because SoupMessage::finished is emitted
         * right before the message is unqueued.
         */
        g_main_context_iteration (async_context, TRUE);
	g_main_loop_unref (loop);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	g_free (uri);

	g_cond_signal (&test1_cond);

	g_main_context_pop_thread_default (async_context);
	return NULL;
}

/* Test 2: An async session in the main thread with its own
 * async_context runs independently of the default main loop.
 */
static gboolean
idle_test2_fail (gpointer user_data)
{
	soup_test_assert (FALSE, "idle ran");
	return FALSE;
}

static void
do_test2 (void)
{
	guint idle;
	GMainContext *async_context;
	SoupSession *session;
	char *uri;
	SoupMessage *msg;
        GBytes *body;
	GMainLoop *loop;

	idle = g_idle_add_full (G_PRIORITY_HIGH, idle_test2_fail, NULL, NULL);

	async_context = g_main_context_new ();
        g_main_context_push_thread_default (async_context);
        session = soup_test_session_new (NULL);
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	debug_printf (1, "  send_message\n");
	msg = soup_message_new ("GET", uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);

	debug_printf (1, "  queue_message\n");
	msg = soup_message_new ("GET", uri);
	loop = g_main_loop_new (async_context, FALSE);
	g_signal_connect (msg, "finished", G_CALLBACK (message_finished), loop);
	soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)message_send_cb,
                                          async_context);
	g_main_loop_run (loop);
	/* We need one more iteration, because SoupMessage::finished is emitted
         * right before the message is unqueued.
         */
        g_main_context_iteration (async_context, TRUE);
	g_main_loop_unref (loop);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	g_free (uri);

	g_source_remove (idle);

	g_main_context_pop_thread_default (async_context);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	GUri *uri;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	uri = soup_test_server_get_uri (server, "http", NULL);
	base_uri = g_uri_to_string (uri);
	g_uri_unref (uri);

	g_test_add_func ("/context/blocking/thread-default", do_test1);
	g_test_add_func ("/context/nested/thread-default", do_test2);

	ret = g_test_run ();

	g_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
