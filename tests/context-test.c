/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <libsoup/soup-address.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-misc.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-server-message.h>
#include <libsoup/soup-session-async.h>
#include <libsoup/soup-session-sync.h>

gboolean debug = FALSE;
int errors = 0;
GThread *server_thread;
char *base_uri;

static void
dprintf (const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

static void
request_failed (SoupMessage *msg, gpointer timeout)
{
	if (SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
		g_source_destroy (timeout);
}

static gboolean
add_body_chunk (gpointer data)
{
	SoupMessage *msg = data;
	SoupServer *server = soup_server_message_get_server (data);

	soup_message_add_chunk (msg, SOUP_BUFFER_STATIC,
				"OK\r\n", 4);
	soup_message_add_final_chunk (msg);
	soup_server_unpause_message (server, msg);
	g_object_unref (msg);

	return FALSE;
}

static void
server_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
	GSource *timeout;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (!strcmp (context->path, "/shutdown")) {
		soup_server_quit (context->server);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	if (!strcmp (context->path, "/fast")) {
		soup_message_set_response (msg, "text/plain",
					   SOUP_BUFFER_STATIC, "OK\r\n", 4);
		return;
	}

	soup_server_message_set_encoding (SOUP_SERVER_MESSAGE (msg),
					  SOUP_TRANSFER_CHUNKED);
	g_object_ref (msg);
	soup_server_pause_message (context->server, msg);

	timeout = soup_add_timeout (
		soup_server_get_async_context (context->server),
		200, add_body_chunk, msg);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (request_failed), timeout);
}

static gpointer
run_server_thread (gpointer user_data)
{
	SoupServer *server = user_data;

	soup_server_add_handler (server, NULL, NULL,
				 server_callback, NULL, NULL);
	soup_server_run (server);
	g_object_unref (server);

	return NULL;
}

static guint
create_server (void)
{
	SoupServer *server;
	GMainContext *async_context;
	guint port;

	async_context = g_main_context_new ();
	server = soup_server_new (SOUP_SERVER_PORT, 0,
				  SOUP_SERVER_ASYNC_CONTEXT, async_context,
				  NULL);
	g_main_context_unref (async_context);

	if (!server) {
		fprintf (stderr, "Unable to bind server\n");
		exit (1);
	}

	port = soup_server_get_port (server);
	server_thread = g_thread_create (run_server_thread, server, TRUE, NULL);

	return port;
}

static void
shutdown_server (void)
{
	SoupSession *session;
	char *uri;
	SoupMessage *msg;

	session = soup_session_sync_new ();
	uri = g_build_filename (base_uri, "shutdown", NULL);
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);
	g_free (uri);

	soup_session_abort (session);
	g_object_unref (session);

	g_thread_join (server_thread);
}

/* Test 1: An async session in another thread with its own
 * async_context can complete a request while the main thread's main
 * loop is stopped.
 */

static gboolean idle_start_test1_thread (gpointer loop);
static gpointer test1_thread (gpointer user_data);

GCond *test1_cond;
GMutex *test1_mutex;

static void
do_test1 (void)
{
	GMainLoop *loop;

	dprintf ("Test 1: blocking the main thread does not block other thread\n");

	test1_cond = g_cond_new ();
	test1_mutex = g_mutex_new ();

	loop = g_main_loop_new (NULL, FALSE);
	g_idle_add (idle_start_test1_thread, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_mutex_free (test1_mutex);
	g_cond_free (test1_cond);
}

static gboolean
idle_start_test1_thread (gpointer loop)
{
	GTimeVal time;
	GThread *thread;

	g_mutex_lock (test1_mutex);
	thread = g_thread_create (test1_thread, base_uri, TRUE, NULL);

	g_get_current_time (&time);
	time.tv_sec += 5;
	if (g_cond_timed_wait (test1_cond, test1_mutex, &time))
		g_thread_join (thread);
	else {
		dprintf ("  timeout!\n");
		errors++;
	}

	g_mutex_unlock (test1_mutex);
	g_main_loop_quit (loop);
	return FALSE;
}

static void
test1_finished (SoupMessage *msg, gpointer loop)
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
	GMainLoop *loop;

	/* Wait for main thread to be waiting on test1_cond */
	g_mutex_lock (test1_mutex);
	g_mutex_unlock (test1_mutex);

	async_context = g_main_context_new ();
	session = soup_session_async_new_with_options (
		SOUP_SESSION_ASYNC_CONTEXT, async_context,
		NULL);
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	dprintf ("  send_message\n");
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		dprintf ("    unexpected status: %d %s\n",
			 msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	dprintf ("  queue_message\n");
	msg = soup_message_new ("GET", uri);
	loop = g_main_loop_new (async_context, FALSE);
	g_object_ref (msg);
	soup_session_queue_message (session, msg, test1_finished, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
	if (msg->status_code != SOUP_STATUS_OK) {
		dprintf ("    unexpected status: %d %s\n",
			 msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_session_abort (session);
	g_object_unref (session);
	g_free (uri);

	g_cond_signal (test1_cond);
	return NULL;
}

/* Test 2: An async session in the main thread with its own
 * async_context runs independently of the default main loop.
 */

static gboolean idle_test2_fail (gpointer user_data);

static void
do_test2 (void)
{
	guint idle;
	GMainContext *async_context;
	SoupSession *session;
	char *uri;
	SoupMessage *msg;

	dprintf ("Test 2: a session with its own context is independent of the main loop.\n");

	idle = g_idle_add_full (G_PRIORITY_HIGH, idle_test2_fail, NULL, NULL);

	async_context = g_main_context_new ();
	session = soup_session_async_new_with_options (
		SOUP_SESSION_ASYNC_CONTEXT, async_context,
		NULL);
	g_main_context_unref (async_context);

	uri = g_build_filename (base_uri, "slow", NULL);

	dprintf ("  send_message\n");
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_OK) {
		dprintf ("    unexpected status: %d %s\n",
			 msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_session_abort (session);
	g_object_unref (session);
	g_free (uri);

	g_source_remove (idle);
}

static gboolean
idle_test2_fail (gpointer user_data)
{
	dprintf ("  idle ran!\n");
	errors++;
	return FALSE;
}


static void
quit (int sig)
{
	/* Exit cleanly on ^C in case we're valgrinding. */
	exit (0);
}

int
main (int argc, char **argv)
{
	int opt;
	guint port;

	g_type_init ();
	g_thread_init (NULL);
	signal (SIGINT, quit);

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n",
				 argv[0]);
			exit (1);
		}
	}

	port = create_server ();
	base_uri = g_strdup_printf ("http://localhost:%u/", port);

	do_test1 ();
	do_test2 ();

	shutdown_server ();
	g_free (base_uri);
	g_main_context_unref (g_main_context_default ());

	dprintf ("\n");
	if (errors) {
		printf ("context-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("context-test: OK\n");
	return errors != 0;
}
