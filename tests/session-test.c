/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static gboolean server_processed_message;
static gboolean timeout;
static GMainLoop *loop;

static gboolean
timeout_cb (gpointer user_data)
{
	gboolean *timeout = user_data;

	*timeout = TRUE;
	return FALSE;
}

static void
server_handler (SoupServer        *server,
		SoupMessage       *msg, 
		const char        *path,
		GHashTable        *query,
		SoupClientContext *client,
		gpointer           user_data)
{
	if (!strcmp (path, "/request-timeout")) {
		GMainContext *context = soup_server_get_async_context (server);
		GSource *timer;

		timer = g_timeout_source_new (100);
		g_source_set_callback (timer, timeout_cb, &timeout, NULL);
		g_source_attach (timer, context);
		g_source_unref (timer);
	} else
		server_processed_message = TRUE;

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "ok\r\n", 4);
}

static void
finished_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
cancel_message_cb (SoupMessage *msg, gpointer session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_main_loop_quit (loop);
}

static void
do_test_for_session (SoupSession *session,
		     const char *uri, const char *timeout_uri,
		     gboolean queue_is_async,
		     gboolean send_is_blocking,
		     gboolean cancel_is_immediate)
{
	SoupMessage *msg;
	gboolean finished, local_timeout;
	guint timeout_id;

	debug_printf (1, "  queue_message\n");
	debug_printf (2, "    requesting timeout\n");
	msg = soup_message_new ("GET", timeout_uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new ("GET", uri);
	server_processed_message = timeout = finished = FALSE;
	soup_session_queue_message (session, msg, finished_cb, &finished);
	while (!timeout)
		g_usleep (100);
	debug_printf (2, "    got timeout\n");

	if (queue_is_async) {
		if (server_processed_message) {
			debug_printf (1, "    message processed without running main loop!\n");
			errors++;
		}
		debug_printf (2, "    waiting for finished\n");
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
		if (!server_processed_message) {
			debug_printf (1, "    message finished without server seeing it???\n");
			errors++;
		}
	} else {
		if (!server_processed_message) {
			debug_printf (1, "    server failed to immediately receive message!\n");
			errors++;
		}
		debug_printf (2, "    waiting for finished\n");
		if (finished) {
			debug_printf (1, "    message finished without main loop running???\n");
			errors++;
		}
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
	}

	debug_printf (1, "  send_message\n");
	msg = soup_message_new ("GET", uri);
	server_processed_message = local_timeout = FALSE;
	timeout_id = g_idle_add_full (G_PRIORITY_HIGH, timeout_cb, &local_timeout, NULL);
	soup_session_send_message (session, msg);

	if (!server_processed_message) {
		debug_printf (1, "    message finished without server seeing it???\n");
		errors++;
	}

	if (send_is_blocking) {
		if (local_timeout) {
			debug_printf (1, "    send_message ran main loop!\n");
			errors++;
		}
	} else {
		if (!local_timeout) {
			debug_printf (1, "    send_message didn't run main loop!\n");
			errors++;
		}
	}

	if (!local_timeout)
		g_source_remove (timeout_id);

	if (!queue_is_async)
		return;

	debug_printf (1, "  cancel_message\n");
	msg = soup_message_new ("GET", uri);
	g_object_ref (msg);
	finished = FALSE;
	soup_session_queue_message (session, msg, finished_cb, &finished);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (cancel_message_cb), session);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	if (cancel_is_immediate) {
		if (!finished) {
			debug_printf (1, "    cancel did not finish message!\n");
			errors++;
			debug_printf (2, "    waiting for finished\n");
			while (!finished)
				g_main_context_iteration (NULL, TRUE);
		}
	} else {
		if (finished) {
			debug_printf (1, "    cancel finished message!\n");
			errors++;
		} else {
			while (!finished)
				g_main_context_iteration (NULL, TRUE);
		}
	}

	if (msg->status_code != SOUP_STATUS_CANCELLED) {
		debug_printf (1, "    message finished with status %d %s!\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);
}

static void
do_plain_tests (char *uri, char *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "SoupSession\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_test_for_session (session, uri, timeout_uri, TRUE, TRUE, FALSE);
	soup_test_session_abort_unref (session);
}

static void
do_async_tests (char *uri, char *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "\nSoupSessionAsync\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_test_for_session (session, uri, timeout_uri, TRUE, FALSE, TRUE);
	soup_test_session_abort_unref (session);
}

static void
do_sync_tests (char *uri, char *timeout_uri)
{
	SoupSession *session;

	debug_printf (1, "\nSoupSessionSync\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_test_for_session (session, uri, timeout_uri, FALSE, TRUE, FALSE);
	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	char *uri, *timeout_uri;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = g_strdup_printf ("http://127.0.0.1:%u",
			       soup_server_get_port (server));
	timeout_uri = g_strdup_printf ("%s/request-timeout", uri);

	do_plain_tests (uri, timeout_uri);
	do_async_tests (uri, timeout_uri);
	do_sync_tests (uri, timeout_uri);

	g_free (uri);
	g_free (timeout_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
