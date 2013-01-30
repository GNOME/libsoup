/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
message_finished (SoupMessage *msg, gpointer user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
request_started_cb (SoupSession *session, SoupMessage *msg,
		    SoupSocket *socket, gpointer user_data)
{
	SoupSocket **ret = user_data;

	*ret = socket;
}

static void
do_message_to_session (SoupSession *session, const char *uri,
		       const char *comment, guint expected_status)
{
	SoupMessage *msg;
	gboolean finished = FALSE;

	debug_printf (1, "    msg %s\n", comment);
	msg = soup_message_new ("GET", uri);

	g_signal_connect (msg, "finished",
			  G_CALLBACK (message_finished), &finished);
	soup_session_send_message (session, msg);

	if (msg->status_code != expected_status) {
		debug_printf (1, "      FAILED: %d %s (expected %d %s)\n",
			      msg->status_code, msg->reason_phrase,
			      expected_status,
			      soup_status_get_phrase (expected_status));
		errors++;
	}

	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code) &&
	    !soup_message_is_keepalive (msg)) {
		debug_printf (1, "      ERROR: message is not keepalive!\n");
		errors++;
	}

	if (!finished) {
		debug_printf (1, "      ERROR: 'finished' was not emitted\n");
		errors++;
	}

	g_signal_handlers_disconnect_by_func (msg,
					      G_CALLBACK (message_finished),
					      &finished);
	g_object_unref (msg);
}

static void
do_msg_tests_for_session (SoupSession *timeout_session,
			  SoupSession *idle_session,
			  SoupSession *plain_session,
			  char *fast_uri, char *slow_uri)
{
	SoupSocket *ret, *idle_first, *idle_second;
	SoupSocket *plain_first, *plain_second;

	if (idle_session) {
		g_signal_connect (idle_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_first = ret;
	}

	if (plain_session) {
		g_signal_connect (plain_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_first = ret;
	}

	do_message_to_session (timeout_session, fast_uri, "fast to timeout", SOUP_STATUS_OK);
	do_message_to_session (timeout_session, slow_uri, "slow to timeout", SOUP_STATUS_IO_ERROR);

	if (idle_session) {
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_second = ret;
		g_signal_handlers_disconnect_by_func (idle_session,
						      (gpointer)request_started_cb,
						      &ret);

		if (idle_first == idle_second) {
			debug_printf (1, "      ERROR: idle_session did not close first connection\n");
			errors++;
		}
	}

	if (plain_session) {
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_second = ret;
		g_signal_handlers_disconnect_by_func (plain_session,
						      (gpointer)request_started_cb,
						      &ret);

		if (plain_first != plain_second) {
			debug_printf (1, "      ERROR: plain_session closed connection\n");
			errors++;
		}
	}
}

static void
do_request_to_session (SoupSession *session, const char *uri,
		       const char *comment, gboolean expect_timeout)
{
	SoupRequest *req;
	SoupMessage *msg;
	GInputStream *stream;
	GError *error = NULL;
	gboolean finished = FALSE;

	debug_printf (1, "    req %s\n", comment);
	req = soup_session_request (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));

	g_signal_connect (msg, "finished",
			  G_CALLBACK (message_finished), &finished);
	stream = soup_test_request_send (req, NULL, 0, &error);

	if (expect_timeout && !error) {
		debug_printf (1, "      FAILED: request did not time out\n");
		errors++;
	} else if (expect_timeout && !g_error_matches (error, G_IO_ERROR,
						       G_IO_ERROR_TIMED_OUT)) {
		debug_printf (1, "      FAILED: wrong error: %s\n",
			      error->message);
		errors++;
	} else if (!expect_timeout && error) {
		debug_printf (1, "      FAILED: expected success but got error: %s\n",
			      error->message);
		errors++;
	}
	g_clear_error (&error);

	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);

		if (error) {
			debug_printf (1, "      ERROR closing string: %s",
				      error->message);
			errors++;
		}
		g_object_unref (stream);
	}

	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code) &&
	    !soup_message_is_keepalive (msg)) {
		debug_printf (1, "      ERROR: message is not keepalive!\n");
		errors++;
	}

	if (!finished) {
		debug_printf (1, "      ERROR: 'finished' was not emitted\n");
		errors++;
	}

	g_signal_handlers_disconnect_by_func (msg,
					      G_CALLBACK (message_finished),
					      &finished);
	g_object_unref (msg);
	g_object_unref (req);
}

static void
do_req_tests_for_session (SoupSession *timeout_session,
			  SoupSession *idle_session,
			  SoupSession *plain_session,
			  char *fast_uri, char *slow_uri)
{
	SoupSocket *ret, *idle_first, *idle_second;
	SoupSocket *plain_first, *plain_second;

	debug_printf (1, "\n");

	if (idle_session) {
		g_signal_connect (idle_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_request_to_session (idle_session, fast_uri, "fast to idle", FALSE);
		idle_first = ret;
	}

	if (plain_session) {
		g_signal_connect (plain_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_request_to_session (plain_session, fast_uri, "fast to plain", FALSE);
		plain_first = ret;
	}

	do_request_to_session (timeout_session, fast_uri, "fast to timeout", FALSE);
	do_request_to_session (timeout_session, slow_uri, "slow to timeout", TRUE);

	if (idle_session) {
		do_request_to_session (idle_session, fast_uri, "fast to idle", FALSE);
		idle_second = ret;
		g_signal_handlers_disconnect_by_func (idle_session,
						      (gpointer)request_started_cb,
						      &ret);

		if (idle_first == idle_second) {
			debug_printf (1, "      ERROR: idle_session did not close first connection\n");
			errors++;
		}
	}

	if (plain_session) {
		do_request_to_session (plain_session, fast_uri, "fast to plain", FALSE);
		plain_second = ret;
		g_signal_handlers_disconnect_by_func (plain_session,
						      (gpointer)request_started_cb,
						      &ret);

		if (plain_first != plain_second) {
			debug_printf (1, "      ERROR: plain_session closed connection\n");
			errors++;
		}
	}
}

static void
do_timeout_tests (char *fast_uri, char *slow_uri)
{
	SoupSession *timeout_session, *idle_session, *plain_session;

	debug_printf (1, "  async\n");
	timeout_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_TIMEOUT, 1,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 NULL);
	idle_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					      SOUP_SESSION_IDLE_TIMEOUT, 1,
					      SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					      NULL);
	/* The "plain" session also has an idle timeout, but it's longer
	 * than the test takes, so for our purposes it should behave like
	 * it has no timeout.
	 */
	plain_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					       SOUP_SESSION_IDLE_TIMEOUT, 2,
					       SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					       NULL);

	do_msg_tests_for_session (timeout_session, idle_session, plain_session,
				  fast_uri, slow_uri);
	do_req_tests_for_session (timeout_session, idle_session, plain_session,
				  fast_uri, slow_uri);
	soup_test_session_abort_unref (timeout_session);
	soup_test_session_abort_unref (idle_session);
	soup_test_session_abort_unref (plain_session);

	debug_printf (1, "\n  sync\n");
	timeout_session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
						 SOUP_SESSION_TIMEOUT, 1,
						 NULL);
	/* SOUP_SESSION_TIMEOUT doesn't work with sync sessions */
	plain_session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					       NULL);
	do_msg_tests_for_session (timeout_session, NULL, plain_session, fast_uri, slow_uri);
	do_req_tests_for_session (timeout_session, NULL, plain_session, fast_uri, slow_uri);
	soup_test_session_abort_unref (timeout_session);
	soup_test_session_abort_unref (plain_session);
}

static gboolean
timeout_finish_message (gpointer msg)
{
	SoupServer *server = g_object_get_data (G_OBJECT (msg), "server");

	soup_server_unpause_message (server, msg);
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
	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "ok\r\n", 4);

	if (!strcmp (path, "/slow")) {
		soup_server_pause_message (server, msg);
		g_object_set_data (G_OBJECT (msg), "server", server);
		soup_add_timeout (soup_server_get_async_context (server),
				  1100, timeout_finish_message, msg);
	}
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	char *fast_uri, *slow_uri;

	test_init (argc, argv, NULL);

	debug_printf (1, "http\n");
	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	fast_uri = g_strdup_printf ("http://127.0.0.1:%u/",
				    soup_server_get_port (server));
	slow_uri = g_strdup_printf ("http://127.0.0.1:%u/slow",
				    soup_server_get_port (server));
	do_timeout_tests (fast_uri, slow_uri);
	g_free (fast_uri);
	g_free (slow_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		debug_printf (1, "\nhttps\n");
		server = soup_test_server_new_ssl (TRUE);
		soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
		fast_uri = g_strdup_printf ("https://127.0.0.1:%u/",
					    soup_server_get_port (server));
		slow_uri = g_strdup_printf ("https://127.0.0.1:%u/slow",
					    soup_server_get_port (server));
		do_timeout_tests (fast_uri, slow_uri);
		g_free (fast_uri);
		g_free (slow_uri);
		soup_test_server_quit_unref (server);
	}

	test_cleanup ();
	return errors != 0;
}
