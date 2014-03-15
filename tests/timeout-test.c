/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static gboolean slow_https;

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

	if (comment)
		debug_printf (1, "    msg %s\n", comment);
	msg = soup_message_new ("GET", uri);

	g_signal_connect (msg, "finished",
			  G_CALLBACK (message_finished), &finished);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, expected_status);
	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		g_assert_true (soup_message_is_keepalive (msg));
	g_assert_true (finished);

	g_signal_handlers_disconnect_by_func (msg,
					      G_CALLBACK (message_finished),
					      &finished);
	g_object_unref (msg);
}

static void
do_msg_tests_for_session (SoupSession *timeout_session,
			  SoupSession *idle_session,
			  SoupSession *plain_session,
			  const char *fast_uri,
			  const char *slow_uri)
{
	SoupSocket *ret, *idle_first, *idle_second;
	SoupSocket *plain_first, *plain_second;

	if (idle_session) {
		g_signal_connect (idle_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_first = g_object_ref (ret);
	}

	if (plain_session) {
		g_signal_connect (plain_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_first = g_object_ref (ret);
	}

	do_message_to_session (timeout_session, fast_uri, "fast to timeout", SOUP_STATUS_OK);
	do_message_to_session (timeout_session, slow_uri, "slow to timeout", SOUP_STATUS_IO_ERROR);

	if (idle_session) {
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_second = ret;
		g_signal_handlers_disconnect_by_func (idle_session,
						      (gpointer)request_started_cb,
						      &ret);

		soup_test_assert (idle_first != idle_second,
				  "idle_session did not close first connection");
		g_object_unref (idle_first);
	}

	if (plain_session) {
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_second = ret;
		g_signal_handlers_disconnect_by_func (plain_session,
						      (gpointer)request_started_cb,
						      &ret);

		soup_test_assert (plain_first == plain_second,
				  "plain_session closed connection");
		g_object_unref (plain_first);
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

	if (expect_timeout)
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT);
	else
		g_assert_no_error (error);
	g_clear_error (&error);

	if (stream) {
		soup_test_request_read_all (req, stream, NULL, &error);
		g_assert_no_error (error);
	}

	if (stream) {
		soup_test_request_close_stream (req, stream, NULL, &error);
		g_assert_no_error (error);
		g_object_unref (stream);
	}

	if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		g_assert_true (soup_message_is_keepalive (msg));
	g_assert_true (finished);

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
			  const char *fast_uri,
			  const char *slow_uri)
{
	SoupSocket *ret, *idle_first, *idle_second;
	SoupSocket *plain_first, *plain_second;

	if (idle_session) {
		g_signal_connect (idle_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_request_to_session (idle_session, fast_uri, "fast to idle", FALSE);
		idle_first = g_object_ref (ret);
	}

	if (plain_session) {
		g_signal_connect (plain_session, "request-started",
				  G_CALLBACK (request_started_cb), &ret);
		do_request_to_session (plain_session, fast_uri, "fast to plain", FALSE);
		plain_first = g_object_ref (ret);
	}

	do_request_to_session (timeout_session, fast_uri, "fast to timeout", FALSE);
	do_request_to_session (timeout_session, slow_uri, "slow to timeout", TRUE);

	if (idle_session) {
		do_request_to_session (idle_session, fast_uri, "fast to idle", FALSE);
		idle_second = ret;
		g_signal_handlers_disconnect_by_func (idle_session,
						      (gpointer)request_started_cb,
						      &ret);

		soup_test_assert (idle_first != idle_second,
				  "idle_session did not close first connection");
		g_object_unref (idle_first);
	}

	if (plain_session) {
		do_request_to_session (plain_session, fast_uri, "fast to plain", FALSE);
		plain_second = ret;
		g_signal_handlers_disconnect_by_func (plain_session,
						      (gpointer)request_started_cb,
						      &ret);

		soup_test_assert (plain_first == plain_second,
				  "plain_session closed connection");
		g_object_unref (plain_first);
	}
}

static void
do_async_timeout_tests (gconstpointer data)
{
	SoupSession *timeout_session, *idle_session, *plain_session;
	const char *fast_uri = data;
	const char *slow_uri = g_build_path ("/", fast_uri, "slow", NULL);
	gboolean extra_slow;

	if (g_str_has_prefix (fast_uri, "https")) {
		SOUP_TEST_SKIP_IF_NO_TLS;

		extra_slow = slow_https;
	} else
		extra_slow = FALSE;

	timeout_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_TIMEOUT, extra_slow ? 3 : 1,
						 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						 NULL);
	idle_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					      SOUP_SESSION_IDLE_TIMEOUT, extra_slow ? 2 : 1,
					      SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					      NULL);
	/* The "plain" session also has an idle timeout, but it's longer
	 * than the test takes, so for our purposes it should behave like
	 * it has no timeout.
	 */
	plain_session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					       SOUP_SESSION_IDLE_TIMEOUT, 20,
					       SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					       NULL);

	do_msg_tests_for_session (timeout_session, idle_session, plain_session,
				  fast_uri, slow_uri);
	do_req_tests_for_session (timeout_session, idle_session, plain_session,
				  fast_uri, slow_uri);
	soup_test_session_abort_unref (timeout_session);
	soup_test_session_abort_unref (idle_session);
	soup_test_session_abort_unref (plain_session);
}

static void
do_sync_timeout_tests (gconstpointer data)
{
	SoupSession *timeout_session, *plain_session;
	const char *fast_uri = data;
	const char *slow_uri = g_build_path ("/", fast_uri, "slow", NULL);
	gboolean extra_slow;

	if (g_str_has_prefix (fast_uri, "https")) {
		SOUP_TEST_SKIP_IF_NO_TLS;

		extra_slow = slow_https;
	} else
		extra_slow = FALSE;

	timeout_session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
						 SOUP_SESSION_TIMEOUT, extra_slow ? 3 : 1,
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
				  4000, timeout_finish_message, msg);
	}
}

int
main (int argc, char **argv)
{
	SoupServer *server, *https_server = NULL;
	char *uri, *https_uri = NULL;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = g_strdup_printf ("http://127.0.0.1:%u/",
			       soup_server_get_port (server));

	if (tls_available) {
		SoupSession *test_session;
		gint64 start, end;

		https_server = soup_test_server_new_ssl (TRUE);
		soup_server_add_handler (https_server, NULL, server_handler, NULL, NULL);
		https_uri = g_strdup_printf ("https://127.0.0.1:%u/",
					     soup_server_get_port (https_server));

		/* The 1-second timeouts are too fast for some machines... */
		test_session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
		start = g_get_monotonic_time ();
		do_message_to_session (test_session, uri, NULL, SOUP_STATUS_OK);
		end = g_get_monotonic_time ();
		soup_test_session_abort_unref (test_session);
		debug_printf (2, "  (https request took %0.3fs)\n", (end - start) / 1000000.0);
		if (end - start > 750000) {
			debug_printf (1, "  (using extra-slow mode)\n\n");
			slow_https = TRUE;
		} else {
			debug_printf (2, "\n");
			slow_https = FALSE;
		}
	} else
		https_uri = g_strdup ("https://fail.");

	g_test_add_data_func ("/timeout/http/async", uri, do_async_timeout_tests);
	g_test_add_data_func ("/timeout/http/sync", uri, do_sync_timeout_tests);
	g_test_add_data_func ("/timeout/https/async", https_uri, do_async_timeout_tests);
	g_test_add_data_func ("/timeout/https/sync", https_uri, do_sync_timeout_tests);

	ret = g_test_run ();

	g_free (uri);
	g_free (https_uri);
	soup_test_server_quit_unref (server);
	if (https_server)
		soup_test_server_quit_unref (https_server);

	test_cleanup ();
	return ret;
}
