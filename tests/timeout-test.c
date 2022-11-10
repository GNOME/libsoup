/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-message-private.h"
#include "soup-connection.h"
#include "soup-uri-utils-private.h"

static gboolean slow_https;

static void
message_finished (SoupMessage *msg, gpointer user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
message_starting_cb (SoupMessage *msg,
		     GSocket    **ret)
{
        SoupConnection *conn = soup_message_get_connection (msg);

	*ret = soup_connection_get_socket (conn);
}

static void
request_queued_cb (SoupSession *session,
		   SoupMessage *msg,
		   GSocket    **ret)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (message_starting_cb),
			  ret);
}

static void
do_message_to_session (SoupSession *session, GUri *uri,
		       const char *comment, guint expected_status)
{
	SoupMessage *msg;
	GBytes *body;
	gboolean finished = FALSE;
	GError *error = NULL;

	if (comment)
		debug_printf (1, "    msg %s\n", comment);
	msg = soup_message_new_from_uri ("GET", uri);

	g_signal_connect (msg, "finished",
			  G_CALLBACK (message_finished), &finished);

	body = soup_test_session_async_send (session, msg, NULL, &error);
	if (expected_status != SOUP_STATUS_NONE) {
		g_assert_no_error (error);
		soup_test_assert_message_status (msg, expected_status);
		g_assert_true (soup_message_is_keepalive (msg));
	} else {
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT);
	}
	g_clear_error (&error);
	g_assert_true (finished);

	g_signal_handlers_disconnect_by_func (msg,
					      G_CALLBACK (message_finished),
					      &finished);
	g_clear_pointer (&body, g_bytes_unref);
	g_object_unref (msg);
}

static void
do_msg_tests_for_session (SoupSession *timeout_session,
			  SoupSession *idle_session,
			  SoupSession *plain_session,
			  GUri *fast_uri,
			  GUri *slow_uri)
{
	GSocket *ret, *idle_first = NULL, *idle_second;
	GSocket *plain_first = NULL, *plain_second;

	if (idle_session) {
		g_signal_connect (idle_session, "request-queued",
				  G_CALLBACK (request_queued_cb), &ret);
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_first = g_object_ref (ret);
	}

	if (plain_session) {
		g_signal_connect (plain_session, "request-queued",
				  G_CALLBACK (request_queued_cb), &ret);
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_first = g_object_ref (ret);
	}

	do_message_to_session (timeout_session, fast_uri, "fast to timeout", SOUP_STATUS_OK);
	do_message_to_session (timeout_session, slow_uri, "slow to timeout", SOUP_STATUS_NONE);

	if (idle_session) {
		do_message_to_session (idle_session, fast_uri, "fast to idle", SOUP_STATUS_OK);
		idle_second = ret;
		g_signal_handlers_disconnect_by_func (idle_session,
						      (gpointer)request_queued_cb,
						      &ret);

		soup_test_assert (idle_first != idle_second,
				  "idle_session did not close first connection");
		g_object_unref (idle_first);
	}

	if (plain_session) {
		do_message_to_session (plain_session, fast_uri, "fast to plain", SOUP_STATUS_OK);
		plain_second = ret;
		g_signal_handlers_disconnect_by_func (plain_session,
						      (gpointer)request_queued_cb,
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
	GUri *fast_uri = (GUri *)data;
	GUri *slow_uri = g_uri_parse_relative (fast_uri, "/slow", SOUP_HTTP_URI_FLAGS, NULL);
	gboolean extra_slow;

	if (soup_uri_is_https (fast_uri)) {
		SOUP_TEST_SKIP_IF_NO_TLS;
		extra_slow = slow_https;
	} else
		extra_slow = FALSE;

	timeout_session = soup_test_session_new ("timeout", extra_slow ? 3 : 1, NULL);
	idle_session = soup_test_session_new ("idle-timeout", extra_slow ? 2 : 1, NULL);
	/* The "plain" session also has an idle timeout, but it's longer
	 * than the test takes, so for our purposes it should behave like
	 * it has no timeout.
	 */
	plain_session = soup_test_session_new ("idle-timeout", 20, NULL);

	do_msg_tests_for_session (timeout_session, idle_session, plain_session,
				  fast_uri, slow_uri);
	soup_test_session_abort_unref (timeout_session);
	soup_test_session_abort_unref (idle_session);
	soup_test_session_abort_unref (plain_session);

	g_uri_unref (slow_uri);
}

static void
do_sync_timeout_tests (gconstpointer data)
{
	SoupSession *timeout_session, *plain_session;
	GUri *fast_uri = (GUri *)data;
	GUri *slow_uri = g_uri_parse_relative (fast_uri, "/slow", SOUP_HTTP_URI_FLAGS, NULL);
	gboolean extra_slow;

	if (soup_uri_is_https (fast_uri)) {
		SOUP_TEST_SKIP_IF_NO_TLS;

		extra_slow = slow_https;
	} else
		extra_slow = FALSE;

	timeout_session = soup_test_session_new ("timeout", extra_slow ? 3 : 1, NULL);
	/* SoupSession:timeout doesn't work with sync sessions */
	plain_session = soup_test_session_new (NULL);
	do_msg_tests_for_session (timeout_session, NULL, plain_session, fast_uri, slow_uri);
	soup_test_session_abort_unref (timeout_session);
	soup_test_session_abort_unref (plain_session);

	g_uri_unref (slow_uri);
}

static gboolean
timeout_finish_message (gpointer msg)
{
	soup_server_message_unpause (msg);
        g_object_unref (msg);
	return FALSE;
}

static void
server_handler (SoupServer        *server,
		SoupServerMessage *msg,
		const char        *path,
		GHashTable        *query,
		gpointer           user_data)
{
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_STATIC,
					  "ok\r\n", 4);

	if (!strcmp (path, "/slow")) {
                GSource *timeout;
		soup_server_message_pause (msg);
		timeout = soup_add_timeout (g_main_context_get_thread_default (),
                                            4000, timeout_finish_message, g_object_ref (msg));
                g_source_unref (timeout);
	}
}

int
main (int argc, char **argv)
{
	SoupServer *server, *https_server = NULL;
	GUri *uri, *https_uri = NULL;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = soup_test_server_get_uri (server, "http", NULL);

	if (tls_available) {
		SoupSession *test_session;
		gint64 start, end;

		https_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (https_server, NULL, server_handler, NULL, NULL);
		https_uri = soup_test_server_get_uri (server, "https", "127.0.0.1");

		/* The 1-second timeouts are too fast for some machines... */
		test_session = soup_test_session_new (NULL);
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
		https_uri = g_uri_parse ("https://fail.", SOUP_HTTP_URI_FLAGS, NULL);

	g_test_add_data_func ("/timeout/http/async", uri, do_async_timeout_tests);
	g_test_add_data_func ("/timeout/http/sync", uri, do_sync_timeout_tests);
	g_test_add_data_func ("/timeout/https/async", https_uri, do_async_timeout_tests);
	g_test_add_data_func ("/timeout/https/sync", https_uri, do_sync_timeout_tests);

	ret = g_test_run ();

	g_uri_unref (uri);
	g_uri_unref (https_uri);
	soup_test_server_quit_unref (server);
	if (https_server)
		soup_test_server_quit_unref (https_server);

	test_cleanup ();
	return ret;
}
