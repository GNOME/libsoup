/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
do_ssl_test_for_session (SoupSession *session, GUri *uri)
{
	SoupMessage *msg;
	GError *error;

	msg = soup_message_new_from_uri ("GET", uri);
	g_assert_null (soup_session_send (session, msg, NULL, &error));
	g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_UNAVAILABLE);
	g_assert_cmpuint (soup_message_get_status (msg), ==, SOUP_STATUS_NONE);
	g_assert_null (soup_message_get_tls_peer_certificate (msg));
	g_assert_cmpuint (soup_message_get_tls_peer_certificate_errors (msg), ==, 0);

	g_error_free (error);
	g_object_unref (msg);
}

static void
do_ssl_tests (gconstpointer data)
{
	GUri *uri = (GUri *)data;
	SoupSession *session;

	g_test_bug ("700518");

	session = soup_test_session_new (NULL);
	do_ssl_test_for_session (session, uri);
	soup_test_session_abort_unref (session);
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
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	GUri *uri;
	GUri *ssl_uri;
	int ret;

	/* Force this test to use the dummy TLS backend */
	g_setenv ("GIO_USE_TLS", "dummy", TRUE);

	test_init (argc, argv, NULL);

	/* Make a non-SSL server and pretend that it's ssl, which is fine
	 * since we won't ever actually talk to it anyway. We don't
	 * currently test that failing to construct an SSL server works.
	 */
	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = soup_test_server_get_uri (server, "http", NULL);
        ssl_uri = soup_uri_copy (uri, SOUP_URI_SCHEME, "https", SOUP_URI_NONE);
	g_uri_unref (uri);

	g_test_add_data_func ("/no-ssl/request-error", ssl_uri, do_ssl_tests);

	ret = g_test_run ();

	g_uri_unref (ssl_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
