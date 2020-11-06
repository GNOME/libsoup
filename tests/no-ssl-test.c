/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
do_ssl_test_for_session (SoupSession *session, SoupURI *uri)
{
	SoupMessage *msg;

	msg = soup_message_new_from_uri ("GET", uri);
	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_SSL_FAILED);

	g_assert_null (soup_message_get_tls_certificate (msg));
	g_assert_cmpuint (soup_message_get_tls_certificate_errors (msg), ==, 0);

	g_object_unref (msg);
}

static void
do_ssl_tests (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
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
	SoupURI *uri;
	guint port;
	int ret;

	/* Force this test to use the dummy TLS backend */
	g_setenv ("GIO_USE_TLS", "dummy", TRUE);

	test_init (argc, argv, NULL);

	/* Make a non-SSL server and pretend that it's ssl, which is fine
	 * since we won't ever actually talk to it anyway. We don't
	 * currently test that failing to construct an SSL server works.
	 */
	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	uri = soup_test_server_get_uri (server, "http", NULL);
	port = uri->port;
	soup_uri_set_scheme (uri, SOUP_URI_SCHEME_HTTPS);
	soup_uri_set_port (uri, port);

	g_test_add_data_func ("/no-ssl/request-error", uri, do_ssl_tests);

	ret = g_test_run ();

	soup_uri_free (uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
