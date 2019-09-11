#include <glib.h>
#include <glib/gstdio.h>

#include <stdio.h>
#include "test-utils.h"

#define DB_FILE "hsts-db.sqlite"

SoupURI *http_uri;
SoupURI *https_uri;

/* This server pseudo-implements the HSTS spec in order to allow us to
   test the Soup HSTS feature.
 */
static void
server_callback  (SoupServer *server, SoupMessage *msg,
		  const char *path, GHashTable *query,
		  SoupClientContext *context, gpointer data)
{
	const char *server_protocol = data;

	if (strcmp (server_protocol, "http") == 0) {
		char *uri_string;
		SoupURI *uri = soup_uri_new ("https://localhost");
		soup_uri_set_path (uri, path);
		uri_string = soup_uri_to_string (uri, FALSE);
		fprintf (stderr, "server is redirecting to HTTPS\n");
		soup_message_set_redirect (msg, SOUP_STATUS_MOVED_PERMANENTLY, uri_string);
		soup_uri_free (uri);
		g_free (uri_string);
	} else if (strcmp (server_protocol, "https") == 0) {
		soup_message_set_status (msg, SOUP_STATUS_OK);
		if (strcmp (path, "/long-lasting") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000");
		} else if (strcmp (path, "/two-seconds") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=2");
		} else if (strcmp (path, "/delete") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=0");
		} else if (strcmp (path, "/subdomains") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000; includeSubDomains");
		}
                else if (strcmp (path, "/very-long-lasting") == 0) {
			soup_message_headers_append (msg->response_headers,
						     "Strict-Transport-Security",
						     "max-age=631138519");
		}
	}
}

static void
session_get_uri (SoupSession *session, const char *uri, SoupStatus expected_status)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, expected_status);
	g_object_unref (msg);
}

/* The HSTS specification does not handle custom ports, so we need to
 * rewrite the URI in the request and add the port where the server is
 * listening before it is sent, to be able to connect to the localhost
 * port where the server is actually running.
 */
static void
rewrite_message_uri (SoupMessage *msg)
{
	if (soup_uri_get_scheme (soup_message_get_uri (msg)) == SOUP_URI_SCHEME_HTTP)
		soup_uri_set_port (soup_message_get_uri (msg), soup_uri_get_port (http_uri));
	else if (soup_uri_get_scheme (soup_message_get_uri (msg)) == SOUP_URI_SCHEME_HTTPS)
		soup_uri_set_port (soup_message_get_uri (msg), soup_uri_get_port (https_uri));
	else
		g_assert_not_reached();
}

static void
on_message_restarted (SoupMessage *msg,
		     gpointer data)
{
	rewrite_message_uri (msg);
}

static void
on_request_queued (SoupSession *session,
		   SoupMessage *msg,
		   gpointer data)
{
	g_signal_connect (msg, "restarted", G_CALLBACK (on_message_restarted), NULL);

	rewrite_message_uri (msg);
}

static SoupSession *
hsts_db_session_new (void)
{
	SoupHSTSEnforcer *hsts_db = soup_hsts_enforcer_db_new (DB_FILE);

	SoupSession *session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						      SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
						      SOUP_SESSION_ADD_FEATURE, hsts_db,
						      NULL);
	g_signal_connect (session, "request-queued", G_CALLBACK (on_request_queued), NULL);
	g_object_unref (hsts_db);

	return session;
}


static void
do_hsts_db_persistency_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	g_remove (DB_FILE);
}

static void
do_hsts_db_subdomains_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/subdomains", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://subdomain.localhost", SOUP_STATUS_SSL_FAILED);
	soup_test_session_abort_unref (session);

	g_remove (DB_FILE);
}

static void
do_hsts_db_large_max_age_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/very-long-lasting", SOUP_STATUS_OK);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	g_remove (DB_FILE);
}

int
main (int argc, char **argv)
{
	int ret;
	SoupServer *server;
	SoupServer *https_server = NULL;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, "http", NULL);
	http_uri = soup_test_server_get_uri (server, "http", NULL);

	if (tls_available) {
		https_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (https_server, NULL, server_callback, "https", NULL);
		https_uri = soup_test_server_get_uri (https_server, "https", NULL);
	}

	g_test_add_func ("/hsts-db/basic", do_hsts_db_persistency_test);
	g_test_add_func ("/hsts-db/subdomains", do_hsts_db_subdomains_test);
	g_test_add_func ("/hsts-db/large-max-age", do_hsts_db_large_max_age_test);

	ret = g_test_run ();

	soup_uri_free (http_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		soup_uri_free (https_uri);
		soup_test_server_quit_unref (https_server);
	}

	test_cleanup ();
	return ret;
}
