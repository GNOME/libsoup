#include "test-utils.h"

#include <glib.h>
#include <glib/gstdio.h>

#include <stdio.h>
#include "soup-uri-utils-private.h"

#define DB_FILE "hsts-db.sqlite"

GUri *http_uri;
GUri *https_uri;

/* This server pseudo-implements the HSTS spec in order to allow us to
   test the Soup HSTS feature.
 */
static void
server_callback  (SoupServer        *server,
                  SoupServerMessage *msg,
		  const char        *path,
                  GHashTable        *query,
		  gpointer           data)
{
        SoupMessageHeaders *response_headers;
	const char *server_protocol = data;

        response_headers = soup_server_message_get_response_headers (msg);

	if (strcmp (server_protocol, "http") == 0) {
                GUri *uri = g_uri_build (SOUP_HTTP_URI_FLAGS, "https", NULL, "localhost", -1, path, NULL, NULL);
		char *uri_string = g_uri_to_string (uri);
		fprintf (stderr, "server is redirecting to HTTPS\n");
		soup_server_message_set_redirect (msg, SOUP_STATUS_MOVED_PERMANENTLY, uri_string);
		g_uri_unref (uri);
		g_free (uri_string);
	} else if (strcmp (server_protocol, "https") == 0) {
		soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
		if (strcmp (path, "/long-lasting") == 0) {
			soup_message_headers_append (response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000");
		} else if (strcmp (path, "/two-seconds") == 0) {
			soup_message_headers_append (response_headers,
						     "Strict-Transport-Security",
						     "max-age=2");
		} else if (strcmp (path, "/delete") == 0) {
			soup_message_headers_append (response_headers,
						     "Strict-Transport-Security",
						     "max-age=0");
		} else if (strcmp (path, "/subdomains") == 0) {
			soup_message_headers_append (response_headers,
						     "Strict-Transport-Security",
						     "max-age=31536000; includeSubDomains");
		}
                else if (strcmp (path, "/very-long-lasting") == 0) {
			soup_message_headers_append (response_headers,
						     "Strict-Transport-Security",
						     "max-age=631138519");
		}
	}
}

static void
hsts_enforced_cb (SoupMessage *msg,
		  gboolean    *enforced)
{
	*enforced = TRUE;
}

static void
session_get_uri (SoupSession *session,
                 const char  *uri,
                 SoupStatus   expected_status,
                 gboolean     expected_enforced)
{
	SoupMessage *msg;
        GBytes *body;
        GError *error = NULL;
        gboolean enforced = FALSE;

	msg = soup_message_new ("GET", uri);
        g_signal_connect (msg, "hsts-enforced", G_CALLBACK (hsts_enforced_cb), &enforced);
	soup_message_add_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
	body = soup_session_send_and_read (session, msg, NULL, &error);
	if (expected_status == SOUP_STATUS_NONE)
		g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);
	else
		g_assert_no_error (error);
	soup_test_assert_message_status (msg, expected_status);
        g_assert_true (enforced == expected_enforced);
        g_clear_error (&error);
        g_bytes_unref (body);
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
	GUri *new_uri;
	if (soup_uri_is_http (soup_message_get_uri (msg)))
		new_uri = soup_uri_copy (soup_message_get_uri (msg), SOUP_URI_PORT, g_uri_get_port (http_uri), SOUP_URI_NONE);
	else if (soup_uri_is_https (soup_message_get_uri (msg)))
		new_uri = soup_uri_copy (soup_message_get_uri (msg), SOUP_URI_PORT, g_uri_get_port (https_uri), SOUP_URI_NONE);
	else
		g_assert_not_reached();
	soup_message_set_uri (msg, new_uri);
	g_uri_unref (new_uri);
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

	SoupSession *session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (hsts_db));
	g_signal_connect (session, "request-queued", G_CALLBACK (on_request_queued), NULL);
	g_object_unref (hsts_db);

	return session;
}


static void
do_hsts_db_persistency_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/long-lasting", SOUP_STATUS_OK, FALSE);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK, TRUE);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK, TRUE);
	soup_test_session_abort_unref (session);

	g_remove (DB_FILE);
}

static void
do_hsts_db_subdomains_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/subdomains", SOUP_STATUS_OK, FALSE);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://subdomain.localhost", SOUP_STATUS_NONE, TRUE);
	soup_test_session_abort_unref (session);

	g_remove (DB_FILE);
}

static void
do_hsts_db_large_max_age_test (void)
{
	SoupSession *session = hsts_db_session_new ();
	session_get_uri (session, "https://localhost/very-long-lasting", SOUP_STATUS_OK, FALSE);
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK, TRUE);
	soup_test_session_abort_unref (session);

	session = hsts_db_session_new ();
	session_get_uri (session, "http://localhost", SOUP_STATUS_OK, TRUE);
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

	g_uri_unref (http_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		g_uri_unref (https_uri);
		soup_test_server_quit_unref (https_server);
	}

	test_cleanup ();
	return ret;
}
