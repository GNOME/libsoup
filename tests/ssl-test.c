/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
do_properties_test_for_session (SoupSession *session, const char *uri)
{
	SoupMessage *msg;
	GTlsCertificate *cert;
	GTlsCertificateFlags flags;

	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (soup_message_get_https_status (msg, &cert, &flags)) {
		g_assert_true (G_IS_TLS_CERTIFICATE (cert));
		g_assert_cmpuint (flags, ==, G_TLS_CERTIFICATE_UNKNOWN_CA);
	} else
		soup_test_assert (FALSE, "Response not https");
	g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);

	g_object_unref (msg);
}

static void
do_async_properties_tests (gconstpointer uri)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_SSL_CA_FILE, "/dev/null",
		      SOUP_SESSION_SSL_STRICT, FALSE,
		      NULL);
	do_properties_test_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_sync_properties_tests (gconstpointer uri)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_SSL_CA_FILE, "/dev/null",
		      SOUP_SESSION_SSL_STRICT, FALSE,
		      NULL);
	do_properties_test_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_one_strict_test (SoupSession *session, const char *uri,
		    gboolean strict, gboolean with_ca_list,
		    guint expected_status)
{
	SoupMessage *msg;

	/* Note that soup_test_session_new() sets
	 * SOUP_SESSION_SSL_CA_FILE by default, and turns off
	 * SOUP_SESSION_SSL_STRICT.
	 */

	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_SSL_STRICT, strict,
		      SOUP_SESSION_SSL_CA_FILE,
		      (with_ca_list ?
		       g_test_get_filename (G_TEST_DIST, "/test-cert.pem", NULL) :
		       "/dev/null"),
		      NULL);
	/* Close existing connections with old params */
	soup_session_abort (session);

	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != expected_status) {
		debug_printf (1, "      FAILED: %d %s (expected %d %s)\n",
			      msg->status_code, msg->reason_phrase,
			      expected_status,
			      soup_status_get_phrase (expected_status));
		if (msg->status_code == SOUP_STATUS_SSL_FAILED) {
			GTlsCertificateFlags flags = 0;

			soup_message_get_https_status (msg, NULL, &flags);
			debug_printf (1, "              tls error flags: 0x%x\n", flags);
		}
	} else if (with_ca_list && SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		g_assert_true (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);
	else
		g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);

	g_assert_true (soup_message_get_https_status (msg, NULL, NULL));

	g_object_unref (msg);
}

static void
do_strict_tests (gconstpointer uri)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_TLS;

	debug_printf (1, "\nstrict/nonstrict\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	debug_printf (1, "  async with CA list\n");
	do_one_strict_test (session, uri, TRUE, TRUE, SOUP_STATUS_OK);
	debug_printf (1, "  async without CA list\n");
	do_one_strict_test (session, uri, TRUE, FALSE, SOUP_STATUS_SSL_FAILED);
	debug_printf (1, "  async non-strict with CA list\n");
	do_one_strict_test (session, uri, FALSE, TRUE, SOUP_STATUS_OK);
	debug_printf (1, "  async non-strict without CA list\n");
	do_one_strict_test (session, uri, FALSE, FALSE, SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	debug_printf (1, "  sync with CA list\n");
	do_one_strict_test (session, uri, TRUE, TRUE, SOUP_STATUS_OK);
	debug_printf (1, "  sync without CA list\n");
	do_one_strict_test (session, uri, TRUE, FALSE, SOUP_STATUS_SSL_FAILED);
	debug_printf (1, "  sync non-strict with CA list\n");
	do_one_strict_test (session, uri, FALSE, TRUE, SOUP_STATUS_OK);
	debug_printf (1, "  sync non-strict without CA list\n");
	do_one_strict_test (session, uri, FALSE, FALSE, SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
property_changed (GObject *object, GParamSpec *param, gpointer user_data)
{
	gboolean *changed = user_data;

	*changed = TRUE;
}

static void
do_session_property_tests (void)
{
	gboolean use_system_changed, tlsdb_changed, ca_file_changed;
	gboolean use_system;
	GTlsDatabase *tlsdb;
	char *ca_file;
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_TLS;

	debug_printf (1, "session properties\n");

	session = soup_session_async_new ();
	g_signal_connect (session, "notify::ssl-use-system-ca-file",
			  G_CALLBACK (property_changed), &use_system_changed);
	g_signal_connect (session, "notify::tls-database",
			  G_CALLBACK (property_changed), &tlsdb_changed);
	g_signal_connect (session, "notify::ssl-ca-file",
			  G_CALLBACK (property_changed), &ca_file_changed);

	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (!use_system,
			  "ssl-use-system-ca-file defaults to TRUE");
	soup_test_assert (tlsdb == NULL,
			  "tls-database set by default");
	soup_test_assert (ca_file == NULL,
			  "ca-file set by default");

	use_system_changed = tlsdb_changed = ca_file_changed = FALSE;
	g_object_set (G_OBJECT (session),
		      "ssl-use-system-ca-file", TRUE,
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (use_system,
			  "setting ssl-use-system-ca-file failed");
	g_assert_true (use_system_changed);
	soup_test_assert (tlsdb != NULL,
			  "setting ssl-use-system-ca-file didn't set tls-database");
	g_assert_true (tlsdb_changed);
	g_clear_object (&tlsdb);
	soup_test_assert (ca_file == NULL,
			  "setting ssl-use-system-ca-file set ssl-ca-file");
	g_assert_false (ca_file_changed);

	use_system_changed = tlsdb_changed = ca_file_changed = FALSE;
	g_object_set (G_OBJECT (session),
		      "ssl-ca-file", g_test_get_filename (G_TEST_DIST, "/test-cert.pem", NULL),
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (!use_system,
			  "setting ssl-ca-file left ssl-use-system-ca-file set");
	g_assert_true (use_system_changed);
	soup_test_assert (tlsdb != NULL,
			  "setting ssl-ca-file didn't set tls-database");
	g_assert_true (tlsdb_changed);
	g_clear_object (&tlsdb);
	soup_test_assert (ca_file != NULL,
			  "setting ssl-ca-file failed");
	g_assert_true (ca_file_changed);
	g_free (ca_file);

	use_system_changed = tlsdb_changed = ca_file_changed = FALSE;
	g_object_set (G_OBJECT (session),
		      "tls-database", NULL,
		      NULL);
	g_object_get (G_OBJECT (session),
		      "ssl-use-system-ca-file", &use_system,
		      "tls-database", &tlsdb,
		      "ssl-ca-file", &ca_file,
		      NULL);
	soup_test_assert (!use_system,
			  "setting tls-database NULL left ssl-use-system-ca-file set");
	g_assert_false (use_system_changed);
	soup_test_assert (tlsdb == NULL,
			  "setting tls-database NULL failed");
	g_assert_true (tlsdb_changed);
	soup_test_assert (ca_file == NULL,
			  "setting tls-database didn't clear ssl-ca-file");
	g_assert_true (ca_file_changed);

	soup_test_session_abort_unref (session);
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
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	char *uri;
	int ret;

	test_init (argc, argv, NULL);

	if (tls_available) {
		server = soup_test_server_new_ssl (TRUE);
		soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
		uri = g_strdup_printf ("https://127.0.0.1:%u/",
				       soup_server_get_port (server));
	}

	g_test_add_func ("/ssl/session-properties", do_session_property_tests);
	g_test_add_data_func ("/ssl/message-properties/async", uri, do_async_properties_tests);
	g_test_add_data_func ("/ssl/message-properties/sync", uri, do_sync_properties_tests);

	/* FIXME: split this up */
	g_test_add_data_func ("/ssl/strict", uri, do_strict_tests);

	ret = g_test_run ();

	if (tls_available) {
		g_free (uri);
		soup_test_server_quit_unref (server);
	}

	test_cleanup ();
	return ret;
}
