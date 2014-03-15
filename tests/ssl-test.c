/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static char *uri;

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

	g_test_bug ("665182");
	g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);

	g_object_unref (msg);
}

static void
do_async_properties_tests (void)
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
do_sync_properties_tests (void)
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

typedef struct {
	const char *name;
	gboolean sync;
	gboolean strict;
	gboolean with_ca_list;
	guint expected_status;
} StrictnessTest;

static const StrictnessTest strictness_tests[] = {
	{ "/ssl/strictness/async/strict/with-ca",
	  FALSE, TRUE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/async/strict/without-ca",
	  FALSE, TRUE, FALSE, SOUP_STATUS_SSL_FAILED },
	{ "/ssl/strictness/async/non-strict/with-ca",
	  FALSE, FALSE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/async/non-strict/without-ca",
	  FALSE, FALSE, FALSE, SOUP_STATUS_OK },
	{ "/ssl/strictness/sync/strict/with-ca",
	  TRUE, TRUE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/sync/strict/without-ca",
	  TRUE, TRUE, FALSE, SOUP_STATUS_SSL_FAILED },
	{ "/ssl/strictness/sync/non-strict/with-ca",
	  TRUE, FALSE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/sync/non-strict/without-ca",
	  TRUE, FALSE, FALSE, SOUP_STATUS_OK },
};

static void
do_strictness_test (gconstpointer data)
{
	const StrictnessTest *test = data;
	SoupSession *session;
	SoupMessage *msg;
	GTlsCertificateFlags flags = 0;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (test->sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
					 NULL);
	if (!test->strict) {
		g_object_set (G_OBJECT (session),
			      SOUP_SESSION_SSL_STRICT, FALSE,
			      NULL);
	}
	if (!test->with_ca_list) {
		g_object_set (G_OBJECT (session),
			      SOUP_SESSION_SSL_CA_FILE, "/dev/null",
			      NULL);
	}

	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, test->expected_status);

	g_test_bug ("690176");
	g_assert_true (soup_message_get_https_status (msg, NULL, &flags));

	g_test_bug ("665182");
	if (test->with_ca_list && SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		g_assert_true (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);
	else
		g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED);

	if (msg->status_code == SOUP_STATUS_SSL_FAILED &&
	    test->expected_status != SOUP_STATUS_SSL_FAILED)
		debug_printf (1, "              tls error flags: 0x%x\n", flags);

	g_object_unref (msg);
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

	g_test_bug ("673678");

	SOUP_TEST_SKIP_IF_NO_TLS;

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
	int i, ret;

	test_init (argc, argv, NULL);

	if (tls_available) {
		server = soup_test_server_new_ssl (TRUE);
		soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
		uri = g_strdup_printf ("https://127.0.0.1:%u/",
				       soup_server_get_port (server));
	}

	g_test_add_func ("/ssl/session-properties", do_session_property_tests);
	g_test_add_func ("/ssl/message-properties/async", do_async_properties_tests);
	g_test_add_func ("/ssl/message-properties/sync", do_sync_properties_tests);

	for (i = 0; i < G_N_ELEMENTS (strictness_tests); i++) {
		g_test_add_data_func (strictness_tests[i].name,
				      &strictness_tests[i],
				      do_strictness_test);
	}

	ret = g_test_run ();

	if (tls_available) {
		g_free (uri);
		soup_test_server_quit_unref (server);
	}

	test_cleanup ();
	return ret;
}
