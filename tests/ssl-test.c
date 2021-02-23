/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-server-message-private.h"

GUri *uri;

typedef struct {
	const char *name;
	gboolean strict;
	gboolean with_ca_list;
	guint expected_status;
} StrictnessTest;

static const StrictnessTest strictness_tests[] = {
	{ "/ssl/strictness/strict/with-ca",
	  TRUE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/strict/without-ca",
	  TRUE, FALSE, SOUP_STATUS_NONE },
	{ "/ssl/strictness/non-strict/with-ca",
	  FALSE, TRUE, SOUP_STATUS_OK },
	{ "/ssl/strictness/non-strict/without-ca",
	  FALSE, FALSE, SOUP_STATUS_OK },
};

static gboolean
accept_certificate (SoupMessage *msg,
		    GTlsCertificate *certificate,
		    GTlsCertificateFlags errors)
{
	return TRUE;
}

static void
do_strictness_test (gconstpointer data)
{
	const StrictnessTest *test = data;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	GTlsCertificateFlags flags = 0;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (NULL);
	if (!test->with_ca_list) {
		GTlsDatabase *tlsdb;

		tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
		g_object_set (G_OBJECT (session),
			      "tls-database", tlsdb,
			      NULL);
		g_object_unref (tlsdb);
	}

	msg = soup_message_new_from_uri ("GET", uri);
	if (!test->strict) {
		g_signal_connect (msg, "accept-certificate",
				  G_CALLBACK (accept_certificate), NULL);
	}
	body = soup_test_session_send (session, msg, NULL, &error);
	soup_test_assert_message_status (msg, test->expected_status);
	if (test->expected_status != SOUP_STATUS_OK)
		g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);

	g_test_bug ("690176");
	g_assert_nonnull (soup_message_get_tls_certificate (msg));
	flags = soup_message_get_tls_certificate_errors (msg);

	g_test_bug ("665182");
	if (test->with_ca_list && !error)
		g_assert_cmpuint (flags, ==, 0);
	else
		g_assert_cmpuint (flags, !=, 0);

	if (soup_message_get_status (msg) == SOUP_STATUS_NONE &&
	    test->expected_status != SOUP_STATUS_NONE)
		debug_printf (1, "              tls error flags: 0x%x\n", flags);

	g_clear_pointer (&body, g_bytes_unref);
	g_clear_error (&error);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

/* GTlsInteraction subclass for do_interaction_test */
typedef GTlsInteraction TestTlsInteraction;
typedef GTlsInteractionClass TestTlsInteractionClass;

GType test_tls_interaction_get_type (void);

G_DEFINE_TYPE (TestTlsInteraction, test_tls_interaction, G_TYPE_TLS_INTERACTION);

static void
test_tls_interaction_init (TestTlsInteraction *interaction)
{

}

static GTlsInteractionResult
test_tls_interaction_request_certificate (GTlsInteraction              *interaction,
					  GTlsConnection               *connection,
					  GTlsCertificateRequestFlags   flags,
					  GCancellable                 *cancellable,
					  GError                      **error)
{
	GTlsCertificate *cert;

	cert = g_object_get_data (G_OBJECT (interaction), "certificate");
	g_tls_connection_set_certificate (connection, cert);

	return G_TLS_INTERACTION_HANDLED;
}

static void
test_tls_interaction_class_init (TestTlsInteractionClass *klass)
{
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	interaction_class->request_certificate = test_tls_interaction_request_certificate;
}


static gboolean
accept_client_certificate (GTlsConnection       *server,
			   GTlsCertificate      *client_cert,
			   GTlsCertificateFlags  errors)
{
	return errors == 0;
}

static void
server_request_started (SoupServer        *server,
			SoupServerMessage *msg,
			GTlsDatabase      *tls_db)
{
	SoupSocket *sock;
	GIOStream *conn;

	sock = soup_server_message_get_soup_socket (msg);
	conn = soup_socket_get_connection (sock);
	g_tls_connection_set_database (G_TLS_CONNECTION (conn), tls_db);
	g_object_set (conn, "authentication-mode", G_TLS_AUTHENTICATION_REQUIRED, NULL);
	g_signal_connect (conn, "accept-certificate",
			  G_CALLBACK (accept_client_certificate),
			  NULL);
}

static void
do_tls_interaction_test (gconstpointer data)
{
	SoupServer *server = (SoupServer *)data;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	GTlsDatabase *tls_db;
	GTlsCertificate *certificate;
	GTlsInteraction *interaction;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (NULL);
	g_object_get (session, "tls-database", &tls_db, NULL);

	g_signal_connect (server, "request-started",
			  G_CALLBACK (server_request_started),
			  tls_db);

	/* Without a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, &error);
	g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
	g_clear_error (&error);
	g_bytes_unref (body);
	g_object_unref (msg);

	interaction = g_object_new (test_tls_interaction_get_type (), NULL);
	/* Yes, we use the same certificate for the client as for the server. Shrug */
	g_object_get (server, "tls-certificate", &certificate, NULL);
	g_object_set_data_full (G_OBJECT (interaction),
				"certificate",
				g_object_ref (certificate),
				g_object_unref);
	g_object_set (session, "tls-interaction", interaction, NULL);
	g_object_unref (interaction);

	/* With a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, &error);
	g_assert_no_error (error);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_nonnull (soup_message_get_tls_certificate (msg));
	g_bytes_unref (body);
	g_object_unref (msg);

	g_signal_handlers_disconnect_by_data (server, tls_db);

	soup_test_session_abort_unref (session);
	g_object_unref (tls_db);
	g_object_unref (certificate);
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
	SoupServer *server = NULL;
	int i, ret;

	test_init (argc, argv, NULL);

	if (tls_available) {
		server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
		uri = soup_test_server_get_uri (server, "https", "127.0.0.1");
	} else
		uri = NULL;

	g_test_add_data_func ("/ssl/tls-interaction", server, do_tls_interaction_test);

	for (i = 0; i < G_N_ELEMENTS (strictness_tests); i++) {
		g_test_add_data_func (strictness_tests[i].name,
				      &strictness_tests[i],
				      do_strictness_test);
	}

	ret = g_test_run ();

	if (tls_available) {
		g_uri_unref (uri);
		soup_test_server_quit_unref (server);
	}

	test_cleanup ();
	return ret;
}
