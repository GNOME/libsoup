/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-server-message-private.h"

#if HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#endif

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
		soup_session_set_tls_database (session, tlsdb);
		g_object_unref (tlsdb);
	}

	msg = soup_message_new_from_uri ("GET", uri);
	if (!test->strict) {
		g_signal_connect (msg, "accept-certificate",
				  G_CALLBACK (accept_certificate), NULL);
	}
	body = soup_session_send_and_read (session, msg, NULL, &error);
	soup_test_assert_message_status (msg, test->expected_status);
	if (test->expected_status != SOUP_STATUS_OK)
		g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE);

	g_test_bug ("690176");
	g_assert_nonnull (soup_message_get_tls_peer_certificate (msg));
	flags = soup_message_get_tls_peer_certificate_errors (msg);

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
	tls_db = soup_session_get_tls_database (session);

	g_signal_connect (server, "request-started",
			  G_CALLBACK (server_request_started),
			  tls_db);

	/* Without a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, &error);
	/* Sometimes glib-networking fails to report the error as certificate required
	 * and we end up with connection reset by peer because the server closes the connection
	 */
	if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
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
	soup_session_set_tls_interaction (session, interaction);
	g_object_unref (interaction);

	/* With a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, &error);
	g_assert_no_error (error);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_nonnull (soup_message_get_tls_peer_certificate (msg));
	g_bytes_unref (body);
	g_object_unref (msg);

	g_signal_handlers_disconnect_by_data (server, tls_db);

	soup_test_session_abort_unref (session);
	g_object_unref (certificate);
}

static gboolean
request_certificate_cb (SoupMessage          *msg,
                        GTlsClientConnection *conn,
                        GTlsCertificate      *certificate)
{
        soup_message_set_tls_client_certificate (msg, certificate);

        return TRUE;
}

typedef struct {
        SoupMessage *msg;
        GTlsCertificate *certificate;
        GTlsPassword *tls_password;
        const guchar *password;
} SetCertificateAsyncData;

static void
set_certificate_async_data_free (SetCertificateAsyncData *data)
{
        g_clear_object (&data->tls_password);
        g_free (data);
}

static gboolean
set_certificate_idle_cb (SetCertificateAsyncData *data)
{
        soup_message_set_tls_client_certificate (data->msg, data->certificate);

        return FALSE;
}

static gboolean
request_certificate_async_cb (SoupMessage          *msg,
                              GTlsClientConnection *conn,
                              GTlsCertificate      *certificate)
{
        SetCertificateAsyncData *data;

        data = g_new0 (SetCertificateAsyncData, 1);
        data->msg = msg;
        data->certificate = certificate;
        g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
                         (GSourceFunc)set_certificate_idle_cb,
                         data,
                         (GDestroyNotify)set_certificate_async_data_free);

        return TRUE;
}

static gboolean
set_certificate_password_idle_cb (SetCertificateAsyncData *data)
{
        g_tls_password_set_value (data->tls_password, data->password, -1);
        soup_message_tls_client_certificate_password_request_complete (data->msg);

        return FALSE;
}

static gboolean
request_certificate_password_async_cb (SoupMessage  *msg,
                                       GTlsPassword *password,
                                       const guchar *pin)
{
        SetCertificateAsyncData *data;

        data = g_new (SetCertificateAsyncData, 1);
        data->msg = msg;
        data->tls_password = g_object_ref (password);
        data->password = pin;
        g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
                         (GSourceFunc)set_certificate_password_idle_cb,
                         data,
                         (GDestroyNotify)set_certificate_async_data_free);

        return TRUE;
}

static void
do_tls_interaction_msg_test (gconstpointer data)
{
        SoupServer *server = (SoupServer *)data;
        SoupSession *session;
        SoupMessage *msg;
        GBytes *body;
        GTlsDatabase *tls_db;
        GTlsCertificate *certificate, *wrong_certificate, *pkcs11_certificate;
        GError *error = NULL;

        SOUP_TEST_SKIP_IF_NO_TLS;

        session = soup_test_session_new (NULL);
        tls_db = soup_session_get_tls_database (session);

        g_signal_connect (server, "request-started",
                          G_CALLBACK (server_request_started),
                          tls_db);

        /* Not handling request-certificate signal */
        msg = soup_message_new_from_uri ("GET", uri);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* Handling the request-certificate signal synchronously */
        g_object_get (server, "tls-certificate", &certificate, NULL);
        g_assert_nonnull (certificate);
        msg = soup_message_new_from_uri ("GET", uri);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_cb),
                          certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* Next load doesn't emit request-certificate because the connection is reused */
        msg = soup_message_new_from_uri ("GET", uri);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* It fails for a new connection */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* request-certificate is not emitted if the certificate is set before the load */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        soup_message_set_tls_client_certificate (msg, certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* Handling the request-certificate signal asynchronously */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_async_cb),
                          certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        /* Using the wrong certificate fails */
        wrong_certificate = g_tls_certificate_new_from_files (
                g_test_get_filename (G_TEST_DIST, "test-cert-2.pem", NULL),
                g_test_get_filename (G_TEST_DIST, "test-key-2.pem", NULL),
                NULL
        );
        g_assert_nonnull (wrong_certificate);
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_async_cb),
                          wrong_certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
        g_assert_null (body);
        g_clear_error (&error);
        g_object_unref (msg);

        /* Using PKCS#11 works, and asks for a PIN */
        pkcs11_certificate = g_tls_certificate_new_from_pkcs11_uris (
                "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%43%65%72%74%69%66%69%63%61%74%65;object=Mock%20Certificate;type=cert",
                "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%50%72%69%76%61%74%65%20%4B%65%79;object=Mock%20Private%20Key;type=private",
                &error
        );
        g_assert_no_error (error);
        g_assert_nonnull (pkcs11_certificate);
        g_assert_true (G_IS_TLS_CERTIFICATE (pkcs11_certificate));
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_async_cb),
                          pkcs11_certificate);
        g_signal_connect (msg, "request-certificate-password",
                          G_CALLBACK (request_certificate_password_async_cb),
                          "ABC123");
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        g_signal_handlers_disconnect_by_data (server, tls_db);

        soup_test_session_abort_unref (session);
        g_object_unref (certificate);
        g_object_unref (wrong_certificate);
        g_object_unref (pkcs11_certificate);
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

#if HAVE_GNUTLS
        char *module_path = soup_test_build_filename_abs (G_TEST_BUILT, "mock-pkcs11.so", NULL);
        g_assert_true (g_file_test (module_path, G_FILE_TEST_EXISTS));

        g_assert (gnutls_pkcs11_init (GNUTLS_PKCS11_FLAG_MANUAL, NULL) == GNUTLS_E_SUCCESS);
        g_assert (gnutls_pkcs11_add_provider (module_path, NULL) == GNUTLS_E_SUCCESS);
        g_free (module_path);
#endif

	if (tls_available) {
		server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
		uri = soup_test_server_get_uri (server, "https", "127.0.0.1");
	} else
		uri = NULL;

	g_test_add_data_func ("/ssl/tls-interaction", server, do_tls_interaction_test);
        g_test_add_data_func ("/ssl/tls-interaction-msg", server, do_tls_interaction_msg_test);

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
