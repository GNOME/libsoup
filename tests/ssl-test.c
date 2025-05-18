/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-message-private.h"
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

        if (test->expected_status == SOUP_STATUS_OK) {
                const char *ciphersuite_name = soup_message_get_tls_ciphersuite_name (msg);
                /* Format changed in https://gitlab.gnome.org/GNOME/glib-networking/-/merge_requests/194 */
                g_assert_true (!g_strcmp0 (ciphersuite_name, "TLS_AES-256-GCM_SHA384")
                               || !g_strcmp0 (ciphersuite_name, "TLS_AES_256_GCM_SHA384"));
                g_assert_cmpuint (soup_message_get_tls_protocol_version (msg), ==, G_TLS_PROTOCOL_VERSION_TLS_1_3);
        } else {
                g_assert_cmpuint (soup_message_get_tls_protocol_version (msg), ==, G_TLS_PROTOCOL_VERSION_UNKNOWN);
                g_assert_null (soup_message_get_tls_ciphersuite_name (msg));
        }

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
accept_client_certificate (SoupServerMessage    *msg,
			   GTlsCertificate      *client_cert,
			   GTlsCertificateFlags  errors)
{
	return errors == 0;
}

static void
server_request_started (SoupServer        *server,
                        SoupServerMessage *msg)
{
        g_signal_connect (msg, "accept-certificate",
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
	GUri *peer_uri;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

        peer_uri = g_uri_parse_relative (uri, "/check-peer", SOUP_HTTP_URI_FLAGS, NULL);
	session = soup_test_session_new (NULL);
	tls_db = soup_session_get_tls_database (session);
        g_object_set (server, "tls-database", tls_db, "tls-auth-mode", G_TLS_AUTHENTICATION_REQUIRED, NULL);

	g_signal_connect (server, "request-started",
                          G_CALLBACK (server_request_started),
                          session);

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
	msg = soup_message_new_from_uri ("GET", peer_uri);
	body = soup_test_session_async_send (session, msg, NULL, &error);
	g_assert_no_error (error);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_nonnull (soup_message_get_tls_peer_certificate (msg));
	g_bytes_unref (body);
	g_object_unref (msg);

        g_object_set (server, "tls-database", NULL, "tls-auth-mode", G_TLS_AUTHENTICATION_NONE, NULL);
	g_signal_handlers_disconnect_by_data (server, session);

	soup_test_session_abort_unref (session);
	g_object_unref (certificate);
	g_uri_unref (peer_uri);
}

static gboolean
request_certificate_cb (SoupMessage          *msg,
                        GTlsClientConnection *conn,
                        GTlsCertificate      *certificate)
{
        soup_message_set_tls_client_certificate (msg, certificate);

        return TRUE;
}

static gboolean
request_certificate_password_cb (SoupMessage  *msg,
                                 GTlsPassword *tls_password,
                                 const guchar *password)
{
        g_tls_password_set_value (tls_password, password, -1);
        soup_message_tls_client_certificate_password_request_complete (msg);

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
        GTlsCertificate *certificate, *wrong_certificate;
        GError *error = NULL;

        SOUP_TEST_SKIP_IF_NO_TLS;

        session = soup_test_session_new (NULL);
        tls_db = soup_session_get_tls_database (session);
        g_object_set (server, "tls-database", tls_db, "tls-auth-mode", G_TLS_AUTHENTICATION_REQUIRED, NULL);

        g_signal_connect (server, "request-started",
                          G_CALLBACK (server_request_started),
                          session);

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
                          G_CALLBACK (request_certificate_cb),
                          wrong_certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
        g_assert_null (body);
        g_clear_error (&error);
        g_object_unref (msg);

        /* Passing NULL certificate fails */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_cb),
                          NULL);
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
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_async_cb),
                          wrong_certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
        g_assert_null (body);
        g_clear_error (&error);
        g_object_unref (msg);

        /* Passing NULL certificate fails */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_async_cb),
                          NULL);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED))
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
        g_assert_null (body);
        g_clear_error (&error);
        g_object_unref (msg);

        /* Currently on the gnutls backend supports pkcs#11 */
        if (ENABLE_PKCS11_TESTS && g_strcmp0 (g_type_name (G_TYPE_FROM_INSTANCE (g_tls_backend_get_default ())), "GTlsBackendGnutls") == 0) {
                g_test_message ("Running PKCS#11 tests");

                /* Using PKCS#11 works, and asks for a PIN */
                GTlsCertificate *pkcs11_certificate = g_tls_certificate_new_from_pkcs11_uris (
                        "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%43%65%72%74%69%66%69%63%61%74%65;object=Mock%20Certificate;type=cert",
                        "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%50%72%69%76%61%74%65%20%4B%65%79;object=Mock%20Private%20Key;type=private",
                        &error
                );
                g_assert_no_error (error);
                g_clear_error (&error);
                g_assert_nonnull (pkcs11_certificate);
                g_assert_true (G_IS_TLS_CERTIFICATE (pkcs11_certificate));
                msg = soup_message_new_from_uri ("GET", uri);
                soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
                g_signal_connect (msg, "request-certificate",
                                G_CALLBACK (request_certificate_cb),
                                pkcs11_certificate);
                g_signal_connect (msg, "request-certificate-password",
                                G_CALLBACK (request_certificate_password_cb),
                                "ABC123");
                body = soup_test_session_async_send (session, msg, NULL, &error);
                g_assert_no_error (error);
                g_clear_error (&error);
                g_bytes_unref (body);
                g_object_unref (msg);

#if GLIB_CHECK_VERSION (2, 69, 1)
                /* glib-networking issue fixed by https://gitlab.gnome.org/GNOME/glib-networking/-/commit/362fb43a5a4816f0706569ac57e645f20eac34ca */
                /* It should safely fail when the PIN is unhandled */
                msg = soup_message_new_from_uri ("GET", uri);
                soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
                g_signal_connect (msg, "request-certificate",
                                G_CALLBACK (request_certificate_cb),
                                pkcs11_certificate);
                body = soup_test_session_async_send (session, msg, NULL, &error);
                g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
                g_clear_error (&error);
                g_bytes_unref (body);
                g_object_unref (msg);
#endif

                /* Handling the request-certificate-password signal asynchronously */
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

                g_clear_object (&pkcs11_certificate);
        }

        g_object_set (server, "tls-database", NULL, "tls-auth-mode", G_TLS_AUTHENTICATION_NONE, NULL);
        g_signal_handlers_disconnect_by_data (server, session);

        soup_test_session_abort_unref (session);
        g_object_unref (certificate);
        g_object_unref (wrong_certificate);
}

static gboolean
preconnect_request_certificate (SoupMessage          *msg,
                                GTlsClientConnection *conn,
                                gboolean             *called)
{
        *called = TRUE;

        return FALSE;
}

static gboolean
preconnect_request_certificate_password (SoupMessage  *msg,
                                         GTlsPassword *password,
                                         gboolean     *called)
{
        *called = TRUE;

        return FALSE;
}

static void
preconnect_finished_cb (SoupSession  *session,
                        GAsyncResult *result,
                        gboolean     *preconnect_finished)
{
        g_assert_true (soup_session_preconnect_finish (session, result, NULL));
        *preconnect_finished = TRUE;
}

static void
do_tls_interaction_preconnect_test (gconstpointer data)
{
        SoupServer *server = (SoupServer *)data;
        SoupSession *session;
        SoupMessage *preconnect_msg;
        SoupMessage *msg;
        GBytes *body;
        GTlsDatabase *tls_db;
        GTlsCertificate *certificate;
        GError *error = NULL;
        gboolean preconnect_request_cert_called = FALSE;
        gboolean preconnect_request_cert_pass_called = FALSE;
        gboolean preconnect_finished = FALSE;

        SOUP_TEST_SKIP_IF_NO_TLS;

        session = soup_test_session_new (NULL);
        tls_db = soup_session_get_tls_database (session);
        g_object_set (server, "tls-database", tls_db, "tls-auth-mode", G_TLS_AUTHENTICATION_REQUIRED, NULL);
        g_object_get (server, "tls-certificate", &certificate, NULL);
        g_signal_connect (server, "request-started",
                          G_CALLBACK (server_request_started),
                          session);

        /* Start a preconnect until it get blocked on tls interaction */
        preconnect_msg = soup_message_new_from_uri ("HEAD", uri);
        g_signal_connect (preconnect_msg, "request-certificate",
                          G_CALLBACK (preconnect_request_certificate),
                          &preconnect_request_cert_called);
        soup_session_preconnect_async (session, preconnect_msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
        while (!soup_message_has_pending_tls_cert_request (preconnect_msg))
                g_main_context_iteration (NULL, TRUE);

        /* New message should steal the preconnect connection */
        msg = soup_message_new_from_uri ("GET", uri);
        g_signal_connect (msg, "request-certificate",
                          G_CALLBACK (request_certificate_cb),
                          certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_assert_false (preconnect_request_cert_called);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);
        g_object_unref (preconnect_msg);

        soup_session_abort (session);

        /* Preconnect finishes if we set the certificate before */
        preconnect_msg = soup_message_new_from_uri ("HEAD", uri);
        g_signal_connect (preconnect_msg, "request-certificate",
                          G_CALLBACK (preconnect_request_certificate),
                          &preconnect_request_cert_called);
        soup_message_set_tls_client_certificate (preconnect_msg, certificate);
        soup_session_preconnect_async (session, preconnect_msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished_cb,
                                       &preconnect_finished);
        while (!preconnect_finished)
                g_main_context_iteration (NULL, TRUE);
        g_assert_false (preconnect_request_cert_called);
        g_object_unref (preconnect_msg);
        /* New request will use the idle connection without having to provide a certificate */
        msg = soup_message_new_from_uri ("GET", uri);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);

        soup_session_abort (session);

        /* request-certificate signal is not emitted either if the message stealing the
         * preconnect connection has a certificate set.
         */
        preconnect_msg = soup_message_new_from_uri ("HEAD", uri);
        g_signal_connect (preconnect_msg, "request-certificate",
                          G_CALLBACK (preconnect_request_certificate),
                          &preconnect_request_cert_called);
        soup_session_preconnect_async (session, preconnect_msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
        while (!soup_message_has_pending_tls_cert_request (preconnect_msg))
                g_main_context_iteration (NULL, TRUE);

        /* New message should steal the preconnect connection */
        msg = soup_message_new_from_uri ("GET", uri);
        soup_message_set_tls_client_certificate (msg, certificate);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_assert_false (preconnect_request_cert_called);
        g_clear_error (&error);
        g_bytes_unref (body);
        g_object_unref (msg);
        g_object_unref (preconnect_msg);

        soup_session_abort (session);

        /* Currently on the gnutls backend supports pkcs#11 */
        if (ENABLE_PKCS11_TESTS && g_strcmp0 (g_type_name (G_TYPE_FROM_INSTANCE (g_tls_backend_get_default ())), "GTlsBackendGnutls") == 0) {
                GTlsCertificate *pkcs11_certificate;

                pkcs11_certificate = g_tls_certificate_new_from_pkcs11_uris (
                        "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%43%65%72%74%69%66%69%63%61%74%65;object=Mock%20Certificate;type=cert",
                        "pkcs11:model=mock;serial=1;token=Mock%20Certificate;id=%4D%6F%63%6B%20%50%72%69%76%61%74%65%20%4B%65%79;object=Mock%20Private%20Key;type=private",
                        &error
                );
                g_assert_no_error (error);

                preconnect_msg = soup_message_new_from_uri ("HEAD", uri);
                g_signal_connect (preconnect_msg, "request-certificate-password",
                                  G_CALLBACK (preconnect_request_certificate_password),
                                  &preconnect_request_cert_pass_called);
                soup_message_set_tls_client_certificate (preconnect_msg, pkcs11_certificate);
                soup_session_preconnect_async (session, preconnect_msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
                while (!soup_message_has_pending_tls_cert_pass_request (preconnect_msg))
                        g_main_context_iteration (NULL, TRUE);

                /* New message should steal the preconnect connection */
                msg = soup_message_new_from_uri ("GET", uri);
                g_signal_connect (msg, "request-certificate-password",
                                  G_CALLBACK (request_certificate_password_cb),
                                  "ABC123");
                body = soup_test_session_async_send (session, msg, NULL, &error);
                g_assert_no_error (error);
                soup_test_assert_message_status (msg, SOUP_STATUS_OK);
                g_assert_false (preconnect_request_cert_pass_called);
                g_clear_error (&error);
                g_bytes_unref (body);
                g_object_unref (msg);
                g_object_unref (preconnect_msg);

                g_object_unref (pkcs11_certificate);
        }

        g_object_set (server, "tls-database", NULL, "tls-auth-mode", G_TLS_AUTHENTICATION_NONE, NULL);
        g_signal_handlers_disconnect_by_data (server, session);

        soup_test_session_abort_unref (session);
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

        if (!strcmp (path, "/check-peer")) {
                GTlsCertificate *certificate;
                GTlsCertificateFlags flags;

                certificate = soup_server_message_get_tls_peer_certificate (msg);
                g_assert_nonnull (certificate);

                flags = soup_server_message_get_tls_peer_certificate_errors (msg);
                g_assert_cmpuint (flags, ==, 0);

                /* Check also the properties are properly working */
                g_object_get (G_OBJECT (msg),
                              "tls-peer-certificate", &certificate,
                              "tls-peer-certificate-errors", &flags,
                              NULL);
                g_assert_nonnull (certificate);
                g_assert_cmpuint (flags, ==, 0);
                g_object_unref (certificate);
        }
}

int
main (int argc, char **argv)
{
	SoupServer *server = NULL;
	int i, ret;

	test_init (argc, argv, NULL);

#if HAVE_GNUTLS && ENABLE_PKCS11_TESTS
        char *module_path = soup_test_build_filename_abs (G_TEST_BUILT, "mock-pkcs11.so", NULL);
        g_assert_true (g_file_test (module_path, G_FILE_TEST_EXISTS));

        g_assert_true (gnutls_pkcs11_init (GNUTLS_PKCS11_FLAG_MANUAL, NULL) == GNUTLS_E_SUCCESS);
        g_assert_true (gnutls_pkcs11_add_provider (module_path, NULL) == GNUTLS_E_SUCCESS);
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
        g_test_add_data_func ("/ssl/tls-interaction/preconnect", server, do_tls_interaction_preconnect_test);

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
