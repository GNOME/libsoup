/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

SoupURI *uri;

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
	  TRUE, FALSE, SOUP_STATUS_SSL_FAILED },
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
	GTlsCertificateFlags flags = 0;

	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new (NULL);
	if (!test->with_ca_list) {
		g_object_set (G_OBJECT (session),
			      "ssl-use-system-ca-file", TRUE,
			      NULL);
	}

	msg = soup_message_new_from_uri ("GET", uri);
	if (!test->strict) {
		g_signal_connect (msg, "accept-certificate",
				  G_CALLBACK (accept_certificate), NULL);
	}
	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, test->expected_status);

	g_test_bug ("690176");
	g_assert_nonnull (soup_message_get_tls_certificate (msg));
	flags = soup_message_get_tls_certificate_errors (msg);

	g_test_bug ("665182");
	if (test->with_ca_list && SOUP_STATUS_IS_SUCCESSFUL (soup_message_get_status (msg)))
		g_assert_cmpuint (flags, ==, 0);
	else
		g_assert_cmpuint (flags, !=, 0);

	if (soup_message_get_status (msg) == SOUP_STATUS_SSL_FAILED &&
	    test->expected_status != SOUP_STATUS_SSL_FAILED)
		debug_printf (1, "              tls error flags: 0x%x\n", flags);

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
	const char *ssl_cert_file, *ssl_key_file;
	GError *my_error = NULL;

	/* Yes, we use the same certificate for the client as for the server. Shrug */
	ssl_cert_file = g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL);
	ssl_key_file = g_test_get_filename (G_TEST_DIST, "test-key.pem", NULL);
	cert = g_tls_certificate_new_from_files (ssl_cert_file,
						 ssl_key_file,
						 &my_error);
	g_assert_no_error (my_error);

	g_tls_connection_set_certificate (connection, cert);
	g_object_unref (cert);

	return G_TLS_INTERACTION_HANDLED;
}

static void
test_tls_interaction_class_init (TestTlsInteractionClass *klass)
{
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);

	interaction_class->request_certificate = test_tls_interaction_request_certificate;
}


#define INTERACTION_TEST_HTTP_RESPONSE "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nOK\r\n"

static gboolean
accept_client_certificate (GTlsConnection       *server,
			   GTlsCertificate      *client_cert,
			   GTlsCertificateFlags  errors)
{
	return TRUE;
}

static void
got_connection (GThreadedSocketService *service,
		GSocketConnection      *connection,
		GObject                *source_object)
{
	GIOStream *tls;
	GTlsCertificate *server_cert;
	GError *error = NULL;
	const char *ssl_cert_file, *ssl_key_file;
	GMainContext *thread_context;

	thread_context = g_main_context_new ();
	g_main_context_push_thread_default (thread_context);

	ssl_cert_file = g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL);
	ssl_key_file = g_test_get_filename (G_TEST_DIST, "test-key.pem", NULL);
	server_cert = g_tls_certificate_new_from_files (ssl_cert_file,
							ssl_key_file,
							&error);
	g_assert_no_error (error);

	tls = g_tls_server_connection_new (G_IO_STREAM (connection),
					   server_cert, &error);
	g_assert_no_error (error);
	g_object_unref (server_cert);

	g_object_set (G_OBJECT (tls),
		      "authentication-mode", G_TLS_AUTHENTICATION_REQUIRED,
		      NULL);
	g_signal_connect (tls, "accept-certificate",
			  G_CALLBACK (accept_client_certificate), NULL);

	if (g_tls_connection_handshake (G_TLS_CONNECTION (tls), NULL, &error)) {
		g_output_stream_write_all (g_io_stream_get_output_stream (tls),
					   INTERACTION_TEST_HTTP_RESPONSE,
					   strlen (INTERACTION_TEST_HTTP_RESPONSE),
					   NULL, NULL, &error);
		g_assert_no_error (error);
	} else {
		g_assert_error (error, G_TLS_ERROR, G_TLS_ERROR_CERTIFICATE_REQUIRED);
		g_clear_error (&error);
	}

	g_io_stream_close (tls, NULL, &error);
	g_assert_no_error (error);

	g_object_unref (tls);

	g_main_context_pop_thread_default (thread_context);
	g_main_context_unref (thread_context);
}

static void
do_tls_interaction_test (void)
{
	GSocketService *service;
	GSocketAddress *address, *bound_address;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	GTlsInteraction *interaction;
	SoupURI *test_uri;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	service = g_threaded_socket_service_new (1);
	address = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_socket_listener_add_address (G_SOCKET_LISTENER (service), address,
				       G_SOCKET_TYPE_STREAM,
				       G_SOCKET_PROTOCOL_TCP,
				       NULL, &bound_address, &error);
	g_assert_no_error (error);
	g_object_unref (address);
	g_signal_connect (service, "run", G_CALLBACK (got_connection), NULL);
	g_socket_service_start (service);

	test_uri = soup_uri_new ("https://127.0.0.1");
	soup_uri_set_port (test_uri, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (bound_address)));
	g_object_unref (bound_address);

	session = soup_test_session_new (NULL);

	/* Without a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", test_uri);
	body = soup_test_session_async_send (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_SSL_FAILED);
	g_bytes_unref (body);
	g_object_unref (msg);

	interaction = g_object_new (test_tls_interaction_get_type (), NULL);
	g_object_set (G_OBJECT (session),
		      "tls-interaction", interaction,
		      NULL);
	g_object_unref (interaction);

	/* With a GTlsInteraction */
	msg = soup_message_new_from_uri ("GET", test_uri);
	body = soup_test_session_async_send (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_nonnull (soup_message_get_tls_certificate (msg));
	g_bytes_unref (body);
	g_object_unref (msg);

	soup_uri_free (test_uri);
	soup_test_session_abort_unref (session);

	g_socket_service_stop (service);
	g_object_unref (service);
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

	g_test_add_func ("/ssl/tls-interaction", do_tls_interaction_test);

	for (i = 0; i < G_N_ELEMENTS (strictness_tests); i++) {
		g_test_add_data_func (strictness_tests[i].name,
				      &strictness_tests[i],
				      do_strictness_test);
	}

	ret = g_test_run ();

	if (tls_available) {
		soup_uri_free (uri);
		soup_test_server_quit_unref (server);
	}

	test_cleanup ();
	return ret;
}
