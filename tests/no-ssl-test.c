/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static void
do_ssl_test_for_session (SoupSession *session, char *uri)
{
  SoupMessage *msg;
  GTlsCertificate *cert;
  GTlsCertificateFlags flags;

  msg = soup_message_new ("GET", uri);
  soup_session_send_message (session, msg);
  if (msg->status_code != SOUP_STATUS_SSL_FAILED) {
    debug_printf (1, "    Unexpected status: %d %s\n",
		  msg->status_code, msg->reason_phrase);
    errors++;
  }

  if (soup_message_get_https_status (msg, &cert, &flags)) {
    debug_printf (1, "    get_http_status() returned TRUE? (flags %x)\n", flags);
    errors++;
    if (cert) {
      debug_printf (1, "    Got GTlsCertificate?\n");
      errors++;
    }
  }
  if (soup_message_get_flags (msg) & SOUP_MESSAGE_CERTIFICATE_TRUSTED) {
    debug_printf (1, "    CERTIFICATE_TRUSTED set?\n");
    errors++;
  }

  g_object_unref (msg);
}

static void
do_ssl_tests (char *uri)
{
  SoupSession *session;

  debug_printf (1, "\nSoupSession without SSL support\n");

  debug_printf (1, "  plain\n");
  session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
  do_ssl_test_for_session (session, uri);
  soup_test_session_abort_unref (session);

  debug_printf (1, "  async\n");
  session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
  do_ssl_test_for_session (session, uri);
  soup_test_session_abort_unref (session);

  debug_printf (1, "  sync\n");
  session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
  do_ssl_test_for_session (session, uri);
  soup_test_session_abort_unref (session);
}

static void
do_session_property_tests (void)
{
  gboolean use_system;
  GTlsDatabase *tlsdb;
  char *ca_file;
  SoupSession *session;

  debug_printf (1, "session properties\n");

  session = soup_session_async_new ();

  g_object_get (G_OBJECT (session),
		"ssl-use-system-ca-file", &use_system,
		"tls-database", &tlsdb,
		"ssl-ca-file", &ca_file,
		NULL);
  if (use_system) {
    debug_printf (1, "  ssl-use-system-ca-file defaults to TRUE?\n");
    errors++;
  }
  if (tlsdb) {
    debug_printf (1, "  tls-database set by default?\n");
    errors++;
    g_object_unref (tlsdb);
  }
  if (ca_file) {
    debug_printf (1, "  ca-file set by default?\n");
    errors++;
    g_free (ca_file);
  }

  g_object_set (G_OBJECT (session),
		"ssl-use-system-ca-file", TRUE,
		NULL);
  g_object_get (G_OBJECT (session),
		"ssl-use-system-ca-file", &use_system,
		"ssl-ca-file", &ca_file,
		NULL);
  if (use_system) {
    debug_printf (1, "  setting ssl-use-system-ca-file did not fail\n");
    errors++;
  }
  if (ca_file) {
    debug_printf (1, "  setting ssl-use-system-ca-file set ssl-ca-file\n");
    errors++;
    g_free (ca_file);
  }

  g_object_set (G_OBJECT (session),
		"ssl-ca-file", SRCDIR "/test-cert.pem",
		NULL);
  g_object_get (G_OBJECT (session),
		"ssl-use-system-ca-file", &use_system,
		"tls-database", &tlsdb,
		"ssl-ca-file", &ca_file,
		NULL);
  if (ca_file) {
    debug_printf (1, "  setting ssl-ca-file did not fail\n");
    errors++;
    g_free (ca_file);
  }
  if (use_system) {
    debug_printf (1, "  setting ssl-ca-file set ssl-use-system-ca-file\n");
    errors++;
  }
  if (tlsdb) {
    debug_printf (1, "  setting ssl-ca-file set tls-database\n");
    errors++;
    g_object_unref (tlsdb);
  }

  g_object_set (G_OBJECT (session),
		"tls-database", NULL,
		NULL);
  g_object_get (G_OBJECT (session),
		"ssl-use-system-ca-file", &use_system,
		"tls-database", &tlsdb,
		"ssl-ca-file", &ca_file,
		NULL);
  if (tlsdb) {
    debug_printf (1, "  setting tls-database NULL failed\n");
    errors++;
    g_object_unref (tlsdb);
  }
  if (use_system) {
    debug_printf (1, "  setting tls-database NULL set ssl-use-system-ca-file\n");
    errors++;
  }
  if (ca_file) {
    debug_printf (1, "  setting tls-database NULL set ssl-ca-file\n");
    errors++;
    g_free (ca_file);
  }

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

  /* Force this test to use the dummy TLS backend */
  g_setenv ("GIO_USE_TLS", "dummy", TRUE);

  test_init (argc, argv, NULL);

  /* Make a non-SSL server and pretend that it's ssl, which is fine
   * since we won't ever actually talk to it anyway. We don't
   * currently test that failing to construct an SSL server works.
   */
  server = soup_test_server_new (TRUE);
  soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
  uri = g_strdup_printf ("https://127.0.0.1:%u/",
			 soup_server_get_port (server));

  do_session_property_tests ();
  do_ssl_tests (uri);

  g_free (uri);
  soup_test_server_quit_unref (server);

  test_cleanup ();
  return errors != 0;
}
