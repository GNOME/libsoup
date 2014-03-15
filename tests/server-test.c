/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

SoupServer *server, *ssl_server;
SoupURI *base_uri, *ssl_base_uri;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	soup_message_headers_append (msg->response_headers,
				     "X-Handled-By", "server_callback");

	if (!strcmp (path, "*")) {
		soup_test_assert (FALSE, "default server_callback got request for '*'");
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC, "index", 5);
}

static void
server_star_callback (SoupServer *server, SoupMessage *msg,
		      const char *path, GHashTable *query,
		      SoupClientContext *context, gpointer data)
{
	soup_message_headers_append (msg->response_headers,
				     "X-Handled-By", "star_callback");

	if (strcmp (path, "*") != 0) {
		soup_test_assert (FALSE, "server_star_callback got request for '%s'", path);
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (msg->method != SOUP_METHOD_OPTIONS) {
		soup_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
}

/* Server handlers for "*" work but are separate from handlers for
 * all other URIs. #590751
 */
static void
do_star_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *star_uri;
	const char *handled_by;

	g_test_bug ("590751");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	star_uri = soup_uri_copy (base_uri);
	soup_uri_set_path (star_uri, "*");

	debug_printf (1, "  Testing with no handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_NOT_FOUND);
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	g_assert_cmpstr (handled_by, ==, NULL);
	g_object_unref (msg);

	soup_server_add_handler (server, "*", server_star_callback, NULL, NULL);

	debug_printf (1, "  Testing with handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	g_assert_cmpstr (handled_by, ==, "star_callback");
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	soup_uri_free (star_uri);
}

static void
do_one_server_aliases_test (SoupURI    *uri,
			    const char *alias,
			    gboolean    succeed)
{
	GSocketClient *client;
	GSocketConnectable *addr;
	GSocketConnection *conn;
	GInputStream *in;
	GOutputStream *out;
	GError *error = NULL;
	GString *req;
	static char buf[1024];

	debug_printf (1, "  %s via %s\n", alias, uri->scheme);

	/* There's no way to make libsoup's client side send an absolute
	 * URI (to a non-proxy server), so we have to fake this.
	 */

	client = g_socket_client_new ();
	if (uri->scheme == SOUP_URI_SCHEME_HTTPS) {
		g_socket_client_set_tls (client, TRUE);
		g_socket_client_set_tls_validation_flags (client, 0);
	}
	addr = g_network_address_new (uri->host, uri->port);

	conn = g_socket_client_connect (client, addr, NULL, &error);
	g_object_unref (addr);
	g_object_unref (client);
	if (!conn) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	in = g_io_stream_get_input_stream (G_IO_STREAM (conn));
	out = g_io_stream_get_output_stream (G_IO_STREAM (conn));

	req = g_string_new (NULL);
	g_string_append_printf (req, "GET %s://%s:%d HTTP/1.1\r\n",
				alias, uri->host, uri->port);
	g_string_append_printf (req, "Host: %s:%d\r\n",
				uri->host, uri->port);
	g_string_append (req, "Connection: close\r\n\r\n");

	if (!g_output_stream_write_all (out, req->str, req->len, NULL, NULL, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		g_object_unref (conn);
		g_string_free (req, TRUE);
		return;
	}
	g_string_free (req, TRUE);

	if (!g_input_stream_read_all (in, buf, sizeof (buf), NULL, NULL, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		g_object_unref (conn);
		return;
	}

	if (succeed)
		g_assert_true (g_str_has_prefix (buf, "HTTP/1.1 200 "));
	else
		g_assert_true (g_str_has_prefix (buf, "HTTP/1.1 400 "));

	g_io_stream_close (G_IO_STREAM (conn), NULL, NULL);
	g_object_unref (conn);
}

static void
do_server_aliases_test (void)
{
	char *http_good[] = { "http", "dav", NULL };
	char *http_bad[] = { "https", "davs", "fred", NULL };
	char *https_good[] = { "https", "davs", NULL };
	char *https_bad[] = { "http", "dav", "fred", NULL };
	int i;

	g_test_bug ("703694");

	for (i = 0; http_good[i]; i++)
		do_one_server_aliases_test (base_uri, http_good[i], TRUE);
	for (i = 0; http_bad[i]; i++)
		do_one_server_aliases_test (base_uri, http_bad[i], FALSE);

	if (tls_available) {
		for (i = 0; https_good[i]; i++)
			do_one_server_aliases_test (ssl_base_uri, https_good[i], TRUE);
		for (i = 0; https_bad[i]; i++)
			do_one_server_aliases_test (ssl_base_uri, https_bad[i], FALSE);
	}
}

static void
do_dot_dot_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;

	g_test_bug ("667635");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	uri = soup_uri_new_with_base (base_uri, "/..%2ftest");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
ipv6_server_callback (SoupServer *server, SoupMessage *msg,
		      const char *path, GHashTable *query,
		      SoupClientContext *context, gpointer data)
{
	const char *host;
	char expected_host[128];

	g_snprintf (expected_host, sizeof (expected_host),
		    "[::1]:%d", soup_server_get_port (server));

	host = soup_message_headers_get_one (msg->request_headers, "Host");
	g_assert_cmpstr (host, ==, expected_host);

	if (g_test_failed ())
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
	else
		soup_message_set_status (msg, SOUP_STATUS_OK);
}

static void
do_ipv6_test (void)
{
	SoupServer *ipv6_server;
	SoupURI *ipv6_uri;
	SoupAddress *ipv6_addr;
	SoupSession *session;
	SoupMessage *msg;

	g_test_bug ("666399");

	ipv6_addr = soup_address_new ("::1", SOUP_ADDRESS_ANY_PORT);
	soup_address_resolve_sync (ipv6_addr, NULL);
	ipv6_server = soup_server_new (SOUP_SERVER_INTERFACE, ipv6_addr,
				       NULL);
	g_object_unref (ipv6_addr);
	if (!ipv6_server) {
		debug_printf (1, "  skipping due to lack of IPv6 support\n");
		return;
	}

	soup_server_add_handler (ipv6_server, NULL, ipv6_server_callback, NULL, NULL);
	soup_server_run_async (ipv6_server);

	ipv6_uri = soup_uri_new ("http://[::1]/");
	soup_uri_set_port (ipv6_uri, soup_server_get_port (ipv6_server));

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	debug_printf (1, "  HTTP/1.1\n");
	msg = soup_message_new_from_uri ("GET", ipv6_uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	debug_printf (1, "  HTTP/1.0\n");
	msg = soup_message_new_from_uri ("GET", ipv6_uri);
	soup_message_set_http_version (msg, SOUP_HTTP_1_0);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	soup_uri_free (ipv6_uri);
	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (ipv6_server);
}

int
main (int argc, char **argv)
{
	char *http_aliases[] = { "dav", NULL };
	char *https_aliases[] = { "davs", NULL };
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	g_object_set (G_OBJECT (server),
		      SOUP_SERVER_HTTP_ALIASES, http_aliases,
		      NULL);

	if (tls_available) {
		ssl_server = soup_test_server_new_ssl (TRUE);
		soup_server_add_handler (ssl_server, NULL, server_callback, NULL, NULL);
		ssl_base_uri = soup_uri_new ("https://127.0.0.1/");
		soup_uri_set_port (ssl_base_uri, soup_server_get_port (ssl_server));
		g_object_set (G_OBJECT (ssl_server),
			      SOUP_SERVER_HTTPS_ALIASES, https_aliases,
			      NULL);
	}

	g_test_add_func ("/server/OPTIONS *", do_star_test);
	g_test_add_func ("/server/aliases", do_server_aliases_test);
	g_test_add_func ("/server/..-in-path", do_dot_dot_test);
	g_test_add_func ("/server/ipv6", do_ipv6_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		soup_uri_free (ssl_base_uri);
		soup_test_server_quit_unref (ssl_server);
	}

	test_cleanup ();
	return ret;
}
