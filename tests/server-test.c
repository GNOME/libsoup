/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

#include <gio/gnetworking.h>

SoupServer *server;
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
	GSocketAddress *addr;
	char expected_host[128];

	addr = soup_client_context_get_local_address (context);
	g_snprintf (expected_host, sizeof (expected_host),
		    "[::1]:%d",
		    g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)));

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
	SoupSession *session;
	SoupMessage *msg;
	GError *error = NULL;

	g_test_bug ("666399");

	ipv6_server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (ipv6_server, NULL, ipv6_server_callback, NULL, NULL);

	if (!soup_server_listen_local (ipv6_server, 0,
				       SOUP_SERVER_LISTEN_IPV6_ONLY,
				       &error)) {
#if GLIB_CHECK_VERSION (2, 41, 0)
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED);
#endif
		g_test_skip ("no IPv6 support");
		return;
	}

	ipv6_uri = soup_test_server_get_uri (ipv6_server, "http", "::1");

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

static void
multi_server_callback (SoupServer *server, SoupMessage *msg,
		       const char *path, GHashTable *query,
		       SoupClientContext *context, gpointer data)
{
	GSocketAddress *addr;
	GInetSocketAddress *iaddr;
	SoupURI *uri;
	char *uristr, *addrstr;

	addr = soup_client_context_get_local_address (context);
	iaddr = G_INET_SOCKET_ADDRESS (addr);

	uri = soup_message_get_uri (msg);
	uristr = soup_uri_to_string (uri, FALSE);

	addrstr = g_inet_address_to_string (g_inet_socket_address_get_address (iaddr));
	g_assert_cmpstr (addrstr, ==, uri->host);
	g_free (addrstr);

	g_assert_cmpint (g_inet_socket_address_get_port (iaddr), ==, uri->port);

	// FIXME ssl

	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_TAKE, uristr, strlen (uristr));
	soup_message_set_status (msg, SOUP_STATUS_OK);
}

static void
do_multi_test (SoupServer *server, SoupURI *uri1, SoupURI *uri2)
{
	char *uristr;
	SoupSession *session;
	SoupMessage *msg;

	soup_server_add_handler (server, NULL, multi_server_callback, NULL, NULL);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	uristr = soup_uri_to_string (uri1, FALSE);
	msg = soup_message_new ("GET", uristr);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpstr (msg->response_body->data, ==, uristr);
	g_object_unref (msg);
	g_free (uristr);

	uristr = soup_uri_to_string (uri2, FALSE);
	msg = soup_message_new ("GET", uristr);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpstr (msg->response_body->data, ==, uristr);
	g_object_unref (msg);
	g_free (uristr);

	soup_test_session_abort_unref (session);

	soup_test_server_quit_unref (server);
	soup_uri_free (uri1);
	soup_uri_free (uri2);
}

static void
do_multi_port_test (void)
{
	SoupServer *server;
	GSList *uris;
	SoupURI *uri1, *uri2;
	GError *error = NULL;

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}
	if (!soup_server_listen_local (server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (server);
	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpint (uri1->port, !=, uri2->port);

	do_multi_test (server, uri1, uri2);
}

static void
do_multi_scheme_test (void)
{
	SoupServer *server;
	GSList *uris;
	SoupURI *uri1, *uri2;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}
	if (!soup_server_listen_local (server, 0,
				       SOUP_SERVER_LISTEN_IPV4_ONLY | SOUP_SERVER_LISTEN_HTTPS,
				       &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (server);
	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpstr (uri1->scheme, !=, uri2->scheme);

	do_multi_test (server, uri1, uri2);
}

static void
do_multi_family_test (void)
{
	SoupServer *server;
	GSList *uris;
	SoupURI *uri1, *uri2;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (server, 0, 0, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (server);
	if (g_slist_length (uris) == 1) {
		gboolean ipv6_works;

		/* No IPv6? Double-check */
		ipv6_works = soup_server_listen_local (server, 0,
						       SOUP_SERVER_LISTEN_IPV6_ONLY,
						       NULL);
		if (ipv6_works)
			g_assert_false (ipv6_works);
		else
			g_test_skip ("no IPv6 support");
		return;
	}

	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpstr (uri1->host, !=, uri2->host);
	g_assert_cmpint (uri1->port, ==, uri2->port);

	do_multi_test (server, uri1, uri2);
}

static void
do_gsocket_import_test (void)
{
	GSocket *gsock;
	GSocketAddress *gaddr;
	SoupServer *server;
	GSList *listeners;
	SoupURI *uri;
	SoupSession *session;
	SoupMessage *msg;
	GError *error = NULL;

	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);

	gaddr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_socket_bind (gsock, gaddr, TRUE, &error);
	g_object_unref (gaddr);
	g_assert_no_error (error);
	g_socket_listen (gsock, &error);
	g_assert_no_error (error);

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);
	g_object_unref (gaddr);

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 0);
	g_slist_free (listeners);

	soup_server_listen_socket (server, gsock, 0, &error);
	g_assert_no_error (error);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	uri = soup_test_server_get_uri (server, "http", "127.0.0.1");
	g_assert_nonnull (uri);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);

	soup_uri_free (uri);
	soup_test_server_quit_unref (server);

	g_assert_false (g_socket_is_connected (gsock));
	g_object_unref (gsock);
}

static void
do_fd_import_test (void)
{
	GSocket *gsock;
	GSocketAddress *gaddr;
	SoupServer *server;
	GSList *listeners;
	SoupURI *uri;
	SoupSession *session;
	SoupMessage *msg;
	int type;
	GError *error = NULL;

	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);

	gaddr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_socket_bind (gsock, gaddr, TRUE, &error);
	g_object_unref (gaddr);
	g_assert_no_error (error);
	g_socket_listen (gsock, &error);
	g_assert_no_error (error);

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);
	g_object_unref (gaddr);

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 0);
	g_slist_free (listeners);

	soup_server_listen_fd (server, g_socket_get_fd (gsock), 0, &error);
	g_assert_no_error (error);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	uri = soup_test_server_get_uri (server, "http", "127.0.0.1");
	g_assert_nonnull (uri);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);

	soup_uri_free (uri);
	soup_test_server_quit_unref (server);

	/* @server should have closed our socket, although @gsock doesn't
	 * know this.
	 */
	g_socket_get_option (gsock, SOL_SOCKET, SO_TYPE, &type, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_clear_error (&error);
	g_object_unref (gsock);
}

int
main (int argc, char **argv)
{
	char *http_aliases[] = { "dav", NULL };
	char *https_aliases[] = { "davs", NULL };
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_object_set (G_OBJECT (server),
		      SOUP_SERVER_HTTP_ALIASES, http_aliases,
		      NULL);

	if (tls_available) {
		ssl_base_uri = soup_test_server_get_uri (server, "https", NULL);
		g_object_set (G_OBJECT (server),
			      SOUP_SERVER_HTTPS_ALIASES, https_aliases,
			      NULL);
	}

	g_test_add_func ("/server/OPTIONS *", do_star_test);
	g_test_add_func ("/server/aliases", do_server_aliases_test);
	g_test_add_func ("/server/..-in-path", do_dot_dot_test);
	g_test_add_func ("/server/ipv6", do_ipv6_test);
	g_test_add_func ("/server/multi/port", do_multi_port_test);
	g_test_add_func ("/server/multi/scheme", do_multi_scheme_test);
	g_test_add_func ("/server/multi/family", do_multi_family_test);
	g_test_add_func ("/server/import/gsocket", do_gsocket_import_test);
	g_test_add_func ("/server/import/fd", do_fd_import_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	if (tls_available)
		soup_uri_free (ssl_base_uri);

	test_cleanup ();
	return ret;
}
