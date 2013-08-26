/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

SoupServer *server;
SoupURI *base_uri;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	soup_message_headers_append (msg->response_headers,
				     "X-Handled-By", "server_callback");

	if (!strcmp (path, "*")) {
		debug_printf (1, "    default server_callback got request for '*'!\n");
		errors++;
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
		debug_printf (1, "    server_star_callback got request for '%s'!\n", path);
		errors++;
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

	debug_printf (1, "\nOPTIONS *\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	star_uri = soup_uri_copy (base_uri);
	soup_uri_set_path (star_uri, "*");

	debug_printf (1, "  Testing with no handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_NOT_FOUND) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	if (handled_by) {
		/* Should have been rejected by SoupServer directly */
		debug_printf (1, "    Message reached handler '%s'\n",
			      handled_by);
		errors++;
	}
	g_object_unref (msg);

	soup_server_add_handler (server, "*", server_star_callback, NULL, NULL);

	debug_printf (1, "  Testing with handler\n");
	msg = soup_message_new_from_uri ("OPTIONS", star_uri);
	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_OK) {
		debug_printf (1, "    Unexpected response: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	handled_by = soup_message_headers_get_one (msg->response_headers,
						   "X-Handled-By");
	if (!handled_by) {
		debug_printf (1, "    Message did not reach handler!\n");
		errors++;
	} else if (strcmp (handled_by, "star_callback") != 0) {
		debug_printf (1, "    Message reached incorrect handler '%s'\n",
			      handled_by);
		errors++;
	}
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	soup_uri_free (star_uri);
}

static void
do_dot_dot_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;

	debug_printf (1, "\n'..' smuggling test\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	uri = soup_uri_new_with_base (base_uri, "/..%2ftest");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_BAD_REQUEST) {
		debug_printf (1, "      FAILED: %d %s (expected Bad Request)\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
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

	host = soup_message_headers_get_one (msg->request_headers, "Host");
	if (!host) {
		debug_printf (1, "    request has no Host header!\n");
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
		return;
	}

	g_snprintf (expected_host, sizeof (expected_host),
		    "[::1]:%d", soup_server_get_port (server));

	if (strcmp (host, expected_host) == 0)
		soup_message_set_status (msg, SOUP_STATUS_OK);
	else {
		debug_printf (1, "    request has incorrect Host header '%s'\n", host);
		errors++;
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
	}
}

static void
do_ipv6_test (void)
{
	SoupServer *ipv6_server;
	SoupURI *ipv6_uri;
	SoupAddress *ipv6_addr;
	SoupSession *session;
	SoupMessage *msg;

	debug_printf (1, "\nIPv6 server test\n");

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
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    request failed: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	debug_printf (1, "  HTTP/1.0\n");
	msg = soup_message_new_from_uri ("GET", ipv6_uri);
	soup_message_set_http_version (msg, SOUP_HTTP_1_0);
	soup_session_send_message (session, msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    request failed: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	soup_uri_free (ipv6_uri);
	soup_test_session_abort_unref (session);
	soup_test_server_quit_unref (ipv6_server);
}

int
main (int argc, char **argv)
{
	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	do_star_test ();
	do_dot_dot_test ();
	do_ipv6_test ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
