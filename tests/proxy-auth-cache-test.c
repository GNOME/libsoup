/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2026 Igalia S.L.
 */

#include "test-utils.h"

/* Two SoupServers stand in as HTTP proxies. When a session uses an HTTP proxy
 * for an http:// URL it sends the full request, including Proxy-Authorization,
 * straight to the proxy, so a SoupServer can observe it without forwarding.
 * After authenticating to the first proxy, switching the session to a second
 * proxy must not send the first proxy's credentials to it. See issue #506.
 */

static gboolean second_proxy_saw_authorization;
static gboolean second_proxy_hit;

static void
first_proxy_cb (SoupServer        *server,
		SoupServerMessage *msg,
		const char        *path,
		GHashTable        *query,
		gpointer           user_data)
{
	SoupMessageHeaders *req = soup_server_message_get_request_headers (msg);

	/* Challenge until the client authenticates */
	if (!soup_message_headers_get_one (req, "Proxy-Authorization")) {
		soup_server_message_set_status (msg, SOUP_STATUS_PROXY_UNAUTHORIZED, NULL);
		soup_message_headers_append (soup_server_message_get_response_headers (msg),
					     "Proxy-Authenticate", "Basic realm=\"first\"");
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_STATIC, "ok", 2);
}

static void
second_proxy_cb (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           user_data)
{
	SoupMessageHeaders *req = soup_server_message_get_request_headers (msg);

	second_proxy_hit = TRUE;
	if (soup_message_headers_get_one (req, "Proxy-Authorization"))
		second_proxy_saw_authorization = TRUE;

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_STATIC, "ok", 2);
}

static gboolean
authenticate_cb (SoupMessage *msg,
		 SoupAuth    *auth,
		 gboolean     retrying,
		 gpointer     user_data)
{
	if (soup_auth_is_for_proxy (auth) && !retrying) {
		soup_auth_authenticate (auth, "user", "password");
		return TRUE;
	}
	return FALSE;
}

static void
send_via_proxy (SoupSession *session, gboolean new_connection)
{
	SoupMessage *msg;
	GBytes *body;
	GError *error = NULL;

	msg = soup_message_new (SOUP_METHOD_GET, "http://origin.test/");
	if (new_connection)
		soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
	g_signal_connect (msg, "authenticate", G_CALLBACK (authenticate_cb), NULL);
	body = soup_test_session_async_send (session, msg, NULL, &error);

	g_assert_no_error (error);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_clear_pointer (&body, g_bytes_unref);
	g_object_unref (msg);
}

static void
do_proxy_switch_no_credential_leak (void)
{
	SoupServer *first, *second;
	GUri *first_uri, *second_uri;
	char *first_str, *second_str;
	GProxyResolver *resolver;
	SoupSession *session;

	first = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (first, NULL, first_proxy_cb, NULL, NULL);
	first_uri = soup_test_server_get_uri (first, "http", "127.0.0.1");
	first_str = g_uri_to_string (first_uri);

	second = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (second, NULL, second_proxy_cb, NULL, NULL);
	second_uri = soup_test_server_get_uri (second, "http", "127.0.0.1");
	second_str = g_uri_to_string (second_uri);

	resolver = g_simple_proxy_resolver_new (first_str, NULL);
	session = soup_test_session_new ("proxy-resolver", resolver, NULL);

	/* Authenticate to the first proxy */
	send_via_proxy (session, FALSE);

	/* Switch the session to the second proxy and send again on a fresh
	 * connection so the request actually goes to the second proxy.
	 */
	g_simple_proxy_resolver_set_default_proxy (G_SIMPLE_PROXY_RESOLVER (resolver), second_str);
	second_proxy_hit = FALSE;
	second_proxy_saw_authorization = FALSE;
	send_via_proxy (session, TRUE);

	/* Make sure the second request really reached the second proxy... */
	g_assert_true (second_proxy_hit);
	/* ...and that the first proxy's credentials did not leak to it */
	g_assert_false (second_proxy_saw_authorization);

	soup_test_session_abort_unref (session);
	g_object_unref (resolver);
	g_free (first_str);
	g_free (second_str);
	g_uri_unref (first_uri);
	g_uri_unref (second_uri);
	soup_test_server_quit_unref (first);
	soup_test_server_quit_unref (second);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/proxy-auth-cache/switch-no-credential-leak",
			 do_proxy_switch_no_credential_leak);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
