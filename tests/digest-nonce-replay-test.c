/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-auth-digest-private.h"

#define REALM "digest-replay-test"

static void
server_cb (SoupServer        *server,
	   SoupServerMessage *msg,
	   const char        *path,
	   GHashTable        *query,
	   gpointer           user_data)
{
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_STATIC, "ok", 2);
}

static char *
auth_callback (SoupAuthDomain    *domain,
	       SoupServerMessage *msg,
	       const char        *username,
	       gpointer           user_data)
{
	if (strcmp (username, "user") != 0)
		return NULL;

	return soup_auth_domain_digest_encode_password ("user", REALM, "password");
}

static SoupMessage *
send_with_authorization (SoupSession *session,
	                 const char  *url,
	                 const char  *authorization)
{
	SoupMessage *msg;
	GBytes *body;
	GError *error = NULL;

	msg = soup_message_new (SOUP_METHOD_GET, url);
	if (authorization) {
		soup_message_headers_replace (soup_message_get_request_headers (msg),
					      "Authorization", authorization);
	}
	body = soup_test_session_async_send (session, msg, NULL, &error);
	g_assert_no_error (error);
	g_clear_pointer (&body, g_bytes_unref);

	return msg;
}

static void
do_digest_nonce_replay_test (void)
{
	SoupServer *server;
	SoupAuthDomain *auth_domain;
	SoupSession *session;
	SoupMessage *msg;
	GUri *base_uri;
	char *base_str, *url;
	const char *www_authenticate;
	GHashTable *challenge_params;
	const char *nonce;
	char hex_urp[33], response[33];
	char *authorization;

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_cb, NULL, NULL);

	auth_domain = soup_auth_domain_digest_new (
		"realm", REALM,
		"auth-callback", auth_callback,
		NULL);
	soup_auth_domain_add_path (auth_domain, "/");
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	base_uri = soup_test_server_get_uri (server, "http", "127.0.0.1");
	base_str = g_uri_to_string (base_uri);
	url = g_strconcat (base_str, "protected", NULL);

	session = soup_test_session_new (NULL);

	/* Get challenged, and extract the nonce the server issued. */
	msg = send_with_authorization (session, url, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_UNAUTHORIZED);
	www_authenticate = soup_message_headers_get_one (soup_message_get_response_headers (msg), "WWW-Authenticate");
	g_assert_nonnull (www_authenticate);
	g_assert_true (g_str_has_prefix (www_authenticate, "Digest "));
	challenge_params = soup_header_parse_param_list (www_authenticate + strlen ("Digest "));
	nonce = g_hash_table_lookup (challenge_params, "nonce");
	g_assert_nonnull (nonce);
	g_object_unref (msg);

	/* Hand-compute a valid Authorization header for that nonce. */
	soup_auth_digest_compute_hex_urp ("user", REALM, "password", hex_urp);
	soup_auth_digest_compute_response ("GET", "/protected", hex_urp,
					   SOUP_AUTH_DIGEST_QOP_AUTH,
					   nonce, "clientnonce", 1, response);
	authorization = g_strdup_printf (
		"Digest username=\"user\", realm=\"%s\", nonce=\"%s\", uri=\"/protected\", "
		"qop=auth, nc=00000001, cnonce=\"clientnonce\", response=\"%s\"",
		REALM, nonce, response);

	/* The first use of this Authorization header must succeed. */
	msg = send_with_authorization (session, url, authorization);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);

	/* Replaying the exact same header -- same nonce, same nc, same
	 * cnonce, same response -- must be rejected.
	 */
	msg = send_with_authorization (session, url, authorization);
	soup_test_assert_message_status (msg, SOUP_STATUS_UNAUTHORIZED);
	g_object_unref (msg);

	g_free (authorization);
	soup_header_free_param_list (challenge_params);
	soup_test_session_abort_unref (session);
	g_free (base_str);
	g_free (url);
	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/digest-nonce-replay/rejected", do_digest_nonce_replay_test);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
