/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include "test-utils.h"

static GUri *base_uri;

static struct {
	gboolean client_sent_basic, client_sent_digest;
	gboolean server_requested_basic, server_requested_digest;
	gboolean succeeded;
} test_data;

static void
curl_exited (GPid pid, int status, gpointer data)
{
	gboolean *done = data;

	*done = TRUE;
	test_data.succeeded = (status == 0);
}

static void
do_test (GUri *base_uri, const char *path,
	 gboolean good_user, gboolean good_password,
	 gboolean offer_basic, gboolean offer_digest,
	 gboolean client_sends_basic, gboolean client_sends_digest,
	 gboolean server_requests_basic, gboolean server_requests_digest,
	 gboolean success)
{
	GUri *uri;
	char *uri_str;
	GPtrArray *args;
	GPid pid;
	gboolean done;

	/* Note that we purposefully do not pass G_URI_FLAGS_ENCODED_PATH here which would lose
           the encoded characters in tests 4. and 5. below. */
        uri = g_uri_parse_relative (base_uri, path, G_URI_FLAGS_NONE, NULL);
	uri_str = g_uri_to_string (uri);
	g_uri_unref (uri);

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "curl");
	g_ptr_array_add (args, "--noproxy");
	g_ptr_array_add (args, "*");
	g_ptr_array_add (args, "-f");
	g_ptr_array_add (args, "-s");
	if (offer_basic || offer_digest) {
		g_ptr_array_add (args, "-u");
		if (good_user) {
			if (good_password)
				g_ptr_array_add (args, "user:password");
			else
				g_ptr_array_add (args, "user:badpassword");
		} else {
			if (good_password)
				g_ptr_array_add (args, "baduser:password");
			else
				g_ptr_array_add (args, "baduser:badpassword");
		}

		if (offer_basic && offer_digest)
			g_ptr_array_add (args, "--anyauth");
		else if (offer_basic)
			g_ptr_array_add (args, "--basic");
		else
			g_ptr_array_add (args, "--digest");
	}
	g_ptr_array_add (args, uri_str);
	g_ptr_array_add (args, NULL);

	memset (&test_data, 0, sizeof (test_data));
	if (g_spawn_async (NULL, (char **)args->pdata, NULL,
			   G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL | G_SPAWN_DO_NOT_REAP_CHILD,
			   NULL, NULL, &pid, NULL)) {
		done = FALSE;
		g_child_watch_add (pid, curl_exited, &done);

		while (!done)
			g_main_context_iteration (NULL, TRUE);
	} else
		test_data.succeeded = FALSE;
	g_ptr_array_free (args, TRUE);
	g_free (uri_str);

	g_assert_cmpint (server_requests_basic, ==, test_data.server_requested_basic);
	g_assert_cmpint (server_requests_digest, ==, test_data.server_requested_digest);
	g_assert_cmpint (client_sends_basic, ==, test_data.client_sent_basic);
	g_assert_cmpint (client_sends_digest, ==, test_data.client_sent_digest);

	g_assert_cmpint (success, ==, test_data.succeeded);
}

#define TEST_USES_BASIC(t)    (((t) & 1) == 1)
#define TEST_USES_DIGEST(t)   (((t) & 2) == 2)
#define TEST_GOOD_USER(t)     (((t) & 4) == 4)
#define TEST_GOOD_PASSWORD(t) (((t) & 8) == 8)

#define TEST_GOOD_AUTH(t)        (TEST_GOOD_USER (t) && TEST_GOOD_PASSWORD (t))
#define TEST_PREEMPTIVE_BASIC(t) (TEST_USES_BASIC (t) && !TEST_USES_DIGEST (t))

static void
do_server_auth_test (gconstpointer data)
{
	int i = GPOINTER_TO_INT (data);

	if (!have_curl()) {
		g_test_skip ("curl is not available");
		return;
	}

	/* 1. No auth required. The server will ignore the
	 * Authorization headers completely, and the request
	 * will always succeed.
	 */
	do_test (base_uri, "/foo",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), FALSE,
		 /* expected from server */
		 FALSE, FALSE,
		 /* success? */
		 TRUE);

	/* 2. Basic auth required. The server will send
	 * "WWW-Authenticate: Basic" if the client fails to
	 * send an Authorization: Basic on the first request,
	 * or if it sends a bad password.
	 */
	do_test (base_uri, "/Basic/foo",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_USES_BASIC (i), FALSE,
		 /* expected from server */
		 !TEST_PREEMPTIVE_BASIC (i) || !TEST_GOOD_AUTH (i), FALSE,
		 /* success? */
		 TEST_USES_BASIC (i) && TEST_GOOD_AUTH (i));

	/* 3. Digest auth required. Simpler than the basic
	 * case because the client can't send Digest auth
	 * premptively.
	 */
	do_test (base_uri, "/Digest/foo",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from server */
		 FALSE, TRUE,
		 /* success? */
		 TEST_USES_DIGEST (i) && TEST_GOOD_AUTH (i));

	/* 4. Digest auth with encoded URI. See #794208.
	 */
	do_test (base_uri, "/Digest/A%20B",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from server */
		 FALSE, TRUE,
		 /* success? */
		 TEST_USES_DIGEST (i) && TEST_GOOD_AUTH (i));

	/* 5. Digest auth with a mixture of encoded and decoded chars in the URI. See #794208.
	 */
	do_test (base_uri, "/Digest/A%20|%20B",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from server */
		 FALSE, TRUE,
		 /* success? */
		 TEST_USES_DIGEST (i) && TEST_GOOD_AUTH (i));

	/* 6. Digest auth with UTF-8 chars in the URI. See #794208.
	 */
	do_test (base_uri, "/Digest/A௹B",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from server */
		 FALSE, TRUE,
		 /* success? */
		 TEST_USES_DIGEST (i) && TEST_GOOD_AUTH (i));

	/* 7. Any auth required. */
	do_test (base_uri, "/Any/foo",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from server */
		 !TEST_PREEMPTIVE_BASIC (i) || !TEST_GOOD_AUTH (i), !TEST_PREEMPTIVE_BASIC (i) || !TEST_GOOD_AUTH (i),
		 /* success? */
		 (TEST_USES_BASIC (i) || TEST_USES_DIGEST (i)) && TEST_GOOD_AUTH (i));

	/* 8. No auth required again. (Makes sure that
	 * SoupAuthDomain:remove-path works.)
	 */
	do_test (base_uri, "/Any/Not/foo",
		 TEST_GOOD_USER (i), TEST_GOOD_PASSWORD (i),
		 /* request */
		 TEST_USES_BASIC (i), TEST_USES_DIGEST (i),
		 /* expected from client */
		 TEST_PREEMPTIVE_BASIC (i), FALSE,
		 /* expected from server */
		 FALSE, FALSE,
		 /* success? */
		 TRUE);
}

static gboolean
basic_auth_callback (SoupAuthDomain    *auth_domain,
		     SoupServerMessage *msg,
		     const char        *username,
		     const char        *password,
		     gpointer           data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static char *
digest_auth_callback (SoupAuthDomain    *auth_domain,
		      SoupServerMessage *msg,
		      const char        *username,
		      gpointer           data)
{
	if (strcmp (username, "user") != 0)
		return NULL;

	/* Note: this is exactly how you *shouldn't* do it in the real
	 * world; you should have the pre-encoded password stored in a
	 * database of some sort rather than using the cleartext
	 * password in the callback.
	 */
	return soup_auth_domain_digest_encode_password ("user",
							"server-auth-test",
							"password");
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *method;

	method = soup_server_message_get_method (msg);
	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_HEAD) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_STATIC,
					  "OK\r\n", 4);
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

static void
got_headers_callback (SoupServerMessage *msg,
		      gpointer           data)
{
	const char *header;

	header = soup_message_headers_get_one (soup_server_message_get_request_headers (msg),
					       "Authorization");
	if (header) {
		if (strstr (header, "Basic "))
			test_data.client_sent_basic = TRUE;
		if (strstr (header, "Digest "))
			test_data.client_sent_digest = TRUE;
	}
}

static void
wrote_headers_callback (SoupServerMessage *msg,
			gpointer           data)
{
	const char *header;

	header = soup_message_headers_get_list (soup_server_message_get_response_headers (msg),
						"WWW-Authenticate");
	if (header) {
		if (strstr (header, "Basic "))
			test_data.server_requested_basic = TRUE;
		if (strstr (header, "Digest "))
			test_data.server_requested_digest = TRUE;
	}
}

static void
request_started_callback (SoupServer        *server,
			  SoupServerMessage *msg,
			  gpointer           data)
{
	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (got_headers_callback), NULL);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (wrote_headers_callback), NULL);
}

static gboolean run_tests = TRUE;

static GOptionEntry no_test_entry[] = {
        { "no-tests", 'n', G_OPTION_FLAG_REVERSE,
          G_OPTION_ARG_NONE, &run_tests,
          "Don't run tests, just run the test server", NULL },
        { NULL }
};

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	SoupAuthDomain *auth_domain;
	int ret;

	test_init (argc, argv, no_test_entry);

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	g_signal_connect (server, "request_started",
			  G_CALLBACK (request_started_callback), NULL);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);

	auth_domain = soup_auth_domain_basic_new (
		"realm", "server-auth-test",
		"auth-callback", basic_auth_callback,
		NULL);
        soup_auth_domain_add_path (auth_domain, "/Basic");
        soup_auth_domain_add_path (auth_domain, "/Any");
        soup_auth_domain_remove_path (auth_domain, "/Any/Not");
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	auth_domain = soup_auth_domain_digest_new (
		"realm", "server-auth-test",
		"auth-callback", digest_auth_callback,
		NULL);
        soup_auth_domain_add_path (auth_domain, "/Digest");
        soup_auth_domain_add_path (auth_domain, "/Any");
        soup_auth_domain_remove_path (auth_domain, "/Any/Not");
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	loop = g_main_loop_new (NULL, TRUE);

	base_uri = soup_test_server_get_uri (server, "http", NULL);
	if (run_tests) {
		int i;

		for (i = 0; i < 16; i++) {
			char *path;
			const char *authtypes;

			if (!TEST_GOOD_USER (i) && !TEST_GOOD_PASSWORD (i))
				continue;
			if (TEST_USES_BASIC (i)) {
				if (TEST_USES_DIGEST (i))
					authtypes = "basic+digest";
				else
					authtypes = "basic";
			} else {
				if (TEST_USES_DIGEST (i))
					authtypes = "digest";
				else
					authtypes = "none";
			}

			path = g_strdup_printf ("/server-auth/%s/%s-user%c%s-password",
						authtypes,
						TEST_GOOD_USER (i) ? "good" : "bad",
						TEST_GOOD_USER (i) ? '/' : '\0',
						TEST_GOOD_PASSWORD (i) ? "good" : "bad");
			g_test_add_data_func (path, GINT_TO_POINTER (i), do_server_auth_test);
			g_free (path);
		}

		ret = g_test_run ();
	} else {
		g_print ("Listening on port %d\n", g_uri_get_port (base_uri));
		g_main_loop_run (loop);
		ret = 0;
	}
	g_uri_unref (base_uri);

	g_main_loop_unref (loop);
	soup_test_server_quit_unref (server);

	if (run_tests)
		test_cleanup ();
	return ret;
}
