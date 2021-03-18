/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

GUri *base_uri;
char *server2_uri;
SoupSession *async_session;

typedef struct {
	const char *method;
	const char *path;
	guint status_code;
	gboolean repeat;
} TestRequest;

typedef struct {
	TestRequest requests[3];
	guint final_status;
	guint error_code;
	const char *bugref;
} TestCase;

static TestCase tests[] = {
	/* A redirecty response to a GET or HEAD should cause a redirect */

	{ { { "GET", "/301", 301 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "GET", "/302", 302 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "GET", "/303", 303 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "GET", "/307", 307 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "GET", "/308", 308 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "HEAD", "/301", 301 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200, 0, "551190" },
	{ { { "HEAD", "/302", 302 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200, 0, "551190" },
	/* 303 is a nonsensical response to HEAD, but some sites do
	 * it anyway. :-/
	 */
	{ { { "HEAD", "/303", 303 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200, 0, "600830" },
	{ { { "HEAD", "/307", 307 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200, 0, "551190" },
	{ { { "HEAD", "/308", 308 },
	    { "HEAD", "/", 200 },
	    { NULL } }, 200, 0, "551190" },

	/* A non-redirecty response to a GET or HEAD should not */

	{ { { "GET", "/300", 300 },
	    { NULL } }, 300, 0, NULL },
	{ { { "GET", "/304", 304 },
	    { NULL } }, 304, 0, NULL },
	{ { { "GET", "/305", 305 },
	    { NULL } }, 305, 0, NULL },
	{ { { "GET", "/306", 306 },
	    { NULL } }, 306, 0, NULL },
	{ { { "HEAD", "/300", 300 },
	    { NULL } }, 300, 0, "551190" },
	{ { { "HEAD", "/304", 304 },
	    { NULL } }, 304, 0, "551190" },
	{ { { "HEAD", "/305", 305 },
	    { NULL } }, 305, 0, "551190" },
	{ { { "HEAD", "/306", 306 },
	    { NULL } }, 306, 0, "551190" },
	
	/* Test double-redirect */

	{ { { "GET", "/301/302", 301 },
	    { "GET", "/302", 302 },
	    { "GET", "/", 200 } }, 200, 0, NULL },
	{ { { "HEAD", "/301/302", 301 },
	    { "HEAD", "/302", 302 },
	    { "HEAD", "/", 200 } }, 200, 0, "551190" },

	/* POST should only automatically redirect on 301, 302 and 303 */

	{ { { "POST", "/301", 301 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, "586692" },
	{ { { "POST", "/302", 302 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "POST", "/303", 303 },
	    { "GET", "/", 200 },
	    { NULL } }, 200, 0, NULL },
	{ { { "POST", "/307", 307 },
	    { NULL } }, 307, 0, NULL },

	/* Test behavior with recoverably-bad Location header */
	{ { { "GET", "/bad", 302 },
	    { "GET", "/bad%20with%20spaces", 200 },
	    { NULL } }, 200, 0, "566530" },

	{ { { "GET", "/bad-no-host", 302 },
	    { NULL } }, 302, SOUP_SESSION_ERROR_REDIRECT_BAD_URI, "528882" },

	{ { { "GET", "/bad-no-location", 302 },
	    { NULL } }, 302, SOUP_SESSION_ERROR_REDIRECT_NO_LOCATION, NULL},

	/* Test infinite redirection */
	{ { { "GET", "/bad-recursive", 302, TRUE },
	    { NULL } }, 302, SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS, "604383" },

	/* Test redirection to a different server */
	{ { { "GET", "/server2", 302 },
	    { "GET", "/on-server2", 200 },
	    { NULL } }, 200, 0, NULL },
};
static const int n_tests = G_N_ELEMENTS (tests);

static void
got_headers (SoupMessage *msg, gpointer user_data)
{
	TestRequest **treq = user_data;
	const char *location;

	debug_printf (2, "    -> %d %s\n", soup_message_get_status (msg),
		      soup_message_get_reason_phrase (msg));
	location = soup_message_headers_get_one (soup_message_get_response_headers (msg),
						 "Location");
	if (location)
		debug_printf (2, "       Location: %s\n", location);

	if (!(*treq)->method)
		return;

	soup_test_assert_message_status (msg, (*treq)->status_code);
}

static void
restarted (SoupMessage *msg, gpointer user_data)
{
	TestRequest **treq = user_data;
	GUri *uri = soup_message_get_uri (msg);

	debug_printf (2, "    %s %s\n", soup_message_get_method (msg), g_uri_get_path (uri));

	if ((*treq)->method && !(*treq)->repeat)
		(*treq)++;

	soup_test_assert ((*treq)->method,
			  "Expected to be done");

	g_assert_cmpstr (soup_message_get_method (msg), ==, (*treq)->method);
	g_assert_cmpstr (g_uri_get_path (uri), ==, (*treq)->path);
}

static void
do_message_api_test (SoupSession *session, TestCase *test)
{
	GUri *uri;
	SoupMessage *msg;
	GBytes *body;
	TestRequest *treq;
	GError *error = NULL;

	if (test->bugref)
		g_test_bug (test->bugref);

	uri = g_uri_parse_relative (base_uri, test->requests[0].path, SOUP_HTTP_URI_FLAGS | G_URI_FLAGS_PARSE_RELAXED, NULL);
        msg = soup_message_new_from_uri (test->requests[0].method, uri);
	g_uri_unref (uri);

	if (soup_message_get_method (msg) == SOUP_METHOD_POST) {
		GBytes *request_body;

		request_body = g_bytes_new_static ("post body", strlen ("post body"));
		soup_message_set_request_body_from_bytes (msg, "text/plain", request_body);
		g_bytes_unref (request_body);
	}

	treq = &test->requests[0];
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), &treq);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (restarted), &treq);

	body = soup_test_session_async_send (session, msg, NULL, &error);

	soup_test_assert_message_status (msg, test->final_status);
	if (test->error_code)
		g_assert_error (error, SOUP_SESSION_ERROR, test->error_code);
	else
		g_assert_no_error (error);

	g_clear_error (&error);
	g_bytes_unref (body);
	g_object_unref (msg);
}

static void
do_async_msg_api_test (gconstpointer test)
{
	do_message_api_test (async_session, (TestCase *)test);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	char *remainder;
	guint status_code;
	SoupMessageHeaders *response_headers;
	const char *method;

	/* Make sure that a HTTP/1.0 redirect doesn't cause an
	 * HTTP/1.0 re-request. (#521848)
	 */
	if (soup_server_message_get_http_version (msg) == SOUP_HTTP_1_0) {
		soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
		return;
	}

	method = soup_server_message_get_method (msg);
	response_headers = soup_server_message_get_response_headers (msg);

	if (g_str_has_prefix (path, "/bad")) {
		if (!strcmp (path, "/bad")) {
			soup_server_message_set_status (msg, SOUP_STATUS_FOUND, NULL);
			soup_message_headers_replace (response_headers,
						      "Location",
						      "/bad with spaces");
		} else if (!strcmp (path, "/bad-recursive")) {
			soup_server_message_set_status (msg, SOUP_STATUS_FOUND, NULL);
			soup_message_headers_replace (response_headers,
						      "Location",
						      "/bad-recursive");
		} else if (!strcmp (path, "/bad-no-host")) {
			soup_server_message_set_status (msg, SOUP_STATUS_FOUND, NULL);
			soup_message_headers_replace (response_headers,
						      "Location",
						      "about:blank");
		} else if (!strcmp (path, "/bad-no-location")) {
			soup_server_message_set_status (msg, SOUP_STATUS_FOUND, NULL);
			soup_message_headers_replace (response_headers,
						      "Location", "");
		} else if (!strcmp (path, "/bad with spaces"))
			soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
		else
			soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		return;
	} else if (!strcmp (path, "/server2")) {
		soup_server_message_set_status (msg, SOUP_STATUS_FOUND, NULL);
		soup_message_headers_replace (response_headers,
					      "Location",
					      server2_uri);
		return;
	} else if (!strcmp (path, "/")) {
		SoupMessageBody *request_body;

		if (method != SOUP_METHOD_GET &&
		    method != SOUP_METHOD_HEAD) {
			soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
			return;
		}

		/* Make sure that redirecting a POST clears the body */
		request_body = soup_server_message_get_request_body (msg);
		if (request_body->length) {
			soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
			return;
		}

		soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

		/* FIXME: this is wrong, though it doesn't matter for
		 * the purposes of this test, and to do the right
		 * thing currently we'd have to set Content-Length by
		 * hand.
		 */
		if (method != SOUP_METHOD_HEAD) {
			soup_server_message_set_response (msg, "text/plain",
							  SOUP_MEMORY_STATIC,
							  "OK\r\n", 4);
		}
		return;
	}

	status_code = strtoul (path + 1, &remainder, 10);
	if (!SOUP_STATUS_IS_REDIRECTION (status_code) ||
	    (*remainder && *remainder != '/')) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		return;
	}

	/* See above comment re bug 521848. We only test this on the
	 * double-redirects so that we get connection-reuse testing
	 * the rest of the time.
	 */
	if (*remainder == '/')
		soup_server_message_set_http_version (msg, SOUP_HTTP_1_0);

	soup_server_message_set_redirect (msg, status_code,
					  *remainder ? remainder : "/");
}

static void
server2_callback (SoupServer        *server,
		  SoupServerMessage *msg,
		  const char        *path,
		  GHashTable        *query,
		  gpointer           data)
{
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server, *server2;
	GUri *uri2, *uri2_with_path;
	char *path;
	int n, ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	server2 = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server2, NULL,
				 server2_callback, NULL, NULL);
	uri2 = soup_test_server_get_uri (server2, "http", NULL);
        uri2_with_path = g_uri_parse_relative (uri2, "/on-server2", SOUP_HTTP_URI_FLAGS, NULL);
        g_uri_unref (uri2);
	server2_uri = g_uri_to_string (uri2_with_path);
	g_uri_unref (uri2_with_path);

	loop = g_main_loop_new (NULL, TRUE);

	async_session = soup_test_session_new (NULL);

	for (n = 0; n < n_tests; n++) {
		path = g_strdup_printf ("/redirect/msg/%d-%s-%d", n,
					tests[n].requests[0].method,
					tests[n].requests[0].status_code);
		g_test_add_data_func (path, &tests[n], do_async_msg_api_test);
		g_free (path);
	}

	ret = g_test_run ();

	g_main_loop_unref (loop);
	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);
	g_free (server2_uri);
	soup_test_server_quit_unref (server2);

	soup_test_session_abort_unref (async_session);

	test_cleanup ();
	return ret;
}
