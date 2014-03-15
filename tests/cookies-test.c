/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Igalia S.L.
 */

#include "test-utils.h"

SoupServer *server;
SoupURI *first_party_uri, *third_party_uri;
const char *first_party = "http://127.0.0.1/";
const char *third_party = "http://localhost/";

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	if (g_str_equal (path, "/index.html")) {
		soup_message_headers_replace (msg->response_headers,
					      "Set-Cookie",
					      "foo=bar");
	} else if (g_str_equal (path, "/foo.jpg")) {
		soup_message_headers_replace (msg->response_headers,
					      "Set-Cookie",
					      "baz=qux");
	} else if (soup_message_headers_get_one (msg->request_headers,
						 "Echo-Set-Cookie")) {
		soup_message_headers_replace (msg->response_headers,
					      "Set-Cookie",
					      soup_message_headers_get_one (msg->request_headers,
									    "Echo-Set-Cookie"));
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
}

typedef struct {
	SoupCookieJarAcceptPolicy policy;
	int n_cookies;
} CookiesForPolicy;

static const CookiesForPolicy validResults[] = {
	{ SOUP_COOKIE_JAR_ACCEPT_ALWAYS, 2 },
	{ SOUP_COOKIE_JAR_ACCEPT_NEVER, 0 },
	{ SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY, 1 }
};

static void
do_cookies_accept_policy_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;
	SoupCookieJar *jar;
	GSList *l, *p;
	int i;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	jar = SOUP_COOKIE_JAR (soup_session_get_feature (session, SOUP_TYPE_COOKIE_JAR));

	for (i = 0; i < G_N_ELEMENTS (validResults); i++) {
		soup_cookie_jar_set_accept_policy (jar, validResults[i].policy);

		uri = soup_uri_new_with_base (first_party_uri, "/index.html");
		msg = soup_message_new_from_uri ("GET", uri);
		soup_message_set_first_party (msg, first_party_uri);
		soup_session_send_message (session, msg);
		soup_uri_free (uri);
		g_object_unref (msg);

		/* We can't use two servers due to limitations in
		 * test_server, so let's swap first and third party here
		 * to simulate a cookie coming from a third party.
		 */
		uri = soup_uri_new_with_base (first_party_uri, "/foo.jpg");
		msg = soup_message_new_from_uri ("GET", uri);
		soup_message_set_first_party (msg, third_party_uri);
		soup_session_send_message (session, msg);
		soup_uri_free (uri);
		g_object_unref (msg);

		l = soup_cookie_jar_all_cookies (jar);
		g_assert_cmpint (g_slist_length (l), ==, validResults[i].n_cookies);

		for (p = l; p; p = p->next) {
			soup_cookie_jar_delete_cookie (jar, p->data);
			soup_cookie_free (p->data);
		}

		g_slist_free (l);
	}

	soup_test_session_abort_unref (session);
}

/* FIXME: moar tests! */
static void
do_cookies_parsing_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupCookieJar *jar;
	GSList *cookies, *iter;
	SoupCookie *cookie;
	gboolean got1, got2, got3;

	g_test_bug ("678753");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	jar = SOUP_COOKIE_JAR (soup_session_get_feature (session, SOUP_TYPE_COOKIE_JAR));

	/* "httponly" is case-insensitive, and its value (if any) is ignored */
	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (msg->request_headers, "Echo-Set-Cookie",
				     "one=1; httponly; max-age=100");
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (msg->request_headers, "Echo-Set-Cookie",
				     "two=2; HttpOnly; max-age=100");
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (msg->request_headers, "Echo-Set-Cookie",
				     "three=3; httpONLY=Wednesday; max-age=100");
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	cookies = soup_cookie_jar_get_cookie_list (jar, first_party_uri, TRUE);
	got1 = got2 = got3 = FALSE;

	for (iter = cookies; iter; iter = iter->next) {
		cookie = iter->data;

		if (!strcmp (soup_cookie_get_name (cookie), "one")) {
			got1 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
		} else if (!strcmp (soup_cookie_get_name (cookie), "two")) {
			got2 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
		} else if (!strcmp (soup_cookie_get_name (cookie), "three")) {
			got3 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
		} else {
			soup_test_assert (FALSE, "got unexpected cookie '%s'",
					  soup_cookie_get_name (cookie));
		}

		soup_cookie_free (cookie);
	}
	g_slist_free (cookies);

	g_assert_true (got1);
	g_assert_true (got2);
	g_assert_true (got3);

	soup_test_session_abort_unref (session);
}	

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	first_party_uri = soup_uri_new (first_party);
	third_party_uri = soup_uri_new (third_party);
	soup_uri_set_port (first_party_uri, soup_server_get_port (server));
	soup_uri_set_port (third_party_uri, soup_server_get_port (server));

	g_test_add_func ("/cookies/accept-policy", do_cookies_accept_policy_test);
	g_test_add_func ("/cookies/parsing", do_cookies_parsing_test);

	ret = g_test_run ();

	soup_uri_free (first_party_uri);
	soup_uri_free (third_party_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
