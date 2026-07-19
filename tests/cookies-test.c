/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Igalia S.L.
 */

#include "test-utils.h"
#include "soup-cookie-jar-db.h"
#include <glib/gstdio.h>
#include <stdint.h>

// This is hardcoded to match sqlite but in theory could change some day.
// https://sqlite.org/limits.html
#define SQLITE_PAGE_SIZE 4096ULL
#define SQLITE_MAX_PAGE_COUNT (G_MAXUINT32 - 1)

static SoupServer *server;
static GUri *first_party_uri, *third_party_uri;

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	SoupMessageHeaders *response_headers;
	SoupMessageHeaders *request_headers;

	response_headers = soup_server_message_get_response_headers (msg);
	request_headers = soup_server_message_get_request_headers (msg);
	if (g_str_equal (path, "/index.html")) {
		soup_message_headers_replace (response_headers,
					      "Set-Cookie",
					      "foo=bar");
	} else if (g_str_equal (path, "/foo.jpg")) {
		soup_message_headers_replace (response_headers,
					      "Set-Cookie",
					      "baz=qux");
	} else if (soup_message_headers_get_one (request_headers,
						 "Echo-Set-Cookie")) {
		soup_message_headers_replace (response_headers,
					      "Set-Cookie",
					      soup_message_headers_get_one (request_headers,
									    "Echo-Set-Cookie"));
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

typedef struct {
	SoupCookieJarAcceptPolicy policy;
	gboolean try_third_party_again;
	int n_cookies;
} CookiesForPolicy;

static const CookiesForPolicy validResults[] = {
	{ SOUP_COOKIE_JAR_ACCEPT_ALWAYS, FALSE, 2 },
	{ SOUP_COOKIE_JAR_ACCEPT_NEVER, FALSE, 0 },
	{ SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY, FALSE, 1 },
	{ SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY, FALSE, 1 },
	{ SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY, TRUE, 2 }
};

static void
do_cookies_accept_policy_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;
	SoupCookieJar *jar;
	GSList *l, *p;
	int i;

	session = soup_test_session_new (NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	jar = SOUP_COOKIE_JAR (soup_session_get_feature (session, SOUP_TYPE_COOKIE_JAR));

	for (i = 0; i < G_N_ELEMENTS (validResults); i++) {
		soup_cookie_jar_set_accept_policy (jar, validResults[i].policy);

		/* We can't use two servers due to limitations in
		 * test_server, so let's swap first and third party here
		 * to simulate a cookie coming from a third party.
		 */
		uri = g_uri_parse_relative (first_party_uri, "/foo.jpg", SOUP_HTTP_URI_FLAGS, NULL);
		msg = soup_message_new_from_uri ("GET", uri);
		soup_message_set_first_party (msg, third_party_uri);
		soup_test_session_send_message (session, msg);
		g_uri_unref (uri);
		g_object_unref (msg);

		uri = g_uri_parse_relative (first_party_uri, "/index.html", SOUP_HTTP_URI_FLAGS, NULL);
		msg = soup_message_new_from_uri ("GET", uri);
		soup_message_set_first_party (msg, first_party_uri);
		soup_test_session_send_message (session, msg);
		g_uri_unref (uri);
		g_object_unref (msg);
        
		if (validResults[i].try_third_party_again) {
                        uri = g_uri_parse_relative (first_party_uri, "/foo.jpg", SOUP_HTTP_URI_FLAGS, NULL);
                        msg = soup_message_new_from_uri ("GET", uri);
			soup_message_set_first_party (msg, third_party_uri);
			soup_test_session_send_message (session, msg);
			g_uri_unref (uri);
			g_object_unref (msg);
		}

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

static void
do_cookies_subdomain_policy_test (void)
{
	SoupCookieJar *jar;
	GSList *cookies;
	GUri *uri1;
	GUri *uri2;
	GUri *uri3;

	g_test_bug ("792130");

	/* Only the base domain should be considered when deciding
	 * whether a cookie is a third-party cookie.
	 */
	uri1 = g_uri_parse ("https://www.gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	uri2 = g_uri_parse ("https://foundation.gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	uri3 = g_uri_parse ("https://www.gnome.org.", SOUP_HTTP_URI_FLAGS, NULL);

	/* We can't check subdomains with a test server running on
	 * localhost, so we'll just check the cookie jar API itself.
	 */

	/* Cookie should be accepted. One cookie in the jar. */
	jar = soup_cookie_jar_new ();
	soup_cookie_jar_set_accept_policy (jar, SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY);
	soup_cookie_jar_set_cookie_with_first_party (jar, uri1, uri2, "1=foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 1);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Cookie should be accepted. Two cookies in the jar. */
	soup_cookie_jar_set_cookie_with_first_party (jar, uri2, uri1, "2=foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 2);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Third-party cookie should be rejected, so there are still
	 * only two cookies in the jar.
	 */
	soup_cookie_jar_set_cookie_with_first_party (jar, third_party_uri, uri1, "3=foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 2);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Now, we allow the "third-party" to set one cookie as the
	 * first party. Three cookies in the jar.
	 */
	soup_cookie_jar_set_cookie_with_first_party (jar, third_party_uri, third_party_uri, "4=foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 3);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Third-party cookie should now be allowed by grandfathering, though
	 * it was blocked before on the same URL. Four cookies in the jar.
	 */
	soup_cookie_jar_set_accept_policy (jar, SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY);
	soup_cookie_jar_set_cookie_with_first_party (jar, third_party_uri, uri1, "5=foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 4);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Now some Domain attribute tests.*/
	soup_cookie_jar_set_accept_policy (jar, SOUP_COOKIE_JAR_ACCEPT_ALWAYS);

	/* The cookie must be rejected if the Domain is not an appropriate
	 * match for the URI. Still four cookies in the jar.
	 */
	soup_cookie_jar_set_cookie (jar, uri1, "6=foo; Domain=gitlab.gnome.org");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 4);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Now the Domain is an appropriate match. Five cookies in the jar. */
	soup_cookie_jar_set_cookie (jar, uri1, "7=foo; Domain=gnome.org");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 5);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* A leading dot in the domain property should not affect things.
	 * This cookie should be accepted. Six cookies in the jar.
	 */
	soup_cookie_jar_set_cookie (jar, uri1, "8=foo; Domain=.www.gnome.org");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 6);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* The cookie must be rejected if the Domain ends in a trailing dot
	 * but the uri doesn't.
	 */
	soup_cookie_jar_set_cookie (jar, uri1, "9=foo; Domain=www.gnome.org.");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 6);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* The cookie should be accepted if both Domain and URI end with a trailing
	 * dot and they are a match. Seven cookies in the jar.
	 */
	soup_cookie_jar_set_cookie (jar, uri3, "10=foo; Domain=gnome.org.");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 7);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* The cookie should be rejected if URI has trailing dot but Domain doesn't.
	 * Seven cookies in the jar.
	 */
	soup_cookie_jar_set_cookie (jar, uri3, "11=foo; Domain=gnome.org");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 7);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* It should not be possible to set a cookie for a TLD. Still seven
	 * cookies in the jar.
	 */
	soup_cookie_jar_set_cookie (jar, uri1, "12=foo; Domain=.org");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 7);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* It should still not be possible to set a cookie for a TLD, even if
	 * we are tricksy and have a trailing dot. Still only seven cookies.
	 */
	soup_cookie_jar_set_cookie (jar, uri3, "13=foo; Domain=.org.");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 7);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	g_uri_unref (uri1);
	g_uri_unref (uri2);
	g_uri_unref (uri3);
	g_object_unref (jar);
}

static void
do_cookies_strict_secure_test (void)
{
	SoupCookieJar *jar;
	GSList *cookies;
	GUri *insecure_uri;
	GUri *secure_uri;

	insecure_uri = g_uri_parse ("http://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	secure_uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	jar = soup_cookie_jar_new ();

	/* Set a cookie from secure origin */
	soup_cookie_jar_set_cookie (jar, secure_uri, "1=foo; secure");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 1);
	g_assert_cmpstr (soup_cookie_get_value(cookies->data), ==, "foo");
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Do not allow an insecure origin to overwrite a secure cookie */
	soup_cookie_jar_set_cookie (jar, insecure_uri, "1=bar");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 1);
	g_assert_cmpstr (soup_cookie_get_value(cookies->data), ==, "foo");
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* Secure can only be set by from secure origin */
	soup_cookie_jar_set_cookie (jar, insecure_uri, "2=foo; secure");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 1);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	/* But we can make one for another path */
	soup_cookie_jar_set_cookie (jar, insecure_uri, "1=foo; path=/foo");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==, 2);
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);

	g_uri_unref (insecure_uri);
	g_uri_unref (secure_uri);
	g_object_unref (jar);
}

static void
do_cookies_prefix_test (void)
{
	SoupCookieJar *jar;
	GSList *cookies;
	GUri *insecure_uri;
	GUri *secure_uri;

	insecure_uri = g_uri_parse ("http://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	secure_uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	jar = soup_cookie_jar_new ();

        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__SeCuRe-Valid-1=1; Path=/; Secure", secure_uri),
                                         secure_uri, NULL);

        /* With NULL uri is considered secure */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__secure-Valid-2=1; Path=/; Secure", secure_uri),
                                         NULL, NULL);

        /* Without Secure */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__SeCuRe-Invalid-1=1;", secure_uri),
                                         secure_uri, NULL);

        /* Insecure host */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__SECURE-Invalid-2=1; Path=/Somethingelse; Secure", insecure_uri),
                                         insecure_uri, NULL);

        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__HoSt-Valid-1=1; Path=/; Secure", secure_uri),
                                         secure_uri, NULL);

        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__HoSt-Valid-2=1; Path=/; Secure", secure_uri),
                                         NULL, NULL);

        /* Invalid Path */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__HOST-Invalid-1=1; Path=/Somethingelse; Secure", secure_uri),
                                         secure_uri, NULL);

        /* Without Secure */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__host-Invalid-2=1; Path=/", secure_uri),
                                         secure_uri, NULL);

        /* Domain forbidden */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__HoSt-Invalid-3=1; Path=/; Secure; Domain=gnome.org", secure_uri),
                                         secure_uri, NULL);

        /* Insecure host */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("__host-Invalid-4=1; Path=/; Secure", insecure_uri),
                                         insecure_uri, NULL);

	/* Impersonator, value pretending to be prefixed. */
        soup_cookie_jar_add_cookie_full (jar, soup_cookie_parse ("=__Secure-Invalid; Path=/; Secure", secure_uri),
                                         secure_uri, NULL);

        cookies = soup_cookie_jar_all_cookies (jar);

        for (GSList *l = cookies; l; l = g_slist_next (l)) {
                SoupCookie *cookie = l->data;

                g_assert_true (strstr (soup_cookie_get_name (cookie), "Valid") != NULL);
        }

        /* In total we expect 4 valid cookies above. */
        g_assert_cmpuint (g_slist_length (cookies), ==, 4);

	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
	g_uri_unref (insecure_uri);
	g_uri_unref (secure_uri);
	g_object_unref (jar);
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

	session = soup_test_session_new (NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	jar = SOUP_COOKIE_JAR (soup_session_get_feature (session, SOUP_TYPE_COOKIE_JAR));

	/* "httponly" is case-insensitive, and its value (if any) is ignored */
	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Echo-Set-Cookie",
				     "one=1; httponly; max-age=100");
	soup_test_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Echo-Set-Cookie",
				     "two=2; HttpOnly; max-age=100; SameSite=Invalid");
	soup_test_session_send_message (session, msg);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", first_party_uri);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Echo-Set-Cookie",
				     "three=3; httpONLY=Wednesday; max-age=100; SameSite=Lax");
	soup_test_session_send_message (session, msg);
	g_object_unref (msg);

	cookies = soup_cookie_jar_get_cookie_list (jar, first_party_uri, TRUE);
	got1 = got2 = got3 = FALSE;

	for (iter = cookies; iter; iter = iter->next) {
		cookie = iter->data;

		if (!strcmp (soup_cookie_get_name (cookie), "one")) {
			got1 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
			g_assert_cmpint (soup_cookie_get_same_site_policy (cookie), ==, SOUP_SAME_SITE_POLICY_LAX);
		} else if (!strcmp (soup_cookie_get_name (cookie), "two")) {
			got2 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
			g_assert_cmpint (soup_cookie_get_same_site_policy (cookie), ==, SOUP_SAME_SITE_POLICY_LAX);
		} else if (!strcmp (soup_cookie_get_name (cookie), "three")) {
			got3 = TRUE;
			g_assert_true (soup_cookie_get_http_only (cookie));
			g_assert_true (soup_cookie_get_expires (cookie) != NULL);
			g_assert_cmpint (soup_cookie_get_same_site_policy (cookie), ==, SOUP_SAME_SITE_POLICY_LAX);
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

static void
do_cookies_parsing_nopath_nullorigin (void)
{
	SoupCookie *cookie = soup_cookie_parse ("NAME=Value", NULL);
	g_assert_nonnull (cookie);
	g_assert_cmpstr ("/", ==, soup_cookie_get_path (cookie));
	soup_cookie_free (cookie);
}

static void
do_cookies_parsing_max_age_int32_overflow (void)
{
	SoupCookie *cookie = soup_cookie_parse ("NAME=VALUE; Max-Age=2147483648", NULL);
	g_assert_nonnull (cookie);
	g_assert_cmpstr ("/", ==, soup_cookie_get_path (cookie));
	g_assert_true (soup_cookie_get_expires (cookie) != NULL);
	g_assert_true (g_date_time_to_unix (soup_cookie_get_expires (cookie)) > time (NULL));
	soup_cookie_free (cookie);
}

static void
do_cookies_parsing_max_age_long_overflow (void)
{
	SoupCookie *cookie = soup_cookie_parse ("NAME=VALUE; Max-Age=99999999999999999999999999999999999", NULL);
	g_assert_nonnull (cookie);
	g_assert_cmpstr ("/", ==, soup_cookie_get_path (cookie));
	g_assert_true (soup_cookie_get_expires (cookie) != NULL);
	g_assert_true (g_date_time_to_unix (soup_cookie_get_expires (cookie)) > time (NULL));
	soup_cookie_free (cookie);
}

static void
do_cookies_parsing_int32_overflow (void)
{
	SoupCookie *cookie = soup_cookie_parse ("Age=1;expires=3Mar9    999:9:9+ 999999999-age=main=gne=", NULL);
	g_test_bug ("https://gitlab.gnome.org/GNOME/libsoup/-/issues/448");
	g_assert_nonnull (cookie);
	g_assert_null (soup_cookie_get_expires (cookie));
	soup_cookie_free (cookie);
}

static void
do_cookies_parsing_invalid_timezone (void)
{
	SoupCookie *cookie = soup_cookie_parse ("NAME=VALUE;expires=Mon, 31 Dec 9999 23:59:59 -1000", NULL);
	g_test_bug ("https://gitlab.gnome.org/GNOME/libsoup/-/issues/459");
	g_assert_nonnull (cookie);
	g_assert_null (soup_cookie_get_expires (cookie));
	soup_cookie_free (cookie);
}

static void
do_cookies_equal_nullpath (void)
{
	SoupCookie *cookie1, *cookie2;

	cookie1 = soup_cookie_new ("one", "1", "127.0.0.1", NULL, 1000);
	cookie2 = soup_cookie_new ("one", "1", "127.0.0.1", "/foo", 1000);

	g_assert_false (soup_cookie_equal (cookie1, cookie2));

	soup_cookie_free (cookie1);
	soup_cookie_free (cookie2);
}

static void
do_cookies_parsing_control_characters (void)
{
	SoupCookieJar *jar;
	GSList *cookies;
	GUri *uri;
	char buf[256];
	int cntrl;

	uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	jar = soup_cookie_jar_new ();

	/* Cookies should not take control characters %x00-1F / %x7F in names or values, 
	 * with the exception of %x09 (the tab character). 
	 */
	for (cntrl = 0x01; cntrl <= 0x1F; cntrl++) {
		if (cntrl == 0x09)
			continue;

		g_snprintf (buf, sizeof(buf), "name%c%x=value%x", cntrl, cntrl, cntrl);
		soup_cookie_jar_set_cookie (jar, uri, buf);
		g_snprintf (buf, sizeof(buf), "name%x=value%c%x", cntrl, cntrl, cntrl);
		soup_cookie_jar_set_cookie (jar, uri, buf);

		cookies = soup_cookie_jar_all_cookies (jar);
		g_assert_cmpint (g_slist_length (cookies), ==,  0);
		g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
	}

	cntrl = 0x7F;
	g_snprintf (buf, sizeof(buf), "name%c%x=value%x", cntrl, cntrl, cntrl);
	soup_cookie_jar_set_cookie (jar, uri, buf);
	g_snprintf (buf, sizeof(buf), "name%x=value%c%x", cntrl, cntrl, cntrl);
	soup_cookie_jar_set_cookie (jar, uri, buf);
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==,  0);

	/* Cookies are accepted with a tab (\t) in name or value. */
	soup_cookie_jar_set_cookie (jar, uri, "name\x099=value9");
	soup_cookie_jar_set_cookie (jar, uri, "name9=value\x099");
	cookies = soup_cookie_jar_all_cookies (jar);
	g_assert_cmpint (g_slist_length (cookies), ==,  2);

	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
	g_uri_unref (uri);
	g_object_unref (jar);
}

static void
do_cookies_parsing_name_value_max_size (void)
{
        SoupCookie *cookie;
        const char *too_long_value = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        const char *longest_alone_value = too_long_value + 1;
        const char *longest_value_with_a_name = longest_alone_value + 1;
        char *name_and_value;

        cookie = soup_cookie_parse(too_long_value, NULL);
        g_assert_null (cookie);

        cookie = soup_cookie_parse(longest_alone_value, NULL);
        g_assert_nonnull (cookie);
        soup_cookie_free (cookie);

        name_and_value = g_strconcat("n=", longest_alone_value, NULL);
        cookie = soup_cookie_parse(name_and_value, NULL);
        g_assert_null (cookie);
        g_free (name_and_value);

        name_and_value = g_strconcat("n=", longest_value_with_a_name, NULL);
        cookie = soup_cookie_parse(name_and_value, NULL);
        g_assert_nonnull (cookie);
        soup_cookie_free (cookie);
        g_free (name_and_value);

        name_and_value = g_strconcat(longest_alone_value, "=", NULL);
        cookie = soup_cookie_parse(name_and_value, NULL);
        g_assert_nonnull (cookie);
        soup_cookie_free (cookie);
        g_free (name_and_value);
}

static void
do_get_cookies_empty_host_test (void)
{
	SoupCookieJar *jar;
	GUri *uri;
	char *cookies;

	jar = soup_cookie_jar_new ();
	uri = g_uri_parse ("file:///whatever.html", SOUP_HTTP_URI_FLAGS, NULL);

	cookies = soup_cookie_jar_get_cookies (jar, uri, FALSE);

	g_assert_null (cookies);

	g_object_unref (jar);
	g_uri_unref (uri);
}

static void
send_callback (GObject *source_object,
	       GAsyncResult *res,
	       GMainLoop *loop)
{
	g_main_loop_quit (loop);
}

static void
do_remove_feature_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;
	GMainLoop *loop;

	session = soup_test_session_new (NULL);
	soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	uri = g_uri_parse_relative (first_party_uri, "/index.html", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_set_first_party (msg, first_party_uri);

	loop = g_main_loop_new (NULL, TRUE);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL,
				 (GAsyncReadyCallback)send_callback, loop);
	soup_session_remove_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);

	g_main_loop_run(loop);

	g_main_loop_unref (loop);
	g_object_unref (msg);
	g_uri_unref (uri);
}

typedef struct {
        SoupSession *session;
        const char *cookie;
} ThreadTestData;

static void
task_sync_function (GTask          *task,
                    GObject        *source,
                    ThreadTestData *data,
                    GCancellable   *cancellable)
{
        SoupMessage *msg;
        GBytes *body;

        msg = soup_message_new_from_uri ("GET", first_party_uri);
        soup_message_headers_append (soup_message_get_request_headers (msg),
                                     "Echo-Set-Cookie", data->cookie);
        body = soup_session_send_and_read (data->session, msg, NULL, NULL);
        g_assert_nonnull (body);
        g_bytes_unref (body);
        g_object_unref (msg);

        g_task_return_boolean (task, TRUE);
}

static void
task_finished_cb (SoupSession  *session,
                  GAsyncResult *result,
                  guint        *finished_count)
{
        g_assert_true (g_task_propagate_boolean (G_TASK (result), NULL));
        g_atomic_int_inc (finished_count);
}

static void
do_cookies_db_init_failure_test (void)
{
	/* Pass a path that exists but is a directory — SQLite cannot open it */
	const char *bad_path = "/tmp";
	GError *error = NULL;
	SoupCookieJar *jar;

	jar = soup_cookie_jar_db_new_with_error (bad_path, FALSE, &error);
	g_assert_null (jar);
	g_assert_error (error, SOUP_COOKIE_JAR_ERROR, SOUP_COOKIE_JAR_ERROR_DB);
	g_clear_error (&error);

	/* Legacy new() must still return a non-NULL jar (compat) */
	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING, "Failed to open cookie jar database:*");
	SoupCookieJar *compat_jar = soup_cookie_jar_db_new (bad_path, FALSE);
	g_test_assert_expected_messages ();
	g_assert_nonnull (compat_jar);
	/* The jar has no open db, so it holds no cookies */
	GSList *cookies = soup_cookie_jar_all_cookies (compat_jar);
	g_assert_null (cookies);
	g_object_unref (compat_jar);
}

static gint
find_cookie (SoupCookie *cookie,
             const char *name)
{
        return g_strcmp0 (soup_cookie_get_name (cookie), name);
}

static void
do_cookies_threads_test (void)
{
        SoupSession *session;
        SoupCookieJar *jar;
        guint n_msgs = 4;
        guint finished_count = 0;
        guint i;
        const char *values[4] = { "one=1", "two=2", "three=3", "four=4" };
        GSList *cookies;

        session = soup_test_session_new (NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
        jar = SOUP_COOKIE_JAR (soup_session_get_feature (session, SOUP_TYPE_COOKIE_JAR));

        for (i = 0; i < n_msgs; i++) {
                GTask *task;
                ThreadTestData *data;

                data = g_new (ThreadTestData, 1);
                data->session = session;
                data->cookie = values[i];

                task = g_task_new (NULL, NULL, (GAsyncReadyCallback)task_finished_cb, &finished_count);
                g_task_set_source_tag (task, do_cookies_threads_test);
                g_task_set_task_data (task, data, g_free);
                g_task_run_in_thread (task, (GTaskThreadFunc)task_sync_function);
                g_object_unref (task);
        }

        while (g_atomic_int_get (&finished_count) != n_msgs)
                g_main_context_iteration (NULL, TRUE);

        cookies = soup_cookie_jar_get_cookie_list (jar, first_party_uri, TRUE);
        g_assert_cmpuint (g_slist_length (cookies), ==, 4);
        g_assert_nonnull (g_slist_find_custom (cookies, "one", (GCompareFunc)find_cookie));
        g_assert_nonnull (g_slist_find_custom (cookies, "two", (GCompareFunc)find_cookie));
        g_assert_nonnull (g_slist_find_custom (cookies, "three", (GCompareFunc)find_cookie));
        g_assert_nonnull (g_slist_find_custom (cookies, "four", (GCompareFunc)find_cookie));

        while (g_main_context_pending (NULL))
                g_main_context_iteration (NULL, FALSE);

        soup_cookies_free (cookies);
        soup_test_session_abort_unref (session);
}

/**
 * do_cookies_persistence_test:
 *
 * Test that cookies are saved in persistent storage medium
 */
static void
do_cookies_persistence_test (void)
{
	SoupCookieJar *jar;
	const char *value = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
	char buf[4096];
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;

	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);
	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);
	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);
	GUri *uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);
	const guint write_cookie_count = 10;

	for (guint i = 0; i < write_cookie_count; i++) {
		g_snprintf (buf, sizeof(buf), "%d=%s; Max-Age=2147483648", i, value);
		soup_cookie_jar_set_cookie (jar, uri, buf);
	}

	// Reopen database to get data effectively written to it, as soup_cookie_jar_set_cookie doesn't
	// return an error in case of write failure and we don't want to rely on failure to write log
	// messages being present or not to decide if the test passed or failed
	g_object_unref (jar);
	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);

	GSList *cookies = soup_cookie_jar_all_cookies (jar);
	guint stored_cookie_count = g_slist_length (cookies);

	g_assert_cmpuint (stored_cookie_count, ==, write_cookie_count);

	g_slist_free_full (cookies, (GDestroyNotify) soup_cookie_free);
	g_uri_unref (uri);
	g_object_unref (jar);
	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);
	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

/**
 * do_cookies_persistence_default_db_max_size_test:
 *
 * Test that default database max size is returned when no other was set
 */
static void
do_cookies_persistence_default_db_max_size_test (void)
{
	SoupCookieJar *jar;
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;

	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);

	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);

	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);

	// Test read using function API

	guint64 max_size = soup_cookie_jar_db_get_max_size (SOUP_COOKIE_JAR_DB(jar));
	g_assert_cmpuint (max_size, ==, 0);

	// Test read using object API
	g_object_get(G_OBJECT(jar), "max-size", &max_size, NULL);
	g_assert_cmpuint (max_size, ==, 0);

	g_object_unref (jar);
	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);
	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

typedef struct {
	guint64 size_requested;
	guint64 size_expected;
	guint write_cookie_count;
	guint min_cookie_count;
	guint max_cookie_count;
} CookiePersistenceMaxSizeStorageWriteTestData;

static const CookiePersistenceMaxSizeStorageWriteTestData cookie_persistence_max_size_storage_test_cases[] = {
	// Page size aligned to match exactly
	{ 5 * SQLITE_PAGE_SIZE, 5 * SQLITE_PAGE_SIZE, 10, 3, 6 },
	// Not aligned to page size to force size truncation
	{ 6 * SQLITE_PAGE_SIZE - 1, 5 * SQLITE_PAGE_SIZE, 10, 3, 6 },
	// Unlimited
	{ 0, 0, 10, 10, 10 },
};

/**
 * do_cookies_persistence_db_max_size_storage_test:
 *
 * Test that database max size is respected when set and that storage does not grow beyond it
 */
static void
do_cookies_persistence_db_max_size_storage_test (gconstpointer user_data)
{
	const CookiePersistenceMaxSizeStorageWriteTestData *test_data = user_data;
	SoupCookieJar *jar;
	const char *value = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
	char buf[4096];
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;

	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);

	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);

	// ******************************************************************************************
	// Phase 1: Configure max database size and try to write beyond it
	// ******************************************************************************************
	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);
	g_assert_nonnull (jar);
	soup_cookie_jar_db_set_max_size (SOUP_COOKIE_JAR_DB(jar), test_data->size_requested, &error);
	g_assert_no_error (error);

	GUri *uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);

	for (guint i = 0; i < test_data->write_cookie_count; i++) {
		g_snprintf (buf, sizeof(buf), "%d=%s; Max-Age=2147483648", i, value);
                g_test_expect_message("libsoup", G_LOG_LEVEL_WARNING, "Failed to execute query: database or disk is full");
		soup_cookie_jar_set_cookie (jar, uri, buf);
	}

	// ******************************************************************************************
	// Phase 2: Reopen database to get data effectively written to it, as the
	//          soup_cookie_jar_set_cookie doesn't return an error in case of write failure and
	//          we don't want to rely on failure to write log messages being present or not to
	//          decide if the test passed or failed. Verify database file size did not grow
	//          beyond the limit
	// ******************************************************************************************

	g_object_unref (jar);
	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);

	GSList *cookies = soup_cookie_jar_all_cookies (jar);
	guint stored_cookie_count = g_slist_length (cookies);

	g_slist_free_full (cookies, (GDestroyNotify) soup_cookie_free);

	// Exact number of cookies will depend on the database overhead to store the data. Give some margin
	// by using min and max values
	g_assert_cmpuint (stored_cookie_count, <=, test_data->max_cookie_count);
	g_assert_cmpuint (stored_cookie_count, >=, test_data->min_cookie_count);

	// Verify actual file size only if size is not unlimited
	if (test_data->size_expected > 0) {
		GFileInfo *info = g_file_query_info (cookies_file,
		                                     G_FILE_ATTRIBUTE_STANDARD_SIZE,
		                                     G_FILE_QUERY_INFO_NONE,
		                                     NULL,
		                                     &error);
		g_assert_no_error (error);
		g_assert_cmpuint (g_file_info_get_size(info), ==, test_data->size_expected);
		g_object_unref (info);
	}

	// Since the database was reopened, confirm that the max size has reverted to the default

	guint64 sqlite_max_size = 0; // Our API sets zero for unlimited
	guint64 max_size_read = soup_cookie_jar_db_get_max_size (SOUP_COOKIE_JAR_DB(jar));
	g_assert_cmpuint (max_size_read, ==, sqlite_max_size);

	// ******************************************************************************************
	// Phase 3: Verify that we can write beyond the previously set limit. This implies
	//          reopening the database again after the write to ensure data did not remain
	//          just in memory
	// ******************************************************************************************

	for (guint i = 0; i < test_data->write_cookie_count; i++) {
		g_snprintf (buf, sizeof(buf), "%d=%s; Max-Age=2147483648", i, value);
		soup_cookie_jar_set_cookie (jar, uri, buf);
	}

	g_object_unref (jar);
	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);

	cookies = soup_cookie_jar_all_cookies (jar);
	stored_cookie_count = g_slist_length (cookies);

	g_slist_free_full (cookies, (GDestroyNotify) soup_cookie_free);

	g_assert_cmpuint (stored_cookie_count, ==, test_data->write_cookie_count);

	// Check file size grew again beyond previously set limit (now reverted)
	GFileInfo *info = g_file_query_info (cookies_file,
		                                     G_FILE_ATTRIBUTE_STANDARD_SIZE,
		                                     G_FILE_QUERY_INFO_NONE,
		                                     NULL,
		                                     &error);
	g_assert_no_error (error);

	g_assert_cmpuint (g_file_info_get_size(info), >, test_data->size_expected);

	g_object_unref (info);
	g_uri_unref (uri);
	g_object_unref (jar);

	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);

	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

typedef struct {
	guint64 size_requested;
	guint64 size_expected;
	guint write_cookie_count;
	guint min_cookie_count;
	guint max_cookie_count;
} CookiePersistenceMaxSizeAtObjectCreationStorageWriteTestData;

static const CookiePersistenceMaxSizeAtObjectCreationStorageWriteTestData cookie_persistence_max_size_at_object_creation_storage_test_cases[] = {
	// Page size aligned to match exactly
	{ 5 * SQLITE_PAGE_SIZE, 5 * SQLITE_PAGE_SIZE, 10, 3, 6 },
	// Not aligned to page size to force size truncation
	{ 6 * SQLITE_PAGE_SIZE - 1, 5 * SQLITE_PAGE_SIZE, 10, 3, 6 },
	// Unlimited
	{  0, 0, 10, 10, 10 }
};
/**
 * do_cookies_persistence_db_max_size_at_object_creation_storage_test:
 *
 * Test that database max size is respected when set during object creation and that storage does
 * not grow beyond it
 */
static void
do_cookies_persistence_db_max_size_at_object_creation_storage_test (gconstpointer user_data)
{
	const CookiePersistenceMaxSizeAtObjectCreationStorageWriteTestData *test_data = user_data;
	SoupCookieJar *jar;
	const char *value = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
	char buf[4096];
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;


	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);
	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);

	// ******************************************************************************************
	// Phase 1: Configure max database size and try to write beyond it
	// ******************************************************************************************
	jar = g_object_new (SOUP_TYPE_COOKIE_JAR_DB,
						"filename", cookies_file_path,
						"read-only", FALSE,
						"max-size", test_data->size_requested,
						NULL);

	GUri *uri = g_uri_parse ("https://gnome.org", SOUP_HTTP_URI_FLAGS, NULL);

	for (guint i = 0; i < test_data->write_cookie_count; i++) {
		g_snprintf (buf, sizeof(buf), "%d=%s; Max-Age=2147483648", i, value);
		soup_cookie_jar_set_cookie (jar, uri, buf);
	}

	// ******************************************************************************************
	// Phase 2: Reopen database to get data effectively written to it, as the
	//          soup_cookie_jar_set_cookie doesn't return an error in case of write failure and
	//          we don't want to rely on failure to write log messages being present or not to
	//          decide if the test passed or failed. Verify database file size did not grow
	//          beyond the limit
	// ******************************************************************************************

	g_object_unref (jar);
	jar = g_object_new (SOUP_TYPE_COOKIE_JAR_DB,
						"filename", cookies_file_path,
						"read-only", FALSE,
						NULL);

	GSList *cookies = soup_cookie_jar_all_cookies (jar);
	guint stored_cookie_count = g_slist_length (cookies);

	g_slist_free_full (cookies, (GDestroyNotify) soup_cookie_free);

	// Exact number of cookies will depend on the database overhead to store the data. Give some margin
	// by using min and max values
	g_assert_cmpuint (stored_cookie_count, <=, test_data->max_cookie_count);
	g_assert_cmpuint (stored_cookie_count, >=, test_data->min_cookie_count);

	// Verify actual file size only if size is not unlimited
	if (test_data->size_expected > 0) {
		// Check file size matches expectation
		GFileInfo *info = g_file_query_info (cookies_file,
		                                     G_FILE_ATTRIBUTE_STANDARD_SIZE,
		                                     G_FILE_QUERY_INFO_NONE,
		                                     NULL,
		                                     &error);
		g_assert_no_error (error);

		g_assert_cmpuint (g_file_info_get_size(info), ==, test_data->size_expected);

		g_object_unref (info);
	}

	// Since the database was reopened, confirm that the max size has reverted to the default

	// Our API sets zero for unlimited
	guint64 sqlite_max_size = 0;
	guint64 max_size_read = G_MAXUINT32;

	g_object_get(G_OBJECT(jar), "max-size", &max_size_read, NULL);

	g_assert_cmpuint (max_size_read, ==, sqlite_max_size);

	// ******************************************************************************************
	// Phase 3: Verify that we can write beyond the previously set limit. This implies
	//          reopening the database again after the write to ensure data did not remain
	//          just in memory
	// ******************************************************************************************

	for (guint i = 0; i < test_data->write_cookie_count; i++) {
		g_snprintf (buf, sizeof(buf), "%d=%s; Max-Age=2147483648", i, value);
		soup_cookie_jar_set_cookie (jar, uri, buf);
	}

	g_object_unref (jar);
	jar = g_object_new (SOUP_TYPE_COOKIE_JAR_DB,
						"filename", cookies_file_path,
						"read-only", FALSE,
						NULL);

	cookies = soup_cookie_jar_all_cookies (jar);
	stored_cookie_count = g_slist_length (cookies);
	g_slist_free_full (cookies, (GDestroyNotify) soup_cookie_free);

	g_assert_cmpuint (stored_cookie_count, ==, test_data->write_cookie_count);

	// Check file size grew again beyond previously set limit (now reverted)
	GFileInfo *info = g_file_query_info (cookies_file,
		                                     G_FILE_ATTRIBUTE_STANDARD_SIZE,
		                                     G_FILE_QUERY_INFO_NONE,
		                                     NULL,
		                                     &error);
	g_assert_no_error (error);

	g_assert_cmpuint (g_file_info_get_size(info), >, test_data->size_expected);

	g_object_unref (info);
	g_uri_unref (uri);
	g_object_unref (jar);
	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);
	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

typedef struct {
	guint64 size_requested;
	guint64 size_expected;
} CookiePersistenceMaxSizeValuesTestData;

static const CookiePersistenceMaxSizeValuesTestData cookie_persistence_max_size_values_test_cases[] = {
	// Page size aligned to match exactly
	{ 10 * SQLITE_PAGE_SIZE, 10 * SQLITE_PAGE_SIZE },
	// Not aligned to page size to force size truncation
	{ 10 * SQLITE_PAGE_SIZE + 100, 10 * SQLITE_PAGE_SIZE },
	// Exceeding max database supported size (maximum size, rounded down)
	{ G_MAXUINT64, SQLITE_MAX_PAGE_COUNT * SQLITE_PAGE_SIZE },
	// Unlimited
	{ 0, 0 },
};

static void
do_cookies_persistence_db_max_size_values_test (gconstpointer user_data)
{
	const CookiePersistenceMaxSizeValuesTestData *test_data = user_data;
	SoupCookieJarDB *jar;
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;

	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);

	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);

	jar = g_object_new (SOUP_TYPE_COOKIE_JAR_DB, "filename", cookies_file_path,
		               "max-size", test_data->size_requested, NULL);

	g_assert_cmpuint (soup_cookie_jar_db_get_max_size (jar), ==, test_data->size_expected);

	g_object_unref (jar);
	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);
	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

typedef struct {
	guint notify_count;
} NotifyData;

static void
on_notify(GObject *obj, GParamSpec *pspec, gpointer user_data)
{
	NotifyData *data = user_data;

	if (g_str_equal (pspec->name, "max-size")) {
		data->notify_count++;
    }
}

typedef struct {
	guint64 size_requested1;
	guint64 notify_count_expected1;
	guint64 size_requested2;
	guint notify_count_expected2;
} CookiePersistenceMaxSizeNotifyTestData;

static const CookiePersistenceMaxSizeNotifyTestData cookie_persistence_max_size_notify_test_cases[] = {
	{10 * SQLITE_PAGE_SIZE, 1, 10 * SQLITE_PAGE_SIZE, 1 },
	{10 * SQLITE_PAGE_SIZE, 1, 20 * SQLITE_PAGE_SIZE, 2 },
	{10 * SQLITE_PAGE_SIZE, 1, 0, 2 },
	{ 0, 0, 10 * SQLITE_PAGE_SIZE, 1 },
};

static void
do_cookies_persistence_db_max_size_notify_test (gconstpointer user_data)
{
	const CookiePersistenceMaxSizeNotifyTestData *test_data = user_data;
	SoupCookieJar *jar;
	GFileIOStream *cookies_file_stream = NULL;
	GError *error = NULL;

	GFile *cookies_file = g_file_new_tmp ("cookies.sqlite.XXXXXX", &cookies_file_stream, &error);

	g_assert_no_error (error);

	// Closing only the stream handle to allow file to be opened by soup implementation, but
	// keeping file handle as we still need it later to check file size. The file will not be
	// deleted automatically so there is no risk of a race condition with other system processes
	// creating same temp file (despite unlikely anyway)
	g_object_unref (cookies_file_stream);

	char *cookies_file_path = g_file_get_path (cookies_file);

	jar = soup_cookie_jar_db_new (cookies_file_path, FALSE);

	NotifyData notify_data = {0};

	g_signal_connect(jar, "notify::max-size", G_CALLBACK (on_notify), &notify_data);

	soup_cookie_jar_db_set_max_size (SOUP_COOKIE_JAR_DB(jar), test_data->size_requested1, NULL);
	g_assert_cmpuint (notify_data.notify_count, ==, test_data->notify_count_expected1);
	soup_cookie_jar_db_set_max_size (SOUP_COOKIE_JAR_DB(jar), test_data->size_requested2, NULL);
	g_assert_cmpuint (notify_data.notify_count, ==, test_data->notify_count_expected2);

	g_object_unref (jar);
	g_file_delete (cookies_file, NULL, &error);
	g_assert_no_error (error);
	g_free (cookies_file_path);
	g_object_unref (cookies_file);
}

int
main (int argc, char **argv)
{
	GUri *server_uri;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	server_uri = soup_test_server_get_uri (server, "http", NULL);

	first_party_uri = g_uri_build (SOUP_HTTP_URI_FLAGS, "http", NULL, "127.0.0.1",
                                       g_uri_get_port (server_uri), "/", NULL, NULL);
        third_party_uri = g_uri_build (SOUP_HTTP_URI_FLAGS, "http", NULL, "localhost",
                                       g_uri_get_port (server_uri), "/", NULL, NULL);

	g_test_add_func ("/cookies/accept-policy", do_cookies_accept_policy_test);
	g_test_add_func ("/cookies/accept-policy-subdomains", do_cookies_subdomain_policy_test);
	g_test_add_func ("/cookies/parsing", do_cookies_parsing_test);
	g_test_add_func ("/cookies/parsing/no-path-null-origin", do_cookies_parsing_nopath_nullorigin);
	g_test_add_func ("/cookies/parsing/max-age-int32-overflow", do_cookies_parsing_max_age_int32_overflow);
	g_test_add_func ("/cookies/parsing/max-age-long-overflow", do_cookies_parsing_max_age_long_overflow);
	g_test_add_func ("/cookies/parsing/int32-overflow", do_cookies_parsing_int32_overflow);
	g_test_add_func ("/cookies/parsing/invalid-timezone", do_cookies_parsing_invalid_timezone);
	g_test_add_func ("/cookies/parsing/equal-nullpath", do_cookies_equal_nullpath);
	g_test_add_func ("/cookies/parsing/control-characters", do_cookies_parsing_control_characters);
        g_test_add_func ("/cookies/parsing/name-value-max-size", do_cookies_parsing_name_value_max_size);
	g_test_add_func ("/cookies/get-cookies/empty-host", do_get_cookies_empty_host_test);
	g_test_add_func ("/cookies/remove-feature", do_remove_feature_test);
	g_test_add_func ("/cookies/secure-cookies", do_cookies_strict_secure_test);
	g_test_add_func ("/cookies/prefix", do_cookies_prefix_test);
        g_test_add_func ("/cookies/threads", do_cookies_threads_test);
	g_test_add_func ("/cookies/db-jar/init-failure", do_cookies_db_init_failure_test);
	g_test_add_func ("/cookies/db-jar/persistence", do_cookies_persistence_test);
	g_test_add_func ("/cookies/db-jar/persistence/max-size-default", do_cookies_persistence_default_db_max_size_test);

	for (guint i = 0; i < G_N_ELEMENTS (cookie_persistence_max_size_storage_test_cases); i++) {
		gchar *name = g_strdup_printf ("/cookies/db-jar/persistence/max-size-storage/%u", i);
		g_test_add_data_func (name, &cookie_persistence_max_size_storage_test_cases[i], do_cookies_persistence_db_max_size_storage_test);
		g_free (name);
	}

	for (guint i = 0; i < G_N_ELEMENTS (cookie_persistence_max_size_at_object_creation_storage_test_cases); i++) {
		gchar *name = g_strdup_printf ("/cookies/db-jar/persistence/max-size-storage-at-object-creation/%u", i);
		g_test_add_data_func (name, &cookie_persistence_max_size_at_object_creation_storage_test_cases[i], do_cookies_persistence_db_max_size_at_object_creation_storage_test);
		g_free (name);
	}

	for (guint i = 0; i < G_N_ELEMENTS (cookie_persistence_max_size_values_test_cases); i++) {
		gchar *name = g_strdup_printf ("/cookies/db-jar/persistence/max-size-values/%u", i);
		g_test_add_data_func (name, &cookie_persistence_max_size_values_test_cases[i], do_cookies_persistence_db_max_size_values_test);
		g_free (name);
	}

	for (guint i = 0; i < G_N_ELEMENTS (cookie_persistence_max_size_notify_test_cases); i++) {
		gchar *name = g_strdup_printf ("/cookies/db-jar/persistence/max-size-notify/%u", i);
		g_test_add_data_func (name, &cookie_persistence_max_size_notify_test_cases[i], do_cookies_persistence_db_max_size_notify_test);
		g_free (name);
	}


	ret = g_test_run ();

	g_uri_unref (first_party_uri);
	g_uri_unref (third_party_uri);
	g_uri_unref (server_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
