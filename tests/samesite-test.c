/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

typedef struct {
	SoupURI *origin_uri;
	SoupURI *cross_uri;
	SoupCookieJar *jar;
	GSList *cookies;
} SameSiteFixture;

static void
same_site_setup (SameSiteFixture *fixture,
                 gconstpointer    data)
{
	SoupCookie *cookie_none, *cookie_lax, *cookie_strict;

	fixture->origin_uri = soup_uri_new ("http://127.0.0.1");
	fixture->cross_uri = soup_uri_new ("http://localhost");
	fixture->jar = soup_cookie_jar_new ();

	cookie_none = soup_cookie_new ("none", "1", "127.0.0.1", "/", 1000);
	cookie_lax = soup_cookie_new ("lax", "1", "127.0.0.1", "/", 1000);
	soup_cookie_set_same_site_policy (cookie_lax, SOUP_SAME_SITE_POLICY_LAX);
	cookie_strict = soup_cookie_new ("strict", "1", "127.0.0.1", "/", 1000);
	soup_cookie_set_same_site_policy (cookie_strict, SOUP_SAME_SITE_POLICY_STRICT);

	soup_cookie_jar_add_cookie_with_first_party (fixture->jar, fixture->origin_uri, cookie_none);
	soup_cookie_jar_add_cookie_with_first_party (fixture->jar, fixture->origin_uri, cookie_lax);
	soup_cookie_jar_add_cookie_with_first_party (fixture->jar, fixture->origin_uri, cookie_strict);
}

static void
same_site_teardown (SameSiteFixture *fixture,
                    gconstpointer    data)
{
	g_object_unref (fixture->jar);
	soup_uri_free (fixture->origin_uri);
	soup_uri_free (fixture->cross_uri);
	g_slist_free_full (fixture->cookies, (GDestroyNotify) soup_cookie_free);
}

static void
assert_highest_policy_visible (GSList *cookies, SoupSameSitePolicy policy)
{
	GSList *l;
	size_t size = 0, expected_count;
	for (l = cookies; l; l = l->next) {
		g_assert_cmpint (soup_cookie_get_same_site_policy (l->data), <=, policy);
		++size;
	}

	switch (policy) {
	case SOUP_SAME_SITE_POLICY_STRICT:
		expected_count = 3;
		break;
	case SOUP_SAME_SITE_POLICY_LAX:
		expected_count = 2;
		break;
	case SOUP_SAME_SITE_POLICY_NONE:
		expected_count = 1;
		break;
	}

	g_assert_cmpuint (size, ==, expected_count);
}

typedef struct {
	const char *name;
	gboolean cross_origin;
	gboolean cookie_uri_is_origin;
	gboolean top_level_nav;
	gboolean javascript;
	gboolean unsafe_method;
	SoupSameSitePolicy visible_policy;
} SameSiteTest;

static void
same_site_test (SameSiteFixture *fixture, gconstpointer user_data)
{
	const SameSiteTest *test = user_data;
	fixture->cookies = soup_cookie_jar_get_cookie_list_with_same_site_info (fixture->jar, fixture->origin_uri,
	                                                                        test->cross_origin ? fixture->cross_uri : fixture->origin_uri,
	                                                                        test->cookie_uri_is_origin ? fixture->origin_uri : NULL,
	                                                                        test->javascript ? FALSE : TRUE,
	                                                                        !test->unsafe_method,
	                                                                        test->top_level_nav);
	assert_highest_policy_visible (fixture->cookies, test->visible_policy);
}

int
main (int argc, char **argv)
{
	int ret, i;
	SameSiteTest same_site_tests[] = {
		/* This does not necessarily cover all combinations since some make no sense in real use */

		/* Situations where Strict are passed: */
		{ .name="/same-site/basic", .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/basic-js", .javascript=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/top-level-to-same-site", .top_level_nav=TRUE,  .cookie_uri_is_origin=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/top-level-to-same-site-js", .top_level_nav=TRUE, .cookie_uri_is_origin=TRUE,  .javascript=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/unsafe-method", .unsafe_method=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/unsafe-method-js", .unsafe_method=TRUE, .javascript=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/cross-top-level-to-same-site", .cross_origin=TRUE, .top_level_nav=TRUE, .cookie_uri_is_origin=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },
		{ .name="/same-site/cross-top-level-to-same-site-js", .cross_origin=TRUE, .javascript=TRUE, .top_level_nav=TRUE, .cookie_uri_is_origin=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_STRICT },

		/* Situations where Lax are passed: */
		{ .name="/same-site/top-level", .top_level_nav=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_LAX },
		{ .name="/same-site/top-level-js", .top_level_nav=TRUE, .javascript=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_LAX },
		{ .name="/same-site/cross-top-level", .cross_origin=TRUE, .top_level_nav=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_LAX },
		{ .name="/same-site/cross-top-level-js", .cross_origin=TRUE, .javascript=TRUE, .top_level_nav=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_LAX },
		{ .name="/same-site/cross-unsafe-method-top-level-js", .cross_origin=TRUE, .javascript=TRUE, .unsafe_method=TRUE, .top_level_nav=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_LAX },

		/* All same-site blocked: */
		{ .name="/same-site/cross-basic", .cross_origin=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_NONE },
		{ .name="/same-site/cross-basic-js", .cross_origin=TRUE, .javascript=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_NONE },
		{ .name="/same-site/cross-unsafe-method", .cross_origin=TRUE, .unsafe_method=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_NONE },
		{ .name="/same-site/cross-unsafe-method-js", .cross_origin=TRUE, .javascript=TRUE, .unsafe_method=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_NONE },
		{ .name="/same-site/cross-unsafe-method-top-level", .cross_origin=TRUE, .unsafe_method=TRUE, .top_level_nav=TRUE, .visible_policy=SOUP_SAME_SITE_POLICY_NONE },
	};

	test_init (argc, argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (same_site_tests); ++i)
		g_test_add (same_site_tests[i].name, SameSiteFixture, &same_site_tests[i],
		            same_site_setup, same_site_test, same_site_teardown);

	ret = g_test_run ();
	test_cleanup ();
	return ret;
}
