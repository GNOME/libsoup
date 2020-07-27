/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static struct {
	const char *one, *two;
        gboolean equal;
        GUriFlags flags_one, flags_two;
} eq_tests[] = {
        // NOTE: GUri doesn't remove dot segments from absolute URIs
	// { "example://a/b/c/%7Bfoo%7D", "eXAMPLE://a/./b/../b/%63/%7Bfoo%7D", "628728" },
	{ "http://example.com", "http://example.com/", TRUE,
          SOUP_HTTP_URI_FLAGS, SOUP_HTTP_URI_FLAGS },
	/* From RFC 2616 */
	{ "http://abc.com:80/~smith/home.html", "http://abc.com:80/~smith/home.html", TRUE,
          SOUP_HTTP_URI_FLAGS, SOUP_HTTP_URI_FLAGS },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com/%7Esmith/home.html", TRUE,
          SOUP_HTTP_URI_FLAGS, SOUP_HTTP_URI_FLAGS },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com:/%7esmith/home.html", TRUE,
          SOUP_HTTP_URI_FLAGS, SOUP_HTTP_URI_FLAGS },
        /* Test flags affecting comparisons */
        { "http://example.com/%2F", "http://example.com/%2F", FALSE,
          G_URI_FLAGS_ENCODED_PATH, G_URI_FLAGS_NONE },
        { "http://example.com/%2F", "http://example.com/%2F", TRUE,
          G_URI_FLAGS_PARSE_RELAXED, G_URI_FLAGS_NONE },
        { "http://example.com/%2F", "http://example.com/%2F", TRUE,
          G_URI_FLAGS_PARSE_RELAXED, G_URI_FLAGS_HAS_PASSWORD },
};
static int num_eq_tests = G_N_ELEMENTS(eq_tests);

static void
do_equality_tests (void)
{
	GUri *uri1, *uri2;
	int i;

	for (i = 0; i < num_eq_tests; i++) {
		uri1 = g_uri_parse (eq_tests[i].one, eq_tests[i].flags_one, NULL);
		uri2 = g_uri_parse (eq_tests[i].two, eq_tests[i].flags_two, NULL);

		debug_printf (1, "<%s> %c= <%s>\n", eq_tests[i].one, eq_tests[i].equal ? '=' : '!', eq_tests[i].two);
                g_assert_cmpint (soup_uri_equal (uri1, uri2), ==, eq_tests[i].equal);

		g_uri_unref (uri1);
		g_uri_unref (uri2);
	}
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/uri/equality", do_equality_tests);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
