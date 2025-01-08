/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"
#include "soup-uri-utils-private.h"

static struct {
	const char *one, *two;
        gboolean equal;
        GUriFlags flags_one, flags_two;
} eq_tests[] = {
	{ "example://a/b/c/%7Bfoo%7D", "eXAMPLE://a/./b/../b/%63/%7Bfoo%7D", TRUE,
          SOUP_HTTP_URI_FLAGS, SOUP_HTTP_URI_FLAGS },
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

static void
do_copy_tests (void)
{
        GUri *uri;
        GUri *uri2;
        GUri *copy;
        char *str;

        uri = g_uri_parse ("http://127.0.0.1:1234/foo#bar", SOUP_HTTP_URI_FLAGS, NULL);
        uri2 = g_uri_parse ("http://127.0.0.1", SOUP_HTTP_URI_FLAGS, NULL);

        /* Exact copy */
        copy = soup_uri_copy (uri, SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "http://127.0.0.1:1234/foo#bar");
        g_free (str);
        g_uri_unref (copy);

        /* Update the path */
        copy = soup_uri_copy (uri, SOUP_URI_PATH, "/baz", SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "http://127.0.0.1:1234/baz#bar");
        g_free (str);
        g_uri_unref (copy);

        /* Add credentials */
        copy = soup_uri_copy (uri, SOUP_URI_USER, "user", SOUP_URI_PASSWORD, "password", SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "http://user:password@127.0.0.1:1234/foo#bar");
        g_free (str);
        g_uri_unref (copy);

        /* Remove the fragment and add a query */
        copy = soup_uri_copy (uri, SOUP_URI_FRAGMENT, NULL, SOUP_URI_QUERY, "baz=1", SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "http://127.0.0.1:1234/foo?baz=1");
        g_free (str);
        g_uri_unref (copy);

        /* Update host and port */
        copy = soup_uri_copy (uri, SOUP_URI_HOST, "localhost", SOUP_URI_PORT, -1, SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "http://localhost/foo#bar");
        g_free (str);
        g_uri_unref (copy);

        /* Switch protocols without explicit port */
        copy = soup_uri_copy (uri2, SOUP_URI_SCHEME, "https", SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "https://127.0.0.1/");
        g_free (str);
        g_uri_unref (copy);

        /* Update everything */
        copy = soup_uri_copy (uri,
                              SOUP_URI_SCHEME, "https",
                              SOUP_URI_USER, "user",
                              SOUP_URI_PASSWORD, "password",
                              SOUP_URI_HOST, "localhost",
                              SOUP_URI_PORT, 4321,
                              SOUP_URI_PATH, "/baz",
                              SOUP_URI_FRAGMENT, "foo",
                              SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "https://user:password@localhost:4321/baz#foo");
        g_free (str);
        g_uri_unref (copy);

        /* Convert to file */
        copy = soup_uri_copy (uri, SOUP_URI_SCHEME, "file", SOUP_URI_HOST, "", SOUP_URI_PORT, -1, SOUP_URI_FRAGMENT, NULL, SOUP_URI_NONE);
        str = g_uri_to_string (copy);
        g_assert_cmpstr (str, ==, "file:///foo");
        g_free (str);
        g_uri_unref (copy);

        g_uri_unref (uri);
        g_uri_unref (uri2);
}

#define CONTENT_TYPE_DEFAULT "text/plain;charset=US-ASCII"

static struct {
	const char *input;
        const char *output;
        const char *content_type;
} data_uri_tests[] = {
        { "invalid:", NULL, NULL },
        { "data:", "", CONTENT_TYPE_DEFAULT },
        { "data:hello", "hello", CONTENT_TYPE_DEFAULT },
        { "data:text/plain,hello", "hello", "text/plain" },
        { "data:text/plain;charset=UTF-8,hello", "hello", "text/plain;charset=UTF-8" },
        { "data:text/plain;base64,aGVsbG8=", "hello", "text/plain" },
        { "data:text/plain;base64,invalid=", "", "text/plain" },
        { "data:,", "", CONTENT_TYPE_DEFAULT },
        { "data:.///", "./", CONTENT_TYPE_DEFAULT },
        { "data:/.//", "./", CONTENT_TYPE_DEFAULT },
};

static void
do_data_uri_tests (void)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (data_uri_tests); i++) {
                char *content_type = NULL;
                GBytes *output = soup_uri_decode_data_uri (data_uri_tests[i].input, &content_type);

                if (data_uri_tests[i].output == NULL) {
                        g_assert_null (output);
                        g_assert_null (content_type);
                        continue;
                }

                g_assert_nonnull (output);
                g_assert_cmpstr (content_type, ==, data_uri_tests[i].content_type);

		g_free (content_type);
		g_bytes_unref (output);
	}
}

static struct {
        const char *input;
        const char *output;
} path_and_query_tests[] = {
        { "https://simple/one?two", "/one?two" },
        { "https://double_path//one?two", "//one?two" },
        { "https://empty", "/" },
        { "https://only_query/?two", "/?two" },
        { "https://trailing_query/one?", "/one?" },
        { "https://path_only/one", "/one" },
};

static void
do_path_and_query_tests (void)
{
        for (int i = 0; i < G_N_ELEMENTS (path_and_query_tests); i++) {
                GUri *uri = g_uri_parse (path_and_query_tests[i].input, SOUP_HTTP_URI_FLAGS, NULL);
                g_assert_nonnull (uri);

                char *path_and_query = soup_uri_get_path_and_query (uri);
                g_assert_cmpstr (path_and_query, ==, path_and_query_tests[i].output);

                g_free (path_and_query);
                g_uri_unref (uri);
        }
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/uri/equality", do_equality_tests);
	g_test_add_func ("/uri/copy", do_copy_tests);
        g_test_add_func ("/data", do_data_uri_tests);
        g_test_add_func ("/path_and_query", do_path_and_query_tests);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
