/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static struct {
	const char *uri_string, *result;
	const SoupURI bits;
} abs_tests[] = {
	{ "foo:", "foo:",
	  { "foo", NULL, NULL, NULL, 0, "", NULL, NULL } },
	{ "file:/dev/null", "file:/dev/null",
	  { "file", NULL, NULL, NULL, 0, "/dev/null", NULL, NULL } },
	{ "file:///dev/null", "file:///dev/null",
	  { "file", NULL, NULL, "", 0, "/dev/null", NULL, NULL } },
	{ "ftp://user@host/path", "ftp://user@host/path",
	  { "ftp", "user", NULL, "host", 21, "/path", NULL, NULL } },
	{ "ftp://user@host:9999/path", "ftp://user@host:9999/path",
	  { "ftp", "user", NULL, "host", 9999, "/path", NULL, NULL } },
	{ "ftp://user:password@host/path", "ftp://user@host/path",
	  { "ftp", "user", "password", "host", 21, "/path", NULL, NULL } },
	{ "ftp://user:password@host:9999/path", "ftp://user@host:9999/path",
	  { "ftp", "user", "password", "host", 9999, "/path", NULL, NULL } },
	{ "ftp://user:password@host", "ftp://user@host",
	  { "ftp", "user", "password", "host", 21, "", NULL, NULL } },
	{ "http://us%65r@host", "http://user@host/",
	  { "http", "user", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%40r@host", "http://us%40r@host/",
	  { "http", "us\x40r", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%3ar@host", "http://us%3Ar@host/",
	  { "http", "us\x3ar", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%2fr@host", "http://us%2Fr@host/",
	  { "http", "us\x2fr", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://us%3fr@host", "http://us%3Fr@host/",
	  { "http", "us\x3fr", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://host?query", "http://host/?query",
	  { "http", NULL, NULL, "host", 80, "/", "query", NULL } },
	{ "http://host/path?query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value",
	  "http://host/path?query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value",
	  { "http", NULL, NULL, "host", 80, "/path", "query=http%3A%2F%2Fhost%2Fpath%3Fchildparam%3Dchildvalue&param=value", NULL } },
	{ "http://control-chars/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F",
	  "http://control-chars/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F",
	  { "http", NULL, NULL, "control-chars", 80, "/%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F%7F", NULL, NULL } },
	{ "http://space/%20",
	  "http://space/%20",
	  { "http", NULL, NULL, "space", 80, "/%20", NULL, NULL } },
	{ "http://delims/%3C%3E%23%25%22",
	  "http://delims/%3C%3E%23%25%22",
	  { "http", NULL, NULL, "delims", 80, "/%3C%3E%23%25%22", NULL, NULL } },
	{ "http://unwise-chars/%7B%7D%7C%5C%5E%5B%5D%60",
	  "http://unwise-chars/%7B%7D%7C%5C%5E%5B%5D%60",
	  { "http", NULL, NULL, "unwise-chars", 80, "/%7B%7D%7C%5C%5E%5B%5D%60", NULL, NULL } },

	/* From RFC 2732 */
	{ "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html",
	  "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/index.html",
	  { "http", NULL, NULL, "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", 80, "/index.html", NULL, NULL } },
	{ "http://[1080:0:0:0:8:800:200C:417A]/index.html",
	  "http://[1080:0:0:0:8:800:200C:417A]/index.html",
	  { "http", NULL, NULL, "1080:0:0:0:8:800:200C:417A", 80, "/index.html", NULL, NULL } },
	{ "http://[3ffe:2a00:100:7031::1]",
	  "http://[3ffe:2a00:100:7031::1]/",
	  { "http", NULL, NULL, "3ffe:2a00:100:7031::1", 80, "/", NULL, NULL } },
	{ "http://[1080::8:800:200C:417A]/foo",
	  "http://[1080::8:800:200C:417A]/foo",
	  { "http", NULL, NULL, "1080::8:800:200C:417A", 80, "/foo", NULL, NULL } },
	{ "http://[::192.9.5.5]/ipng",
	  "http://[::192.9.5.5]/ipng",
	  { "http", NULL, NULL, "::192.9.5.5", 80, "/ipng", NULL, NULL } },
	{ "http://[::FFFF:129.144.52.38]:80/index.html",
	  "http://[::FFFF:129.144.52.38]/index.html",
	  { "http", NULL, NULL, "::FFFF:129.144.52.38", 80, "/index.html", NULL, NULL } },
	{ "http://[2010:836B:4179::836B:4179]",
	  "http://[2010:836B:4179::836B:4179]/",
	  { "http", NULL, NULL, "2010:836B:4179::836B:4179", 80, "/", NULL, NULL } },

	/* Try to recover certain kinds of invalid URIs */
	{ "http://host/path with spaces",
	  "http://host/path%20with%20spaces",
	  { "http", NULL, NULL, "host", 80, "/path%20with%20spaces", NULL, NULL } },
	{ "  http://host/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://host/path  ", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://host  ", "http://host/",
	  { "http", NULL, NULL, "host", 80, "/", NULL, NULL } },
	{ "http://host:999  ", "http://host:999/",
	  { "http", NULL, NULL, "host", 999, "/", NULL, NULL } },
	{ "http://host/pa\nth", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http:\r\n//host/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },
	{ "http://\thost/path", "http://host/path",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, NULL } },

	/* Bug 594405; 0-length is different from not-present */
	{ "http://host/path?", "http://host/path?",
	  { "http", NULL, NULL, "host", 80, "/path", "", NULL } },
	{ "http://host/path#", "http://host/path#",
	  { "http", NULL, NULL, "host", 80, "/path", NULL, "" } },

	/* Bug 590524; ignore badly-%-encoding */
	{ "http://host/path%", "http://host/path%",
	  { "http", NULL, NULL, "host", 80, "/path%", NULL, NULL } },
	{ "http://h%ost/path", "http://h%25ost/path",
	  { "http", NULL, NULL, "h%ost", 80, "/path", NULL, NULL } },
	{ "http://host/path%%", "http://host/path%%",
	  { "http", NULL, NULL, "host", 80, "/path%%", NULL, NULL } },
	{ "http://host/path%%%", "http://host/path%%%",
	  { "http", NULL, NULL, "host", 80, "/path%%%", NULL, NULL } },
	{ "http://host/path%/x/", "http://host/path%/x/",
	  { "http", NULL, NULL, "host", 80, "/path%/x/", NULL, NULL } },
	{ "http://host/path%0x/", "http://host/path%0x/",
	  { "http", NULL, NULL, "host", 80, "/path%0x/", NULL, NULL } },
	{ "http://host/path%ax", "http://host/path%ax",
	  { "http", NULL, NULL, "host", 80, "/path%ax", NULL, NULL } },

	/* Bug 662806; %-encode non-ASCII characters */
	{ "http://host/p\xc3\xa4th/", "http://host/p%C3%A4th/",
	  { "http", NULL, NULL, "host", 80, "/p%C3%A4th/", NULL, NULL } },

	{ "HTTP:////////////////", "http:////////////////",
	  { "http", NULL, NULL, "", 80, "//////////////", NULL, NULL } },

	{ "http://@host", "http://@host/",
	  { "http", "", NULL, "host", 80, "/", NULL, NULL } },
	{ "http://:@host", "http://@host/",
	  { "http", "", "", "host", 80, "/", NULL, NULL } },

	{ "http://host/keep%00nuls", "http://host/keep%00nuls",
	  { "http", NULL, NULL, "host", 80, "/keep%00nuls", NULL, NULL } },
};
static int num_abs_tests = G_N_ELEMENTS(abs_tests);

/* From RFC 3986. */
static const char *base = "http://a/b/c/d;p?q";
static struct {
	const char *uri_string, *result;
	const SoupURI bits;
} rel_tests[] = {
	{ "g:h", "g:h",
	  { "g", NULL, NULL, NULL, 0, "h", NULL, NULL } },
	{ "g", "http://a/b/c/g",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, NULL } },
	{ "./g", "http://a/b/c/g",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, NULL } },
	{ "g/", "http://a/b/c/g/",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/", NULL, NULL } },
	{ "/g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "//g", "http://g/",
	  { "http", NULL, NULL, "g", 80, "/", NULL, NULL } },
	{ "?y", "http://a/b/c/d;p?y",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "y", NULL } },
	{ "g?y", "http://a/b/c/g?y",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y", NULL } },
	{ "#s", "http://a/b/c/d;p?q#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "q", "s" } },
	{ "g#s", "http://a/b/c/g#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s" } },
	{ "g?y#s", "http://a/b/c/g?y#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y", "s" } },
	{ ";x", "http://a/b/c/;x",
	  { "http", NULL, NULL, "a", 80, "/b/c/;x", NULL, NULL } },
	{ "g;x", "http://a/b/c/g;x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x", NULL, NULL } },
	{ "g;x?y#s", "http://a/b/c/g;x?y#s",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x", "y", "s" } },
	{ ".", "http://a/b/c/",
	  { "http", NULL, NULL, "a", 80, "/b/c/", NULL, NULL } },
	{ "./", "http://a/b/c/",
	  { "http", NULL, NULL, "a", 80, "/b/c/", NULL, NULL } },
	{ "..", "http://a/b/",
	  { "http", NULL, NULL, "a", 80, "/b/", NULL, NULL } },
	{ "../", "http://a/b/",
	  { "http", NULL, NULL, "a", 80, "/b/", NULL, NULL } },
	{ "../g", "http://a/b/g",
	  { "http", NULL, NULL, "a", 80, "/b/g", NULL, NULL } },
	{ "../..", "http://a/",
	  { "http", NULL, NULL, "a", 80, "/", NULL, NULL } },
	{ "../../", "http://a/",
	  { "http", NULL, NULL, "a", 80, "/", NULL, NULL } },
	{ "../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "", "http://a/b/c/d;p?q",
	  { "http", NULL, NULL, "a", 80, "/b/c/d;p", "q", NULL } },
	{ "../../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "../../../../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "/./g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "/../g", "http://a/g",
	  { "http", NULL, NULL, "a", 80, "/g", NULL, NULL } },
	{ "g.", "http://a/b/c/g.",
	  { "http", NULL, NULL, "a", 80, "/b/c/g.", NULL, NULL } },
	{ ".g", "http://a/b/c/.g",
	  { "http", NULL, NULL, "a", 80, "/b/c/.g", NULL, NULL } },
	{ "g..", "http://a/b/c/g..",
	  { "http", NULL, NULL, "a", 80, "/b/c/g..", NULL, NULL } },
	{ "..g", "http://a/b/c/..g",
	  { "http", NULL, NULL, "a", 80, "/b/c/..g", NULL, NULL } },
	{ "./../g", "http://a/b/g",
	  { "http", NULL, NULL, "a", 80, "/b/g", NULL, NULL } },
	{ "./g/.", "http://a/b/c/g/",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/", NULL, NULL } },
	{ "g/./h", "http://a/b/c/g/h",
	  { "http", NULL, NULL, "a", 80, "/b/c/g/h", NULL, NULL } },
	{ "g/../h", "http://a/b/c/h",
	  { "http", NULL, NULL, "a", 80, "/b/c/h", NULL, NULL } },
	{ "g;x=1/./y", "http://a/b/c/g;x=1/y",
	  { "http", NULL, NULL, "a", 80, "/b/c/g;x=1/y", NULL, NULL } },
	{ "g;x=1/../y", "http://a/b/c/y",
	  { "http", NULL, NULL, "a", 80, "/b/c/y", NULL, NULL } },
	{ "g?y/./x", "http://a/b/c/g?y/./x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y/./x", NULL } },
	{ "g?y/../x", "http://a/b/c/g?y/../x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", "y/../x", NULL } },
	{ "g#s/./x", "http://a/b/c/g#s/./x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s/./x" } },
	{ "g#s/../x", "http://a/b/c/g#s/../x",
	  { "http", NULL, NULL, "a", 80, "/b/c/g", NULL, "s/../x" } },

	/* RFC 3986 notes that some old parsers will parse this as
	 * a relative URL ("http://a/b/c/g"), but it should be
	 * interpreted as absolute. libsoup should parse it
	 * correctly as being absolute, but then reject it since it's
	 * an http URL with no host.
	 */
	{ "http:g", NULL, { NULL } }
};
static int num_rel_tests = G_N_ELEMENTS(rel_tests);

static struct {
	const char *one, *two;
} eq_tests[] = {
	{ "example://a/b/c/%7Bfoo%7D", "eXAMPLE://a/./b/../b/%63/%7Bfoo%7D" },
	{ "http://example.com", "http://example.com/" },
	/* From RFC 2616 */
	{ "http://abc.com:80/~smith/home.html", "http://abc.com:80/~smith/home.html" },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com/%7Esmith/home.html" },
	{ "http://abc.com:80/~smith/home.html", "http://ABC.com:/%7esmith/home.html" },
};
static int num_eq_tests = G_N_ELEMENTS(eq_tests);

#define test_cmpstr(a, b) _test_cmpstr (#a, #b, a, b)

static gboolean
_test_cmpstr (const char *got_desc,
	      const char *exp_desc,
	      const char *got,
	      const char *expected)
{
	if (got == expected)
		return TRUE;

	if (got == NULL) {
		debug_printf (1, "ERR\n  %s = NULL, expected %s = \"%s\"\n",
			      got_desc, exp_desc, expected);
		return FALSE;
	}

	if (expected == NULL) {
		debug_printf (1, "ERR\n  %s = \"%s\", expected %s = NULL\n",
			      got_desc, got, exp_desc);
		return FALSE;
	}

	if (strcmp (got, expected) != 0) {
		debug_printf (1, "ERR\n  %s = \"%s\", expected %s = \"%s\"\n",
			      got_desc, got, exp_desc, expected);
		return FALSE;
	}

	return TRUE;
}

static gboolean
do_uri (SoupURI *base_uri, const char *base_str,
	const char *in_uri, const char *out_uri,
	const SoupURI *bits)
{
	SoupURI *uri;
	char *uri_string;

	if (base_uri) {
		debug_printf (1, "<%s> + <%s> = <%s>? ", base_str, in_uri,
			      out_uri ? out_uri : "ERR");
		uri = soup_uri_new_with_base (base_uri, in_uri);
	} else {
		debug_printf (1, "<%s> => <%s>? ", in_uri,
			      out_uri ? out_uri : "ERR");
		uri = soup_uri_new (in_uri);
	}

	if (!uri) {
		if (out_uri) {
			debug_printf (1, "ERR\n  Could not parse %s\n", in_uri);
			return FALSE;
		} else {
			debug_printf (1, "OK\n");
			return TRUE;
		}
	}

	if (bits != NULL) {
		gboolean failed = FALSE;

		if (!test_cmpstr (uri->scheme, bits->scheme))
			failed = TRUE;

		if (!test_cmpstr (uri->user, bits->user))
			failed = TRUE;

		if (!test_cmpstr (uri->password, bits->password))
			failed = TRUE;

		if (!test_cmpstr (uri->host, bits->host))
			failed = TRUE;

		if (uri->port != bits->port) {
			debug_printf (1, "ERR\n  port was %u, expected %u\n",
				      uri->port, bits->port);
			failed = TRUE;
		}

		if (!test_cmpstr (uri->path, bits->path))
			failed = TRUE;

		if (!test_cmpstr (uri->query, bits->query))
			failed = TRUE;

		if (!test_cmpstr (uri->fragment, bits->fragment))
			failed = TRUE;

		if (failed)
			return FALSE;
	}

	uri_string = soup_uri_to_string (uri, FALSE);
	soup_uri_free (uri);

	if (!out_uri) {
		debug_printf (1, "ERR\n  Got %s\n", uri_string);
		return FALSE;
	}

	if (strcmp (uri_string, out_uri) != 0) {
		debug_printf (1, "NO\n  Unparses to <%s>\n", uri_string);
		g_free (uri_string);
		return FALSE;
	}
	g_free (uri_string);

	debug_printf (1, "OK\n");
	return TRUE;
}

static void
do_soup_uri_null_tests (void)
{
	SoupURI *uri, *uri2;
	char *uri_string;

	debug_printf (1, "\nsoup_uri_new (NULL)\n");
	uri = soup_uri_new (NULL);
	if (SOUP_URI_IS_VALID (uri) || SOUP_URI_VALID_FOR_HTTP (uri)) {
		debug_printf (1, "  ERROR: soup_uri_new(NULL) returns valid URI?\n");
		errors++;
	}

	/* This implicitly also verifies that none of these methods g_warn */
	if (soup_uri_get_scheme (uri) ||
	    soup_uri_get_user (uri) ||
	    soup_uri_get_password (uri) ||
	    soup_uri_get_host (uri) ||
	    soup_uri_get_port (uri) ||
	    soup_uri_get_path (uri) ||
	    soup_uri_get_query (uri) ||
	    soup_uri_get_fragment (uri)) {
		debug_printf (1, "  ERROR: soup_uri_new(NULL) returns non-empty URI?\n");
		errors++;
	}

	expect_warning = TRUE;
	uri2 = soup_uri_new_with_base (uri, "/path");
	if (uri2 || expect_warning) {
		debug_printf (1, "  ERROR: soup_uri_new_with_base didn't fail on NULL URI?\n");
		errors++;
		expect_warning = FALSE;
	}

	expect_warning = TRUE;
	uri_string = soup_uri_to_string (uri, FALSE);
	if (expect_warning) {
		debug_printf (1, "  ERROR: soup_uri_to_string didn't fail on NULL URI?\n");
		errors++;
		expect_warning = FALSE;
	} else if (*uri_string) {
		debug_printf (1, "  ERROR: soup_uri_to_string on NULL URI returned '%s'\n",
			      uri_string);
		errors++;
	}
	g_free (uri_string);

	soup_uri_set_scheme (uri, SOUP_URI_SCHEME_HTTP);
	if (SOUP_URI_IS_VALID (uri) || SOUP_URI_VALID_FOR_HTTP (uri)) {
		debug_printf (1, "  ERROR: setting scheme on NULL URI makes it valid?\n");
		errors++;
	}

	expect_warning = TRUE;
	uri_string = soup_uri_to_string (uri, FALSE);
	if (expect_warning) {
		debug_printf (1, "  ERROR: soup_uri_to_string didn't fail on scheme-only URI?\n");
		errors++;
		expect_warning = FALSE;
	} else if (strcmp (uri_string, "http:") != 0) {
		debug_printf (1, "  ERROR: soup_uri_to_string returned '%s' instead of 'http:'\n",
			      uri_string);
		errors++;
	}
	g_free (uri_string);

	soup_uri_set_host (uri, "localhost");
	if (SOUP_URI_IS_VALID (uri)) {
		debug_printf (1, "  ERROR: setting scheme+host on NULL URI makes it valid?\n");
		errors++;
	}
	if (SOUP_URI_VALID_FOR_HTTP (uri)) {
		debug_printf (1, "  ERROR: setting scheme+host on NULL URI makes it valid for http?\n");
		errors++;
	}

	expect_warning = TRUE;
	uri_string = soup_uri_to_string (uri, FALSE);
	if (expect_warning) {
		debug_printf (1, "  ERROR: soup_uri_to_string didn't fail on scheme+host URI?\n");
		errors++;
		expect_warning = FALSE;
	} else if (strcmp (uri_string, "http://localhost/") != 0) {
		debug_printf (1, "  ERROR: soup_uri_to_string with NULL path returned '%s' instead of 'http://localhost/'\n",
			      uri_string);
		errors++;
	}
	g_free (uri_string);

	expect_warning = TRUE;
	uri2 = soup_uri_new_with_base (uri, "/path");
	if (expect_warning) {
		debug_printf (1, "  ERROR: soup_uri_new_with_base didn't warn on NULL+scheme URI?\n");
		errors++;
		expect_warning = FALSE;
	} else if (!uri2) {
		debug_printf (1, "  ERROR: soup_uri_new_with_base didn't fix path on NULL+scheme URI\n");
		errors++;
	}

	if (uri2) {
		uri_string = soup_uri_to_string (uri2, FALSE);
		if (!uri_string) {
			debug_printf (1, "  ERROR: soup_uri_to_string failed on uri2?\n");
			errors++;
		} else if (strcmp (uri_string, "http://localhost/path") != 0) {
			debug_printf (1, "  ERROR: soup_uri_to_string returned '%s' instead of 'http://localhost/path'\n",
				      uri_string);
			errors++;
		}
		g_free (uri_string);
		soup_uri_free (uri2);
	}

	expect_warning = TRUE;
	soup_uri_set_path (uri, NULL);
	if (expect_warning) {
		debug_printf (1, "  ERROR: setting path to NULL doesn't warn\n");
		errors++;
		expect_warning = FALSE;
	}
	if (!uri->path || *uri->path) {
		debug_printf (1, "  ERROR: setting path to NULL != \"\"\n");
		errors++;
		soup_uri_set_path (uri, "");
	}

	uri_string = soup_uri_to_string (uri, FALSE);
	if (!uri_string) {
		debug_printf (1, "  ERROR: soup_uri_to_string failed on complete URI?\n");
		errors++;
	} else if (strcmp (uri_string, "http://localhost/") != 0) {
		debug_printf (1, "  ERROR: soup_uri_to_string with empty path returned '%s' instead of 'http://localhost/'\n",
			      uri_string);
		errors++;
	}
	g_free (uri_string);

	if (!SOUP_URI_IS_VALID (uri)) {
		debug_printf (1, "  ERROR: setting scheme+path on NULL URI doesn't make it valid?\n");
		errors++;
	}
	if (!SOUP_URI_VALID_FOR_HTTP (uri)) {
		debug_printf (1, "  ERROR: setting scheme+host+path on NULL URI doesn't make it valid for http?\n");
		errors++;
	}

	soup_uri_free (uri);
}

static struct {
	const char *uri_string, *unescape_extra, *result;
} normalization_tests[] = {
	{ "fo%6fbar",         NULL, "foobar" },
	{ "foo%2fbar",        NULL, "foo%2fbar" },
	{ "foo%2Fbar",        NULL, "foo%2Fbar" },
	{ "foo%2fbar",        "/",  "foo/bar" },
	{ "foo bar",          NULL, "foo%20bar" },
	{ "foo bar",          " ",  "foo bar" },
	{ "fo\xc3\xb6" "bar", NULL, "fo%C3%B6bar" },
	{ "fo\xc3\xb6 bar",   " ",  "fo%C3%B6 bar" }
};
static int num_normalization_tests = G_N_ELEMENTS (normalization_tests);

static void
do_normalization_tests (void)
{
	char *normalized;
	int i;

	debug_printf (1, "\nsoup_uri_normalize\n");

	for (i = 0; i < num_normalization_tests; i++) {
		if (normalization_tests[i].unescape_extra) {
			debug_printf (1, "<%s> unescaping <%s> => <%s>: ",
				      normalization_tests[i].uri_string,
				      normalization_tests[i].unescape_extra,
				      normalization_tests[i].result);
		} else {
			debug_printf (1, "<%s> => <%s>: ",
				      normalization_tests[i].uri_string,
				      normalization_tests[i].result);
		}

		normalized = soup_uri_normalize (normalization_tests[i].uri_string,
						 normalization_tests[i].unescape_extra);

		if (!strcmp (normalized, normalization_tests[i].result))
			debug_printf (1, "OK\n");
		else {
			debug_printf (1, "NO, got <%s>\n", normalized);
			errors++;
		}
		g_free (normalized);
	}
}

int
main (int argc, char **argv)
{
	SoupURI *base_uri, *uri1, *uri2;
	char *uri_string;
	int i;

	test_init (argc, argv, NULL);

	debug_printf (1, "Absolute URI parsing\n");
	for (i = 0; i < num_abs_tests; i++) {
		if (!do_uri (NULL, NULL, abs_tests[i].uri_string,
			     abs_tests[i].result, &abs_tests[i].bits))
			errors++;
	}

	debug_printf (1, "\nRelative URI parsing\n");
	base_uri = soup_uri_new (base);
	if (!base_uri) {
		g_printerr ("Could not parse %s!\n", base);
		exit (1);
	}

	uri_string = soup_uri_to_string (base_uri, FALSE);
	if (strcmp (uri_string, base) != 0) {
		g_printerr ("URI <%s> unparses to <%s>\n",
			    base, uri_string);
		errors++;
	}
	g_free (uri_string);

	for (i = 0; i < num_rel_tests; i++) {
		if (!do_uri (base_uri, base, rel_tests[i].uri_string,
			     rel_tests[i].result, &rel_tests[i].bits))
			errors++;
	}
	soup_uri_free (base_uri);

	debug_printf (1, "\nURI equality testing\n");
	for (i = 0; i < num_eq_tests; i++) {
		uri1 = soup_uri_new (eq_tests[i].one);
		uri2 = soup_uri_new (eq_tests[i].two);
		debug_printf (1, "<%s> == <%s>? ", eq_tests[i].one, eq_tests[i].two);
		if (soup_uri_equal (uri1, uri2))
			debug_printf (1, "OK\n");
		else {
			debug_printf (1, "NO\n");
			debug_printf (1, "%s : %s : %s\n%s : %s : %s\n",
				      uri1->scheme, uri1->host, uri1->path,
				      uri2->scheme, uri2->host, uri2->path);
			errors++;
		}
		soup_uri_free (uri1);
		soup_uri_free (uri2);
	}

	do_soup_uri_null_tests ();
	do_normalization_tests ();

	test_cleanup ();
	return errors != 0;
}
