#include <config.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libsoup/soup-uri.h"

struct {
	char *uri_string, *result;
} abs_tests[] = {
	{ "foo:", "foo:" },
	{ "file:/dev/null", "file:/dev/null" },
	{ "file:///dev/null", "file:///dev/null" },
	{ "ftp://user@host/path", "ftp://user@host/path" },
	{ "ftp://user@host:9999/path", "ftp://user@host:9999/path" },
	{ "ftp://user:password@host/path", "ftp://user@host/path" },
	{ "ftp://user:password@host:9999/path", "ftp://user@host:9999/path" },
	{ "http://us%65r@host", "http://user@host" },
	{ "http://us%40r@host", "http://us%40r@host" },
	{ "http://us%3ar@host", "http://us%3ar@host" },
	{ "http://us%2fr@host", "http://us%2fr@host" }
};
int num_abs_tests = G_N_ELEMENTS(abs_tests);

/* From RFC 2396. */
char *base = "http://a/b/c/d;p?q";
struct {
	char *uri_string, *result;
} rel_tests[] = {
	{ "g:h", "g:h" },
	{ "g", "http://a/b/c/g" },
	{ "./g", "http://a/b/c/g" },
	{ "g/", "http://a/b/c/g/" },
	{ "/g", "http://a/g" },
	{ "//g", "http://g" },
	{ "?y", "http://a/b/c/?y" },
	{ "g?y", "http://a/b/c/g?y" },
	{ "#s", "http://a/b/c/d;p?q#s" },
	{ "g#s", "http://a/b/c/g#s" },
	{ "g?y#s", "http://a/b/c/g?y#s" },
	{ ";x", "http://a/b/c/;x" },
	{ "g;x", "http://a/b/c/g;x" },
	{ "g;x?y#s", "http://a/b/c/g;x?y#s" },
	{ ".", "http://a/b/c/" },
	{ "./", "http://a/b/c/" },
	{ "..", "http://a/b/" },
	{ "../", "http://a/b/" },
	{ "../g", "http://a/b/g" },
	{ "../..", "http://a/" },
	{ "../../", "http://a/" },
	{ "../../g", "http://a/g" },
	{ "", "http://a/b/c/d;p?q" },
	{ "../../../g", "http://a/../g" },
	{ "../../../../g", "http://a/../../g" },
	{ "/./g", "http://a/./g" },
	{ "/../g", "http://a/../g" },
	{ "g.", "http://a/b/c/g." },
	{ ".g", "http://a/b/c/.g" },
	{ "g..", "http://a/b/c/g.." },
	{ "..g", "http://a/b/c/..g" },
	{ "./../g", "http://a/b/g" },
	{ "./g/.", "http://a/b/c/g/" },
	{ "g/./h", "http://a/b/c/g/h" },
	{ "g/../h", "http://a/b/c/h" },
	{ "g;x=1/./y", "http://a/b/c/g;x=1/y" },
	{ "g;x=1/../y", "http://a/b/c/y" },
	{ "g?y/./x", "http://a/b/c/g?y/./x" },
	{ "g?y/../x", "http://a/b/c/g?y/../x" },
	{ "g#s/./x", "http://a/b/c/g#s/./x" },
	{ "g#s/../x", "http://a/b/c/g#s/../x" },
	{ "http:g", "http:g" }
};
int num_rel_tests = G_N_ELEMENTS(rel_tests);

static gboolean
do_uri (SoupUri *base_uri, const char *base_str,
	const char *in_uri, const char *out_uri)
{
	SoupUri *uri;
	char *uri_string;

	if (base_uri) {
		printf ("<%s> + <%s> = <%s>? ", base_str, in_uri, out_uri);
		uri = soup_uri_new_with_base (base_uri, in_uri);
	} else {
		printf ("<%s> => <%s>? ", in_uri, out_uri);
		uri = soup_uri_new (in_uri);
	}

	if (!uri) {
		printf ("ERR\n  Could not parse %s\n", in_uri);
		return FALSE;
	}

	uri_string = soup_uri_to_string (uri, FALSE);
	soup_uri_free (uri);

	if (strcmp (uri_string, out_uri) != 0) {
		printf ("NO\n  Unparses to <%s>\n", uri_string);
		g_free (uri_string);
		return FALSE;
	}
	g_free (uri_string);

	printf ("OK\n");
	return TRUE;
}

int
main (int argc, char **argv)
{
	SoupUri *base_uri, *uri;
	char *uri_string;
	int i, errs = 0;

	printf ("Absolute URI parsing\n");
	for (i = 0; i < num_abs_tests; i++) {
		if (!do_uri (NULL, NULL, abs_tests[i].uri_string,
			     abs_tests[i].result))
			errs++;
	}

	printf ("\nRelative URI parsing\n");
	base_uri = soup_uri_new (base);
	if (!base_uri) {
		fprintf (stderr, "Could not parse %s!\n", base);
		exit (1);
	}

	uri_string = soup_uri_to_string (base_uri, FALSE);
	if (strcmp (uri_string, base) != 0) {
		fprintf (stderr, "URI <%s> unparses to <%s>\n",
			 base, uri_string);
		errs++;
	}
	g_free (uri_string);

	for (i = 0; i < num_rel_tests; i++) {
		if (!do_uri (base_uri, base, rel_tests[i].uri_string,
			     rel_tests[i].result))
			errs++;
	}

	printf ("\n%d errors\n", errs);
	return errs;
}
