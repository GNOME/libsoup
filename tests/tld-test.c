/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Igalia S.L.
 */

#include "test-utils.h"

/* From http://publicsuffix.org/list/test.txt */
static struct {
  const char *hostname;
  const char *result;
} tld_tests[] = {
  /* NULL input. Not checked here because the API requires a valid hostname. */
  /* { NULL, NULL }, */
  /* Mixed case. Not checked because the API requires a valid hostname. */
  /* { "COM", NULL }, */
  /* { "example.COM", "example.com" }, */
  /* { "WwW.example.COM", "example.com" }, */
  /* Leading dot. */
  { ".com", NULL },
  { ".example", NULL },
  { ".example.com", NULL },
  { ".example.example", NULL },
  /* TLD with only 1 rule. */
  { "biz", NULL },
  { "domain.biz", "domain.biz" },
  { "b.domain.biz", "domain.biz" },
  { "a.b.domain.biz", "domain.biz" },
  /* TLD with some 2-level rules. */
  { "com", NULL },
  { "example.com", "example.com" },
  { "b.example.com", "example.com" },
  { "a.b.example.com", "example.com" },
  { "uk.com", NULL },
  { "example.uk.com", "example.uk.com" },
  { "b.example.uk.com", "example.uk.com" },
  { "a.b.example.uk.com", "example.uk.com" },
  { "test.ac", "test.ac" },
  /* TLD with only 1 (wildcard) rule. */
  { "cy", NULL },
  { "c.cy", NULL },
  { "b.c.cy", "b.c.cy" },
  { "a.b.c.cy", "b.c.cy" },
  /* More complex TLD. */
  { "jp", NULL },
  { "test.jp", "test.jp" },
  { "www.test.jp", "test.jp" },
  { "ac.jp", NULL },
  { "test.ac.jp", "test.ac.jp" },
  { "www.test.ac.jp", "test.ac.jp" },
  { "kyoto.jp", NULL },
  { "minami.kyoto.jp", NULL },
  { "b.minami.kyoto.jp", "b.minami.kyoto.jp" },
  { "a.b.minami.kyoto.jp", "b.minami.kyoto.jp" },
  { "pref.kyoto.jp", "pref.kyoto.jp" },
  { "www.pref.kyoto.jp", "pref.kyoto.jp" },
  { "city.kyoto.jp", "city.kyoto.jp" },
  { "www.city.kyoto.jp", "city.kyoto.jp" },
  /* TLD with a wildcard rule and exceptions. */
  { "om", NULL },
  { "test.om", NULL },
  { "b.test.om", "b.test.om" },
  { "a.b.test.om", "b.test.om" },
  { "songfest.om", "songfest.om" },
  { "www.songfest.om", "songfest.om" },
  /* US K12. */
  { "us", NULL },
  { "test.us", "test.us" },
  { "www.test.us", "test.us" },
  { "ak.us", NULL },
  { "test.ak.us", "test.ak.us" },
  { "www.test.ak.us", "test.ak.us" },
  { "k12.ak.us", NULL },
  { "test.k12.ak.us", "test.k12.ak.us" },
  { "www.test.k12.ak.us", "test.k12.ak.us" },
  /* This is not in http://publicsuffix.org/list/test.txt but we want to check it anyway. */
  { "co.uk", NULL },
  /* The original list does not include non-ASCII tests. Let's add a couple. */
  { "公司.cn", NULL },
  { "a.b.åfjord.no", "b.åfjord.no" }
},
/* Non Internet TLDs have NULL as expected result
 */
non_inet_tld_tests[] = {
  /* Unlisted TLD.*/
  { "example", NULL },
  { "example.example", NULL },
  { "b.example.example", NULL },
  { "a.b.example.example", NULL },
  /* Listed, but non-Internet, TLD. */
  { "local", NULL },
  { "example.local", NULL },
  { "b.example.local", NULL },
  { "a.b.example.local", NULL }
};

int
main (int argc, char **argv)
{
	int i;

	test_init (argc, argv, NULL);

	errors = 0;
	for (i = 0; i < G_N_ELEMENTS (tld_tests); ++i) {
		GError *error = NULL;
		gboolean is_public = soup_tld_domain_is_public_suffix (tld_tests[i].hostname);
		const char *base_domain = soup_tld_get_base_domain (tld_tests[i].hostname, &error);

		debug_printf (1, "Testing %s: ", tld_tests[i].hostname);

		if (is_public && tld_tests[i].result) {
			debug_printf (1, "ERROR: domain is public but base_domain is not NULL (%s)\n",
				      base_domain);
			++errors;
		} else if (g_strcmp0 (tld_tests[i].result, base_domain)) {
			debug_printf (1, "ERROR: %s expected as base domain but got %s\n",
				      tld_tests[i].result, base_domain);
			++errors;

		} else if (!tld_tests[i].result && !is_public &&
			   !g_error_matches (error, SOUP_TLD_ERROR, SOUP_TLD_ERROR_INVALID_HOSTNAME)) {
			debug_printf (1, "ERROR: not public domain with NULL expected result\n");
			++errors;
		} else
			debug_printf (1, "OK\n");

		g_clear_error(&error);
	}

	for (i = 0; i < G_N_ELEMENTS (non_inet_tld_tests); ++i) {
		gboolean is_public = soup_tld_domain_is_public_suffix (non_inet_tld_tests[i].hostname);
		const char *base_domain = soup_tld_get_base_domain (non_inet_tld_tests[i].hostname, NULL);

		debug_printf (1, "Testing %s: ", non_inet_tld_tests[i].hostname);

		if (is_public) {
			debug_printf (1, "ERROR: domain incorrectly clasified as public\n");
			++errors;
		} else if (base_domain) {
			debug_printf (1, "ERROR: non NULL base domain (%s) for local url\n",
				      base_domain);
			++errors;
		} else
			debug_printf (1, "OK\n");
	}

	test_cleanup ();

	return errors != 0;
}
