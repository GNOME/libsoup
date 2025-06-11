/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#include "test-utils.h"

static void check_ok (gconstpointer data);

static GDateTime *
make_date (const char *strdate)
{
	char *dup;
	GDateTime *date;

	/* We do it this way so that if soup_date_time_new_from_http_string()
	 * reads off the end of the string, it will trigger an error
	 * when valgrinding, rather than just reading the start of the
	 * next const string.
	 */
	dup = g_strdup (strdate);
	date = soup_date_time_new_from_http_string (dup);
	g_free (dup);
	return date;
}

static GDateTime *
check_correct_date (const char *strdate)
{
	GDateTime *date;

	date = make_date (strdate);
	if (!date) {
		g_assert_nonnull (date);
		return NULL;
	}

	g_assert_cmpint (g_date_time_get_year (date),   ==, 2004);
	g_assert_cmpint (g_date_time_get_month (date),  ==, 11);
	g_assert_cmpint (g_date_time_get_day_of_month (date), ==, 6);
	g_assert_cmpint (g_date_time_get_hour (date),   ==, 8);
	g_assert_cmpint (g_date_time_get_minute (date), ==, 9);
	g_assert_cmpint (g_date_time_get_second (date), ==, 7);

	return date;
}

typedef struct {
	SoupDateFormat format;
	const char *date;
	const char *bugref;
} GoodDate;

static const GoodDate good_dates[] = {
	{ SOUP_DATE_HTTP,            "Sat, 06 Nov 2004 08:09:07 GMT", NULL },
	{ SOUP_DATE_COOKIE,          "Sat, 06-Nov-2004 08:09:07 GMT", NULL },
};

static void
check_good (gconstpointer data)
{
	GoodDate *good = (GoodDate *)data;
	GDateTime *date;
	char *strdate2;

	if (good->bugref)
		g_test_bug (good->bugref);

	date = check_correct_date (good->date);
	if (!date)
		return;

	strdate2 = soup_date_time_to_string (date, good->format);
	g_date_time_unref (date);

	soup_test_assert (strcmp (good->date, strdate2) == 0,
			  "restringification failed: '%s' -> '%s'\n",
			  good->date, strdate2);
	g_free (strdate2);
}

typedef struct {
	const char *date;
	const char *bugref;
} OkDate;

static const OkDate ok_dates[] = {
	/* rfc1123-date, and broken variants */
	{ "Sat, 06 Nov 2004 08:09:07 GMT", NULL },
	{ "Sat, 6 Nov 2004 08:09:07 GMT", NULL },
	{ "Sat,  6 Nov 2004 08:09:07 GMT", NULL },
	{ "Sat, 06 Nov 2004 08:09:07", NULL },
	{ "06 Nov 2004 08:09:07 GMT", NULL },
	{ "SAT, 06 NOV 2004 08:09:07 +1000", "644048" },
	{ "Sat, 06-Nov-2004 08:09:07 -10000", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },
	{ "Sat, 06-Nov-2004 08:09:07 +01:30", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },
	{ "Sat, 06-Nov-2004 08:09:07 +0:180", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },
	{ "Sat, 06-Nov-2004 08:09:07 +100:100", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },
	{ "Sat, 06-Nov-2004 08:09:07 Z", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },

	/* rfc850-date, and broken variants */
	{ "Saturday, 06-Nov-04 08:09:07 GMT", NULL },
	{ "Saturday, 6-Nov-04 08:09:07 GMT", NULL },
	{ "Saturday,  6-Nov-04 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov-104 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov-2004 08:09:07 GMT", NULL },
	{ "Saturday, 6-Nov-2004 08:09:07 GMT", NULL },
	{ "Saturday,  6-Nov-2004 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov-04 08:09:07", NULL },
	{ "06-Nov-04 08:09:07 GMT", NULL },

	/* asctime-date, and broken variants */
	{ "Sat Nov  6 08:09:07 2004", NULL },
	{ "Sat Nov 06 08:09:07 2004", NULL },
	{ "Sat Nov 6 08:09:07 2004", NULL },
	{ "Sat Nov  6 08:09:07 2004 GMT", NULL },
	{ "Sat Nov 6 08:09:07 2004 NoZone", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },
	{ "Sat Nov 6 08:09:07 2004 UTC", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" },

	/* Netscape cookie spec date, and broken variants */
	{ "Sat, 06-Nov-2004 08:09:07 GMT", NULL },
	{ "Sat, 6-Nov-2004 08:09:07 GMT", NULL },
	{ "Sat,  6-Nov-2004 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-2004 08:09:07", NULL },

	/* Original version of Netscape cookie spec, and broken variants */
	{ "Sat, 06-Nov-04 08:09:07 GMT", NULL },
	{ "Sat, 6-Nov-04 08:09:07 GMT", NULL },
	{ "Sat,  6-Nov-04 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-104 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-04 08:09:07", NULL },

	/* Miscellaneous broken formats seen on the web */
	{ "Sat 06-Nov-2004  08:9:07", NULL },
	{ "Saturday, 06-Nov-04 8:9:07 GMT", NULL },
	{ "Sat, 06 Nov 2004 08:09:7 GMT", NULL }
};

static void
check_ok (gconstpointer data)
{
	OkDate *ok = (OkDate *)data;
	GDateTime *date;

	if (ok->bugref)
		g_test_bug (ok->bugref);

	date = check_correct_date (ok->date);
	if (!date)
		return;
	g_date_time_unref (date);
}

typedef struct {
	const char *date;
	const char *bugref;
} BadDate;

static const BadDate bad_dates[] = {
	/* broken rfc1123-date */
	{ ", 06 Nov 2004 08:09:07 GMT", NULL },
	{ "Sat, Nov 2004 08:09:07 GMT", NULL },
	{ "Sat, 06 2004 08:09:07 GMT", NULL },
	{ "Sat, 06 Nov 08:09:07 GMT", NULL },
	{ "Sat, 06 Nov 2004 :09:07 GMT", NULL },
	{ "Sat, 06 Nov 2004 09:07 GMT", NULL },
	{ "Sat, 06 Nov 2004 08::07 GMT", NULL },
	{ "Sat, 06 Nov 2004 08:09: GMT", NULL },

	/* broken rfc850-date */
	{ ", 06-Nov-04 08:09:07 GMT", NULL },
	{ "Saturday, -Nov-04 08:09:07 GMT", NULL },
	{ "Saturday, Nov-04 08:09:07 GMT", NULL },
	{ "Saturday, 06-04 08:09:07 GMT", NULL },
	{ "Saturday, 06--04 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov- 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov 08:09:07 GMT", NULL },
	{ "Saturday, 06-Nov-04 :09:07 GMT", NULL },
	{ "Saturday, 06-Nov-04 09:07 GMT", NULL },
	{ "Saturday, 06-Nov-04 08::07 GMT", NULL },
	{ "Saturday, 06-Nov-04 08:09: GMT", NULL },

	/* broken asctime-date */
	{ "Nov  6 08:09:07 2004", NULL },
	{ "Sat  6 08:09:07 2004", NULL },
	{ "Sat Nov 08:09:07 2004", NULL },
	{ "Sat Nov  6 :09:07 2004", NULL },
	{ "Sat Nov  6 09:07 2004", NULL },
	{ "Sat Nov  6 08::07 2004", NULL },
	{ "Sat Nov  6 08:09: 2004", NULL },
	{ "Sat Nov  6 08:09:07", NULL },
	{ "Sat Nov  6 08:09:07 GMT 2004", NULL },

	/* range constraints added "https://gitlab.gnome.org/GNOME/libsoup/-/issues/448" */
	{ "Sat, 00-Nov-2004 08:09:07 GMT", NULL },
	{ "Sat, 32-Nov-2004 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-0 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-9999 08:09:07 GMT", NULL },
	{ "Sat, 06-Nov-2004 0-1:09:07 GMT", NULL },
	{ "(Sat), Nov  6 -1:09:07 2004", NULL },
	{ "Sat, 06-Nov-2004 24:09:07 GMT", NULL },
	{ "Sat, 06-Nov-2004 08:-1:07 GMT", NULL },
	{ "Sat, 06-Nov-2004 08:60:07 GMT", NULL },
	{ "Sat, 06-Nov-2004 08:09:-10 GMT", NULL },
	{ "Sat, 06-Nov-2004 08:09:60 GMT", NULL },
	{ "Sat, 06-Nov-71 08:09:99 UTC", NULL },
	{ "Sat, 31-Feb-2004 08:09:07 UTC", NULL },
	{ "2004-11-06T08:09:07Z", NULL }
};

static void
check_bad (gconstpointer data)
{
	BadDate *bad = (BadDate *)data;
	GDateTime *date;

	if (bad->bugref)
		g_test_bug (bad->bugref);

	date = make_date (bad->date);
	soup_test_assert (date == NULL,
			  "date parsing succeeded for '%s': %d %d %d - %d %d %d",
			  bad->date,
			  g_date_time_get_year (date),
			  g_date_time_get_month (date),
			  g_date_time_get_day_of_month (date),
			  g_date_time_get_hour (date),
			  g_date_time_get_minute (date),
			  g_date_time_get_second (date));
	g_clear_pointer (&date, g_date_time_unref);
}

typedef struct {
	const char *source;
	const char *http, *cookie;
} DateConversion;

static const DateConversion conversions[] = {
	/* SOUP_DATE_HTTP */
	{ "Sat, 06 Nov 2004 08:09:07 GMT",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT" },

	/* RFC2822 GMT */
	{ "Sat, 6 Nov 2004 08:09:07 +0000",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT" },

	/* RFC2822 with positive offset */
	{ "Sat, 6 Nov 2004 08:09:07 +0430",

	  "Sat, 06 Nov 2004 03:39:07 GMT",
	  "Sat, 06-Nov-2004 03:39:07 GMT" },

	/* RFC2822 with negative offset */
	{ "Sat, 6 Nov 2004 08:09:07 -0430",

	  "Sat, 06 Nov 2004 12:39:07 GMT",
	  "Sat, 06-Nov-2004 12:39:07 GMT" },

	/* RFC2822 floating */
	{ "Sat, 6 Nov 2004 08:09:07 -0000",

	  "Sat, 06 Nov 2004 08:09:07 GMT",
	  "Sat, 06-Nov-2004 08:09:07 GMT" }
};

static void
check_conversion (gconstpointer data)
{
	const DateConversion *conv = data;
	GDateTime *date;
	char *str;

	date = make_date (conv->source);
	if (!date) {
		soup_test_assert (FALSE, "date parsing failed for '%s'.", conv->source);
		return;
	}

	str = soup_date_time_to_string (date, SOUP_DATE_HTTP);
	g_assert_cmpstr (str, ==, conv->http);
	g_free (str);

	str = soup_date_time_to_string (date, SOUP_DATE_COOKIE);
	g_assert_cmpstr (str, ==, conv->cookie);
	g_free (str);

	g_date_time_unref (date);
}

int
main (int argc, char **argv)
{
	int i, ret;
	char *path;

	test_init (argc, argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (good_dates); i++) {
		path = g_strdup_printf ("/date/good/%s", good_dates[i].date);
		g_test_add_data_func (path, &good_dates[i], check_good);
		g_free (path);
	}

	for (i = 0; i < G_N_ELEMENTS (ok_dates); i++) {
		path = g_strdup_printf ("/date/ok/%s", ok_dates[i].date);
		g_test_add_data_func (path, &ok_dates[i], check_ok);
		g_free (path);
	}

	for (i = 0; i < G_N_ELEMENTS (bad_dates); i++) {
		path = g_strdup_printf ("/date/bad/%s", bad_dates[i].date);
		g_test_add_data_func (path, &bad_dates[i], check_bad);
		g_free (path);
	}

	for (i = 0; i < G_N_ELEMENTS (conversions); i++) {
		path = g_strdup_printf ("/date/conversions/%s", conversions[i].source);
		g_test_add_data_func (path, &conversions[i], check_conversion);
		g_free (path);
	}

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
