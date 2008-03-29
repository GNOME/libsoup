/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#include <stdio.h>
#include <string.h>

#include <libsoup/soup-date.h>
#include <glib.h>

#include "test-utils.h"

static const struct {
	SoupDateFormat format;
	const char *date;
} good_dates[] = {
	{ SOUP_DATE_HTTP,            "Sat, 06 Nov 2004 08:09:07 GMT" },
	{ SOUP_DATE_COOKIE,          "Sat, 06-Nov-2004 08:09:07 GMT" },
#ifdef NOT_YET
	{ SOUP_DATE_RFC2822,         "Sat, 06 Nov 2004 08:09:07 +0000" },
#endif
	{ SOUP_DATE_ISO8601_COMPACT, "20041106T080907" },
	{ SOUP_DATE_ISO8601_FULL,    "2004-11-06T08:09:07" },
	{ SOUP_DATE_ISO8601_XMLRPC,  "20041106T08:09:07" }
};

static const char *ok_dates[] = {
	/* rfc1123-date, and broken variants */
	"Sat, 06 Nov 2004 08:09:07 GMT",
	"Sat, 6 Nov 2004 08:09:07 GMT",
	"Sat,  6 Nov 2004 08:09:07 GMT",
	"Sat, 06 Nov 2004 08:09:07",
	"06 Nov 2004 08:09:07 GMT",

	/* rfc850-date, and broken variants */
	"Saturday, 06-Nov-04 08:09:07 GMT",
	"Saturday, 6-Nov-04 08:09:07 GMT",
	"Saturday,  6-Nov-04 08:09:07 GMT",
	"Saturday, 06-Nov-104 08:09:07 GMT",
	"Saturday, 06-Nov-04 08:09:07",
	"06-Nov-04 08:09:07 GMT",

	/* asctime-date, and broken variants */
	"Sat Nov  6 08:09:07 2004",
	"Sat Nov 06 08:09:07 2004",
	"Sat Nov 6 08:09:07 2004",
	"Sat Nov  6 08:09:07 2004 GMT",

	/* ISO 8601 */
	"2004-11-06T08:09:07Z",
	"20041106T08:09:07Z",
	"20041106T08:09:07+00:00",
	"20041106T080907+00:00",

	/* Netscape cookie spec date, and broken variants */
	"Sat, 06-Nov-2004 08:09:07 GMT",
	"Sat, 6-Nov-2004 08:09:07 GMT",
	"Sat,  6-Nov-2004 08:09:07 GMT",
	"Sat, 06-Nov-2004 08:09:07",

	/* Original version of Netscape cookie spec, and broken variants */
	"Sat, 06-Nov-04 08:09:07 GMT",
	"Sat, 6-Nov-04 08:09:07 GMT",
	"Sat,  6-Nov-04 08:09:07 GMT",
	"Sat, 06-Nov-104 08:09:07 GMT",
	"Sat, 06-Nov-04 08:09:07",

	/* Netscape cookie spec example syntax, and broken variants */
	"Saturday, 06-Nov-04 08:09:07 GMT",
	"Saturday, 6-Nov-04 08:09:07 GMT",
	"Saturday,  6-Nov-04 08:09:07 GMT",
	"Saturday, 06-Nov-104 08:09:07 GMT",
	"Saturday, 06-Nov-2004 08:09:07 GMT",
	"Saturday, 6-Nov-2004 08:09:07 GMT",
	"Saturday,  6-Nov-2004 08:09:07 GMT",
	"Saturday, 06-Nov-04 08:09:07",

	/* Miscellaneous broken formats seen on the web */
	"Sat 06-Nov-2004  08:9:07",
	"Saturday, 06-Nov-04 8:9:07 GMT",
	"Sat, 06 Nov 2004 08:09:7 GMT"
};

static const char *bad_dates[] = {
	/* broken rfc1123-date */
	", 06 Nov 2004 08:09:07 GMT",
	"Sat, Nov 2004 08:09:07 GMT",
	"Sat, 06 2004 08:09:07 GMT",
	"Sat, 06 Nov 08:09:07 GMT",
	"Sat, 06 Nov 2004 :09:07 GMT",
	"Sat, 06 Nov 2004 09:07 GMT",
	"Sat, 06 Nov 2004 08::07 GMT",
	"Sat, 06 Nov 2004 08:09: GMT",

	/* broken rfc850-date */
	", 06-Nov-04 08:09:07 GMT",
	"Saturday, -Nov-04 08:09:07 GMT",
	"Saturday, Nov-04 08:09:07 GMT",
	"Saturday, 06-04 08:09:07 GMT",
	"Saturday, 06--04 08:09:07 GMT",
	"Saturday, 06-Nov- 08:09:07 GMT",
	"Saturday, 06-Nov 08:09:07 GMT",
	"Saturday, 06-Nov-04 :09:07 GMT",
	"Saturday, 06-Nov-04 09:07 GMT",
	"Saturday, 06-Nov-04 08::07 GMT",
	"Saturday, 06-Nov-04 08:09: GMT",

	/* broken asctime-date */
	"Nov  6 08:09:07 2004",
	"Sat  6 08:09:07 2004",
	"Sat Nov 08:09:07 2004",
	"Sat Nov  6 :09:07 2004",
	"Sat Nov  6 09:07 2004",
	"Sat Nov  6 08::07 2004",
	"Sat Nov  6 08:09: 2004",
	"Sat Nov  6 08:09:07",
	"Sat Nov  6 08:09:07 GMT 2004"
};

#define TIME_T 1099728547L
#define TIME_T_STRING "1099728547"

static gboolean
check_ok (const char *strdate, SoupDate *date)
{
	debug_printf (2, "%s\n", strdate);

	if (date &&
	    date->year == 2004 && date->month == 11 && date->day == 6 &&
	    date->hour == 8 && date->minute == 9 && date->second == 7) {
		soup_date_free (date);
		return TRUE;
	}

	debug_printf (1, "  date parsing failed for '%s'.\n", strdate);
	if (date) {
		debug_printf (1, "    got: %d %d %d - %d %d %d\n\n",
			      date->year, date->month, date->day,
			      date->hour, date->minute, date->second);
		soup_date_free (date);
	}
	errors++;
	return FALSE;
}

static void
check_good (SoupDateFormat format, const char *strdate)
{
	SoupDate *date;
	char *strdate2;

	date = soup_date_new_from_string (strdate);
	if (date)
		strdate2 = soup_date_to_string (date, format);
	if (!check_ok (strdate, date))
		return;

	if (strcmp (strdate, strdate2) != 0) {
		debug_printf (1, "  restringification failed: '%s' -> '%s'\n",
			      strdate, strdate2);
		errors++;
	}
	g_free (strdate2);
}

static void
check_bad (const char *strdate, SoupDate *date)
{
	debug_printf (2, "%s\n", strdate);

	if (!date)
		return;
	errors++;

	debug_printf (1, "  date parsing succeeded for '%s'!\n", strdate);
	debug_printf (1, "    got: %d %d %d - %d %d %d\n\n",
		      date->year, date->month, date->day,
		      date->hour, date->minute, date->second);
	soup_date_free (date);
}

int
main (int argc, char **argv)
{
	int i;

	test_init (argc, argv, NULL);

	debug_printf (1, "Good dates:\n");
	for (i = 0; i < G_N_ELEMENTS (good_dates); i++)
		check_good (good_dates[i].format, good_dates[i].date);

	debug_printf (1, "\nOK dates:\n");
	for (i = 0; i < G_N_ELEMENTS (ok_dates); i++)
		check_ok (ok_dates[i], soup_date_new_from_string (ok_dates[i]));
	check_ok (TIME_T_STRING, soup_date_new_from_time_t (TIME_T));

	debug_printf (1, "\nBad dates:\n");
	for (i = 0; i < G_N_ELEMENTS (bad_dates); i++)
		check_bad (bad_dates[i], soup_date_new_from_string (bad_dates[i]));

	test_cleanup ();
	return errors != 0;
}
