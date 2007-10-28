/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#include <stdio.h>
#include <string.h>

#include <libsoup/soup-date.h>
#include <glib.h>

static int errors = 0;

#define RFC1123_DATE   "Sun, 06 Nov 1994 08:49:37 GMT"
#define RFC850_DATE    "Sunday, 06-Nov-94 08:49:37 GMT"
#define ASCTIME_DATE   "Sun Nov  6 08:49:37 1994"
#define ISO8601_1_DATE "1994-11-06T08:49:37Z"
#define ISO8601_2_DATE "19941106T08:49:37Z"
#define ISO8601_3_DATE "19941106T08:49:37+00:00"
#define ISO8601_4_DATE "19941106T084937+00:00"

#define EXPECTED     784111777

static void
check (const char *test, const char *date, time_t got)
{
	if (got == EXPECTED)
		return;

	fprintf (stderr, "%s date parsing failed for '%s'.\n", test, date);
	fprintf (stderr, "  expected: %lu, got: %lu\n\n",
		 (unsigned long)EXPECTED, (unsigned long)got);
	errors++;
}

int
main (int argc, char **argv)
{
	char *date;

	check ("RFC1123", RFC1123_DATE, soup_date_parse (RFC1123_DATE));
	check ("RFC850", RFC850_DATE, soup_date_parse (RFC850_DATE));
	check ("asctime", ASCTIME_DATE, soup_date_parse (ASCTIME_DATE));
	check ("iso8610[1]", ISO8601_1_DATE, soup_date_iso8601_parse (ISO8601_1_DATE));
	check ("iso8610[2]", ISO8601_2_DATE, soup_date_iso8601_parse (ISO8601_2_DATE));
	check ("iso8610[3]", ISO8601_3_DATE, soup_date_iso8601_parse (ISO8601_3_DATE));
	check ("iso8610[4]", ISO8601_4_DATE, soup_date_iso8601_parse (ISO8601_4_DATE));

	date = soup_date_generate (EXPECTED);
	if (strcmp (date, RFC1123_DATE) != 0) {
		fprintf (stderr, "date generation failed.\n");
		fprintf (stderr, "  expected: %s\n  got:      %s\n\n",
			 RFC1123_DATE, date);
		errors++;
	}
	g_free (date);

	if (errors == 0)
		printf ("date: OK\n");
	else
		fprintf (stderr, "date: %d errors\n", errors);
	return errors;
}
