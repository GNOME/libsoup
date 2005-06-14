/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-date.c: Date/time functions
 *
 * Copyright (C) 2005, Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "soup-date.h"

/* Do not internationalize */
static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* Do not internationalize */
static const char *days[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const int days_before[] = {
	0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
};

static int
parse_month (const char *month)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (months); i++) {
		if (!strncmp (month, months[i], 3))
			return i;
	}
	return -1;
}

/**
 * soup_mktime_utc:
 * @tm: the UTC time
 *
 * Converts @tm to a #time_t. Unlike with mktime(), @tm is interpreted
 * as being a UTC time.
 *
 * Return value: @tm as a #time_t
 **/
time_t
soup_mktime_utc (struct tm *tm)
{
	time_t tt;

	/* We check the month because (a) if we don't, the
	 * days_before[] part below may access random memory, and (b)
	 * soup_date_parse() doesn't check the return value of
	 * parse_month(). The caller is responsible for ensure the
	 * sanity of everything else.
	 */
	if (tm->tm_mon < 0 || tm->tm_mon > 11)
		return (time_t)-1;

	tt = (tm->tm_year - 70) * 365;
	tt += (tm->tm_year - 68) / 4;
	tt += days_before[tm->tm_mon] + tm->tm_mday - 1;
	if (tm->tm_year % 4 == 2 && tm->tm_mon < 2)
		tt--;
	tt = ((((tt * 24) + tm->tm_hour) * 60) + tm->tm_min) * 60 + tm->tm_sec;
	return tt;
}

/**
 * soup_gmtime:
 * @when: a #time_t
 * @tm: a struct tm to be filled in with the expansion of @when
 *
 * Expands @when into @tm (as a UTC time). This is just a wrapper
 * around gmtime_r() (or gmtime() on lame platforms).
 **/
void
soup_gmtime (const time_t *when, struct tm *tm)
{
#ifdef HAVE_GMTIME_R
	gmtime_r (when, tm);
#else
	*tm = *gmtime (when);
#endif
}

/**
 * soup_date_parse:
 * @timestamp: a timestamp, in any of the allowed HTTP 1.1 formats
 *
 * Parses @timestamp and returns its value as a #time_t.
 *
 * Return value: the #time_t corresponding to @timestamp, or -1 if
 * @timestamp couldn't be parsed.
 **/
time_t
soup_date_parse (const char *timestamp)
{
	struct tm tm;
	int len = strlen (timestamp);

	if (len < 4)
		return (time_t)-1;

	switch (timestamp[3]) {
	case ',':
		/* rfc1123-date = wkday "," SP date1 SP time SP "GMT"
		 * date1        = 2DIGIT SP month SP 4DIGIT
		 * time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
		 *
		 * eg, "Sun, 06 Nov 1994 08:49:37 GMT"
		 */
		if (len != 29 || strcmp (timestamp + 25, " GMT") != 0)
			return (time_t)-1;

		tm.tm_mday = atoi (timestamp + 5);
		tm.tm_mon = parse_month (timestamp + 8);
		tm.tm_year = atoi (timestamp + 12) - 1900;
		tm.tm_hour = atoi (timestamp + 17);
		tm.tm_min = atoi (timestamp + 20);
		tm.tm_sec = atoi (timestamp + 23);
		break;

	case ' ':
		/* asctime-date = wkday SP date3 SP time SP 4DIGIT
		 * date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
		 * time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
		 *
		 * eg, "Sun Nov  6 08:49:37 1994"
		 */
		if (len != 24)
			return (time_t)-1;

		tm.tm_mon = parse_month (timestamp + 4);
		tm.tm_mday = atoi (timestamp + 8);
		tm.tm_hour = atoi (timestamp + 11);
		tm.tm_min = atoi (timestamp + 14);
		tm.tm_sec = atoi (timestamp + 17);
		tm.tm_year = atoi (timestamp + 20) - 1900;
		break;

	default:
		/* rfc850-date  = weekday "," SP date2 SP time SP "GMT"
		 * date2        = 2DIGIT "-" month "-" 2DIGIT
		 * time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
		 *
		 * eg, "Sunday, 06-Nov-94 08:49:37 GMT"
		 */
		timestamp = strchr (timestamp, ',');
		if (timestamp == NULL || strlen (timestamp) != 24 || strcmp (timestamp + 20, " GMT") != 0)
			return (time_t)-1;

		tm.tm_mday = atoi (timestamp + 2);
		tm.tm_mon = parse_month (timestamp + 5);
		tm.tm_year = atoi (timestamp + 9);
		tm.tm_hour = atoi (timestamp + 12);
		tm.tm_min = atoi (timestamp + 15);
		tm.tm_sec = atoi (timestamp + 18);
		break;
	}

	return soup_mktime_utc (&tm);
}

/**
 * soup_date_generate:
 * @when: the time to generate a timestamp for
 *
 * Generates an HTTP 1.1 Date header corresponding to @when.
 *
 * Return value: the timestamp, which the caller must free.
 **/
char *
soup_date_generate (time_t when)
{
	struct tm tm;
	gmtime_r (&when, &tm);

	/* RFC1123 format, eg, "Sun, 06 Nov 1994 08:49:37 GMT" */
	return g_strdup_printf ("%s, %02d %s %04d %02d:%02d:%02d GMT",
				days[tm.tm_wday], tm.tm_mday,
				months[tm.tm_mon], tm.tm_year + 1900,
				tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/**
 * soup_date_iso8601_parse:
 * @timestamp: an ISO8601 timestamp
 *
 * Converts @timestamp to a %time_t value. @timestamp can be in any of the
 * iso8601 formats that specify both a date and a time.
 *
 * Return value: the %time_t corresponding to @timestamp, or -1 on error.
 **/
time_t
soup_date_iso8601_parse (const char *timestamp)
{
	struct tm tm;
	long val;
	time_t tt;

	val = strtoul (timestamp, (char **)&timestamp, 10);
	if (*timestamp == '-') {
		// YYYY-MM-DD
		tm.tm_year = val - 1900;
		timestamp++;
		tm.tm_mon = strtoul (timestamp, (char **)&timestamp, 10) - 1;
		if (*timestamp++ != '-')
			return -1;
		tm.tm_mday = strtoul (timestamp, (char **)&timestamp, 10);
	} else {
		// YYYYMMDD
		tm.tm_mday = val % 100;
		tm.tm_mon = (val % 10000) / 100;
		tm.tm_year = val / 10000;
	}

	if (*timestamp++ != 'T')
		return -1;

	val = strtoul (timestamp, (char **)&timestamp, 10);
	if (*timestamp == ':') {
		// hh:mm:ss
		tm.tm_hour = val;
		timestamp++;
		tm.tm_min = strtoul (timestamp, (char **)&timestamp, 10);
		if (*timestamp++ != ':')
			return -1;
		tm.tm_sec = strtoul (timestamp, (char **)&timestamp, 10);
	} else {
		// hhmmss
		tm.tm_sec = val % 100;
		tm.tm_min = (val % 10000) / 100;
		tm.tm_hour = val / 10000;
	}

	tt = soup_mktime_utc (&tm);

	if (*timestamp == '.')
		strtoul (timestamp + 1, (char **)&timestamp, 10);

	if (*timestamp == '+' || *timestamp == '-') {
		int sign = (*timestamp == '+') ? -1 : 1;
		val = strtoul (timestamp + 1, (char **)&timestamp, 10);
		if (*timestamp == ':')
			val = 60 * val + strtoul (timestamp + 1, NULL, 10);
		else
			val = 60 * (val / 100) + (val % 100);
		tt += sign * val;
	}

	return tt;
}
