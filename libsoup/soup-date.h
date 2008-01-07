/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifndef SOUP_DATE_H
#define SOUP_DATE_H 1

#include <time.h>
#include <libsoup/soup-types.h>

G_BEGIN_DECLS

/**
 * SoupDate:
 * @year: the year, 1 to 9999
 * @month: the month, 1 to 12
 * @day: day of the month, 1 to 31
 * @hour: hour of the day, 0 to 23
 * @minute: minute, 0 to 59
 * @second: second, 0 to 59 (or up to 61 in the case of leap seconds)
 * @utc: %TRUE if the date is in UTC
 * @offset: offset from UTC

 * A date and time. The date is assumed to be in the (proleptic)
 * Gregorian calendar. The time is in UTC if @utc is %TRUE. Otherwise,
 * the time is a local time, and @offset gives the offset from UTC in
 * minutes (such that adding @offset to the time would give the
 * correct UTC time). If @utc is %FALSE and @offset is 0, then the
 * %SoupDate represents a "floating" time with no associated timezone
 * information.
 **/
typedef struct {
	int      year;
	int      month;
	int      day;

	int      hour;
	int      minute;
	int      second;

	gboolean utc;
	int      offset;
} SoupDate;

/**
 * SoupDateFormat:
 * @SOUP_DATE_HTTP: RFC 1123 format, used by the HTTP "Date" header. Eg
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 * @SOUP_DATE_COOKIE: The format for the "Expires" timestamp in the
 * Netscape cookie specification. Eg, "Sun, 06-Nov-1994 08:49:37 GMT".
 * @SOUP_DATE_RFC2822: RFC 2822 format, eg "Sun, 6 Nov 1994 09:49:37 -0100"
 * @SOUP_DATE_ISO8601_COMPACT: ISO 8601 date/time with no optional
 * punctuation. Eg, "19941106T094937-0100".
 * @SOUP_DATE_ISO8601_FULL: ISO 8601 date/time with all optional
 * punctuation. Eg, "1994-11-06T09:49:37-01:00".
 * @SOUP_DATE_ISO8601_XMLRPC: ISO 8601 date/time as used by XML-RPC.
 * Eg, "19941106T09:49:37".
 * @SOUP_DATE_ISO8601: An alias for @SOUP_DATE_ISO8601_FULL.
 *
 * Date formats that soup_date_to_string() can use.
 *
 * @SOUP_DATE_HTTP and @SOUP_DATE_COOKIE always coerce the time to
 * UTC. @SOUP_DATE_ISO8601_XMLRPC uses the time as given, ignoring the
 * offset completely. @SOUP_DATE_RFC2822 and the other ISO 8601
 * variants use the local time, appending the offset information if
 * available.
 *
 * This enum may be extended with more values in future releases.
 **/
typedef enum {
	SOUP_DATE_HTTP = 1,
	SOUP_DATE_COOKIE,
	SOUP_DATE_RFC2822,
	SOUP_DATE_ISO8601_COMPACT,
	SOUP_DATE_ISO8601_FULL,
	SOUP_DATE_ISO8601 = SOUP_DATE_ISO8601_FULL,
	SOUP_DATE_ISO8601_XMLRPC
} SoupDateFormat;

GType soup_date_get_type (void);
#define SOUP_TYPE_DATE (soup_date_get_type ())

SoupDate *soup_date_new             (int             year,
				     int             month,
				     int             day, 
				     int             hour,
				     int             minute,
				     int             second);
SoupDate *soup_date_new_from_string (const char     *date_string);
SoupDate *soup_date_new_from_time_t (time_t          when);
SoupDate *soup_date_new_from_now    (int             offset_seconds);

char     *soup_date_to_string       (SoupDate       *date,
				     SoupDateFormat  format);
SoupDate *soup_date_copy            (SoupDate       *date);
void      soup_date_free            (SoupDate       *date);

G_END_DECLS

#endif /* SOUP_DATE_H */
