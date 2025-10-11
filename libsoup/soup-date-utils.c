/*
 * Copyright (C) 2020 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "soup-date-utils.h"
#include "soup-date-utils-private.h"

/**
 * soup_date_time_is_past:
 * @date: a #GDateTime
 *
 * Determines if @date is in the past.
 *
 * Returns: %TRUE if @date is in the past
 */
gboolean
soup_date_time_is_past (GDateTime *date)
{
        g_return_val_if_fail (date != NULL, TRUE);

	/* optimization */
	if (g_date_time_get_year (date) < 2025)
		return TRUE;

	return g_date_time_to_unix (date) < time (NULL);
}

/**
 * SoupDateFormat:
 * @SOUP_DATE_HTTP: RFC 1123 format, used by the HTTP "Date" header. Eg
 *   "Sun, 06 Nov 1994 08:49:37 GMT".
 * @SOUP_DATE_COOKIE: The format for the "Expires" timestamp in the
 *   Netscape cookie specification. Eg, "Sun, 06-Nov-1994 08:49:37 GMT".
 *
 * Date formats that [func@date_time_to_string] can use.
 *
 * @SOUP_DATE_HTTP and @SOUP_DATE_COOKIE always coerce the time to
 * UTC.
 *
 * This enum may be extended with more values in future releases.
 **/

/* Do not internationalize */
static const char *const months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* Do not internationalize */
static const char *const days[] = {
	"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
};

/**
 * soup_date_time_to_string:
 * @date: a #GDateTime
 * @format: the format to generate the date in
 *
 * Converts @date to a string in the format described by @format.
 *
 * Returns: (transfer full): @date as a string or %NULL
 **/
char *
soup_date_time_to_string (GDateTime      *date,
                          SoupDateFormat  format)
{
	g_return_val_if_fail (date != NULL, NULL);

	if (format == SOUP_DATE_HTTP || format == SOUP_DATE_COOKIE) {
		/* HTTP and COOKIE formats require UTC timestamp, so coerce
		 * @date if it's non-UTC.
		 */
		GDateTime *utcdate = g_date_time_to_utc (date);
                char *date_format;
                char *formatted_date;

                if (!utcdate)
                        return NULL;

                // We insert days/months ourselves to avoid locale specific formatting
                if (format == SOUP_DATE_HTTP) {
			/* "Sun, 06 Nov 1994 08:49:37 GMT" */
                        date_format = g_strdup_printf ("%s, %%d %s %%Y %%T GMT",
                                                       days[g_date_time_get_day_of_week (utcdate) - 1],
                                                       months[g_date_time_get_month (utcdate) - 1]);
                } else {
			/* "Sun, 06-Nov-1994 08:49:37 GMT" */
                        date_format = g_strdup_printf ("%s, %%d-%s-%%Y %%T GMT",
                                                       days[g_date_time_get_day_of_week (utcdate) - 1],
                                                       months[g_date_time_get_month (utcdate) - 1]);
		}

                formatted_date = g_date_time_format (utcdate, (const char*)date_format);
                g_date_time_unref (utcdate);
                g_free (date_format);
                return formatted_date;
	}

        g_return_val_if_reached (NULL);
}

static inline gboolean
parse_day (int *day, const char **date_string)
{
	char *end;

	*day = strtoul (*date_string, &end, 10);
	if (end == (char *)*date_string)
		return FALSE;

	while (*end == ' ' || *end == '-')
		end++;
	*date_string = end;
	return *day >= 1 && *day <= 31;
}

static inline gboolean
parse_month (int *month, const char **date_string)
{
	int i;

	for (i = 0; i < G_N_ELEMENTS (months); i++) {
		if (!g_ascii_strncasecmp (*date_string, months[i], 3)) {
			*month = i + 1;
			*date_string += 3;
			while (**date_string == ' ' || **date_string == '-')
				(*date_string)++;
			return TRUE;
		}
	}
	return FALSE;
}

static inline gboolean
parse_year (int *year, const char **date_string)
{
	char *end;

	*year = strtoul (*date_string, &end, 10);
	if (end == (char *)*date_string)
		return FALSE;

	if (end == (char *)*date_string + 2) {
		if (*year < 70)
			*year += 2000;
		else
			*year += 1900;
	} else if (end == (char *)*date_string + 3)
		*year += 1900;

	while (*end == ' ' || *end == '-')
		end++;
	*date_string = end;
	return *year > 0 && *year < 9999;
}

static inline gboolean
parse_time (int *hour, int *minute, int *second, const char **date_string)
{
	char *p, *end;

	*hour = strtoul (*date_string, &end, 10);
	if (end == (char *)*date_string || *end++ != ':')
		return FALSE;
	p = end;
	*minute = strtoul (p, &end, 10);
	if (end == p || *end++ != ':')
		return FALSE;
	p = end;
	*second = strtoul (p, &end, 10);
	if (end == p)
		return FALSE;
	p = end;

	while (*p == ' ')
		p++;
	*date_string = p;
	return *hour >= 0 && *hour < 24 && *minute >= 0 && *minute < 60 && *second >= 0 && *second < 60;
}

static inline gboolean
parse_timezone (GTimeZone **timezone, const char **date_string)
{
        gint32 offset_minutes;
        gboolean utc;

	if (!**date_string) {
                utc = FALSE;
		offset_minutes = 0;
	} else if (**date_string == '+' || **date_string == '-') {
		gulong val;
		int sign = (**date_string == '+') ? 1 : -1;
		val = strtoul (*date_string + 1, (char **)date_string, 10);
		if (val > 9999)
			return FALSE;
		if (**date_string == ':') {
			gulong val2 = strtoul (*date_string + 1, (char **)date_string, 10);
			if (val > 99 || val2 > 99)
				return FALSE;
			val = 60 * val + val2;
		} else
			val =  60 * (val / 100) + (val % 100);
		offset_minutes = sign * val;
		utc = (sign == -1) && !val;
	} else if (**date_string == 'Z') {
		offset_minutes = 0;
		utc = TRUE;
		(*date_string)++;
	} else if (!strcmp (*date_string, "GMT") ||
		   !strcmp (*date_string, "UTC")) {
		offset_minutes = 0;
		utc = TRUE;
		(*date_string) += 3;
	} else if (strchr ("ECMP", **date_string) &&
		   ((*date_string)[1] == 'D' || (*date_string)[1] == 'S') &&
		   (*date_string)[2] == 'T') {
		offset_minutes = -60 * (5 * strcspn ("ECMP", *date_string));
		if ((*date_string)[1] == 'D')
			offset_minutes += 60;
                utc = FALSE;
	} else
		return FALSE;

        if (utc)
                *timezone = g_time_zone_new_utc ();
        else
                *timezone = g_time_zone_new_offset (offset_minutes * 60);
	return TRUE;
}

static GDateTime *
parse_textual_date (const char *date_string)
{
        int month, day, year, hour, minute, second;
        GTimeZone *tz = NULL;
        GDateTime *date;

	/* If it starts with a word, it must be a weekday, which we skip */
	if (g_ascii_isalpha (*date_string)) {
		while (g_ascii_isalpha (*date_string))
			date_string++;
		if (*date_string == ',')
			date_string++;
		while (g_ascii_isspace (*date_string))
			date_string++;
	}

	/* If there's now another word, this must be an asctime-date */
	if (g_ascii_isalpha (*date_string)) {
		/* (Sun) Nov  6 08:49:37 1994 */
		if (!parse_month (&month, &date_string) ||
		    !parse_day (&day, &date_string) ||
		    !parse_time (&hour, &minute, &second, &date_string) ||
		    !parse_year (&year, &date_string) ||
		    !g_date_valid_dmy (day, month, year))
			return NULL;

		/* There shouldn't be a timezone, but check anyway */
		parse_timezone (&tz, &date_string);
	} else {
		/* Non-asctime date, so some variation of
		 * (Sun,) 06 Nov 1994 08:49:37 GMT
		 */
		if (!parse_day (&day, &date_string) ||
		    !parse_month (&month, &date_string) ||
		    !parse_year (&year, &date_string) ||
		    !parse_time (&hour, &minute, &second, &date_string) ||
		    !g_date_valid_dmy (day, month, year))
			return NULL;

		/* This time there *should* be a timezone, but we
		 * survive if there isn't.
		 */
		parse_timezone (&tz, &date_string);
	}

        if (!tz)
                tz = g_time_zone_new_utc ();

        date = g_date_time_new (tz, year, month, day, hour, minute, second);
        g_time_zone_unref (tz);

        return date;
}

/**
 * soup_date_time_new_from_http_string:
 * @date_string: The date as a string
 *
 * Parses @date_string and tries to extract a date from it.
 *
 * This recognizes all of the "HTTP-date" formats from RFC 2616, RFC 2822 dates,
 * and reasonable approximations thereof. (Eg, it is lenient about whitespace,
 * leading "0"s, etc.)
 *
 * Returns: (nullable): a new #GDateTime, or %NULL if @date_string
 *   could not be parsed.
 **/
GDateTime *
soup_date_time_new_from_http_string (const char *date_string)
{
        g_return_val_if_fail (date_string != NULL, NULL);

	while (g_ascii_isspace (*date_string))
		date_string++;

        /* If it starts with a digit, it's either an ISO 8601 date, or
         * an RFC2822 date without the optional weekday; in the later
         * case, there will be a month name later on, so look for one
         * of the month-start letters.
         * Previous versions of this library supported parsing iso8601 strings
         * however g_date_time_new_from_iso8601() should be used now. Just
         * catch those in case for testing.
         */
	if (G_UNLIKELY (g_ascii_isdigit (*date_string) && !strpbrk (date_string, "JFMASOND"))) {
                g_debug ("Unsupported format passed to soup_date_time_new_from_http_string(): %s", date_string);
                return NULL;
        }

	return parse_textual_date (date_string);
}
