/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-headers.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#include <string.h>
#include <stdio.h>

#include "soup-headers.h"

/*
 * "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n          567\r\n\r\n"
 *                     ^             ^ ^    ^            ^   ^
 *                     |             | |    |            |   |
 *                    key            0 val  0          val+  0
 *                                         , <---memmove-...
 * 
 * key: "Content-Length"
 * val: "1234, 567"
 */
static gboolean
soup_headers_parse (gchar      *str, 
		    gint        len, 
		    GHashTable *dest)
{
	gchar *key = NULL, *val = NULL, *end = NULL;
	gint offset = 0, lws = 0;

	key = strstr (str, "\r\n");
	key += 2;

	/* join continuation headers, using a comma */
	while ((key = strstr (key, "\r\n"))) {
		key += 2;
		offset = key - str;

		/* pointing at another \r means end of header */
		if (*key == '\r') break;

		/* check if first character on the line is whitespace */
		if (*key == ' ' || *key == '\t') {
			key -= 2;

			/* eat any trailing space from the previous line*/
			while (key [-1] == ' ' || key [-1] == '\t') key--;

			/* count how many characters are whitespace */
			lws = strspn (key, " \t\r\n");

			/* if continuation line, replace whitespace with ", " */
			if (key [-1] != ':') {
				lws -= 2;
				key [0] = ',';
				key [1] = ' ';
			}

			g_memmove (key, &key [lws], len - offset - lws);
		}
	}

	key = str;

	/* set eos for header key and value and add to hashtable */
        while ((key = strstr (key, "\r\n"))) {
		
		/* set end of last val, or end of http reason phrase */
                key [0] = '\0';
		key += 2;

		/* pointing at another \r means end of header */
		if (*key == '\r') break;

                val = strchr (key, ':'); /* find start of val */

		if (!val || val > strchr (key, '\r'))
			goto THROW_MALFORMED_HEADER;

		/* set end of key */
		val [0] = '\0';
		
		val++;
		val += strspn (val, " \t");  /* skip whitespace */

		/* find the end of the value */
		end = strstr (val, "\r\n");
		if (!end)
			goto THROW_MALFORMED_HEADER;

		g_hash_table_insert (dest, g_strdup (key), g_strndup (val, end - val));

		key = end;
        }

	return TRUE;

 THROW_MALFORMED_HEADER:
	return FALSE;
}

gboolean
soup_headers_parse_request (gchar       *str, 
			    gint         len, 
			    GHashTable  *dest, 
			    gchar      **req_method,
			    gchar      **req_path) 
{
	guint http_major, http_minor;
	gchar method[16], path[1024];

	if (!str || !*str || len < sizeof ("GET / HTTP/0.0\r\n\r\n"))
		goto THROW_MALFORMED_HEADER;

	if (sscanf (str, 
		    "%16s %1024s HTTP/%1u.%1u", 
		    method,
		    path,
		    &http_major,
		    &http_minor) < 4)
		goto THROW_MALFORMED_HEADER;

	if (!soup_headers_parse (str, len, dest)) 
		goto THROW_MALFORMED_HEADER;

	*req_method = g_strdup (method);
	*req_path = g_strdup (path);

	return TRUE;

 THROW_MALFORMED_HEADER:
	return FALSE;
}

gboolean
soup_headers_parse_response (gchar        *str, 
			     gint          len, 
			     GHashTable   *dest, 
			     guint        *status_code,
			     gchar const **status_phrase)
{
	guint http_major, http_minor;
	guint phrase_start = 0;

	if (!str || !*str || len < sizeof ("HTTP/0.0 000 A\r\n\r\n"))
		goto THROW_MALFORMED_HEADER;

	if (sscanf (str, 
		    "HTTP/%1u.%1u %3u %n", 
		    &http_major,
		    &http_minor,
		    status_code, 
		    &phrase_start) < 3 || !phrase_start)
		goto THROW_MALFORMED_HEADER;

	if (!soup_headers_parse (str, len, dest)) 
		goto THROW_MALFORMED_HEADER;

	*status_phrase = &str [phrase_start];

	return TRUE;

 THROW_MALFORMED_HEADER:
	return FALSE;
}
