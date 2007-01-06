/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-headers.c: HTTP message header parsing
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "soup-headers.h"
#include "soup-misc.h"

static gboolean
soup_headers_parse (const char *str, 
		    int         len, 
		    GHashTable *dest)
{
	const char *end = str + len;
	const char *name_start, *name_end, *value_start, *value_end;
	char *name, *value, *eol, *sol;
	GSList *hdrs;

	/* As per RFC 2616 section 19.3, we treat '\n' as the
	 * line terminator, and '\r', if it appears, merely as
	 * ignorable trailing whitespace.
	 */

	/* Skip over the Request-Line / Status-Line */
	value_end = memchr (str, '\n', len);
	if (!value_end)
		return FALSE;

	while (value_end < end - 1) {
		name_start = value_end + 1;
		name_end = memchr (name_start, ':', end - name_start);
		if (!name_end)
			return FALSE;

		/* Find the end of the value; ie, an end-of-line that
		 * isn't followed by a continuation line.
		 */
		value_end = memchr (name_start, '\n', end - name_start);
		if (!value_end || value_end < name_end)
			return FALSE;
		while (value_end != end - 1 &&
		       (*(value_end + 1) == ' ' || *(value_end + 1) == '\t')) {
			value_end = memchr (value_end + 1, '\n', end - value_end);
			if (!value_end)
				return FALSE;
		}

		name = g_strndup (name_start, name_end - name_start);

		value_start = name_end + 1;
		while (value_start < value_end &&
		       (*value_start == ' ' || *value_start == '\t' ||
			*value_start == '\r' || *value_start == '\n'))
			value_start++;
		value = g_strndup (value_start, value_end - value_start);

		/* Collapse continuation lines inside value */
		while ((eol = strchr (value, '\n'))) {
			/* find start of next line */
			sol = eol + 1;
			while (*sol == ' ' || *sol == '\t')
				sol++;

			/* back up over trailing whitespace on current line */
			while (eol[-1] == ' ' || eol[-1] == '\t' || eol[-1] == '\r')
				eol--;

			/* Delete all but one SP */
			*eol = ' ';
			g_memmove (eol + 1, sol, strlen (sol) + 1);
		}

		/* clip trailing whitespace */
		eol = strchr (value, '\0');
		while (eol > value &&
		       (eol[-1] == ' ' || eol[-1] == '\t' || eol[-1] == '\r'))
			eol--;
		*eol = '\0';

		hdrs = g_hash_table_lookup (dest, name);
		hdrs = g_slist_append (hdrs, value);
		if (!hdrs->next)
			g_hash_table_insert (dest, name, hdrs);
		else
			g_free (name);
        }

	return TRUE;
}

/**
 * soup_headers_parse_request:
 * @str: the header string (including the trailing blank line)
 * @len: length of @str up to (but not including) the terminating blank line.
 * @dest: #GHashTable to store the header values in
 * @req_method: if non-%NULL, will be filled in with the request method
 * @req_path: if non-%NULL, will be filled in with the request path
 * @ver: if non-%NULL, will be filled in with the HTTP version
 *
 * Parses the headers of an HTTP request in @str and stores the
 * results in @req_method, @req_path, @ver, and @dest.
 *
 * Return value: success or failure.
 **/
gboolean
soup_headers_parse_request (const char       *str, 
			    int               len, 
			    GHashTable       *dest, 
			    char            **req_method,
			    char            **req_path,
			    SoupHttpVersion  *ver) 
{
	const char *method, *method_end, *path, *path_end, *version, *headers;
	int minor_version;

	if (!str || !*str)
		return FALSE;

	/* RFC 2616 4.1 "servers SHOULD ignore any empty line(s)
	 * received where a Request-Line is expected."
	 */
	while (*str == '\r' || *str == '\n') {
		str++;
		len--;
	}

	/* RFC 2616 19.3 "[servers] SHOULD accept any amount of SP or
	 * HT characters between [Request-Line] fields"
	 */

	method = method_end = str;
	while (method_end < str + len && *method_end != ' ' && *method_end != '\t')
		method_end++;
	if (method_end >= str + len)
		return FALSE;

	path = method_end;
	while (path < str + len && (*path == ' ' || *path == '\t'))
		path++;
	if (path >= str + len)
		return FALSE;

	path_end = path;
	while (path_end < str + len && *path_end != ' ' && *path_end != '\t')
		path_end++;
	if (path_end >= str + len)
		return FALSE;

	version = path_end;
	while (version < str + len && (*version == ' ' || *version == '\t'))
		version++;
	if (version + 8 >= str + len)
		return FALSE;

	/* FIXME: we want SoupServer to return
	 * SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED here
	 */
	if (strncmp (version, "HTTP/1.", 7) != 0)
		return FALSE;
	minor_version = version[7] - '0';
	if (minor_version < 0 || minor_version > 1)
		return FALSE;

	headers = version + 8;
	if (headers < str + len && *headers == '\r')
		headers++;
	if (headers >= str + len || *headers != '\n')
		return FALSE;

	if (!soup_headers_parse (str, len, dest)) 
		return FALSE;

	if (req_method)
		*req_method = g_strndup (method, method_end - method);
	if (req_path)
		*req_path = g_strndup (path, path_end - path);
	if (ver)
		*ver = (minor_version == 0) ? SOUP_HTTP_1_0 : SOUP_HTTP_1_1;

	return TRUE;
}

/**
 * soup_headers_parse_status_line:
 * @status_line: an HTTP Status-Line
 * @ver: if non-%NULL, will be filled in with the HTTP version
 * @status_code: if non-%NULL, will be filled in with the status code
 * @reason_phrase: if non-%NULL, will be filled in with the reason
 * phrase
 *
 * Parses the HTTP Status-Line string in @status_line into @ver,
 * @status_code, and @reason_phrase. @status_line must be terminated by
 * either '\0' or '\r\n'.
 *
 * Return value: %TRUE if @status_line was parsed successfully.
 **/
gboolean
soup_headers_parse_status_line (const char       *status_line,
				SoupHttpVersion  *ver,
				guint            *status_code,
				char            **reason_phrase)
{
	guint minor_version, code;
	const char *code_start, *code_end, *phrase_start, *phrase_end;

	if (strncmp (status_line, "HTTP/1.", 7) != 0)
		return FALSE;
	minor_version = status_line[7] - '0';
	if (minor_version < 0 || minor_version > 1)
		return FALSE;
	if (ver)
		*ver = (minor_version == 0) ? SOUP_HTTP_1_0 : SOUP_HTTP_1_1;

	code_start = status_line + 8;
	while (*code_start == ' ' || *code_start == '\t')
		code_start++;
	code_end = code_start;
	while (*code_end >= '0' && *code_end <= '9')
		code_end++;
	if (code_end != code_start + 3)
		return FALSE;
	code = atoi (code_start);
	if (code < 100 || code > 599)
		return FALSE;
	if (status_code)
		*status_code = code;

	phrase_start = code_end;
	while (*phrase_start == ' ' || *phrase_start == '\t')
		phrase_start++;
	phrase_end = strchr (phrase_start, '\n');
	if (!phrase_end)
		return FALSE;
	while (phrase_end > phrase_start &&
	       (phrase_end[-1] == '\r' || phrase_end[-1] == ' ' || phrase_end[-1] == '\t'))
		phrase_end--;
	if (reason_phrase)
		*reason_phrase = g_strndup (phrase_start, phrase_end - phrase_start);

	return TRUE;
}

/**
 * soup_headers_parse_response:
 * @str: the header string (including the trailing blank line)
 * @len: length of @str up to (but not including) the terminating blank line.
 * @dest: #GHashTable to store the header values in
 * @ver: if non-%NULL, will be filled in with the HTTP version
 * @status_code: if non-%NULL, will be filled in with the status code
 * @reason_phrase: if non-%NULL, will be filled in with the reason
 * phrase
 *
 * Parses the headers of an HTTP response in @str and stores the
 * results in @ver, @status_code, @reason_phrase, and @dest.
 *
 * Return value: success or failure.
 **/
gboolean
soup_headers_parse_response (const char       *str, 
			     int               len, 
			     GHashTable       *dest,
			     SoupHttpVersion  *ver,
			     guint            *status_code,
			     char            **reason_phrase)
{
	if (!str || !*str)
		return FALSE;

	if (!soup_headers_parse (str, len, dest)) 
		return FALSE;

	if (!soup_headers_parse_status_line (str, 
					     ver, 
					     status_code, 
					     reason_phrase))
		return FALSE;

	return TRUE;
}


/*
 * HTTP parameterized header parsing
 */

char *
soup_header_param_copy_token (GHashTable *tokens, char *t)
{
	char *data;

	g_return_val_if_fail (tokens, NULL);
	g_return_val_if_fail (t, NULL);

	if ( (data = g_hash_table_lookup (tokens, t)))
		return g_strdup (data);
	else
		return NULL;
}

static void
decode_lwsp (char **in)
{
	char *inptr = *in;

	while (isspace (*inptr))
		inptr++;

	*in = inptr;
}

static char *
decode_quoted_string (char **in)
{
	char *inptr = *in;
	char *out = NULL, *outptr;
	int outlen;
	int c;

	decode_lwsp (&inptr);
	if (*inptr == '"') {
		char *intmp;
		int skip = 0;

                /* first, calc length */
                inptr++;
                intmp = inptr;
                while ( (c = *intmp++) && c != '"') {
                        if (c == '\\' && *intmp) {
                                intmp++;
                                skip++;
                        }
                }

                outlen = intmp - inptr - skip;
                out = outptr = g_malloc (outlen + 1);

                while ( (c = *inptr++) && c != '"') {
                        if (c == '\\' && *inptr) {
                                c = *inptr++;
                        }
                        *outptr++ = c;
                }
                *outptr = 0;
        }

        *in = inptr;

        return out;
}

char *
soup_header_param_decode_token (char **in)
{
	char *inptr = *in;
	char *start;

	decode_lwsp (&inptr);
	start = inptr;

	while (*inptr && *inptr != '=' && *inptr != ',')
		inptr++;

	if (inptr > start) {
		*in = inptr;
		return g_strndup (start, inptr - start);
	}
	else
		return NULL;
}

static char *
decode_value (char **in)
{
	char *inptr = *in;

	decode_lwsp (&inptr);
	if (*inptr == '"')
		return decode_quoted_string (in);
	else
		return soup_header_param_decode_token (in);
}

GHashTable *
soup_header_param_parse_list (const char *header)
{
	char *ptr;
	gboolean added = FALSE;
	GHashTable *params = g_hash_table_new (soup_str_case_hash, 
					       soup_str_case_equal);

	ptr = (char *) header;
	while (ptr && *ptr) {
		char *name;
		char *value;

		name = soup_header_param_decode_token (&ptr);
		if (*ptr == '=') {
			ptr++;
			value = decode_value (&ptr);
			g_hash_table_insert (params, name, value);
			added = TRUE;
		}

		if (*ptr == ',')
			ptr++;
	}

	if (!added) {
		g_hash_table_destroy (params);
		params = NULL;
	}

	return params;
}

static void
destroy_param_hash_elements (gpointer key, gpointer value, gpointer user_data)
{
	g_free (key);
	g_free (value);
}

void
soup_header_param_destroy_hash (GHashTable *table)
{
	g_hash_table_foreach (table, destroy_param_hash_elements, NULL);
	g_hash_table_destroy (table);
}
