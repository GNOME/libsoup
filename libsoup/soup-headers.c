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
soup_headers_parse (const char *str, int len, SoupMessageHeaders *dest)
{
	const char *headers_start;
	char *headers_copy, *name, *name_end, *value, *value_end;
	char *eol, *sol;
	gboolean success = FALSE;

	/* Technically, the grammar does allow NUL bytes in the
	 * headers, but this is probably a bug, and if it's not, we
	 * can't deal with them anyway.
	 */
	if (memchr (str, '\0', len))
		return FALSE;

	/* As per RFC 2616 section 19.3, we treat '\n' as the
	 * line terminator, and '\r', if it appears, merely as
	 * ignorable trailing whitespace.
	 */

	/* Skip over the Request-Line / Status-Line */
	headers_start = memchr (str, '\n', len);
	if (!headers_start)
		return FALSE;

	/* We work on a copy of the headers, which we can write '\0's
	 * into, so that we don't have to individually g_strndup and
	 * then g_free each header name and value.
	 */
	headers_copy = g_strndup (headers_start, len - (headers_start - str));
	value_end = headers_copy;

	while (*(value_end + 1)) {
		name = value_end + 1;
		name_end = strchr (name, ':');
		if (!name_end)
			goto done;

		/* Find the end of the value; ie, an end-of-line that
		 * isn't followed by a continuation line.
		 */
		value = name_end + 1;
		value_end = strchr (name, '\n');
		if (!value_end || value_end < name_end)
			goto done;
		while (*(value_end + 1) == ' ' || *(value_end + 1) == '\t') {
			value_end = strchr (value_end + 1, '\n');
			if (!value_end)
				goto done;
		}

		*name_end = '\0';
		*value_end = '\0';

		/* Skip leading whitespace */
		while (value < value_end &&
		       (*value == ' ' || *value == '\t' ||
			*value == '\r' || *value == '\n'))
			value++;

		/* Collapse continuation lines */
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

		soup_message_headers_append (dest, name, value);
        }
	success = TRUE;

done:
	g_free (headers_copy);
	return success;
}

/**
 * soup_headers_parse_request:
 * @str: the header string (including the trailing blank line)
 * @len: length of @str up to (but not including) the terminating blank line.
 * @req_headers: #SoupMessageHeaders to store the header values in
 * @req_method: if non-%NULL, will be filled in with the request method
 * @req_path: if non-%NULL, will be filled in with the request path
 * @ver: if non-%NULL, will be filled in with the HTTP version
 *
 * Parses the headers of an HTTP request in @str and stores the
 * results in @req_method, @req_path, @ver, and @req_headers.
 *
 * Beware that @req_headers may be modified even on failure.
 *
 * Return value: %SOUP_STATUS_OK if the headers could be parsed, or an
 * HTTP error to be returned to the client if they could not be.
 **/
guint
soup_headers_parse_request (const char          *str, 
			    int                  len, 
			    SoupMessageHeaders  *req_headers,
			    char               **req_method,
			    char               **req_path,
			    SoupHTTPVersion     *ver) 
{
	const char *method, *method_end, *path, *path_end;
	const char *version, *version_end, *headers;
	unsigned long major_version, minor_version;
	char *p;

	g_return_val_if_fail (str && *str, SOUP_STATUS_MALFORMED);

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
		return SOUP_STATUS_BAD_REQUEST;

	path = method_end;
	while (path < str + len && (*path == ' ' || *path == '\t'))
		path++;
	if (path >= str + len)
		return SOUP_STATUS_BAD_REQUEST;

	path_end = path;
	while (path_end < str + len && *path_end != ' ' && *path_end != '\t')
		path_end++;
	if (path_end >= str + len)
		return SOUP_STATUS_BAD_REQUEST;

	version = path_end;
	while (version < str + len && (*version == ' ' || *version == '\t'))
		version++;
	if (version + 8 >= str + len)
		return SOUP_STATUS_BAD_REQUEST;

	if (strncmp (version, "HTTP/", 5) != 0 ||
	    !g_ascii_isdigit (version[5]))
		return SOUP_STATUS_BAD_REQUEST;
	major_version = strtoul (version + 5, &p, 10);
	if (*p != '.' || !g_ascii_isdigit (p[1]))
		return SOUP_STATUS_BAD_REQUEST;
	minor_version = strtoul (p + 1, &p, 10);
	version_end = p;
	if (major_version != 1)
		return SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED;
	if (minor_version < 0 || minor_version > 1)
		return SOUP_STATUS_HTTP_VERSION_NOT_SUPPORTED;

	headers = version_end;
	while (headers < str + len && (*headers == '\r' || *headers == ' '))
		headers++;
	if (headers >= str + len || *headers != '\n')
		return SOUP_STATUS_BAD_REQUEST;

	if (!soup_headers_parse (str, len, req_headers)) 
		return SOUP_STATUS_BAD_REQUEST;

	if (req_method)
		*req_method = g_strndup (method, method_end - method);
	if (req_path)
		*req_path = g_strndup (path, path_end - path);
	if (ver)
		*ver = (minor_version == 0) ? SOUP_HTTP_1_0 : SOUP_HTTP_1_1;

	return SOUP_STATUS_OK;
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
 * either "\0" or "\r\n".
 *
 * Return value: %TRUE if @status_line was parsed successfully.
 **/
gboolean
soup_headers_parse_status_line (const char       *status_line,
				SoupHTTPVersion  *ver,
				guint            *status_code,
				char            **reason_phrase)
{
	unsigned long major_version, minor_version, code;
	const char *code_start, *code_end, *phrase_start, *phrase_end;
	char *p;

	if (strncmp (status_line, "HTTP/", 5) != 0 ||
	    !g_ascii_isdigit (status_line[5]))
		return FALSE;
	major_version = strtoul (status_line + 5, &p, 10);
	if (*p != '.' || !g_ascii_isdigit (p[1]))
		return FALSE;
	minor_version = strtoul (p + 1, &p, 10);
	if (major_version != 1)
		return FALSE;
	if (minor_version < 0 || minor_version > 1)
		return FALSE;
	if (ver)
		*ver = (minor_version == 0) ? SOUP_HTTP_1_0 : SOUP_HTTP_1_1;

	code_start = p;
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
	phrase_end = phrase_start + strcspn (phrase_start, "\n");
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
 * @headers: #SoupMessageheaders to store the header values in
 * @ver: if non-%NULL, will be filled in with the HTTP version
 * @status_code: if non-%NULL, will be filled in with the status code
 * @reason_phrase: if non-%NULL, will be filled in with the reason
 * phrase
 *
 * Parses the headers of an HTTP response in @str and stores the
 * results in @ver, @status_code, @reason_phrase, and @headers.
 *
 * Beware that @headers may be modified even on failure.
 *
 * Return value: success or failure.
 **/
gboolean
soup_headers_parse_response (const char          *str, 
			     int                  len, 
			     SoupMessageHeaders  *headers,
			     SoupHTTPVersion     *ver,
			     guint               *status_code,
			     char               **reason_phrase)
{
	if (!str || !*str)
		return FALSE;

	if (!soup_headers_parse (str, len, headers)) 
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
