/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* soup-uri.c : utility functions to parse URLs */

/*
 * Copyright 1999-2003 Ximian, Inc.
 */

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "soup-uri.h"

static void append_uri_encoded (GString *str, const char *in, const char *extra_enc_chars);

static inline SoupProtocol
soup_uri_get_protocol (const char *proto, int len)
{
	char proto_buf[128];

	g_return_val_if_fail (len < sizeof (proto_buf), 0);

	memcpy (proto_buf, proto, len);
	proto_buf[len] = '\0';
	return g_quark_from_string (proto_buf);
}

static inline const char *
soup_protocol_name (SoupProtocol proto)
{
	return g_quark_to_string (proto);
}

static inline guint
soup_protocol_default_port (SoupProtocol proto)
{
	if (proto == SOUP_PROTOCOL_HTTP)
		return 80;
	else if (proto == SOUP_PROTOCOL_HTTPS)
		return 443;
	else
		return 0;
}

/**
 * soup_uri_new_with_base:
 * @base: a base URI
 * @uri_string: the URI
 *
 * Parses @uri_string relative to @base.
 *
 * Return value: a parsed #SoupUri.
 **/
SoupUri *
soup_uri_new_with_base (const SoupUri *base, const char *uri_string)
{
	SoupUri *uri;
	const char *end, *hash, *colon, *at, *slash, *question;
	const char *p;

	uri = g_new0 (SoupUri, 1);

	/* See RFC2396 for details. IF YOU CHANGE ANYTHING IN THIS
	 * FUNCTION, RUN tests/uri-parsing AFTERWARDS.
	 */

	/* Find fragment. */
	end = hash = strchr (uri_string, '#');
	if (hash && hash[1]) {
		uri->fragment = g_strdup (hash + 1);
		soup_uri_decode (uri->fragment);
	} else
		end = uri_string + strlen (uri_string);

	/* Find protocol: initial [a-z+.-]* substring until ":" */
	p = uri_string;
	while (p < end && (isalnum ((unsigned char)*p) ||
			   *p == '.' || *p == '+' || *p == '-'))
		p++;

	if (p > uri_string && *p == ':') {
		uri->protocol = soup_uri_get_protocol (uri_string, p - uri_string);
		if (!uri->protocol) {
			soup_uri_free (uri);
			return NULL;
		}
		uri_string = p + 1;
	}

	if (!*uri_string && !base)
		return uri;

	/* Check for authority */
	if (strncmp (uri_string, "//", 2) == 0) {
		uri_string += 2;

		slash = uri_string + strcspn (uri_string, "/#");
		at = strchr (uri_string, '@');
		if (at && at < slash) {
			colon = strchr (uri_string, ':');
			if (colon && colon < at) {
				uri->passwd = g_strndup (colon + 1,
							 at - colon - 1);
				soup_uri_decode (uri->passwd);
			} else {
				uri->passwd = NULL;
				colon = at;
			}

			uri->user = g_strndup (uri_string, colon - uri_string);
			soup_uri_decode (uri->user);
			uri_string = at + 1;
		} else
			uri->user = uri->passwd = NULL;

		/* Find host and port. */
		colon = strchr (uri_string, ':');
		if (colon && colon < slash) {
			uri->host = g_strndup (uri_string, colon - uri_string);
			uri->port = strtoul (colon + 1, NULL, 10);
		} else {
			uri->host = g_strndup (uri_string, slash - uri_string);
			soup_uri_decode (uri->host);
		}

		uri_string = slash;
	}

	/* Find query */
	question = memchr (uri_string, '?', end - uri_string);
	if (question) {
		if (question[1]) {
			uri->query = g_strndup (question + 1,
						end - (question + 1));
			soup_uri_decode (uri->query);
		}
		end = question;
	}

	if (end != uri_string) {
		uri->path = g_strndup (uri_string, end - uri_string);
		soup_uri_decode (uri->path);
	}

	/* Apply base URI. Again, this is spelled out in RFC 2396. */
	if (base && !uri->protocol && uri->host)
		uri->protocol = base->protocol;
	else if (base && !uri->protocol) {
		uri->protocol = base->protocol;
		uri->user = g_strdup (base->user);
		uri->passwd = g_strdup (base->passwd);
		uri->host = g_strdup (base->host);
		uri->port = base->port;

		if (!uri->path) {
			if (uri->query)
				uri->path = g_strdup ("");
			else {
				uri->path = g_strdup (base->path);
				uri->query = g_strdup (base->query);
			}
		}

		if (*uri->path != '/') {
			char *newpath, *last, *p, *q;

			last = strrchr (base->path, '/');
			if (last) {
				newpath = g_strdup_printf ("%.*s/%s",
							   last - base->path,
							   base->path,
							   uri->path);
			} else
				newpath = g_strdup_printf ("/%s", uri->path);

			/* Remove "./" where "." is a complete segment. */
			for (p = newpath + 1; *p; ) {
				if (*(p - 1) == '/' &&
				    *p == '.' && *(p + 1) == '/')
					memmove (p, p + 2, strlen (p + 2) + 1);
				else
					p++;
			}
			/* Remove "." at end. */
			if (p > newpath + 2 &&
			    *(p - 1) == '.' && *(p - 2) == '/')
				*(p - 1) = '\0';
			/* Remove "<segment>/../" where <segment> != ".." */
			for (p = newpath + 1; *p; ) {
				if (!strncmp (p, "../", 3)) {
					p += 3;
					continue;
				}
				q = strchr (p + 1, '/');
				if (!q)
					break;
				if (strncmp (q, "/../", 4) != 0) {
					p = q + 1;
					continue;
				}
				memmove (p, q + 4, strlen (q + 4) + 1);
				p = newpath + 1;
			}
			/* Remove "<segment>/.." at end where <segment> != ".." */
			q = strrchr (newpath, '/');
			if (q && !strcmp (q, "/..")) {
				p = q - 1;
				while (p > newpath && *p != '/')
					p--;
				if (strncmp (p, "/../", 4) != 0)
					*(p + 1) = 0;
			}

			g_free (uri->path);
			uri->path = newpath;
		}
	}

	/* Sanity check */
	if ((uri->protocol == SOUP_PROTOCOL_HTTP ||
	     uri->protocol == SOUP_PROTOCOL_HTTPS) && !uri->host) {
		soup_uri_free (uri);
		return NULL;
	}

	if (!uri->port)
		uri->port = soup_protocol_default_port (uri->protocol);
	if (!uri->path)
		uri->path = g_strdup ("");

	return uri;
}

/**
 * soup_uri_new:
 * @uri_string: a URI
 *
 * Parses an absolute URI.
 *
 * Return value: a #SoupUri, or %NULL.
 **/
SoupUri *
soup_uri_new (const char *uri_string)
{
	SoupUri *uri;

	uri = soup_uri_new_with_base (NULL, uri_string);
	if (!uri)
		return NULL;
	if (!uri->protocol) {
		soup_uri_free (uri);
		return NULL;
	}

	return uri;
}


static inline void
append_uri (GString *str, const char *in, const char *extra_enc_chars,
	    gboolean pre_encoded)
{
	if (pre_encoded)
		g_string_append (str, in);
	else
		append_uri_encoded (str, in, extra_enc_chars);
}

/**
 * soup_uri_to_string:
 * @uri: a #SoupUri
 * @just_path: if %TRUE, output just the path and query portions
 *
 * Returns a string representing @uri.
 *
 * Return value: a string representing @uri, which the caller must free.
 **/
char *
soup_uri_to_string (const SoupUri *uri, gboolean just_path)
{
	GString *str;
	char *return_result;
	gboolean pre_encoded = uri->broken_encoding;

	/* IF YOU CHANGE ANYTHING IN THIS FUNCTION, RUN
	 * tests/uri-parsing AFTERWARD.
	 */

	str = g_string_sized_new (20);

	if (uri->protocol && !just_path)
		g_string_sprintfa (str, "%s:", soup_protocol_name (uri->protocol));
	if (uri->host && !just_path) {
		g_string_append (str, "//");
		if (uri->user) {
			append_uri (str, uri->user, ":;@/", pre_encoded);
			g_string_append_c (str, '@');
		}
		append_uri (str, uri->host, ":/", pre_encoded);
		if (uri->port && uri->port != soup_protocol_default_port (uri->protocol))
			g_string_append_printf (str, ":%d", uri->port);
		if (!uri->path && (uri->query || uri->fragment))
			g_string_append_c (str, '/');
	}

	if (uri->path && *uri->path)
		append_uri (str, uri->path, "?", pre_encoded);
	else if (just_path)
		g_string_append_c (str, '/');

	if (uri->query) {
		g_string_append_c (str, '?');
		append_uri (str, uri->query, NULL, pre_encoded);
	}
	if (uri->fragment && !just_path) {
		g_string_append_c (str, '#');
		append_uri (str, uri->fragment, NULL, pre_encoded);
	}

	return_result = str->str;
	g_string_free (str, FALSE);

	return return_result;
}

/**
 * soup_uri_copy:
 * @uri: a #SoupUri
 *
 * Copies @uri
 *
 * Return value: a copy of @uri, which must be freed with soup_uri_free()
 **/
SoupUri *
soup_uri_copy (const SoupUri *uri)
{
	SoupUri *dup;

	g_return_val_if_fail (uri != NULL, NULL);

	dup = g_new0 (SoupUri, 1);
	dup->protocol = uri->protocol;
	dup->user     = g_strdup (uri->user);
	dup->passwd   = g_strdup (uri->passwd);
	dup->host     = g_strdup (uri->host);
	dup->port     = uri->port;
	dup->path     = g_strdup (uri->path);
	dup->query    = g_strdup (uri->query);
	dup->fragment = g_strdup (uri->fragment);

	dup->broken_encoding = uri->broken_encoding;

	return dup;
}

/**
 * soup_uri_copy_root:
 * @uri: a #SoupUri
 *
 * Copies the protocol, host, and port of @uri into a new #SoupUri
 * (all other fields in the new URI will be empty.)
 *
 * Return value: a partial copy of @uri, which must be freed with
 * soup_uri_free()
 **/
SoupUri *
soup_uri_copy_root (const SoupUri *uri)
{
	SoupUri *dup;

	g_return_val_if_fail (uri != NULL, NULL);

	dup = g_new0 (SoupUri, 1);
	dup->protocol = uri->protocol;
	dup->host     = g_strdup (uri->host);
	dup->port     = uri->port;

	return dup;
}

static inline gboolean
parts_equal (const char *one, const char *two)
{
	if (!one && !two)
		return TRUE;
	if (!one || !two)
		return FALSE;
	return !strcmp (one, two);
}

/**
 * soup_uri_equal:
 * @uri1: a #SoupUri
 * @uri2: another #SoupUri
 *
 * Tests whether or not @uri1 and @uri2 are equal in all parts
 *
 * Return value: %TRUE or %FALSE
 **/
gboolean 
soup_uri_equal (const SoupUri *uri1, const SoupUri *uri2)
{
	if (uri1->protocol != uri2->protocol              ||
	    uri1->port     != uri2->port                  ||
	    !parts_equal (uri1->user, uri2->user)         ||
	    !parts_equal (uri1->passwd, uri2->passwd)     ||
	    !parts_equal (uri1->host, uri2->host)         ||
	    !parts_equal (uri1->path, uri2->path)         ||
	    !parts_equal (uri1->query, uri2->query)       ||
	    !parts_equal (uri1->fragment, uri2->fragment))
		return FALSE;

	return TRUE;
}

/**
 * soup_uri_free:
 * @uri: a #SoupUri
 *
 * Frees @uri.
 **/
void
soup_uri_free (SoupUri *uri)
{
	g_return_if_fail (uri != NULL);

	g_free (uri->user);
	g_free (uri->passwd);
	g_free (uri->host);
	g_free (uri->path);
	g_free (uri->query);
	g_free (uri->fragment);

	g_free (uri);
}

/* From RFC 2396 2.4.3, the characters that should always be encoded */
static const char uri_encoded_char[] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x00 - 0x0f */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x10 - 0x1f */
	1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  ' ' - '/'  */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,  /*  '0' - '?'  */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  '@' - 'O'  */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,  /*  'P' - '_'  */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /*  '`' - 'o'  */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,  /*  'p' - 0x7f */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

static void
append_uri_encoded (GString *str, const char *in, const char *extra_enc_chars)
{
	const unsigned char *s = (const unsigned char *)in;

	while (*s) {
		if (uri_encoded_char[*s] ||
		    (extra_enc_chars && strchr (extra_enc_chars, *s)))
			g_string_append_printf (str, "%%%02x", (int)*s++);
		else
			g_string_append_c (str, *s++);
	}
}

/**
 * soup_uri_encode:
 * @part: a URI part
 * @escape_extra: additional characters beyond " \"%#<>{}|\^[]`"
 * to escape (or %NULL)
 *
 * This %-encodes the given URI part and returns the escaped version
 * in allocated memory, which the caller must free when it is done.
 *
 * Return value: the encoded URI part
 **/
char *
soup_uri_encode (const char *part, const char *escape_extra)
{
	GString *str;
	char *encoded;

	str = g_string_new (NULL);
	append_uri_encoded (str, part, escape_extra);
	encoded = str->str;
	g_string_free (str, FALSE);

	return encoded;
}

/**
 * soup_uri_decode:
 * @part: a URI part
 *
 * %-decodes the passed-in URI *in place*. The decoded version is
 * never longer than the encoded version, so there does not need to
 * be any additional space at the end of the string.
 */
void
soup_uri_decode (char *part)
{
	unsigned char *s, *d;

#define XDIGIT(c) ((c) <= '9' ? (c) - '0' : ((c) & 0x4F) - 'A' + 10)

	s = d = (unsigned char *)part;
	do {
		if (*s == '%' && s[1] && s[2]) {
			*d++ = (XDIGIT (s[1]) << 4) + XDIGIT (s[2]);
			s += 2;
		} else
			*d++ = *s;
	} while (*s++);
}

/**
 * soup_uri_uses_default_port:
 * @uri: a #SoupUri
 *
 * Tests if @uri uses the default port for its protocol. (Eg, 80 for
 * http.)
 *
 * Return value: %TRUE or %FALSE
 **/
gboolean
soup_uri_uses_default_port (const SoupUri *uri)
{
	return uri->port == soup_protocol_default_port (uri->protocol);
}
