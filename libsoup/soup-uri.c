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
	int i;

	g_return_val_if_fail (len < sizeof (proto_buf) - 1, 0);

	for (i = 0; i < len; i++)
		proto_buf[i] = g_ascii_tolower (proto[i]);
	proto_buf[i] = '\0';
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
	const char *end, *hash, *colon, *at, *path, *question;
	const char *p, *hostend;
	gboolean remove_dot_segments = TRUE;

	uri = g_new0 (SoupUri, 1);

	/* See RFC 3986 for details. IF YOU CHANGE ANYTHING IN THIS
	 * FUNCTION, RUN tests/uri-parsing AFTERWARDS.
	 */

	/* Find fragment. */
	end = hash = strchr (uri_string, '#');
	if (hash && hash[1]) {
		uri->fragment = g_strdup (hash + 1);
		if (!soup_uri_normalize (uri->fragment, NULL)) {
			soup_uri_free (uri);
			return NULL;
		}
	} else
		end = uri_string + strlen (uri_string);

	/* Find protocol: initial [a-z+.-]* substring until ":" */
	p = uri_string;
	while (p < end && (g_ascii_isalnum (*p) ||
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

		path = uri_string + strcspn (uri_string, "/?#");
		at = strchr (uri_string, '@');
		if (at && at < path) {
			colon = strchr (uri_string, ':');
			if (colon && colon < at) {
				uri->passwd = g_strndup (colon + 1,
							 at - colon - 1);
				if (!soup_uri_decode (uri->passwd)) {
					soup_uri_free (uri);
					return NULL;
				}
			} else {
				uri->passwd = NULL;
				colon = at;
			}

			uri->user = g_strndup (uri_string, colon - uri_string);
			if (!soup_uri_decode (uri->user)) {
				soup_uri_free (uri);
				return NULL;
			}
			uri_string = at + 1;
		} else
			uri->user = uri->passwd = NULL;

		/* Find host and port. */
		if (*uri_string == '[') {
			uri_string++;
			hostend = strchr (uri_string, ']');
			if (!hostend || hostend > path) {
				soup_uri_free (uri);
				return NULL;
			}
			if (*(hostend + 1) == ':')
				colon = hostend + 1;
			else
				colon = NULL;
		} else {
			colon = memchr (uri_string, ':', path - uri_string);
			hostend = colon ? colon : path;
		}

		uri->host = g_strndup (uri_string, hostend - uri_string);
		if (!soup_uri_decode (uri->host)) {
			soup_uri_free (uri);
			return NULL;
		}

		if (colon && colon != path - 1) {
			char *portend;
			uri->port = strtoul (colon + 1, &portend, 10);
			if (portend != (char *)path) {
				soup_uri_free (uri);
				return NULL;
			}
		}

		uri_string = path;
	}

	/* Find query */
	question = memchr (uri_string, '?', end - uri_string);
	if (question) {
		if (question[1]) {
			uri->query = g_strndup (question + 1,
						end - (question + 1));
			if (!soup_uri_normalize (uri->query, NULL)) {
				soup_uri_free (uri);
				return NULL;
			}
		}
		end = question;
	}

	if (end != uri_string) {
		uri->path = g_strndup (uri_string, end - uri_string);
		if (!soup_uri_normalize (uri->path, NULL)) {
			soup_uri_free (uri);
			return NULL;
		}
	}

	/* Apply base URI. Again, this is spelled out in RFC 3986. */
	if (base && !uri->protocol && uri->host)
		uri->protocol = base->protocol;
	else if (base && !uri->protocol) {
		uri->protocol = base->protocol;
		uri->user = g_strdup (base->user);
		uri->passwd = g_strdup (base->passwd);
		uri->host = g_strdup (base->host);
		uri->port = base->port;

		if (!uri->path) {
			uri->path = g_strdup (base->path);
			if (!uri->query)
				uri->query = g_strdup (base->query);
			remove_dot_segments = FALSE;
		} else if (*uri->path != '/') {
			char *newpath, *last;

			last = strrchr (base->path, '/');
			if (last) {
				newpath = g_strdup_printf ("%.*s/%s",
							   (int)(last - base->path),
							   base->path,
							   uri->path);
			} else
				newpath = g_strdup_printf ("/%s", uri->path);

			g_free (uri->path);
			uri->path = newpath;
		}
	}

	if (remove_dot_segments && uri->path && *uri->path) {
		char *p = uri->path, *q;

		/* Remove "./" where "." is a complete segment. */
		for (p = uri->path + 1; *p; ) {
			if (*(p - 1) == '/' &&
			    *p == '.' && *(p + 1) == '/')
				memmove (p, p + 2, strlen (p + 2) + 1);
			else
				p++;
		}
		/* Remove "." at end. */
		if (p > uri->path + 2 &&
		    *(p - 1) == '.' && *(p - 2) == '/')
			*(p - 1) = '\0';

		/* Remove "<segment>/../" where <segment> != ".." */
		for (p = uri->path + 1; *p; ) {
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
			p = uri->path + 1;
		}
		/* Remove "<segment>/.." at end where <segment> != ".." */
		q = strrchr (uri->path, '/');
		if (q && !strcmp (q, "/..")) {
			p = q - 1;
			while (p > uri->path && *p != '/')
				p--;
			if (strncmp (p, "/../", 4) != 0)
				*(p + 1) = 0;
		}

		/* Remove extraneous initial "/.."s */
		while (!strncmp (uri->path, "/../", 4))
			memmove (uri->path, uri->path + 3, strlen (uri->path) - 2);
		if (!strcmp (uri->path, "/.."))
			uri->path[1] = '\0';
	}

	/* HTTP-specific stuff */
	if (uri->protocol == SOUP_PROTOCOL_HTTP || uri->protocol == SOUP_PROTOCOL_HTTPS) {
		if (!uri->host) {
			soup_uri_free (uri);
			return NULL;
		}
		if (!uri->path)
			uri->path = g_strdup ("/");
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

	/* IF YOU CHANGE ANYTHING IN THIS FUNCTION, RUN
	 * tests/uri-parsing AFTERWARD.
	 */

	str = g_string_sized_new (20);

	if (uri->protocol && !just_path)
		g_string_sprintfa (str, "%s:", soup_protocol_name (uri->protocol));
	if (uri->host && !just_path) {
		g_string_append (str, "//");
		if (uri->user) {
			append_uri_encoded (str, uri->user, ":;@?/");
			g_string_append_c (str, '@');
		}
		if (strchr (uri->host, ':')) {
			g_string_append_c (str, '[');
			g_string_append (str, uri->host);
			g_string_append_c (str, ']');
		} else
			append_uri_encoded (str, uri->host, ":/");
		if (uri->port && uri->port != soup_protocol_default_port (uri->protocol))
			g_string_append_printf (str, ":%d", uri->port);
		if (!uri->path && (uri->query || uri->fragment))
			g_string_append_c (str, '/');
	}

	if (uri->path && *uri->path)
		g_string_append (str, uri->path);

	if (uri->query) {
		g_string_append_c (str, '?');
		g_string_append (str, uri->query);
	}
	if (uri->fragment && !just_path) {
		g_string_append_c (str, '#');
		g_string_append (str, uri->fragment);
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
parts_equal (const char *one, const char *two, gboolean insensitive)
{
	if (!one && !two)
		return TRUE;
	if (!one || !two)
		return FALSE;
	return insensitive ? !g_ascii_strcasecmp (one, two) : !strcmp (one, two);
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
	if (uri1->protocol != uri2->protocol                 ||
	    uri1->port     != uri2->port                     ||
	    !parts_equal (uri1->user, uri2->user, FALSE)     ||
	    !parts_equal (uri1->passwd, uri2->passwd, FALSE) ||
	    !parts_equal (uri1->host, uri2->host, TRUE)      ||
	    !parts_equal (uri1->path, uri2->path, FALSE)     ||
	    !parts_equal (uri1->query, uri2->query, FALSE)   ||
	    !parts_equal (uri1->fragment, uri2->fragment, FALSE))
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

/* From RFC 3986 */
#define SOUP_URI_UNRESERVED  0
#define SOUP_URI_PCT_ENCODED 1
#define SOUP_URI_GEN_DELIMS  2
#define SOUP_URI_SUB_DELIMS  4
static const char uri_encoded_char[] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x00 - 0x0f */
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  /* 0x10 - 0x1f */
	1, 4, 1, 2, 4, 1, 4, 4, 4, 4, 4, 4, 4, 0, 0, 2,  /*  !"#$%&'()*+,-./ */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 1, 4, 1, 2,  /* 0123456789:;<=>? */
	2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* @ABCDEFGHIJKLMNO */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2, 1, 0,  /* PQRSTUVWXYZ[\]^_ */
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  /* `abcdefghijklmno */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,  /* pqrstuvwxyz{|}~  */
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
		if ((uri_encoded_char[*s] & (SOUP_URI_PCT_ENCODED | SOUP_URI_GEN_DELIMS)) ||
		    (extra_enc_chars && strchr (extra_enc_chars, *s)))
			g_string_append_printf (str, "%%%02X", (int)*s++);
		else
			g_string_append_c (str, *s++);
	}
}

/**
 * soup_uri_encode:
 * @part: a URI part
 * @escape_extra: additional reserved characters to escape (or %NULL)
 *
 * This %%-encodes the given URI part and returns the escaped version
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

#define XDIGIT(c) ((c) <= '9' ? (c) - '0' : ((c) & 0x4F) - 'A' + 10)
#define HEXCHAR(s) ((XDIGIT (s[1]) << 4) + XDIGIT (s[2]))

/**
 * soup_uri_decode:
 * @part: a URI part
 *
 * Fully %%-decodes the passed-in URI *in place*. The decoded version
 * is never longer than the encoded version, so there does not need to
 * be any additional space at the end of the string.
 *
 * Return value: %TRUE on success, %FALSE if an invalid %%-code was
 * encountered.
 */
gboolean
soup_uri_decode (char *part)
{
	unsigned char *s, *d;

	s = d = (unsigned char *)part;
	do {
		if (*s == '%') {
			if (!g_ascii_isxdigit (s[1]) ||
			    !g_ascii_isxdigit (s[2]))
				return FALSE;
			*d++ = HEXCHAR (s);
			s += 2;
		} else
			*d++ = *s;
	} while (*s++);

	return TRUE;
}

/**
 * soup_uri_normalize:
 * @part: a URI part
 * @unescape_extra: reserved characters to unescape (or %NULL)
 *
 * %%-decodes any "unreserved" characters (or characters in
 * @unescape_extra) in the passed-in URI. The decoding is done *in
 * place*. The decoded version is never longer than the encoded
 * version, so there does not need to be any additional space at the
 * end of the string.
 *
 * Return value: %TRUE on success, %FALSE if an invalid %%-code was
 * encountered.
 */
gboolean
soup_uri_normalize (char *part, const char *unescape_extra)
{
	unsigned char *s, *d, c;

	s = d = (unsigned char *)part;
	do {
		if (*s == '%') {
			if (!g_ascii_isxdigit (s[1]) ||
			    !g_ascii_isxdigit (s[2]))
				return FALSE;

			c = HEXCHAR (s);
			if (uri_encoded_char[c] == SOUP_URI_UNRESERVED ||
			    (unescape_extra && strchr (unescape_extra, c))) {
				*d++ = c;
				s += 2;
			} else {
				*d++ = *s++;
				*d++ = g_ascii_toupper (*s++);
				*d++ = g_ascii_toupper (*s);
			}
		} else
			*d++ = *s;
	} while (*s++);

	return TRUE;
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
