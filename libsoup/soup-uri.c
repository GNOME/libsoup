/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* soup-uri.c : utility functions to parse URLs */

/*
 * Copyright 1999-2003 Ximian, Inc.
 */

#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "soup-uri.h"

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

static void append_uri_encoded (GString *str, const char *in, const char *extra_enc_chars);

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
	const char *end, *hash, *colon, *semi, *at, *slash, *question;
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

			semi = strchr (uri_string, ';');
			if (semi && semi < colon &&
			    !strncasecmp (semi, ";auth=", 6)) {
				uri->authmech = g_strndup (semi + 6,
							   colon - semi - 6);
				soup_uri_decode (uri->authmech);
			} else {
				uri->authmech = NULL;
				semi = colon;
			}

			uri->user = g_strndup (uri_string, semi - uri_string);
			soup_uri_decode (uri->user);
			uri_string = at + 1;
		} else
			uri->user = uri->passwd = uri->authmech = NULL;

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
		uri->authmech = g_strdup (base->authmech);
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
			append_uri_encoded (str, uri->user, ":;@/");
			if (uri->authmech && *uri->authmech) {
				g_string_append (str, ";auth=");
				append_uri_encoded (str, uri->authmech, ":@/");
			}
			g_string_append_c (str, '@');
		}
		append_uri_encoded (str, uri->host, ":/");
		if (uri->port && uri->port != soup_protocol_default_port (uri->protocol))
			g_string_append_printf (str, ":%d", uri->port);
		if (!uri->path && (uri->query || uri->fragment))
			g_string_append_c (str, '/');
	}

	if (uri->path && *uri->path)
		append_uri_encoded (str, uri->path, "?");
	else if (just_path)
		g_string_append_c (str, '/');

	if (uri->query) {
		g_string_append_c (str, '?');
		append_uri_encoded (str, uri->query, NULL);
	}
	if (uri->fragment && !just_path) {
		g_string_append_c (str, '#');
		append_uri_encoded (str, uri->fragment, NULL);
	}

	return_result = str->str;
	g_string_free (str, FALSE);

	return return_result;
}

SoupUri *
soup_uri_copy (const SoupUri *uri)
{
	SoupUri *dup;

	g_return_val_if_fail (uri != NULL, NULL);

	dup = g_new0 (SoupUri, 1);
	dup->protocol = uri->protocol;
	dup->user     = g_strdup (uri->user);
	dup->authmech = g_strdup (uri->authmech);
	dup->passwd   = g_strdup (uri->passwd);
	dup->host     = g_strdup (uri->host);
	dup->port     = uri->port;
	dup->path     = g_strdup (uri->path);
	dup->query    = g_strdup (uri->query);
	dup->fragment = g_strdup (uri->fragment);

	return dup;
}

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

gboolean 
soup_uri_equal (const SoupUri *u1, const SoupUri *u2)
{
	if (u1->protocol != u2->protocol              ||
	    u1->port     != u2->port                  ||
	    !parts_equal (u1->user, u2->user)         ||
	    !parts_equal (u1->authmech, u2->authmech) ||
	    !parts_equal (u1->passwd, u2->passwd)     ||
	    !parts_equal (u1->host, u2->host)         ||
	    !parts_equal (u1->path, u2->path)         ||
	    !parts_equal (u1->query, u2->query)       ||
	    !parts_equal (u1->fragment, u2->fragment))
		return FALSE;

	return TRUE;
}

void
soup_uri_free (SoupUri *uri)
{
	g_return_if_fail (uri != NULL);

	g_free (uri->user);
	g_free (uri->authmech);
	g_free (uri->passwd);
	g_free (uri->host);
	g_free (uri->path);
	g_free (uri->query);
	g_free (uri->fragment);

	g_free (uri);
}

void
soup_uri_set_auth  (SoupUri    *uri, 
		    const char *user, 
		    const char *passwd, 
		    const char *authmech)
{
	g_return_if_fail (uri != NULL);

	g_free (uri->user);
	g_free (uri->passwd);
	g_free (uri->authmech);

	uri->user = g_strdup (user);
	uri->passwd = g_strdup (passwd);
	uri->authmech = g_strdup (authmech);
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

gboolean
soup_uri_uses_default_port (const SoupUri *uri)
{
	return uri->port == soup_protocol_default_port (uri->protocol);
}
