/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* soup-uri.c : utility functions to parse URLs */

/*
 * Authors :
 *  Bertrand Guiheneuf <bertrand@helixcode.com>
 *  Dan Winship <danw@helixcode.com>
 *  Alex Graveley <alex@ximian.com>
 *
 * Copyright 1999, 2000 Helix Code, Inc. (http://www.helixcode.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */



/*
 * Here we deal with URLs following the general scheme:
 *   protocol://user;AUTH=mech:password@host:port/name
 * where name is a path-like string (ie dir1/dir2/....) See RFC 1738
 * for the complete description of Uniform Resource Locators. The
 * ";AUTH=mech" addition comes from RFC 2384, "POP URL Scheme".
 */

/* XXX TODO:
 * recover the words between #'s or ?'s after the path
 * % escapes
 */

#include <string.h>
#include <stdlib.h>

#include "soup-uri.h"
#include "soup-misc.h"

typedef struct {
	SoupProtocol  proto;
	gchar        *str;
	gint          port;
} SoupKnownProtocols;

SoupKnownProtocols known_protocols [] = {
	{ SOUP_PROTOCOL_HTTP,   "http://",   80 },
	{ SOUP_PROTOCOL_HTTPS,  "https://",  443 },
	{ SOUP_PROTOCOL_SMTP,   "mailto:",   25 },
	{ SOUP_PROTOCOL_SOCKS4, "socks4://", -1 },
	{ SOUP_PROTOCOL_SOCKS5, "socks5://", -1 },
	{ 0 }
};

static SoupProtocol
soup_uri_get_protocol (const gchar *proto, int *len)
{
	SoupKnownProtocols *known = known_protocols;

	while (known->proto) {
		if (!g_strncasecmp (proto, known->str, strlen (known->str))) {
			*len = strlen (known->str);
			return known->proto;
		}
		known++;
	}

	*len = 0;
	return 0;
}

static gchar *
soup_uri_protocol_to_string (SoupProtocol proto)
{
	SoupKnownProtocols *known = known_protocols;

	while (known->proto) {
		if (known->proto == proto) return known->str;
		known++;
	}

	return "";
}

gint
soup_uri_get_default_port (SoupProtocol proto)
{
	SoupKnownProtocols *known = known_protocols;

	while (known->proto) {
		if (known->proto == proto) return known->port;
		known++;
	}

	return -1;
}

/*
 * Ripped off from libxml
 */
static void
normalize_path (gchar *path)
{
	char *cur, *out;

	/* 
	 * Skip all initial "/" chars.  We want to get to the beginning of the
	 * first non-empty segment.
	 */
	cur = path;
	while (cur[0] == '/')
		++cur;
	if (cur[0] == '\0')
		return;

	/* Keep everything we've seen so far.  */
	out = cur;

	/*
	 * Analyze each segment in sequence for cases (c) and (d).
	 */
	while (cur[0] != '\0') {
		/*
		 * c) All occurrences of "./", where "." is a complete path
		 * segment, are removed from the buffer string.  
		 */
		if ((cur[0] == '.') && (cur[1] == '/')) {
			cur += 2;
			/* 
			 * '//' normalization should be done at this point too
			 */
			while (cur[0] == '/')
				cur++;
			continue;
		}

		/*
		 * d) If the buffer string ends with "." as a complete path
		 * segment, that "." is removed.  
		 */
		if ((cur[0] == '.') && (cur[1] == '\0'))
			break;

		/* Otherwise keep the segment.  */
		while (cur[0] != '/') {
			if (cur[0] == '\0')
				goto done_cd;
			(out++)[0] = (cur++)[0];
		}
		/* nomalize '//' */
		while ((cur[0] == '/') && (cur[1] == '/'))
			cur++;
		
		(out++)[0] = (cur++)[0];
	}
 done_cd:
	out[0] = '\0';

	/* Reset to the beginning of the first segment for the next sequence. */
	cur = path;
	while (cur[0] == '/')
		++cur;
	if (cur[0] == '\0')
		return;

	/*
	 * Analyze each segment in sequence for cases (e) and (f).
	 *
	 * e) All occurrences of "<segment>/../", where <segment> is a
	 *    complete path segment not equal to "..", are removed from the
	 *    buffer string.  Removal of these path segments is performed
	 *    iteratively, removing the leftmost matching pattern on each
	 *    iteration, until no matching pattern remains.
	 *
	 * f) If the buffer string ends with "<segment>/..", where <segment>
	 *    is a complete path segment not equal to "..", that
	 *    "<segment>/.." is removed.
	 *
	 * To satisfy the "iterative" clause in (e), we need to collapse the
	 * string every time we find something that needs to be removed.  Thus,
	 * we don't need to keep two pointers into the string: we only need a
	 * "current position" pointer.
	 */
	while (1) {
		char *segp;

		/* 
		 * At the beginning of each iteration of this loop, "cur" points
		 * to the first character of the segment we want to examine.  
		 */

		/* Find the end of the current segment.  */
		segp = cur;
		while ((segp[0] != '/') && (segp[0] != '\0'))
			++segp;

		/* 
		 * If this is the last segment, we're done (we need at least two
		 * segments to meet the criteria for the (e) and (f) cases).
		 */
		if (segp[0] == '\0')
			break;

		/* 
		 * If the first segment is "..", or if the next segment _isn't_
		 * "..", keep this segment and try the next one.  
		 */
		++segp;
		if (((cur[0] == '.') && (cur[1] == '.') && (segp == cur+3))
		    || ((segp[0] != '.') || (segp[1] != '.')
			|| ((segp[2] != '/') && (segp[2] != '\0')))) {
			cur = segp;
			continue;
		}

		/* 
		 * If we get here, remove this segment and the next one and back
		 * up to the previous segment (if there is one), to implement
		 * the "iteratively" clause.  It's pretty much impossible to
		 * back up while maintaining two pointers into the buffer, so
		 * just compact the whole buffer now.  
		 */

		/* If this is the end of the buffer, we're done.  */
		if (segp[2] == '\0') {
			cur[0] = '\0';
			break;
		}
		strcpy(cur, segp + 3);

		/* 
		 * If there are no previous segments, then keep going from
		 * here. 
		 */
		segp = cur;
		while ((segp > path) && ((--segp)[0] == '/'))
			;
		if (segp == path)
			continue;

		/* 
		 * "segp" is pointing to the end of a previous segment; find
		 * it's start.  We need to back up to the previous segment and
		 * start over with that to handle things like "foo/bar/../..".
		 * If we don't do this, then on the first pass we'll remove the
		 * "bar/..", but be pointing at the second ".." so we won't
		 * realize we can also remove the "foo/..".  
		 */
		cur = segp;
		while ((cur > path) && (cur[-1] != '/'))
			--cur;
	}
	out[0] = '\0';

	/*
	 * g) If the resulting buffer string still begins with one or more
	 *    complete path segments of "..", then the reference is
	 *    considered to be in error. Implementations may handle this
	 *    error by retaining these components in the resolved path (i.e.,
	 *    treating them as part of the final URI), by removing them from
	 *    the resolved path (i.e., discarding relative levels above the
	 *    root), or by avoiding traversal of the reference.
	 *
	 * We discard them from the final path.
	 */
	if (path[0] == '/') {
		cur = path;
		while ((cur[1] == '.') && (cur[2] == '.')
		       && ((cur[3] == '/') || (cur[3] == '\0')))
			cur += 3;

		if (cur != path) {
			out = path;
			while (cur[0] != '\0')
				(out++)[0] = (cur++)[0];
			out[0] = 0;
		}
	}

	return;
}

/**
 * soup_uri_new: create a SoupUri object from a string
 * @uri_string: The string containing the URL to scan
 *
 * This routine takes a gchar and parses it as a
 * URL of the form:
 *   protocol://user;AUTH=mech:password@host:port/path?querystring
 * There is no test on the values. For example,
 * "port" can be a string, not only a number!
 * The SoupUri structure fields are filled with
 * the scan results. When a member of the
 * general URL can not be found, the corresponding
 * SoupUri member is NULL.
 * Fields filled in the SoupUri structure are allocated
 * and url_string is not modified.
 *
 * Return value: a SoupUri structure containing the URL items.
 **/
SoupUri *
soup_uri_new (const gchar* uri_string)
{
	SoupUri *g_uri;
	char *semi, *colon, *at, *slash, *path, *query = NULL;
	char **split;

	g_uri = g_new0 (SoupUri,1);

	/* Find protocol: initial substring until "://" */
	colon = strchr (uri_string, ':');
	if (colon) {
		gint protolen;
		g_uri->protocol = soup_uri_get_protocol (uri_string, &protolen);
		uri_string += protolen;
	}

	/* Must have a protocol */
	if (!g_uri->protocol) return NULL;

	/* If there is an @ sign, look for user, authmech, and
	 * password before it.
	 */
	at = strchr (uri_string, '@');
	if (at) {
		colon = strchr (uri_string, ':');
		if (colon && colon < at)
			g_uri->passwd = g_strndup (colon + 1, at - colon - 1);
		else {
			g_uri->passwd = NULL;
			colon = at;
		}

		semi = strchr(uri_string, ';');
		if (semi && semi < colon && !g_strncasecmp (semi, ";auth=", 6))
			g_uri->authmech = g_strndup (semi + 6,
						     colon - semi - 6);
		else {
			g_uri->authmech = NULL;
			semi = colon;
		}

		g_uri->user = g_strndup (uri_string, semi - uri_string);
		uri_string = at + 1;
	} else
		g_uri->user = g_uri->passwd = g_uri->authmech = NULL;

	/* Find host (required) and port. */
	slash = strchr (uri_string, '/');
	colon = strchr (uri_string, ':');
	if (slash && colon > slash)
		colon = 0;

	if (colon) {
		g_uri->host = g_strndup (uri_string, colon - uri_string);
		if (slash)
			g_uri->port = atoi(colon + 1);
		else
			g_uri->port = atoi(colon + 1);
	} else if (slash) {
		g_uri->host = g_strndup (uri_string, slash - uri_string);
		g_uri->port = soup_uri_get_default_port (g_uri->protocol);
	} else {
		g_uri->host = g_strdup (uri_string);
		g_uri->port = soup_uri_get_default_port (g_uri->protocol);
	}

	/* setup a fallback, if relative, then empty string, else
	   it will be from root */
	if (slash == NULL) {
		slash = "/";
	}
	if (slash && *slash && !g_uri->protocol)
		slash++;

	split = g_strsplit(slash, " ", 0);
	path = g_strjoinv("%20", split);
	g_strfreev(split);

	if (path)
		query = strchr (path, '?');

	if (path && query) {
		g_uri->path = g_strndup (path, query - path);
		g_uri->querystring = g_strdup (++query);
		g_uri->query_elems = g_strsplit (g_uri->querystring, "&", 0);
		g_free (path);
	} else {
		g_uri->path = path;
		g_uri->querystring = NULL;
	}

	if (g_uri->path)
		normalize_path (g_uri->path);

	return g_uri;
}

/* Need to handle mailto which apparantly doesn't use the "//" after the : */
gchar *
soup_uri_to_string (const SoupUri *uri, gboolean show_passwd)
{
	g_return_val_if_fail (uri != NULL, NULL);

	if (uri->port != -1 &&
	    uri->port != soup_uri_get_default_port (uri->protocol))
		return g_strdup_printf(
			"%s%s%s%s%s%s%s%s:%d%s%s%s",
			soup_uri_protocol_to_string (uri->protocol),
			uri->user ? uri->user : "",
			uri->authmech ? ";auth=" : "",
			uri->authmech ? uri->authmech : "",
			uri->passwd && show_passwd ? ":" : "",
			uri->passwd && show_passwd ? uri->passwd : "",
			uri->user ? "@" : "",
			uri->host,
			uri->port,
			uri->path ? uri->path : "",
			uri->querystring ? "?" : "",
			uri->querystring ? uri->querystring : "");
	else
		return g_strdup_printf(
			"%s%s%s%s%s%s%s%s%s%s%s",
			soup_uri_protocol_to_string (uri->protocol),
			uri->user ? uri->user : "",
			uri->authmech ? ";auth=" : "",
			uri->authmech ? uri->authmech : "",
			uri->passwd && show_passwd ? ":" : "",
			uri->passwd && show_passwd ? uri->passwd : "",
			uri->user ? "@" : "",
			uri->host,
			uri->path ? uri->path : "",
			uri->querystring ? "?" : "",
			uri->querystring ? uri->querystring : "");
}

gchar *
soup_uri_to_proxyable_string (const SoupUri *uri)
{
	g_return_val_if_fail (uri != NULL, NULL);

	if (uri->port != -1 &&
	    uri->port != soup_uri_get_default_port (uri->protocol))
		return g_strdup_printf(
			"%s%s:%d%s%s%s",
			soup_uri_protocol_to_string (uri->protocol),
			uri->host,
			uri->port,
			uri->path ? uri->path : "",
			uri->querystring ? "?" : "",
			uri->querystring ? uri->querystring : "");
	else
		return g_strdup_printf(
			"%s%s%s%s%s",
			soup_uri_protocol_to_string (uri->protocol),
			uri->host,
			uri->path ? uri->path : "",
			uri->querystring ? "?" : "",
			uri->querystring ? uri->querystring : "");
}

SoupUri *
soup_uri_copy (const SoupUri* uri)
{
	gchar *uri_str;
	SoupUri *dup;

	g_return_val_if_fail (uri != NULL, NULL);

	uri_str = soup_uri_to_string (uri, TRUE);
	dup = soup_uri_new (uri_str);
	g_free (uri_str);

	return dup;
}

void
soup_uri_free (SoupUri *uri)
{
	g_assert (uri);

	g_free (uri->user);
	g_free (uri->authmech);
	g_free (uri->passwd);
	g_free (uri->host);
	g_free (uri->path);
	g_free (uri->querystring);
	g_strfreev (uri->query_elems);

	g_free (uri);
}

void
soup_debug_print_uri (SoupUri *uri)
{
	g_return_if_fail (uri != NULL);

	g_print ("Protocol: %s\n", soup_uri_protocol_to_string (uri->protocol));
	g_print ("User:     %s\n", uri->user);
	g_print ("Authmech: %s\n", uri->authmech);
	g_print ("Password: %s\n", uri->passwd);
	g_print ("Host:     %s\n", uri->host);
	g_print ("Path:     %s\n", uri->path);
	g_print ("Querystr: %s\n", uri->querystring);
}

