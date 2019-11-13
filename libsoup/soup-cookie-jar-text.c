/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar-text.c: cookies.txt-based cookie storage
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "soup-cookie-jar-text.h"
#include "soup.h"

/**
 * SECTION:soup-cookie-jar-text
 * @short_description: Text-file-based ("cookies.txt") Cookie Jar
 *
 * #SoupCookieJarText is a #SoupCookieJar that reads cookies from and
 * writes them to a text file in the Mozilla "cookies.txt" format.
 **/

enum {
	PROP_0,

	PROP_FILENAME,

	LAST_PROP
};

typedef struct {
	char *filename;

} SoupCookieJarTextPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (SoupCookieJarText, soup_cookie_jar_text, SOUP_TYPE_COOKIE_JAR)

static void load (SoupCookieJar *jar);

static void
soup_cookie_jar_text_init (SoupCookieJarText *text)
{
}

static void
soup_cookie_jar_text_finalize (GObject *object)
{
	SoupCookieJarTextPrivate *priv =
		soup_cookie_jar_text_get_instance_private (SOUP_COOKIE_JAR_TEXT (object));

	g_free (priv->filename);

	G_OBJECT_CLASS (soup_cookie_jar_text_parent_class)->finalize (object);
}

static void
soup_cookie_jar_text_set_property (GObject *object, guint prop_id,
				   const GValue *value, GParamSpec *pspec)
{
	SoupCookieJarTextPrivate *priv =
		soup_cookie_jar_text_get_instance_private (SOUP_COOKIE_JAR_TEXT (object));

	switch (prop_id) {
	case PROP_FILENAME:
		priv->filename = g_value_dup_string (value);
		load (SOUP_COOKIE_JAR (object));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_cookie_jar_text_get_property (GObject *object, guint prop_id,
				   GValue *value, GParamSpec *pspec)
{
	SoupCookieJarTextPrivate *priv =
		soup_cookie_jar_text_get_instance_private (SOUP_COOKIE_JAR_TEXT (object));

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * soup_cookie_jar_text_new:
 * @filename: the filename to read to/write from
 * @read_only: %TRUE if @filename is read-only
 *
 * Creates a #SoupCookieJarText.
 *
 * @filename will be read in at startup to create an initial set of
 * cookies. If @read_only is %FALSE, then the non-session cookies will
 * be written to @filename when the 'changed' signal is emitted from
 * the jar. (If @read_only is %TRUE, then the cookie jar will only be
 * used for this session, and changes made to it will be lost when the
 * jar is destroyed.)
 *
 * Return value: the new #SoupCookieJar
 *
 * Since: 2.26
 **/
SoupCookieJar *
soup_cookie_jar_text_new (const char *filename, gboolean read_only)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_object_new (SOUP_TYPE_COOKIE_JAR_TEXT,
			     SOUP_COOKIE_JAR_TEXT_FILENAME, filename,
			     SOUP_COOKIE_JAR_READ_ONLY, read_only,
			     NULL);
}

static SoupSameSitePolicy
string_to_same_site_policy (const char *string)
{
	if (strcmp (string, "Lax") == 0)
		return SOUP_SAME_SITE_POLICY_LAX;
	else if (strcmp (string, "Strict") == 0)
		return SOUP_SAME_SITE_POLICY_STRICT;
	else if (strcmp (string, "None") == 0)
		return SOUP_SAME_SITE_POLICY_NONE;
	else
		g_return_val_if_reached (SOUP_SAME_SITE_POLICY_NONE);
}

static const char *
same_site_policy_to_string (SoupSameSitePolicy policy)
{
	switch (policy) {
	case SOUP_SAME_SITE_POLICY_STRICT:
		return "Strict";
	case SOUP_SAME_SITE_POLICY_LAX:
		return "Lax";
	case SOUP_SAME_SITE_POLICY_NONE:
		return "None";
	}

	g_return_val_if_reached ("None");
}

static SoupCookie*
parse_cookie (char *line, time_t now)
{
	char **result;
	SoupCookie *cookie = NULL;
	gboolean http_only;
	gulong expire_time;
	int max_age;
	char *host, *path, *secure, *expires, *name, *value, *samesite = NULL;
	gsize result_length;

	if (g_str_has_prefix (line, "#HttpOnly_")) {
		http_only = TRUE;
		line += strlen ("#HttpOnly_");
	} else if (*line == '#' || g_ascii_isspace (*line))
		return cookie;
	else
		http_only = FALSE;

	result = g_strsplit (line, "\t", -1);
	result_length = g_strv_length (result);
	if (result_length < 7)
		goto out;

	/* Check this first */
	expires = result[4];
	expire_time = strtoul (expires, NULL, 10);
	if (now >= expire_time)
		goto out;
	max_age = (expire_time - now <= G_MAXINT ? expire_time - now : G_MAXINT);

	host = result[0];

	/* result[1] is not used because it's redundat; it's a boolean
	 * value regarding whether the cookie should be used for
	 * sub-domains of the domain that is set for the cookie. It is
	 * TRUE if host starts with '.', and FALSE otherwise.
	 */

	path = result[2];
	secure = result[3];

	name = result[5];
	value = result[6];

	if (result_length == 8)
		samesite = result[7];

	cookie = soup_cookie_new (name, value, host, path, max_age);

	if (samesite != NULL)
		soup_cookie_set_same_site_policy (cookie, string_to_same_site_policy (samesite));

	if (strcmp (secure, "FALSE") != 0)
		soup_cookie_set_secure (cookie, TRUE);
	if (http_only)
		soup_cookie_set_http_only (cookie, TRUE);

 out:
	g_strfreev (result);

	return cookie;
}

static void
parse_line (SoupCookieJar *jar, char *line, time_t now)
{
	SoupCookie *cookie;

	cookie = parse_cookie (line, now);
	if (cookie)
		soup_cookie_jar_add_cookie (jar, cookie);
}

static void
load (SoupCookieJar *jar)
{
	SoupCookieJarTextPrivate *priv =
		soup_cookie_jar_text_get_instance_private (SOUP_COOKIE_JAR_TEXT (jar));
	char *contents = NULL, *line, *p;
	gsize length = 0;
	time_t now = time (NULL);

	/* FIXME: error? */
	if (!g_file_get_contents (priv->filename, &contents, &length, NULL))
		return;

	line = contents;
	for (p = contents; *p; p++) {
		/* \r\n comes out as an extra empty line and gets ignored */
		if (*p == '\r' || *p == '\n') {
			*p = '\0';
			parse_line (jar, line, now);
			line = p + 1;
		}
	}
	parse_line (jar, line, now);

	g_free (contents);
}

static void
write_cookie (FILE *out, SoupCookie *cookie)
{
	fseek (out, 0, SEEK_END);

	fprintf (out, "%s%s\t%s\t%s\t%s\t%lu\t%s\t%s\t%s\n",
		 cookie->http_only ? "#HttpOnly_" : "",
		 cookie->domain,
		 *cookie->domain == '.' ? "TRUE" : "FALSE",
		 cookie->path,
		 cookie->secure ? "TRUE" : "FALSE",
		 (gulong)soup_date_to_time_t (cookie->expires),
		 cookie->name,
		 cookie->value,
		 same_site_policy_to_string (soup_cookie_get_same_site_policy (cookie)));
}

static void
delete_cookie (const char *filename, SoupCookie *cookie)
{
	char *contents = NULL, *line, *p;
	gsize length = 0;
	FILE *f;
	SoupCookie *c;
	time_t now = time (NULL);

	if (!g_file_get_contents (filename, &contents, &length, NULL))
		return;

	f = fopen (filename, "w");
	if (!f) {
		g_free (contents);
		return;
	}

	line = contents;
	for (p = contents; *p; p++) {
		/* \r\n comes out as an extra empty line and gets ignored */
		if (*p == '\r' || *p == '\n') {
			*p = '\0';
			c = parse_cookie (line, now);
			line = p + 1;
			if (!c)
				continue;
			if (!soup_cookie_equal (cookie, c))
				write_cookie (f, c);
			soup_cookie_free (c);
		}
	}
	c = parse_cookie (line, now);
	if (c) {
		if (!soup_cookie_equal (cookie, c))
			write_cookie (f, c);
		soup_cookie_free (c);
	}

	g_free (contents);
	fclose (f);
}

static void
soup_cookie_jar_text_changed (SoupCookieJar *jar,
			      SoupCookie    *old_cookie,
			      SoupCookie    *new_cookie)
{
	FILE *out;
	SoupCookieJarTextPrivate *priv =
		soup_cookie_jar_text_get_instance_private (SOUP_COOKIE_JAR_TEXT (jar));

	/* We can sort of ignore the semantics of the 'changed'
	 * signal here and simply delete the old cookie if present
	 * and write the new cookie if present. That will do the
	 * right thing for all 'added', 'deleted' and 'modified'
	 * meanings.
	 */
	/* Also, delete_cookie takes the filename and write_cookie
	 * a FILE pointer. Seems more convenient that way considering
	 * the implementations of the functions
	 */
	if (old_cookie)
		delete_cookie (priv->filename, old_cookie);

	if (new_cookie) {
		gboolean write_header = FALSE;

		if (!g_file_test (priv->filename, G_FILE_TEST_EXISTS))
			write_header = TRUE;

		out = fopen (priv->filename, "a");
		if (!out) {
			/* FIXME: error? */
			return;
		}

		if (write_header) {
			fprintf (out, "# HTTP Cookie File\n");
			fprintf (out, "# http://www.netscape.com/newsref/std/cookie_spec.html\n");
			fprintf (out, "# This is a generated file!  Do not edit.\n");
			fprintf (out, "# To delete cookies, use the Cookie Manager.\n\n");
		}

		if (new_cookie->expires)
			write_cookie (out, new_cookie);

		if (fclose (out) != 0) {
			/* FIXME: error? */
			return;
		}
	}
}

static gboolean
soup_cookie_jar_text_is_persistent (SoupCookieJar *jar)
{
	return TRUE;
}

static void
soup_cookie_jar_text_class_init (SoupCookieJarTextClass *text_class)
{
	SoupCookieJarClass *cookie_jar_class =
		SOUP_COOKIE_JAR_CLASS (text_class);
	GObjectClass *object_class = G_OBJECT_CLASS (text_class);

	cookie_jar_class->is_persistent = soup_cookie_jar_text_is_persistent;
	cookie_jar_class->changed       = soup_cookie_jar_text_changed;

	object_class->finalize     = soup_cookie_jar_text_finalize;
	object_class->set_property = soup_cookie_jar_text_set_property;
	object_class->get_property = soup_cookie_jar_text_get_property;

	/**
	 * SOUP_COOKIE_JAR_TEXT_FILENAME:
	 *
	 * Alias for the #SoupCookieJarText:filename property. (The
	 * cookie-storage filename.)
	 **/
	g_object_class_install_property (
		object_class, PROP_FILENAME,
		g_param_spec_string (SOUP_COOKIE_JAR_TEXT_FILENAME,
				     "Filename",
				     "Cookie-storage filename",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));
}
