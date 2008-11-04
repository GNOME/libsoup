/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar-sqlite.c: ff sqlite-based cookie storage
 *
 * Using danw's soup-cookie-jar-text as template
 * Copyright (C) 2008 Diego Escalante Urrelo
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "soup-cookie-jar-sqlite.h"
#include "soup-cookie.h"
#include "soup-date.h"

/**
 * SECTION:soup-cookie-jar-sqlite
 * @short_description: SQLite-based Cookie Jar
 *
 * #SoupCookieJarSqlite is a #SoupCookieJar that reads cookies from and
 * writes them to an SQLite file in the new Mozilla format.
 **/

enum {
	PROP_0,

	PROP_FILENAME,

	LAST_PROP
};

typedef struct {
	char *filename;

} SoupCookieJarSqlitePrivate;

#define SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_COOKIE_JAR_SQLITE, SoupCookieJarSqlitePrivate))

G_DEFINE_TYPE (SoupCookieJarSqlite, soup_cookie_jar_sqlite, SOUP_TYPE_COOKIE_JAR)

static void load (SoupCookieJar *jar);
static void changed (SoupCookieJar *jar,
		     SoupCookie    *old_cookie,
		     SoupCookie    *new_cookie);

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_cookie_jar_sqlite_init (SoupCookieJarSqlite *sqlite)
{
}

static void
finalize (GObject *object)
{
	SoupCookieJarSqlitePrivate *priv =
		SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE (object);

	g_free (priv->filename);

	G_OBJECT_CLASS (soup_cookie_jar_sqlite_parent_class)->finalize (object);
}

static void
soup_cookie_jar_sqlite_class_init (SoupCookieJarSqliteClass *sqlite_class)
{
	SoupCookieJarClass *cookie_jar_class =
		SOUP_COOKIE_JAR_CLASS (sqlite_class);
	GObjectClass *object_class = G_OBJECT_CLASS (sqlite_class);

	g_type_class_add_private (sqlite_class, sizeof (SoupCookieJarSqlitePrivate));

	cookie_jar_class->changed = changed;

	object_class->finalize     = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	g_object_class_install_property (
		object_class, PROP_FILENAME,
		g_param_spec_string (SOUP_COOKIE_JAR_SQLITE_FILENAME,
				     "Filename",
				     "Cookie-storage filename",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupCookieJarSqlitePrivate *priv =
		SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE (object);

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
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupCookieJarSqlitePrivate *priv =
		SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE (object);

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
 * soup_cookie_jar_sqlite_new:
 * @filename: the filename to read to/write from, or %NULL
 * @read_only: %TRUE if @filename is read-only
 *
 * Creates a #SoupCookieJarSqlite.
 *
 * @filename will be read in at startup to create an initial set of
 * cookies. If @read_only is %FALSE, then the non-session cookies will
 * be written to @filename when the 'changed' signal is emitted from
 * the jar. (If @read_only is %TRUE, then the cookie jar will only be
 * used for this session, and changes made to it will be lost when the
 * jar is destroyed.)
 *
 * Return value: the new #SoupCookieJar
 **/
SoupCookieJar *
soup_cookie_jar_sqlite_new (const char *filename, gboolean read_only)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_object_new (SOUP_TYPE_COOKIE_JAR_SQLITE,
			     SOUP_COOKIE_JAR_SQLITE_FILENAME, filename,
			     SOUP_COOKIE_JAR_READ_ONLY, read_only,
			     NULL);
}

#define QUERY_ALL "SELECT * FROM moz_cookies;"
#define QUERY_INSERT "INSERT INTO moz_cookies VALUES(NULL, %Q, %Q, %Q, %Q, %d, NULL, %d, %d);"
#define QUERY_DELETE "DELETE FROM moz_cookies WHERE name=%Q AND domain=%Q;"

enum {
	COL_ID,
	COL_NAME,
	COL_VALUE,
	COL_HOST,
	COL_PATH,
	COL_EXPIRY,
	COL_LAST_ACCESS,
	COL_SECURE,
	COL_HTTP_ONLY,
	N_COL,
};

static int
callback (void *data, int argc, char **argv, char **colname)
{
	SoupCookie *cookie = NULL;
	SoupCookieJar *jar = SOUP_COOKIE_JAR (data);

	char *name, *value, *host, *path;
	time_t max_age, now;
	gboolean http_only = FALSE, secure = FALSE;

	now = time (NULL);

	name = argv[COL_NAME];
	value = argv[COL_VALUE];
	host = argv[COL_HOST];
	path = argv[COL_PATH];
	max_age = strtoul (argv[COL_EXPIRY], NULL, 10) - now;

	if (max_age <= 0)
		return 0;

	http_only = (strcmp (argv[COL_HTTP_ONLY], "FALSE") != 0);
	secure = (strcmp (argv[COL_SECURE], "FALSE") != 0);

	cookie = soup_cookie_new (name, value, host, path, max_age);

	if (secure)
		soup_cookie_set_secure (cookie, TRUE);
	if (http_only)
		soup_cookie_set_http_only (cookie, TRUE);

	soup_cookie_jar_add_cookie (jar, cookie);

	return 0;
}

static void
load (SoupCookieJar *jar)
{
	SoupCookieJarSqlitePrivate *priv =
		SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE (jar);

	sqlite3 *db;
	char *error = 0;

	if (sqlite3_open (priv->filename, &db)) {
		sqlite3_close (db);
		g_debug ("Can't open %s", priv->filename);
	}

	if (sqlite3_exec (db, QUERY_ALL, callback, (void *)jar, &error)) {
		g_debug ("Failed to execute query: %s", error);
		sqlite3_free (error);
	}

	sqlite3_close (db);
}

static void
changed (SoupCookieJar *jar,
	 SoupCookie    *old_cookie,
	 SoupCookie    *new_cookie)
{
	SoupCookieJarSqlitePrivate *priv =
		SOUP_COOKIE_JAR_SQLITE_GET_PRIVATE (jar);
	sqlite3 *db;
	char *error = NULL;
	char *query;

	if (sqlite3_open (priv->filename, &db)) {
		sqlite3_close (db);
		g_warning ("Can't open %s", priv->filename);
		return;
	}

	if (old_cookie) {
		query = sqlite3_mprintf (QUERY_DELETE,
					 old_cookie->name,
					 old_cookie->domain);
		if (sqlite3_exec (db, query, NULL, NULL, &error)) {
			g_warning ("Failed to execute query: %s", error);
			sqlite3_free (error);
		}
		sqlite3_free (query);
	}

	if (new_cookie) {
		int expires;

		if (new_cookie->expires)
			expires = soup_date_to_time_t (new_cookie->expires);
		else
			expires = 0;

		query = sqlite3_mprintf (QUERY_INSERT, 
					 new_cookie->name,
					 new_cookie->value,
					 new_cookie->domain,
					 new_cookie->path,
					 expires,
					 new_cookie->secure,
					 new_cookie->http_only);
		if (sqlite3_exec (db, query, NULL, NULL, &error)) {
			g_warning ("Failed to execute query: %s", error);
			sqlite3_free (error);
		}
		sqlite3_free (query);
	}

	sqlite3_close (db);
}
