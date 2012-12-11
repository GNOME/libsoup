/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar-sqlite.c: deprecated version of sqlite-based cookie storage
 *
 * Copyright 2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

/* Avoid deprecation warnings */
#define SOUP_VERSION_MIN_REQUIRED SOUP_VERSION_2_40

#include "soup.h"
#include "soup-cookie-jar-sqlite.h"

enum {
	PROP_0,

	PROP_FILENAME,

	LAST_PROP
};

G_DEFINE_TYPE (SoupCookieJarSqlite, soup_cookie_jar_sqlite, SOUP_TYPE_COOKIE_JAR_DB)

static void
soup_cookie_jar_sqlite_init (SoupCookieJarSqlite *sqlite)
{
}

SoupCookieJar *
soup_cookie_jar_sqlite_new (const char *filename, gboolean read_only)
{
	g_return_val_if_fail (filename != NULL, NULL);

	return g_object_new (SOUP_TYPE_COOKIE_JAR_SQLITE,
			     SOUP_COOKIE_JAR_SQLITE_FILENAME, filename,
			     SOUP_COOKIE_JAR_READ_ONLY, read_only,
			     NULL);
}

static void
soup_cookie_jar_sqlite_class_init (SoupCookieJarSqliteClass *sqlite_class)
{
}
