/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Diego Escalante Urrelo
 */

#ifndef __SOUP_COOKIE_JAR_SQLITE_H__
#define __SOUP_COOKIE_JAR_SQLITE_H__ 1

#include <libsoup/soup-cookie-jar-db.h>

G_BEGIN_DECLS

#define SOUP_TYPE_COOKIE_JAR_SQLITE            (soup_cookie_jar_sqlite_get_type ())
#define SOUP_COOKIE_JAR_SQLITE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_COOKIE_JAR_SQLITE, SoupCookieJarSqlite))
#define SOUP_COOKIE_JAR_SQLITE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_COOKIE_JAR_SQLITE, SoupCookieJarSqliteClass))
#define SOUP_IS_COOKIE_JAR_SQLITE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_COOKIE_JAR_SQLITE))
#define SOUP_IS_COOKIE_JAR_SQLITE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_COOKIE_JAR_SQLITE))
#define SOUP_COOKIE_JAR_SQLITE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_COOKIE_JAR_SQLITE, SoupCookieJarSqliteClass))

typedef struct {
	SoupCookieJarDB parent;

} SoupCookieJarSqlite;

typedef struct {
	SoupCookieJarDBClass parent_class;

} SoupCookieJarSqliteClass;

#define SOUP_COOKIE_JAR_SQLITE_FILENAME  "filename"

SOUP_AVAILABLE_IN_2_26
SOUP_DEPRECATED_IN_2_42_FOR(soup_cookie_jar_db_get_type)
GType soup_cookie_jar_sqlite_get_type (void);

SOUP_AVAILABLE_IN_2_26
SOUP_DEPRECATED_IN_2_42_FOR(soup_cookie_jar_db_new)
SoupCookieJar *soup_cookie_jar_sqlite_new (const char *filename,
					   gboolean    read_only);

G_END_DECLS

#endif /* __SOUP_COOKIE_JAR_SQLITE_H__ */
