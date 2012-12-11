/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Diego Escalante Urrelo
 */

#ifndef SOUP_COOKIE_JAR_DB_H
#define SOUP_COOKIE_JAR_DB_H 1

#include <libsoup/soup-cookie-jar.h>

G_BEGIN_DECLS

#define SOUP_TYPE_COOKIE_JAR_DB            (soup_cookie_jar_db_get_type ())
#define SOUP_COOKIE_JAR_DB(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_COOKIE_JAR_DB, SoupCookieJarDB))
#define SOUP_COOKIE_JAR_DB_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_COOKIE_JAR_DB, SoupCookieJarDBClass))
#define SOUP_IS_COOKIE_JAR_DB(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_COOKIE_JAR_DB))
#define SOUP_IS_COOKIE_JAR_DB_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_COOKIE_JAR_DB))
#define SOUP_COOKIE_JAR_DB_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_COOKIE_JAR_DB, SoupCookieJarDBClass))

typedef struct {
	SoupCookieJar parent;

} SoupCookieJarDB;

typedef struct {
	SoupCookieJarClass parent_class;

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupCookieJarDBClass;

#define SOUP_COOKIE_JAR_DB_FILENAME  "filename"

SOUP_AVAILABLE_IN_2_42
GType soup_cookie_jar_db_get_type (void);

SOUP_AVAILABLE_IN_2_42
SoupCookieJar *soup_cookie_jar_db_new (const char *filename,
				       gboolean    read_only);

G_END_DECLS

#endif /* SOUP_COOKIE_JAR_DB_H */
