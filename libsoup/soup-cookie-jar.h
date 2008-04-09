/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_COOKIE_JAR_H
#define SOUP_COOKIE_JAR_H 1

#include <libsoup/soup-types.h>

#define SOUP_TYPE_COOKIE_JAR            (soup_cookie_jar_get_type ())
#define SOUP_COOKIE_JAR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_COOKIE_JAR, SoupCookieJar))
#define SOUP_COOKIE_JAR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_COOKIE_JAR, SoupCookieJarClass))
#define SOUP_IS_COOKIE_JAR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_COOKIE_JAR))
#define SOUP_IS_COOKIE_JAR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_COOKIE_JAR))
#define SOUP_COOKIE_JAR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_COOKIE_JAR, SoupCookieJarClass))

typedef struct {
	GObject parent;

} SoupCookieJar;

typedef struct {
	GObjectClass parent_class;

	void (*save) (SoupCookieJar *jar);

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupCookieJarClass;

GType          soup_cookie_jar_get_type    (void);

SoupCookieJar *soup_cookie_jar_new         (void);

void           soup_cookie_jar_save        (SoupCookieJar *jar);

char          *soup_cookie_jar_get_cookies (SoupCookieJar *jar,
					    SoupURI       *uri,
					    gboolean       for_http);
void           soup_cookie_jar_set_cookie  (SoupCookieJar *jar,
					    SoupURI       *uri,
					    const char    *cookie);

#endif /* SOUP_COOKIE_JAR_H */
