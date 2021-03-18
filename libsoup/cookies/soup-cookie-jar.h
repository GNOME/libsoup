/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_COOKIE_JAR            (soup_cookie_jar_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupCookieJar, soup_cookie_jar, SOUP, COOKIE_JAR, GObject)

struct _SoupCookieJarClass {
	GObjectClass parent_class;

	void     (*save)          (SoupCookieJar *jar);
	gboolean (*is_persistent) (SoupCookieJar *jar);

	/* signals */
	void (*changed) (SoupCookieJar *jar,
			 SoupCookie    *old_cookie,
			 SoupCookie    *new_cookie);

	/* Padding for future expansion */
	gpointer padding[6];
};

typedef enum {
	SOUP_COOKIE_JAR_ACCEPT_ALWAYS,
	SOUP_COOKIE_JAR_ACCEPT_NEVER,
	SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY,
	SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY
} SoupCookieJarAcceptPolicy;

SOUP_AVAILABLE_IN_ALL
SoupCookieJar *           soup_cookie_jar_new                         (void);
SOUP_AVAILABLE_IN_ALL
char          *           soup_cookie_jar_get_cookies                 (SoupCookieJar             *jar,
								       GUri                      *uri,
								       gboolean                   for_http);
SOUP_AVAILABLE_IN_ALL
GSList        *           soup_cookie_jar_get_cookie_list             (SoupCookieJar             *jar,
								       GUri                      *uri,
								       gboolean                   for_http);
SOUP_AVAILABLE_IN_ALL
GSList        *           soup_cookie_jar_get_cookie_list_with_same_site_info (
	                                                               SoupCookieJar             *jar,
	                                                               GUri                      *uri,
								       GUri                      *top_level,
								       GUri                      *site_for_cookies,
								       gboolean                   for_http,
								       gboolean                   is_safe_method,
								       gboolean                   is_top_level_navigation);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_set_cookie                  (SoupCookieJar             *jar,
								       GUri                      *uri,
								       const char                *cookie);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_set_cookie_with_first_party (SoupCookieJar             *jar,
								       GUri                      *uri,
								       GUri                      *first_party,
								       const char                *cookie);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_add_cookie                  (SoupCookieJar             *jar,
								       SoupCookie                *cookie);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_add_cookie_with_first_party (SoupCookieJar             *jar,
								       GUri                      *first_party,
								       SoupCookie                *cookie);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_add_cookie_full             (SoupCookieJar             *jar,
                                                                       SoupCookie                *cookie,
								       GUri                      *uri,
								       GUri                      *first_party);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_delete_cookie               (SoupCookieJar             *jar,
								       SoupCookie                *cookie);
SOUP_AVAILABLE_IN_ALL
GSList        *           soup_cookie_jar_all_cookies                 (SoupCookieJar             *jar);
SOUP_AVAILABLE_IN_ALL
void                      soup_cookie_jar_set_accept_policy           (SoupCookieJar             *jar,
								       SoupCookieJarAcceptPolicy  policy);
SOUP_AVAILABLE_IN_ALL
SoupCookieJarAcceptPolicy soup_cookie_jar_get_accept_policy           (SoupCookieJar             *jar);
SOUP_AVAILABLE_IN_ALL
gboolean                  soup_cookie_jar_is_persistent               (SoupCookieJar             *jar);

G_END_DECLS
