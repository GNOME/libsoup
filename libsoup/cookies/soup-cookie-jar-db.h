/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Diego Escalante Urrelo
 */

#pragma once

#include "soup-cookie-jar.h"

G_BEGIN_DECLS

#define SOUP_TYPE_COOKIE_JAR_DB (soup_cookie_jar_db_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupCookieJarDB, soup_cookie_jar_db, SOUP, COOKIE_JAR_DB, SoupCookieJar)

SOUP_AVAILABLE_IN_ALL
SoupCookieJar *soup_cookie_jar_db_new (const char *filename,
				       gboolean    read_only);

G_END_DECLS
