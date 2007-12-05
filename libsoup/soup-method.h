/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifndef SOUP_METHOD_H
#define SOUP_METHOD_H 1

G_BEGIN_DECLS

#define SOUP_METHOD_POST      (g_intern_static_string ("POST"))
#define SOUP_METHOD_GET       (g_intern_static_string ("GET"))
#define SOUP_METHOD_HEAD      (g_intern_static_string ("HEAD"))
#define SOUP_METHOD_OPTIONS   (g_intern_static_string ("OPTIONS"))
#define SOUP_METHOD_PUT       (g_intern_static_string ("PUT"))
#define SOUP_METHOD_MOVE      (g_intern_static_string ("MOVE"))
#define SOUP_METHOD_COPY      (g_intern_static_string ("COPY"))
#define SOUP_METHOD_DELETE    (g_intern_static_string ("DELETE"))
#define SOUP_METHOD_TRACE     (g_intern_static_string ("TRACE"))
#define SOUP_METHOD_CONNECT   (g_intern_static_string ("CONNECT"))
#define SOUP_METHOD_MKCOL     (g_intern_static_string ("MKCOL"))
#define SOUP_METHOD_PROPPATCH (g_intern_static_string ("PROPPATCH"))
#define SOUP_METHOD_PROPFIND  (g_intern_static_string ("PROPFIND"))
#define SOUP_METHOD_PATCH     (g_intern_static_string ("PATCH"))
#define SOUP_METHOD_LOCK      (g_intern_static_string ("LOCK"))
#define SOUP_METHOD_UNLOCK    (g_intern_static_string ("UNLOCK"))

G_END_DECLS

#endif /* SOUP_METHOD_H */
