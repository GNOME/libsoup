/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef __SOUP_TYPES_H__
#define __SOUP_TYPES_H__ 1

#include <gio/gio.h>

#include "soup-version.h"
#include "soup-status.h"

G_BEGIN_DECLS

#define _SOUP_ATOMIC_INTERN_STRING(variable, value) ((const char *)(g_atomic_pointer_get (&(variable)) ? (variable) : (g_atomic_pointer_set (&(variable), (gpointer)g_intern_static_string (value)), (variable))))

typedef struct _SoupAuth                SoupAuth;
typedef struct _SoupAuthDomain          SoupAuthDomain;
typedef struct _SoupCookie              SoupCookie;
typedef struct _SoupCookieJar           SoupCookieJar;
typedef struct _SoupHSTSEnforcer        SoupHSTSEnforcer;
typedef struct _SoupHSTSPolicy          SoupHSTSPolicy;
typedef struct _SoupMessage             SoupMessage;
typedef struct _SoupMessageMetrics      SoupMessageMetrics;
typedef struct _SoupServer              SoupServer;
typedef struct _SoupServerMessage       SoupServerMessage;
typedef struct _SoupSession             SoupSession;
typedef struct _SoupSessionFeature      SoupSessionFeature;
typedef struct _SoupWebsocketConnection SoupWebsocketConnection;
typedef struct _SoupWebsocketExtension  SoupWebsocketExtension;

G_END_DECLS

#endif /* __SOUP_TYPES_H__ */
