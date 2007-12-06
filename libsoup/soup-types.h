/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef SOUP_TYPES_H
#define SOUP_TYPES_H 1

#include <glib/gtypes.h>
#include <glib-object.h>

#include <libsoup/soup-status.h>

G_BEGIN_DECLS

typedef struct SoupAddress           SoupAddress;
typedef struct SoupMessage           SoupMessage;
typedef struct SoupMessageFilter     SoupMessageFilter;
typedef struct SoupServer            SoupServer;
typedef union  SoupServerAuth        SoupServerAuth;
typedef struct SoupServerAuthContext SoupServerAuthContext;
typedef struct SoupServerMessage     SoupServerMessage;
typedef struct SoupSession           SoupSession;
typedef struct SoupSessionAsync      SoupSessionAsync;
typedef struct SoupSessionSync       SoupSessionSync;
typedef struct SoupSocket            SoupSocket;
typedef struct SoupUri               SoupUri;

G_END_DECLS

#endif
