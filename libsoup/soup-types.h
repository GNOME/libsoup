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
typedef struct SoupAuth              SoupAuth;
typedef struct SoupAuthDomain        SoupAuthDomain;
typedef struct SoupMessage           SoupMessage;
typedef struct SoupServer            SoupServer;
typedef struct SoupSession           SoupSession;
typedef struct SoupSessionAsync      SoupSessionAsync;
typedef struct SoupSessionSync       SoupSessionSync;
typedef struct SoupSocket            SoupSocket;
typedef struct SoupURI               SoupURI;

G_END_DECLS

#endif
