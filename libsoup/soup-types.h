/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef SOUP_TYPES_H
#define SOUP_TYPES_H 1

#include <glib/gtypes.h>
#include <glib-object.h>

#include <libsoup/soup-error.h>

typedef struct SoupAddress           SoupAddress;
typedef struct SoupConnection        SoupConnection;
typedef struct SoupContext           SoupContext;
typedef struct SoupMessage           SoupMessage;
typedef struct SoupServer            SoupServer;
typedef union  SoupServerAuth        SoupServerAuth;
typedef struct SoupServerAuthContext SoupServerAuthContext;
typedef struct SoupServerMessage     SoupServerMessage;
typedef struct SoupSocket            SoupSocket;
typedef struct SoupUri               SoupUri;

#endif
