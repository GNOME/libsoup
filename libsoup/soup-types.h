/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef __SOUP_TYPES_H__
#define __SOUP_TYPES_H__ 1

#include <gio/gio.h>

#include <libsoup/soup-version.h>
#include <libsoup/soup-status.h>

G_BEGIN_DECLS

typedef struct _SoupAddress             SoupAddress;
typedef struct _SoupAuth                SoupAuth;
typedef struct _SoupAuthDomain          SoupAuthDomain;
typedef struct _SoupCookie              SoupCookie;
typedef struct _SoupCookieJar           SoupCookieJar;
typedef struct _SoupDate                SoupDate;
typedef struct _SoupHSTSEnforcer        SoupHSTSEnforcer;
typedef struct _SoupHSTSPolicy          SoupHSTSPolicy;
typedef struct _SoupMessage             SoupMessage;
typedef struct _SoupRequest             SoupRequest;
typedef struct _SoupRequestHTTP         SoupRequestHTTP;
typedef struct _SoupServer              SoupServer;
typedef struct _SoupSession             SoupSession;
typedef struct _SoupSessionAsync        SoupSessionAsync;
typedef struct _SoupSessionFeature      SoupSessionFeature;
typedef struct _SoupSessionSync         SoupSessionSync;
typedef struct _SoupSocket              SoupSocket;
typedef struct _SoupURI                 SoupURI;
typedef struct _SoupWebsocketConnection SoupWebsocketConnection;
typedef struct _SoupWebsocketExtension  SoupWebsocketExtension;

/*< private >*/
typedef struct _SoupConnection        SoupConnection;
typedef struct _SoupMessageQueue      SoupMessageQueue;
typedef struct _SoupMessageQueueItem  SoupMessageQueueItem;

G_END_DECLS

#endif /* __SOUP_TYPES_H__ */
