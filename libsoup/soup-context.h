/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef  SOUP_CONTEXT_H
#define  SOUP_CONTEXT_H 1

#include <glib.h>

#include "soup-uri.h"

typedef struct _SoupContextPrivate SoupContextPrivate;

typedef struct {
	SoupContextPrivate       *priv;
	SoupUri                  *uri;
	GList                    *custom_headers;
} SoupContext;

typedef enum {
	SOUP_CONNECT_ERROR_NONE,
	SOUP_CONNECT_ERROR_ADDR_RESOLVE,
	SOUP_CONNECT_ERROR_NETWORK
} SoupConnectErrorCode;

typedef void (*SoupConnectCallbackFn) (SoupContext          *ctx,
				       SoupConnectErrorCode  err,
				       GTcpSocket           *socket, 
				       gpointer              user_data);

SoupContext *soup_context_get               (gchar                 *uri);

void         soup_context_free              (SoupContext           *ctx);

void         soup_context_add_header        (SoupContext           *ctx,
					     gchar                 *name,
					     gchar                 *value);

void         soup_context_get_connection    (SoupContext           *ctx,
					     SoupConnectCallbackFn  cb,
					     gpointer               user_data);

void         soup_context_return_connection (SoupContext           *ctx,
					     GTcpSocket            *socket);

#endif /*SOUP_CONTEXT_H*/
