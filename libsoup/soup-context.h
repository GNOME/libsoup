/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_CONTEXT_H
#define SOUP_CONTEXT_H 1

#include <glib.h>
#include <gnet/gnet.h>

typedef struct _SoupContext SoupContext;

typedef enum {
	SOUP_CONNECT_ERROR_NONE,
	SOUP_CONNECT_ERROR_ADDR_RESOLVE,
	SOUP_CONNECT_ERROR_NETWORK
} SoupConnectErrorCode;

typedef void (*SoupConnectCallbackFn) (SoupContext          *ctx,
				       SoupConnectErrorCode  err,
				       GTcpSocket           *socket, 
				       gpointer              user_data);

typedef gpointer SoupConnectId;

SoupContext  *soup_context_get                (gchar                *uri);

void          soup_context_ref                (SoupContext          *ctx);

void          soup_context_unref              (SoupContext          *ctx);

SoupConnectId soup_context_get_connection     (SoupContext          *ctx,
					       SoupConnectCallbackFn cb,
					       gpointer              user_data);

void          soup_context_release_connection (SoupContext          *ctx,
					       GTcpSocket           *socket);

void          soup_context_cancel_connect     (SoupConnectId         tag);

gchar        *soup_context_get_uri            (SoupContext          *ctx);

#endif /*SOUP_CONTEXT_H*/
