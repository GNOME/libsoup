/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

/* 
 * All the things SOUP users shouldn't need to know about except under
 * extraneous circumstances.
 */

#ifndef  SOAP_PRIVATE_H
#define  SOAP_PRIVATE_H 1

#include "soup-queue.h"

#define DEFAULT_CHUNK_SIZE  1024
#define RESPONSE_BLOCK_SIZE 1024

typedef struct {
	guint       port;
	gboolean    in_use;
	GTcpSocket *socket;
} SoupConnection;

typedef struct {
	gchar      *host;
	GSList     *connections;  /* CONTAINS: SoupConnection */
	GHashTable *contexts;     /* KEY: uri->path, VALUE: SoupContext */
} SoupServer;

extern GHashTable *servers;
extern guint connection_count;
extern GList *active_requests;

struct _SoupContextPrivate {
	SoupServer *server;

	gboolean    keep_alive;
	gint        chunk_size;
};

struct _SoupRequestPrivate {
	GTcpSocket *socket;

	gulong write_len;
	gulong read_len;

	guint connect_tag;
	guint read_tag;
	guint write_tag;
	guint timeout_tag;

	SoupCallbackFn callback;
	gpointer user_data;
};

SoupCallbackResult soup_request_issue_callback (SoupRequest   *req, 
						SoupErrorCode  error);

#endif /*SOUP_PRIVATE_H*/
