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

#ifndef SOAP_PRIVATE_H
#define SOAP_PRIVATE_H 1

#include "soup-queue.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESPONSE_BLOCK_SIZE 8192

extern gint        connection_count;
extern GSList     *active_requests;   /* CONTAINS: SoupRequest */
extern GHashTable *servers;           /* KEY: uri->host, VALUE: SoupServer */

typedef struct {
	GTcpSocket *socket;
	guint       port;
	gboolean    in_use;
	guint       last_used_id;
} SoupConnection;

typedef struct {
	gchar      *host;
	GSList     *connections;      /* CONTAINS: SoupConnection */
	GHashTable *contexts;         /* KEY: uri->path, VALUE: SoupContext */
} SoupServer;

typedef enum {
	SOUP_PROTOCOL_HTTP_1_1,
	SOUP_PROTOCOL_HTTP_1_0,
	SOUP_PROTOCOL_SMTP
} SoupProtocol;

struct _SoupContextPrivate {
	SoupServer   *server;
	guint         refcnt;

	SoupProtocol  protocol;
	gboolean      keep_alive;
	gboolean      is_chunked;
};

struct _SoupRequestPrivate {
	GTcpSocket     *socket;

	SoupConnectId   connect_tag;
	guint           read_tag;
	guint           write_tag;
	guint           error_tag;
	guint           timeout_tag;

	gulong          write_len;
	gulong          read_len;

	GString        *req_header;
	GByteArray     *recv_buf;

	SoupCallbackFn  callback;
	gpointer        user_data;
};

SoupCallbackResult soup_request_issue_callback (SoupRequest   *req, 
						SoupErrorCode  error);

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
