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

#include <gnet/gnet.h>

#include "soup-queue.h"
#include "soup-uri.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESPONSE_BLOCK_SIZE 8192

extern GSList     *soup_active_requests; /* CONTAINS: SoupRequest */
extern GHashTable *soup_servers;         /* KEY: uri->host, VALUE: SoupServer */

typedef struct {
	gchar      *host;
	GSList     *connections;        /* CONTAINS: SoupConnection */
	GHashTable *contexts;           /* KEY: uri->path, VALUE: SoupContext */
} SoupServer;

struct _SoupConnection {
	SoupServer *server;
	GTcpSocket *socket;
	guint       port;
	gboolean    in_use;
	guint       last_used_id;

	gboolean    keep_alive;
};

typedef enum {
	SOUP_PROTOCOL_HTTP,
	SOUP_PROTOCOL_SHTTP,
	SOUP_PROTOCOL_SMTP
} SoupProtocol;

struct _SoupContext {
	SoupProtocol  protocol;
	SoupUri      *uri;
	SoupServer   *server;
	guint         refcnt;
};

struct _SoupRequestPrivate {
	SoupConnection *conn;

	SoupConnectId   connect_tag;
	guint           read_tag;
	guint           write_tag;
	guint           error_tag;
	guint           timeout_tag;

	guint           write_len;
	guint           read_len;
	guint           header_len;

	gulong          content_length;
	gboolean        is_chunked;

	GString        *req_header;
	GByteArray     *recv_buf;

	SoupCallbackFn  callback;
	gpointer        user_data;
};

/* from soup-request.c */

SoupCallbackResult soup_request_issue_callback (SoupRequest   *req, 
						SoupErrorCode  error);

void               soup_request_cleanup        (SoupRequest   *req);

/* from soup-misc.c */

guint              soup_str_case_hash          (gconstpointer  key);

gboolean           soup_str_case_equal         (gconstpointer  v1,
						gconstpointer  v2);

gint               soup_substring_index        (gchar         *str, 
						gint           len, 
						gchar         *substr);

gchar             *soup_base64_encode          (gchar         *text);

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
