/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-private.h: Asyncronous Callback-based SOAP Request Queue.
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

#include <netinet/in.h>

#include "soup-context.h"
#include "soup-server.h"
#include "soup-socket.h"
#include "soup-uri.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESPONSE_BLOCK_SIZE 8192

extern gboolean    soup_initialized;
extern GSList     *soup_active_requests; /* CONTAINS: SoupMessage */
extern GHashTable *soup_servers;         /* KEY: uri->host, VALUE: SoupServer */

typedef struct {
	gchar      *host;
	GSList     *connections;        /* CONTAINS: SoupConnection */
	GHashTable *contexts;           /* KEY: uri->path, VALUE: SoupContext */
} SoupServer;

struct _SoupAddress {
	gchar*          name;
	struct sockaddr sa;
	guint           ref_count;
};

struct _SoupSocket {
	gint            sockfd;
	struct sockaddr sa; /* Why not an InetAddr? */
	guint           ref_count;
	GIOChannel     *iochannel;
};

struct _SoupContext {
	SoupProtocol  protocol;
	SoupUri      *uri;
	SoupServer   *server;
	guint         refcnt;
};

struct _SoupConnection {
	SoupServer   *server;
	SoupContext  *context;
	GIOChannel   *channel;
	SoupSocket   *socket;
	guint         port;
	gboolean      in_use;
	guint         last_used_id;
	gboolean      keep_alive;
};

struct _SoupMessagePrivate {
	SoupConnection *conn;

	SoupConnectId   connect_tag;
	guint           read_tag;
	guint           write_tag;
	guint           error_tag;
	guint           timeout_tag;

	guint           write_len;
	guint           header_len;

	guint           content_length;
	gboolean        is_chunked;
	guint           cur_chunk_len;
	guint           cur_chunk_idx;

	GString        *req_header;
	GByteArray     *recv_buf;

	SoupCallbackFn  callback;
	gpointer        user_data;
	
	SoupErrorCode   errorcode;
};

typedef struct {
	gchar                *methodname;
	SoupServerCallbackFn  cb;
	gpointer              user_data;
	SoupServerAuthorizeFn auth_fn;
	gpointer              auth_user_data;
	gint                  auth_allowed_types;
} SoupServerHandler;

/* from soup-message.c */

void      soup_message_issue_callback (SoupMessage   *req, 
				       SoupErrorCode  error);

void      soup_message_cleanup        (SoupMessage   *req);

/* from soup-misc.c */

guint     soup_str_case_hash          (gconstpointer  key);

gboolean  soup_str_case_equal         (gconstpointer  v1,
				       gconstpointer  v2);
	
gint      soup_substring_index        (gchar         *str, 
				       gint           len, 
				       gchar         *substr);

gchar    *soup_base64_encode          (const gchar   *text,
				       gint           len);

/* from soup-queue.c */

void      soup_queue_shutdown         (void);

/* from soup-server.c */

SoupServerHandler *soup_server_get_handler (const gchar *methodname);

gboolean           soup_server_authorize   (SoupMessage *msg,
					    const gchar *username, 
					    const gchar *password,
					    const gchar *realm);

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
