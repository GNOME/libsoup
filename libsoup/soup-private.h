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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef SOUP_WIN32
#define VERSION "Win/0.4.4"
#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#endif

#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-socket.h>
#include <libsoup/soup-uri.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RESPONSE_BLOCK_SIZE 8192

extern gboolean    soup_initialized;
extern GSList     *soup_active_requests; /* CONTAINS: SoupMessage */
extern GHashTable *soup_servers;         /* KEY: uri->host, VALUE: SoupServer */
extern GSList     *soup_server_handlers;

typedef struct {
	gchar      *host;
	GSList     *connections;        /* CONTAINS: SoupConnection */
	GHashTable *contexts;           /* KEY: uri->path, VALUE: SoupContext */
} SoupServer;

struct _SoupAddress {
	gchar*          name;
	struct sockaddr sa;
	gint            ref_count;
};

struct _SoupSocket {
	gint            sockfd;
	SoupAddress    *addr;
	guint           ref_count;
	GIOChannel     *iochannel;
};

typedef struct _SoupAuth SoupAuth;

struct _SoupContext {
	SoupUri      *uri;
	SoupServer   *server;
	SoupAuth     *auth;
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
	guint           timeout_tag;

	GString        *req_header;

	SoupCallbackFn  callback;
	gpointer        user_data;
	
	SoupErrorCode   errorcode;

	guint           msg_flags;

	GSList         *content_handlers;

	SoupHttpVersion http_version;
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

void          soup_message_issue_callback (SoupMessage      *req, 
					   SoupErrorCode     error);

SoupErrorCode soup_message_run_handlers   (SoupMessage      *msg,
					   SoupHandlerType   invoke_type);

void          soup_message_cleanup        (SoupMessage      *req);

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

gboolean           soup_server_authorize   (SoupMessage         *msg,
					    SoupServerAuthToken *token);

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
