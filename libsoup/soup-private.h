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
 * All the things Soup users shouldn't need to know about except under
 * extraneous circumstances.
 */

#ifndef SOAP_PRIVATE_H
#define SOAP_PRIVATE_H 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef SOUP_WIN32
#  include <malloc.h>
#  define alloca _alloca
#else
#  ifdef HAVE_ALLOCA_H
#    include <alloca.h>
#  else
#    ifdef _AIX
#      pragma alloca
#    else
#      ifndef alloca /* predefined by HP cc +Olibcalls */
         char *alloca ();
#      endif
#    endif
#  endif
#endif

#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef SOUP_WIN32
#define VERSION "Win/0.7.4"
#include <windows.h>
#include <winbase.h>
#include <winuser.h>
#endif

#include <libsoup/soup-auth.h>
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
extern GHashTable *soup_hosts;           /* KEY: uri->host, VALUE: SoupHost */

extern SoupAuthorizeFn soup_auth_fn;
extern gpointer        soup_auth_fn_user_data;

typedef struct {
	gchar      *host;
	GSList     *connections;        /* CONTAINS: SoupConnection */
	GHashTable *contexts;           /* KEY: uri->path, VALUE: SoupContext */
	GHashTable *valid_auths;        /* KEY: uri->path, VALUE: SoupAuth */
} SoupHost;

struct _SoupAddress {
	gchar*          name;
	struct sockaddr sa;
	gint            ref_count;
	gint            cached;
};

struct _SoupSocket {
	gint            sockfd;
	SoupAddress    *addr;
	guint           ref_count;
	GIOChannel     *iochannel;
};

struct _SoupContext {
	SoupUri      *uri;
	SoupHost     *server;
	guint         refcnt;
};

struct _SoupConnection {
	SoupHost     *server;
	SoupContext  *context;
	GIOChannel   *channel;
	SoupSocket   *socket;
	SoupAuth     *auth;
	guint         port;
	gboolean      in_use;
	guint         last_used_id;
	gboolean      keep_alive;
	guint         death_tag;
};

struct _SoupServer {
	SoupProtocol       proto;
	gint               port;

	guint              refcnt;
	GMainLoop         *loop;

	guint              accept_tag;
	SoupSocket        *listen_sock;

	GIOChannel        *cgi_read_chan;
	GIOChannel        *cgi_write_chan;

	GHashTable        *handlers;   /* KEY: path, VALUE: SoupServerHandler */
	SoupServerHandler *default_handler;
};

struct _SoupMessagePrivate {
	SoupConnectId      connect_tag;
	guint              read_tag;
	guint              write_tag;
	guint              timeout_tag;

	SoupCallbackFn     callback;
	gpointer           user_data;

	guint              msg_flags;

	GSList            *content_handlers;

	SoupHttpVersion    http_version;

	SoupServer        *server;
	SoupSocket        *server_sock;
	SoupServerMessage *server_msg;
};

/* from soup-message.c */

void     soup_message_issue_callback (SoupMessage      *req);

gboolean soup_message_run_handlers   (SoupMessage      *msg,
				      SoupHandlerType   invoke_type);

void     soup_message_cleanup        (SoupMessage      *req);

/* from soup-misc.c */

guint     soup_str_case_hash   (gconstpointer  key);
gboolean  soup_str_case_equal  (gconstpointer  v1,
				gconstpointer  v2);

gint      soup_substring_index (gchar         *str,
				gint           len,
				gchar         *substr);

/* from soup-socket.c */

gboolean  soup_gethostbyname (const gchar         *hostname,
			      struct sockaddr_in  *sa,
			      gchar              **nicename);

gchar    *soup_gethostbyaddr (const gchar         *addr, 
			      size_t               length, 
			      int                  type);

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
