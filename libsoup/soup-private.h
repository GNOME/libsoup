/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-private.h: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

/* 
 * All the things Soup users shouldn't need to know about except under
 * extraneous circumstances.
 */

#ifndef SOUP_PRIVATE_H
#define SOUP_PRIVATE_H 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <libsoup/soup-auth.h>
#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-server-message.h>
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
	GSList     *connections;      /* CONTAINS: SoupConnection */
	GHashTable *contexts;         /* KEY: uri->path, VALUE: SoupContext */

	GHashTable *auth_realms;      /* KEY: uri->path, VALUE: scheme:realm */
	GHashTable *auths;            /* KEY: scheme:realm, VALUE: SoupAuth */

	GHashTable *ntlm_auths;	      /* KEY: SoupConnection, VALUE: SoupAuth */
} SoupHost;

#ifdef HAVE_IPV6
#define soup_sockaddr_max sockaddr_in6
#else
#define soup_sockaddr_max sockaddr_in
#endif

/* from soup-context.c */

SoupAuth   *soup_context_lookup_auth       (SoupContext    *ctx,
					    SoupMessage    *msg);

gboolean    soup_context_update_auth       (SoupContext    *ctx,
					    SoupMessage    *msg);

gboolean    soup_context_authenticate_auth (SoupContext    *ctx,
					    SoupAuth       *auth);

void        soup_context_invalidate_auth   (SoupContext    *ctx,
					    SoupAuth       *auth);
					  
/* from soup-misc.c */

guint     soup_str_case_hash   (gconstpointer  key);
gboolean  soup_str_case_equal  (gconstpointer  v1,
				gconstpointer  v2);

gint      soup_substring_index (gchar         *str,
				gint           len,
				gchar         *substr);


#define SOUP_MAKE_TYPE(l,t,ci,i,parent) \
GType l##_get_type(void)\
{\
	static GType type = 0;				\
	if (!type){					\
		static GTypeInfo const object_info = {	\
			sizeof (t##Class),		\
							\
			(GBaseInitFunc) NULL,		\
			(GBaseFinalizeFunc) NULL,	\
							\
			(GClassInitFunc) ci,		\
			(GClassFinalizeFunc) NULL,	\
			NULL,	/* class_data */	\
							\
			sizeof (t),			\
			0,	/* n_preallocs */	\
			(GInstanceInitFunc) i,		\
		};					\
		type = g_type_register_static (parent, #t, &object_info, 0); \
	}						\
	return type;					\
}

#ifdef __cplusplus
}
#endif

#endif /*SOUP_PRIVATE_H*/
