/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_SERVER_H
#define SOUP_SERVER_H 1

#include <glib.h>

#include "soup-message.h"

typedef enum {
	SOUP_AUTH_TYPE_BASIC  = (1 << 0),
	SOUP_AUTH_TYPE_DIGEST = (1 << 1),
	SOUP_AUTH_TYPE_NTLM   = (1 << 2),
	SOUP_AUTH_TYPE_DENY   = (1 << 3)
} SoupServerAuthType;

typedef struct {
	SoupServerAuthType  type;
	const gchar        *realm;
	const gchar        *username;
	const gchar        *password;
} SoupServerBasicToken;

typedef struct {
	SoupServerAuthType  type;
	const gchar        *realm;
	const gchar        *username;
	const gchar        *password_hash;
} SoupServerDigestToken;

typedef struct {
	SoupServerAuthType  type;
	const gchar        *host;
	const gchar        *domain;
	const gchar        *user;
	const gchar        *lm_hash;
	const gchar        *nt_hash;
} SoupServerNTLMToken;

typedef union {
	SoupServerAuthType     type;
	SoupServerBasicToken   basic;
	SoupServerDigestToken  digest;
	SoupServerNTLMToken    ntlm;
} SoupServerAuthToken;

typedef gboolean (*SoupServerAuthorizeFn) (SoupMessage         *msg, 
					   SoupServerAuthToken *token,
					   gpointer             user_data);

void  soup_server_set_global_auth    (gint                   allow_types,
				      SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

void  soup_server_set_method_auth    (gchar                 *methodname,
				      gint                   allow_types,
				      SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

typedef void  (*SoupServerCallbackFn) (SoupMessage *msg, gpointer user_data);

void  soup_server_register           (const gchar           *methodname, 
				      SoupServerCallbackFn   cb,
				      gpointer               user_data);

void  soup_server_register_full      (const gchar           *methodname, 
				      SoupServerCallbackFn   cb,
				      gpointer               user_data,
				      gint                   auth_allow_types,
				      SoupServerAuthorizeFn  auth_cb,
				      gpointer               auth_user_data);

void  soup_server_unregister         (const gchar           *methodname);

void  soup_server_set_unknown_path_handler (SoupServerCallbackFn   cb,
					    gpointer               user_data);

/* CGI Server methods */

void  soup_server_main               (void);

void  soup_server_main_quit          (void);

/* Apache module initializtion */
/* Implement soup_server_init() in your library. */

extern void soup_server_init         (void);

#endif /* SOUP_SERVER_H */
