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
#include <libsoup/soup-message.h>
#include <libsoup/soup-uri.h>

typedef enum {
	SOUP_AUTH_TYPE_BASIC  = (1 << 1),
	SOUP_AUTH_TYPE_DIGEST = (1 << 2),
	SOUP_AUTH_TYPE_NTLM   = (1 << 3)
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

typedef void (*SoupServerCallbackFn) (SoupMessage          *msg, 
				      SoupServerAuthToken  *token,
				      gpointer              data);

typedef struct {
	gchar                *path;
	guint                 auth_types;
	SoupServerCallbackFn  cb;
	gpointer              user_data;
} SoupServerHandler;

typedef struct _SoupServer SoupServer;

extern SoupServer *SOUP_CGI_SERVER;
extern SoupServer *SOUP_HTTPD_SERVER;
extern SoupServer *SOUP_HTTPD_SSL_SERVER;

SoupServer *       soup_server_new              (SoupProtocol          proto,
						 guint                 port);

void               soup_server_free             (SoupServer           *serv);

gint               soup_server_get_port         (SoupServer           *serv);

void               soup_server_run              (SoupServer           *serv);

void               soup_server_run_async        (SoupServer           *serv);

void               soup_server_quit             (SoupServer           *serv);

void               soup_server_add_list         (SoupServer           *serv,
						 SoupServerHandler    *list);

void               soup_server_remove_list      (SoupServer           *serv,
						 SoupServerHandler    *list);

void               soup_server_register         (SoupServer           *serv,
						 const gchar          *path,
						 guint                 authtype,
						 SoupServerCallbackFn  cb,
						 gpointer              data);

void               soup_server_register_default (SoupServer           *serv,
						 guint                 authtype,
						 SoupServerCallbackFn  cb,
						 gpointer              data);

void               soup_server_unregister       (SoupServer           *serv,
						 const gchar          *path);

SoupServerHandler *soup_server_get_handler      (SoupServer           *serv,
						 const gchar          *path);

void               soup_server_set_auth         (SoupServer  *serv,
						 const gchar *path,
						 guint        auth_types,
						 const gchar *realm);

void               soup_server_require_auth     (SoupMessage *message,
						 guint        auth_types,
						 const gchar *realm);


/* Apache module initializtion */
/* Implement soup_server_init() in your library. */
extern void soup_server_init      (void);

#endif /* SOUP_SERVER_H */
