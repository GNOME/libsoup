/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_SERVER_AUTH_H
#define SOUP_SERVER_AUTH_H 1

#include <glib.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-misc.h>

typedef struct {
	SoupAuthType  type;
	const gchar  *realm;
	const gchar  *username;
	const gchar  *password;
} SoupServerAuthBasic;

typedef struct {
	SoupAuthType  type;
	const gchar  *realm;
	const gchar  *username;
	const gchar  *password_hash;
} SoupServerAuthDigest;

typedef struct {
	SoupAuthType  type;
	const gchar  *host;
	const gchar  *domain;
	const gchar  *user;
	const gchar  *lm_hash;
	const gchar  *nt_hash;
} SoupServerAuthNTLM;

typedef union {
	SoupAuthType          type;
	SoupServerAuthBasic   basic;
	SoupServerAuthDigest  digest;
	SoupServerAuthNTLM    ntlm;
} SoupServerAuth;

typedef gboolean (*SoupServerAuthCallbackFn) (SoupServerAuth       *auth,
					      SoupMessage          *msg, 
					      gpointer              data);

typedef struct {
	const gchar              *realm;
	guint                     types;
	SoupServerAuthCallbackFn  callback;
	gpointer                  user_data;
} SoupServerAuthContext;

#endif /* SOUP_SERVER_AUTH_H */
