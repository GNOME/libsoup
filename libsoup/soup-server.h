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

typedef void  (*SoupServerCallbackFn) (SoupMessage *msg, gpointer user_data);

void  soup_server_register           (const gchar          *methodname, 
				      SoupServerCallbackFn  cb,
				      gpointer              user_data);

void  soup_server_unregister         (const gchar          *methodname);

typedef gboolean (*SoupServerAuthorizeFn) (SoupMessage  *msg, 
					   const gchar  *username, 
					   const gchar  *password,
					   const gchar  *realm,
					   gpointer      user_data);

typedef enum {
	SOUP_AUTH_TYPE_BASIC,
	SOUP_AUTH_TYPE_DIGEST,
	SOUP_AUTH_TYPE_ANONYMOUS,
	SOUP_AUTH_TYPE_DENY
} SoupServerAuthType;

void  soup_server_set_global_auth    (gint                   allow_types,
				      SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

void  soup_server_set_method_auth    (gchar                 *methodname,
				      gint                   allow_type,
				      SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

/* CGI Server methods */

void  soup_server_main               (void);

void  soup_server_main_quit          (void);


/* Apache module initializtion */

extern void soup_server_init         (void);

/* Implement soup_server_init() in your library. */

#endif /* SOUP_SERVER_H */
