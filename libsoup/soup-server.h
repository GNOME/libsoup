/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
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

typedef gboolean (*SoupServerAuthorizeFn) (SoupMessage *msg, 
					   gchar       *username, 
					   gchar       *password,
					   gchar       *realm,
					   gpointer     user_data);

void  soup_server_set_global_auth    (SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

void  soup_server_set_method_auth    (gchar                 *methodname,
				      SoupServerAuthorizeFn  cb,
				      gpointer              *user_data);

/* CGI Server methods */

void  soup_server_main               (void);

void  soup_server_main_quit          (void);


/* Apache module initializtion */

typedef void (*SoupServerInit) (void);

extern SoupServerInit soup_server_init;

/* Implement soup_server_init() in your library. */

#endif /* SOUP_SERVER_H */
