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

void  soup_server_unregister_by_name (const gchar          *methodname);

void  soup_server_unregister_by_cb   (SoupServerCallbackFn  cb);

void  soup_server_unregister_by_data (gpointer              user_data);

/* CGI Server methods */

void  soup_server_main               (void);

void  soup_server_main_quit          (void);


/* Apache module initializtion */

typedef void (*SoupServerInit) (void);

/* Implement soup_server_init() in your library. */

#endif /* SOUP_SERVER_H */
