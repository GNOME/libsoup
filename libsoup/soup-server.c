/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <glib.h>

#include "soup-server.h"
#include "soup-headers.h"
#include "soup-private.h"

static GSList                *soup_server_handlers = NULL;

static SoupServerAuthorizeFn  soup_server_global_auth = NULL;
static gpointer               soup_server_global_auth_user_data = NULL;
static gint                   soup_server_global_auth_allowed_types = 0;

SoupServerHandler *
soup_server_get_handler (const gchar *methodname)
{
	GSList *iter;
	gchar *name;
	gint len;

	g_return_val_if_fail (methodname != NULL, NULL);

	name = g_strdup (methodname);
	g_strstrip (name);
	len = strlen (name);

	/* Strip quotes */
	if (name [0] == '"' && name [len] == '"') {
		name [len--] = '\0';
		name++;
	}

 RETRY_MATCH:
	for (iter = soup_server_handlers; iter; iter = iter->next) {
		SoupServerHandler *hand = iter->data;
		if (!strcmp (hand->methodname, name)) {
			g_free (name);
			return hand;
		}
	}

	/* Try again without the URI */
	methodname = strchr (name, '#');
	if (methodname && strlen (name) > 1) {
		name++;
		goto RETRY_MATCH;
	}

	g_free (name);
	return NULL;
}

void  
soup_server_register (const gchar          *methodname, 
		      SoupServerCallbackFn  cb,
		      gpointer              user_data)
{
	SoupServerHandler *hand;

	g_return_if_fail (methodname != NULL);

	hand = g_new0 (SoupServerHandler, 1);
	hand->methodname = g_strdup (methodname);
	hand->cb = cb;
	hand->user_data = user_data;

	soup_server_handlers = g_slist_prepend (soup_server_handlers, hand);
}

void  
soup_server_unregister (const gchar *methodname)
{
	SoupServerHandler *hand;

	g_return_if_fail (methodname != NULL);

	hand = soup_server_get_handler (methodname);
	soup_server_handlers = g_slist_remove (soup_server_handlers, hand);
	g_free (hand->methodname);
	g_free (hand);
}

void  
soup_server_set_global_auth (gint                   allow_types,
			     SoupServerAuthorizeFn  cb,
			     gpointer              *user_data)
{
	soup_server_global_auth = cb;
	soup_server_global_auth_user_data = user_data;
	soup_server_global_auth_allowed_types = allow_types;
}

void  
soup_server_set_method_auth (gchar                 *methodname,
			     gint                   allow_types,
			     SoupServerAuthorizeFn  cb,
			     gpointer              *user_data)
{
	SoupServerHandler *hand = soup_server_get_handler (methodname);
	if (!hand) return;

	hand->auth_fn = cb;
	hand->auth_user_data = user_data;
	hand->auth_allowed_types = allow_types;
}

gboolean 
soup_server_authorize (SoupMessage *msg,
		       const gchar *username, 
		       const gchar *password,
		       const gchar *realm)
{
	SoupServerHandler *hand = soup_server_get_handler (msg->action);

	if (hand && hand->auth_fn)
		return (hand->auth_fn) (msg,
					username,
					password,
					realm,
					hand->auth_user_data);

	if (soup_server_global_auth) 
		return (soup_server_global_auth) (msg,
						  username,
						  password,
						  realm,
						  soup_server_global_auth_user_data);

	return TRUE;
}
