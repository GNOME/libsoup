/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <ctype.h>

#include "soup-misc.h"
#include "soup-private.h"

static gint max_connections = -1;

static SoupContext *proxy_context;

void         
soup_set_proxy (SoupContext *context)
{
	if (proxy_context)
		soup_context_unref (proxy_context);

	proxy_context = context;
	soup_context_ref (proxy_context);
}

SoupContext *
soup_get_proxy (void)
{
	return proxy_context;
}

void         
soup_set_connection_limit (guint max_conn)
{
	max_connections = max_conn;
}

guint
soup_get_connection_limit (void)
{
	return max_connections;
}


guint
soup_str_case_hash (gconstpointer key)
{
	const char *p = key;
	guint h = toupper(*p);
	
	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + toupper(*p);
	
	return h;
}

gboolean
soup_str_case_equal (gconstpointer v1,
		     gconstpointer v2)
{
	const gchar *string1 = v1;
	const gchar *string2 = v2;
	
	return g_strcasecmp (string1, string2) == 0;
}
