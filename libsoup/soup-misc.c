/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include "soup-misc.h"

gint max_connections = -1;

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

