/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socks.h: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifndef SOUP_SOCKS_H
#define SOUP_SOCKS_H 1

#include <glib.h>
#include <libsoup/soup-context.h>

void soup_connect_socks_proxy (SoupConnection        *conn, 
			       SoupContext           *dest_ctx, 
			       SoupConnectCallbackFn  cb,
			       gpointer               user_data);

#endif /*SOUP_SOCKS_H*/
