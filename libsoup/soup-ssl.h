/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifndef SOUP_SSL_H
#define SOUP_SSL_H 1

#include <glib.h>

typedef enum {
	SOUP_SSL_TYPE_CLIENT = 0,
	SOUP_SSL_TYPE_SERVER
} SoupSSLType;

GIOChannel *soup_ssl_get_iochannel (GIOChannel *sock);
GIOChannel *soup_ssl_get_server_iochannel (GIOChannel *sock);

#endif /* SOUP_SSL_H */
