/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-gnutls.h"
#include "soup-ssl.h"

#ifdef HAVE_SSL
GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	return soup_gnutls_get_iochannel (sock, SOUP_SSL_TYPE_CLIENT);
}

GIOChannel *
soup_ssl_get_server_iochannel (GIOChannel *sock)
{
	return soup_gnutls_get_iochannel (sock, SOUP_SSL_TYPE_SERVER);
}
#endif /* HAVE_SSL */
