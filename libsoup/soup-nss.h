/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-nss.h: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifndef SOUP_NSS_H
#define SOUP_NSS_H 1

#include <glib.h>
#include <libsoup/soup-misc.h>
#include <libsoup/soup-ssl.h>

GIOChannel *soup_nss_get_iochannel       (GIOChannel *sock, SoupSSLType type);

void        soup_nss_set_security_policy (SoupSecurityPolicy policy);

gboolean    soup_nss_init                (void);

#endif /* SOUP_NSS_H */
