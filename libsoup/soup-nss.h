/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-nss.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef SOUP_NSS_H
#define SOUP_NSS_H 1

#include <glib.h>
#include <libsoup/soup-misc.h>

GIOChannel *soup_nss_get_iochannel       (GIOChannel *sock);

void        soup_nss_set_security_policy (SoupSecurityPolicy policy);

gboolean    soup_nss_init                (void);

#endif /* SOUP_NSS_H */
