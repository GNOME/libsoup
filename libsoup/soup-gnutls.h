/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-gnutls.h
 *
 * Authors:
 *      Ian Peters <itp@ximian.com>
 *
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifndef SOUP_GNUTLS_H
#define SOUP_GNUTLS_H

#include <glib.h>
#include <libsoup/soup-ssl.h>
#include <libsoup/soup-misc.h>

GIOChannel *soup_gnutls_get_iochannel        (GIOChannel *sock,
					      SoupSSLType type);

void        soup_gnutls_set_security_policy  (SoupSecurityPolicy policy);

#endif /* SOUP_GNUTLS_H */
