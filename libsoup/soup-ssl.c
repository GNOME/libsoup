/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#include <config.h>
#include <gmodule.h>

#include "soup-ssl.h"

#ifdef HAVE_SECURITY_SSL_H
#include "soup-nss.h"
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include "soup-openssl.h"
#endif

static gint ssl_library = 0; /* -1 = fail,
				 0 = first time, 
				 1 = nss, 
				 2 = openssl */
static SoupSecurityPolicy ssl_security_level = SOUP_SECURITY_DOMESTIC;

void 
soup_set_security_policy (SoupSecurityPolicy policy)
{
	ssl_security_level = policy;

	switch (ssl_library) {
	case -1:
	case 0:
		break;
#ifdef HAVE_SECURITY_SSL_H
	case 1:
		soup_nss_set_security_policy (policy);
		break;
#endif
#ifdef HAVE_OPENSSL_SSL_H
	case 2:
		soup_openssl_set_security_policy (policy);
		break;
#endif
	}
}

static void 
soup_ssl_init (void)
{
	ssl_library = -1;

	if (!g_module_supported ()) return;

#ifdef HAVE_SECURITY_SSL_H
	if (ssl_library == -1) ssl_library = soup_nss_init () ? 1 : -1;
#endif

#ifdef HAVE_OPENSSL_SSL_H
	if (ssl_library == -1) ssl_library = soup_openssl_init () ? 2 : -1;
#endif

	if (ssl_library == -1) return;

	soup_set_security_policy (ssl_security_level);
}

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	switch (ssl_library) {
	case -1:
		g_warning ("SSL Not Supported.");
		return NULL;
	case 0:
	default:
		soup_ssl_init ();
		return soup_ssl_get_iochannel (sock);
#ifdef HAVE_SECURITY_SSL_H
	case 1:
		return soup_nss_get_iochannel (sock);
#endif
#ifdef HAVE_OPENSSL_SSL_H
	case 2:
		return soup_openssl_get_iochannel (sock);
#endif
	}
}
