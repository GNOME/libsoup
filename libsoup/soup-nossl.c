/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-nossl.c
 *
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_SSL

#include "soup-ssl.h"
#include "soup-misc.h"

gboolean soup_ssl_supported = FALSE;

GIOChannel *
soup_ssl_wrap_iochannel (GIOChannel *sock, SoupSSLType type,
			 const char *hostname, gpointer cred_pointer)
{
	return NULL;
}

gpointer
soup_ssl_get_client_credentials (const char *ca_file)
{
	return NULL;
}

void
soup_ssl_free_client_credentials (gpointer client_creds)
{
	;
}

gpointer
soup_ssl_get_server_credentials (const char *cert_file, const char *key_file)
{
	return NULL;
}

void
soup_ssl_free_server_credentials (gpointer server_creds)
{
	;
}

#endif /* ! HAVE_SSL */
