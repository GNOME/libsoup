/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SSL_H
#define SOUP_SSL_H 1

#include <glib.h>

typedef enum {
	SOUP_SSL_TYPE_CLIENT = 0,
	SOUP_SSL_TYPE_SERVER
} SoupSSLType;

gpointer    soup_ssl_get_client_credentials  (const char  *ca_file);
void        soup_ssl_free_client_credentials (gpointer     creds);
gpointer    soup_ssl_get_server_credentials  (const char  *cert_file,
					      const char  *key_file);
void        soup_ssl_free_server_credentials (gpointer     creds);

GIOChannel *soup_ssl_wrap_iochannel          (GIOChannel  *sock,
					      SoupSSLType  type,
					      const char  *remote_host,
					      gpointer     credentials);

#define SOUP_SSL_ERROR soup_ssl_error_quark()

GQuark soup_ssl_error_quark (void);

typedef enum {
	SOUP_SSL_ERROR_HANDSHAKE_NEEDS_READ,
	SOUP_SSL_ERROR_HANDSHAKE_NEEDS_WRITE,
	SOUP_SSL_ERROR_CERTIFICATE,
} SoupSocketError;

#endif /* SOUP_SSL_H */
