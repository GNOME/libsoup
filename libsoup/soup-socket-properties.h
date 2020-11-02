/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011-2014 Red Hat, Inc.
 */

#ifndef __SOUP_SOCKET_PROPERTIES_H__
#define __SOUP_SOCKET_PROPERTIES_H__ 1

#include <gio/gio.h>

typedef struct {
	GProxyResolver *proxy_resolver;
	GInetSocketAddress *local_addr;

	GTlsDatabase *tlsdb;
	GTlsInteraction *tls_interaction;
	gboolean ssl_strict;

	guint io_timeout;
	guint idle_timeout;

	/*< private >*/
	guint ref_count;
} SoupSocketProperties;

GType soup_socket_properties_get_type (void);
#define SOUP_TYPE_SOCKET_PROPERTIES (soup_socket_properties_get_type ())

SoupSocketProperties *soup_socket_properties_new   (GProxyResolver     *proxy_resolver,
			                            GInetSocketAddress *local_addr,
						    GTlsDatabase       *tlsdb,
						    GTlsInteraction    *tls_interaction,
						    gboolean            ssl_strict,
						    guint               io_timeout,
						    guint               idle_timeout);

SoupSocketProperties *soup_socket_properties_ref   (SoupSocketProperties *props);
void                  soup_socket_properties_unref (SoupSocketProperties *props);

#endif /* __SOUP_SOCKET_PROPERTIES_H__ */
