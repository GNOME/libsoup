/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2011-2014 Red Hat, Inc.
 */

#ifndef __SOUP_SOCKET_PROPERTIES_H__
#define __SOUP_SOCKET_PROPERTIES_H__ 1

#include <gio/gio.h>

typedef struct {
	GProxyResolver *proxy_resolver;
	gboolean proxy_use_default;
	GInetSocketAddress *local_addr;

	GTlsDatabase *tlsdb;
	gboolean tlsdb_use_default;
	GTlsInteraction *tls_interaction;

	guint io_timeout;
	guint idle_timeout;
} SoupSocketProperties;

GType soup_socket_properties_get_type (void);
#define SOUP_TYPE_SOCKET_PROPERTIES (soup_socket_properties_get_type ())

SoupSocketProperties *soup_socket_properties_new                (GInetSocketAddress   *local_addr,
								 GTlsInteraction      *tls_interaction,
								 guint                 io_timeout,
								 guint                 idle_timeout);

SoupSocketProperties *soup_socket_properties_ref                (SoupSocketProperties *props);
void                  soup_socket_properties_unref              (SoupSocketProperties *props);

void                  soup_socket_properties_set_proxy_resolver (SoupSocketProperties *props,
								 GProxyResolver       *proxy_resolver);
void                  soup_socket_properties_set_tls_database   (SoupSocketProperties *props,
								 GTlsDatabase         *tlsdb);

#endif /* __SOUP_SOCKET_PROPERTIES_H__ */
