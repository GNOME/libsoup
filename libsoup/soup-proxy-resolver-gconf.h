/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_PROXY_RESOLVER_GCONF_H
#define SOUP_PROXY_RESOLVER_GCONF_H 1

#include <libsoup/soup-proxy-resolver.h>

#define SOUP_TYPE_PROXY_RESOLVER_GCONF            (soup_proxy_resolver_gconf_get_type ())
#define SOUP_PROXY_RESOLVER_GCONF(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_PROXY_RESOLVER_GCONF, SoupProxyResolverGConf))
#define SOUP_PROXY_RESOLVER_GCONF_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PROXY_RESOLVER_GCONF, SoupProxyResolverGConfClass))
#define SOUP_IS_PROXY_RESOLVER_GCONF(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_PROXY_RESOLVER_GCONF))
#define SOUP_IS_PROXY_RESOLVER_GCONF_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_PROXY_RESOLVER_GCONF))
#define SOUP_PROXY_RESOLVER_GCONF_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PROXY_RESOLVER_GCONF, SoupProxyResolverGConfClass))

typedef struct {
	GObject parent;

} SoupProxyResolverGConf;

typedef struct {
	GObjectClass parent_class;

} SoupProxyResolverGConfClass;

GType soup_proxy_resolver_gconf_get_type (void);

SoupProxyResolver *soup_proxy_resolver_gconf_new (void);

#endif /*SOUP_PROXY_RESOLVER_GCONF_H*/
