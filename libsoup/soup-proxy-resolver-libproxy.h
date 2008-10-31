/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_PROXY_RESOLVER_LIBPROXY_H
#define SOUP_PROXY_RESOLVER_LIBPROXY_H 1

#include <libsoup/soup-proxy-resolver.h>

#define SOUP_TYPE_PROXY_RESOLVER_LIBPROXY            (soup_proxy_resolver_libproxy_get_type ())
#define SOUP_PROXY_RESOLVER_LIBPROXY(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY, SoupProxyResolverLibproxy))
#define SOUP_PROXY_RESOLVER_LIBPROXY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY, SoupProxyResolverLibproxyClass))
#define SOUP_IS_PROXY_RESOLVER_LIBPROXY(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY))
#define SOUP_IS_PROXY_RESOLVER_LIBPROXY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY))
#define SOUP_PROXY_RESOLVER_LIBPROXY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY, SoupProxyResolverLibproxyClass))

typedef struct {
	GObject parent;

} SoupProxyResolverLibproxy;

typedef struct {
	GObjectClass parent_class;

} SoupProxyResolverLibproxyClass;

GType soup_proxy_resolver_libproxy_get_type (void);

SoupProxyResolver *soup_proxy_resolver_libproxy_new (void);

#endif /*SOUP_PROXY_RESOLVER_LIBPROXY_H*/
