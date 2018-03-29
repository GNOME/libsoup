/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __SOUP_PROXY_RESOLVER_WRAPPER_H__
#define __SOUP_PROXY_RESOLVER_WRAPPER_H__ 1

#include "soup-proxy-uri-resolver.h"
#include "soup-uri.h"

#define SOUP_TYPE_PROXY_RESOLVER_WRAPPER            (soup_proxy_resolver_wrapper_get_type ())
#define SOUP_PROXY_RESOLVER_WRAPPER(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_PROXY_RESOLVER_WRAPPER, SoupProxyResolverWrapper))
#define SOUP_PROXY_RESOLVER_WRAPPER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PROXY_RESOLVER_WRAPPER, SoupProxyResolverWrapperClass))
#define SOUP_IS_PROXY_RESOLVER_WRAPPER(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_PROXY_RESOLVER_WRAPPER))
#define SOUP_IS_PROXY_RESOLVER_WRAPPER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_PROXY_RESOLVER_WRAPPER))
#define SOUP_PROXY_RESOLVER_WRAPPER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PROXY_RESOLVER_WRAPPER, SoupProxyResolverWrapperClass))

typedef struct {
	GObject parent;

	SoupProxyURIResolver *soup_resolver;
} SoupProxyResolverWrapper;

typedef struct {
	GObjectClass parent_class;

} SoupProxyResolverWrapperClass;

GType soup_proxy_resolver_wrapper_get_type (void);

GProxyResolver *soup_proxy_resolver_wrapper_new (SoupProxyURIResolver *soup_resolver);

#endif /* __SOUP_PROXY_RESOLVER_WRAPPER_H__ */
