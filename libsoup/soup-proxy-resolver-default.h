/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2011 Collabora Ltd.
 */

#ifndef __SOUP_PROXY_RESOLVER_DEFAULT_H__
#define __SOUP_PROXY_RESOLVER_DEFAULT_H__ 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_PROXY_RESOLVER_DEFAULT(object)	    (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_PROXY_RESOLVER_DEFAULT, SoupProxyResolverDefault))
#define SOUP_PROXY_RESOLVER_DEFAULT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_PROXY_RESOLVER_DEFAULT, SoupProxyResolverDefaultClass))
#define SOUP_IS_PROXY_RESOLVER_DEFAULT(object)	    (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_PROXY_RESOLVER_DEFAULT))
#define SOUP_IS_PROXY_RESOLVER_DEFAULT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_PROXY_RESOLVER_DEFAULT))
#define SOUP_PROXY_RESOLVER_DEFAULT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_PROXY_RESOLVER_DEFAULT, SoupProxyResolverDefaultClass))

typedef struct {
	GObject parent;

} SoupProxyResolverDefault;

typedef struct {
	GObjectClass parent_class;

} SoupProxyResolverDefaultClass;

SOUP_AVAILABLE_IN_2_4
GType soup_proxy_resolver_default_get_type (void);
#define SOUP_TYPE_PROXY_RESOLVER_DEFAULT (soup_proxy_resolver_default_get_type ())

G_END_DECLS

#endif /* __SOUP_PROXY_RESOLVER_DEFAULT_H__ */
