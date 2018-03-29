/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver.c: HTTP proxy resolver interface
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-proxy-resolver.h"
#include "soup.h"

G_DEFINE_INTERFACE_WITH_CODE (SoupProxyResolver, soup_proxy_resolver, G_TYPE_OBJECT,
			      g_type_interface_add_prerequisite (g_define_type_id, SOUP_TYPE_SESSION_FEATURE);
			      )

static void
soup_proxy_resolver_default_init (SoupProxyResolverInterface *iface)
{
}

/**
 * SoupProxyResolverCallback:
 * @proxy_resolver:
 * @msg:
 * @arg:
 * @addr:
 * @user_data:
 *
 * Deprecated: 2.28: Use SoupProxyURIResolver instead
 **/

/**
 * soup_proxy_resolver_get_proxy_async: (virtual get_proxy_async)
 * @proxy_resolver:
 * @msg:
 * @async_context:
 * @cancellable:
 * @callback: (scope async)
 * @user_data:
 *
 * Deprecated: 2.28: Use SoupProxyURIResolver.get_proxy_uri_async instead
 **/
void
soup_proxy_resolver_get_proxy_async (SoupProxyResolver  *proxy_resolver,
				     SoupMessage        *msg,
				     GMainContext       *async_context,
				     GCancellable       *cancellable,
				     SoupProxyResolverCallback callback,
				     gpointer            user_data)
{
#ifdef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#endif
	SOUP_PROXY_RESOLVER_GET_CLASS (proxy_resolver)->
		get_proxy_async (proxy_resolver, msg,
				 async_context, cancellable,
				 callback, user_data);
#ifdef G_GNUC_END_IGNORE_DEPRECATIONS
G_GNUC_END_IGNORE_DEPRECATIONS
#endif
}

/**
 * soup_proxy_resolver_get_proxy_sync: (virtual get_proxy_sync)
 * @proxy_resolver:
 * @msg:
 * @cancellable:
 * @addr: (out) (transfer none):
 *
 * Deprecated: 2.28: Use SoupProxyURIResolver.get_proxy_uri_sync() instead
 **/
guint
soup_proxy_resolver_get_proxy_sync (SoupProxyResolver  *proxy_resolver,
				    SoupMessage        *msg,
				    GCancellable       *cancellable,
				    SoupAddress       **addr)
{
#ifdef G_GNUC_BEGIN_IGNORE_DEPRECATIONS
G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#endif
	return SOUP_PROXY_RESOLVER_GET_CLASS (proxy_resolver)->
		get_proxy_sync (proxy_resolver, msg, cancellable, addr);
#ifdef G_GNUC_END_IGNORE_DEPRECATIONS
G_GNUC_END_IGNORE_DEPRECATIONS
#endif
}
