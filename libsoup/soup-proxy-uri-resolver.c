/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-uri-resolver.c: HTTP proxy resolver interface, take 2
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#undef SOUP_VERSION_MIN_REQUIRED
#define SOUP_VERSION_MIN_REQUIRED SOUP_VERSION_2_42

#include "soup-proxy-uri-resolver.h"
#include "soup.h"

/**
 * SECTION:soup-proxy-uri-resolver
 * @short_description: Interface for locating HTTP proxies
 *
 * #SoupProxyURIResolver is an interface for finding appropriate HTTP
 * proxies to use.
 *
 * Deprecated: #SoupSession now has a #SoupSession:proxy-resolver
 * property that takes a #GProxyResolver (which is semantically
 * identical to #SoupProxyURIResolver).
 *
 * Even in older releases of libsoup, you are not likely to have to
 * implement this interface on your own; instead, you should usually
 * just be able to use #SoupProxyResolverDefault.
 */

G_DEFINE_INTERFACE_WITH_CODE (SoupProxyURIResolver, soup_proxy_uri_resolver, G_TYPE_OBJECT,
			      g_type_interface_add_prerequisite (g_define_type_id, SOUP_TYPE_SESSION_FEATURE);
			      )

static void
soup_proxy_uri_resolver_default_init (SoupProxyURIResolverInterface *iface)
{
}

/**
 * SoupProxyURIResolverCallback:
 * @resolver: the #SoupProxyURIResolver
 * @status: a #SoupStatus
 * @proxy_uri: the resolved proxy URI, or %NULL
 * @user_data: data passed to soup_proxy_uri_resolver_get_proxy_uri_async()
 *
 * Callback for soup_proxy_uri_resolver_get_proxy_uri_async()
 */

/**
 * soup_proxy_uri_resolver_get_proxy_uri_async:
 * @proxy_uri_resolver: the #SoupProxyURIResolver
 * @uri: the #SoupURI you want a proxy for
 * @async_context: (allow-none): the #GMainContext to invoke @callback in
 * @cancellable: a #GCancellable, or %NULL
 * @callback: (scope async): callback to invoke with the proxy address
 * @user_data: data for @callback
 *
 * Asynchronously determines a proxy URI to use for @msg and calls
 * @callback.
 *
 * Since: 2.26.3
 *
 * Deprecated: #SoupProxyURIResolver is deprecated in favor of
 * #GProxyResolver
 */
void
soup_proxy_uri_resolver_get_proxy_uri_async (SoupProxyURIResolver  *proxy_uri_resolver,
					     SoupURI               *uri,
					     GMainContext          *async_context,
					     GCancellable          *cancellable,
					     SoupProxyURIResolverCallback callback,
					     gpointer               user_data)
{
	SOUP_PROXY_URI_RESOLVER_GET_CLASS (proxy_uri_resolver)->
		get_proxy_uri_async (proxy_uri_resolver, uri,
				     async_context, cancellable,
				     callback, user_data);
}

/**
 * soup_proxy_uri_resolver_get_proxy_uri_sync:
 * @proxy_uri_resolver: the #SoupProxyURIResolver
 * @uri: the #SoupURI you want a proxy for
 * @cancellable: a #GCancellable, or %NULL
 * @proxy_uri: (out): on return, will contain the proxy URI
 *
 * Synchronously determines a proxy URI to use for @uri. If @uri
 * should be sent via proxy, *@proxy_uri will be set to the URI of the
 * proxy, else it will be set to %NULL.
 *
 * Return value: %SOUP_STATUS_OK if successful, or a transport-level
 * error.
 *
 * Since: 2.26.3
 *
 * Deprecated: #SoupProxyURIResolver is deprecated in favor of
 * #GProxyResolver
 */
guint
soup_proxy_uri_resolver_get_proxy_uri_sync (SoupProxyURIResolver  *proxy_uri_resolver,
					    SoupURI               *uri,
					    GCancellable          *cancellable,
					    SoupURI              **proxy_uri)
{
	return SOUP_PROXY_URI_RESOLVER_GET_CLASS (proxy_uri_resolver)->
		get_proxy_uri_sync (proxy_uri_resolver, uri, cancellable, proxy_uri);
}
