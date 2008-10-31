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
#include "soup-session-feature.h"

GType
soup_proxy_resolver_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;
  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      GType g_define_type_id =
        g_type_register_static_simple (G_TYPE_INTERFACE,
                                       g_intern_static_string ("SoupProxyResolver"),
                                       sizeof (SoupProxyResolverInterface),
                                       (GClassInitFunc)NULL,
                                       0,
                                       (GInstanceInitFunc)NULL,
                                       (GTypeFlags) 0);
      g_type_interface_add_prerequisite (g_define_type_id, G_TYPE_OBJECT);
      g_type_interface_add_prerequisite (g_define_type_id, SOUP_TYPE_SESSION_FEATURE);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }
  return g_define_type_id__volatile;
}

/**
 * soup_proxy_resovler_get_proxy_async:
 * @proxy_resolver: the #SoupProxyResolver
 * @msg: the #SoupMessage you want a proxy for
 * @async_context: the #GMainContext to invoke @callback in
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to invoke with the proxy address
 * @user_data: data for @callback
 *
 * Asynchronously determines a proxy server address to use for @msg
 * and calls @callback.
 **/
void
soup_proxy_resolver_get_proxy_async (SoupProxyResolver  *proxy_resolver,
				     SoupMessage        *msg,
				     GMainContext       *async_context,
				     GCancellable       *cancellable,
				     SoupProxyResolverCallback callback,
				     gpointer            user_data)
{
	SOUP_PROXY_RESOLVER_GET_CLASS (proxy_resolver)->
		get_proxy_async (proxy_resolver, msg,
				 async_context, cancellable,
				 callback, user_data);
}

/**
 * soup_proxy_resovler_get_proxy_sync:
 * @proxy_resolver: the #SoupProxyResolver
 * @msg: the #SoupMessage you want a proxy for
 * @cancellable: a #GCancellable, or %NULL
 * @addr: on return, will contain the proxy address
 *
 * Synchronously determines a proxy server address to use for @msg. If
 * @msg should be sent via proxy, *@addr will be set to the address of
 * the proxy, else it will be set to %NULL.
 *
 * Return value: SOUP_STATUS_OK if successful, or a transport-level
 * error.
 **/
guint
soup_proxy_resolver_get_proxy_sync (SoupProxyResolver  *proxy_resolver,
				    SoupMessage        *msg,
				    GCancellable       *cancellable,
				    SoupAddress       **addr)
{
	return SOUP_PROXY_RESOLVER_GET_CLASS (proxy_resolver)->
		get_proxy_sync (proxy_resolver, msg, cancellable, addr);
}
