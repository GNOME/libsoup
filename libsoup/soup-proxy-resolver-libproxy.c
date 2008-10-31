/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver-libproxy.c: libproxy-based proxy resolution
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-proxy-resolver-libproxy.h"
#include "soup-address.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

#include <proxy.h>

typedef struct {
	pxProxyFactory *factory;
} SoupProxyResolverLibproxyPrivate;
	
#define SOUP_PROXY_RESOLVER_LIBPROXY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_PROXY_RESOLVER_LIBPROXY, SoupProxyResolverLibproxyPrivate))

static void soup_proxy_resolver_libproxy_interface_init (SoupProxyResolverInterface *proxy_resolver_interface);

G_DEFINE_TYPE_EXTENDED (SoupProxyResolverLibproxy, soup_proxy_resolver_libproxy, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE, NULL)
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_PROXY_RESOLVER, soup_proxy_resolver_libproxy_interface_init))

static void get_proxy_async (SoupProxyResolver  *proxy_resolver,
			     SoupMessage        *msg,
			     GMainContext       *async_context,
			     GCancellable       *cancellable,
			     SoupProxyResolverCallback callback,
			     gpointer            user_data);
static guint get_proxy_sync (SoupProxyResolver  *proxy_resolver,
			     SoupMessage        *msg,
			     GCancellable       *cancellable,
			     SoupAddress       **addr);

static void
soup_proxy_resolver_libproxy_init (SoupProxyResolverLibproxy *libproxy)
{
	SoupProxyResolverLibproxyPrivate *priv =
		SOUP_PROXY_RESOLVER_LIBPROXY_GET_PRIVATE (libproxy);

	priv->factory = px_proxy_factory_new ();
}

static void
finalize (GObject *object)
{
	SoupProxyResolverLibproxyPrivate *priv =
		SOUP_PROXY_RESOLVER_LIBPROXY_GET_PRIVATE (object);

	px_proxy_factory_free (priv->factory);

	G_OBJECT_CLASS (soup_proxy_resolver_libproxy_parent_class)->finalize (object);
}

static void
soup_proxy_resolver_libproxy_class_init (SoupProxyResolverLibproxyClass *libproxy_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (libproxy_class);

	g_type_class_add_private (libproxy_class, sizeof (SoupProxyResolverLibproxyPrivate));

	object_class->finalize = finalize;
}

static void
soup_proxy_resolver_libproxy_interface_init (SoupProxyResolverInterface *proxy_resolver_interface)
{
	proxy_resolver_interface->get_proxy_async = get_proxy_async;
	proxy_resolver_interface->get_proxy_sync = get_proxy_sync;
}

SoupProxyResolver *
soup_proxy_resolver_libproxy_new (void)
{
	return g_object_new (SOUP_TYPE_PROXY_RESOLVER_LIBPROXY, NULL);
}

typedef struct {
	SoupProxyResolver *proxy_resolver;
	SoupMessage *msg;
	GMainContext *async_context;
	GCancellable *cancellable;
	guint status;
	SoupAddress *addr;
	SoupProxyResolverCallback callback;
	gpointer user_data;
} SoupLibproxyAsyncData;

static gboolean
resolve_callback (gpointer data)
{
	SoupLibproxyAsyncData *slad = data;

	slad->callback (slad->proxy_resolver, slad->msg,
			slad->status, slad->addr, slad->user_data);
	g_object_unref (slad->proxy_resolver);
	g_object_unref (slad->msg);
	if (slad->addr)
		g_object_unref (slad->addr);
	g_slice_free (SoupLibproxyAsyncData, slad);

	return FALSE;
}

static gpointer
resolve_thread (gpointer data)
{
	SoupLibproxyAsyncData *slad = data;

	slad->status = get_proxy_sync (slad->proxy_resolver,
				       slad->msg,
				       slad->cancellable,
				       &slad->addr);
	soup_add_idle (slad->async_context, resolve_callback, slad);
	return NULL;
}

static void
get_proxy_async (SoupProxyResolver  *proxy_resolver,
		 SoupMessage        *msg,
		 GMainContext       *async_context,
		 GCancellable       *cancellable,
		 SoupProxyResolverCallback callback,
		 gpointer            user_data)
{
	SoupLibproxyAsyncData *slad;

	slad = g_slice_new0 (SoupLibproxyAsyncData);
	slad->proxy_resolver = g_object_ref (proxy_resolver);
	slad->msg = g_object_ref (msg);
	slad->async_context = async_context;
	slad->cancellable = cancellable;
	slad->callback = callback;
	slad->user_data = user_data;

	g_thread_create (resolve_thread, slad, FALSE, NULL);
}

static void
free_proxies (char **proxies)
{
	int i;

	for (i = 0; proxies[i]; i++)
		free (proxies[i]);
	free (proxies);
}

static guint
get_proxy_sync (SoupProxyResolver  *proxy_resolver,
		SoupMessage        *msg,
		GCancellable       *cancellable,
		SoupAddress       **addr)
{
	SoupProxyResolverLibproxyPrivate *priv =
		SOUP_PROXY_RESOLVER_LIBPROXY_GET_PRIVATE (proxy_resolver);
	char *msg_uri, **proxies;
	SoupURI *proxy_uri;
	int i;

	msg_uri = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
	proxies = px_proxy_factory_get_proxies (priv->factory, msg_uri);
	g_free (msg_uri);

	if (!proxies) {
		*addr = NULL;
		return SOUP_STATUS_OK;
	}

	if (proxies[0] && !strcmp (proxies[0], "direct://")) {
		free_proxies (proxies);
		*addr = NULL;
		return SOUP_STATUS_OK;
	}

	for (i = 0; proxies[i]; i++) {
		if (strncmp (proxies[i], "http://", 7) == 0)
			break;
	}
	if (!proxies[i]) {
		free_proxies (proxies);
		*addr = NULL;
		return SOUP_STATUS_CANT_RESOLVE_PROXY;
	}

	proxy_uri = soup_uri_new (proxies[i]);
	free_proxies (proxies);
	if (!proxy_uri) {
		*addr = NULL;
		return SOUP_STATUS_CANT_RESOLVE_PROXY;
	}

	*addr = soup_address_new (proxy_uri->host, proxy_uri->port);
	soup_uri_free (proxy_uri);
	return soup_status_proxify (soup_address_resolve_sync (*addr, cancellable));
}
