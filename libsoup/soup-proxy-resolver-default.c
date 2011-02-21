/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver-default.c: proxy resolution based on GIO's GProxyResolver
 *
 * Copyright (C) 2011 Collabora Ltd.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "soup-proxy-resolver-default.h"
#include "soup-proxy-uri-resolver.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

static void soup_proxy_resolver_default_interface_init (SoupProxyURIResolverInterface *proxy_resolver_interface);

G_DEFINE_TYPE_EXTENDED (SoupProxyResolverDefault, soup_proxy_resolver_default, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE, NULL)
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_PROXY_URI_RESOLVER, soup_proxy_resolver_default_interface_init))


static void
soup_proxy_resolver_default_init (SoupProxyResolverDefault *resolver)
{
}

static void
soup_proxy_resolver_default_class_init (SoupProxyResolverDefaultClass *klass)
{
}

typedef struct {
	SoupProxyURIResolver *resolver;
	GCancellable *cancellable;
	SoupProxyURIResolverCallback callback;
	gpointer user_data;
} SoupAsyncData;

static void
resolved_proxy (GObject *object, GAsyncResult *result, gpointer data)
{
	GProxyResolver *proxy_resolver = G_PROXY_RESOLVER (object);
	SoupAsyncData *async_data = data;
	GError *error = NULL;
	char **proxy_uris = NULL;
	SoupURI *proxy_uri = NULL;
	guint status = SOUP_STATUS_OK;

	proxy_uris = g_proxy_resolver_lookup_finish (proxy_resolver,
						     result,
						     &error);

	if (error || proxy_uris == NULL || proxy_uris[0] == NULL) {
		status = SOUP_STATUS_CANT_RESOLVE_PROXY;
		goto finish;
	}

	/* We need to handle direct:// specially, otherwise
	 * SoupSession will try to resolve it as the proxy address.
	 */
	if (!g_strcmp0 (proxy_uris[0], "direct://"))
		goto finish;

	proxy_uri = soup_uri_new (proxy_uris[0]);
	if (proxy_uri == NULL)
		status = SOUP_STATUS_CANT_RESOLVE_PROXY;

finish:
	async_data->callback (async_data->resolver,
			      status,
			      proxy_uri,
			      async_data->user_data);

	if (async_data->cancellable)
		g_object_unref (async_data->cancellable);

	g_strfreev (proxy_uris);

	if (proxy_uri)
		soup_uri_free (proxy_uri);

	g_object_unref (async_data->resolver);
	g_slice_free (SoupAsyncData, async_data);
}

static void
get_proxy_uri_async (SoupProxyURIResolver  *resolver,
		     SoupURI		   *uri,
		     GMainContext	   *async_context,
		     GCancellable	   *cancellable,
		     SoupProxyURIResolverCallback callback,
		     gpointer		    user_data)
{
	SoupAsyncData *async_data;
	char *uri_string;

	async_data = g_slice_new0 (SoupAsyncData);
	async_data->resolver = (SoupProxyURIResolver*) g_object_ref (resolver);
	async_data->cancellable = cancellable;
	async_data->callback = callback;
	async_data->user_data = user_data;

	uri_string = soup_uri_to_string (uri, FALSE);

	g_proxy_resolver_lookup_async (g_proxy_resolver_get_default (),
				       uri_string,
				       cancellable ? g_object_ref (cancellable) : NULL,
				       resolved_proxy,
				       async_data);

	g_free (uri_string);
}

static guint
get_proxy_uri_sync (SoupProxyURIResolver  *resolver,
		    SoupURI		  *uri,
		    GCancellable	  *cancellable,
		    SoupURI		 **proxy_uri)
{
	GError *error = NULL;
	char** proxy_uris = NULL;
	char *uri_string;
	guint status = SOUP_STATUS_OK;

	uri_string = soup_uri_to_string (uri, FALSE);

	proxy_uris = g_proxy_resolver_lookup (g_proxy_resolver_get_default (),
					      uri_string,
					      cancellable,
					      &error);

	g_free (uri_string);

	if (error || proxy_uris == NULL || proxy_uris[0] == NULL) {
		status = SOUP_STATUS_CANT_RESOLVE_PROXY;
		goto cleanup;
	}

	/* We need to handle direct:// specially, otherwise
	 * SoupSession will try to resolve it as the proxy address.
	 */
	if (!g_strcmp0 (proxy_uris[0], "direct://"))
		goto cleanup;

	*proxy_uri = soup_uri_new (proxy_uris[0]);

	if (!*proxy_uri)
		status = SOUP_STATUS_CANT_RESOLVE_PROXY;

cleanup:
	g_strfreev (proxy_uris);
	if (error)
		g_clear_error (&error);
	return status;
}

static void
soup_proxy_resolver_default_interface_init (SoupProxyURIResolverInterface *iface)
{
	iface->get_proxy_uri_async = get_proxy_uri_async;
	iface->get_proxy_uri_sync = get_proxy_uri_sync;
}
