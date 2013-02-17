/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver-wrapper.c: SoupProxyURIResolver -> GProxyResolver wrapper
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-proxy-resolver-wrapper.h"
#include "soup.h"

static void soup_proxy_resolver_wrapper_interface_init (GProxyResolverInterface *proxy_resolver_interface);

G_DEFINE_TYPE_WITH_CODE (SoupProxyResolverWrapper, soup_proxy_resolver_wrapper, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_PROXY_RESOLVER, soup_proxy_resolver_wrapper_interface_init);
			 )

static void
soup_proxy_resolver_wrapper_init (SoupProxyResolverWrapper *resolver_wrapper)
{
}

static void
soup_proxy_resolver_wrapper_finalize (GObject *object)
{
	SoupProxyResolverWrapper *wrapper =
		SOUP_PROXY_RESOLVER_WRAPPER (object);

	g_clear_object (&wrapper->soup_resolver);

	G_OBJECT_CLASS (soup_proxy_resolver_wrapper_parent_class)->finalize (object);
}

static char **
convert_response (SoupURI *source_uri, guint status,
		  SoupURI *proxy_uri, GError **error)
{
	char **proxies = NULL;

	if (status == SOUP_STATUS_CANT_RESOLVE_PROXY) {
		g_set_error (error, G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND,
			     "%s (%s)", soup_status_get_phrase (status),
			     source_uri->host);
	} else if (status == SOUP_STATUS_CANT_CONNECT_PROXY) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED,
			     "%s (%s)", soup_status_get_phrase (status),
			     source_uri->host);
	} else {
		g_return_val_if_fail (status == SOUP_STATUS_OK, NULL);

		proxies = g_new (char *, 2);
		proxies[0] = soup_uri_to_string (proxy_uri, FALSE);
		proxies[1] = NULL;

		soup_uri_free (proxy_uri);
	}

	return proxies;
}

static void
wrapper_lookup_async_complete (SoupProxyURIResolver *resolver,
			       guint status, SoupURI *proxy_uri,
			       gpointer user_data)
{
	GTask *task = user_data;
	SoupURI *source_uri = g_task_get_task_data (task);
	char **proxies;
	GError *error = NULL;

	proxies = convert_response (source_uri, status, proxy_uri, &error);
	if (error)
		g_task_return_error (task, error);
	else
		g_task_return_pointer (task, proxies, (GDestroyNotify) g_strfreev);
	g_object_unref (task);
}

static void
soup_proxy_resolver_wrapper_lookup_async (GProxyResolver       *resolver,
					  const gchar          *uri,
					  GCancellable         *cancellable,
					  GAsyncReadyCallback   callback,
					  gpointer              user_data)
{
	SoupProxyResolverWrapper *wrapper =
		SOUP_PROXY_RESOLVER_WRAPPER (resolver);
	GTask *task;
	SoupURI *source_uri;

	task = g_task_new (resolver, cancellable, callback, user_data);
	source_uri = soup_uri_new (uri);
	g_task_set_task_data (task, source_uri, (GDestroyNotify) soup_uri_free);

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	soup_proxy_uri_resolver_get_proxy_uri_async (wrapper->soup_resolver,
						     source_uri,
						     g_main_context_get_thread_default (),
						     cancellable,
						     wrapper_lookup_async_complete,
						     task);
	G_GNUC_END_IGNORE_DEPRECATIONS;
}

static char **
soup_proxy_resolver_wrapper_lookup_finish (GProxyResolver       *resolver,
					   GAsyncResult         *result,
					   GError              **error)
{
	return g_task_propagate_pointer (G_TASK (result), error);
}

static gchar **
soup_proxy_resolver_wrapper_lookup (GProxyResolver  *resolver,
				    const gchar     *uri,
				    GCancellable    *cancellable,
				    GError         **error)
{
	SoupProxyResolverWrapper *wrapper =
		SOUP_PROXY_RESOLVER_WRAPPER (resolver);
	SoupURI *source_uri, *proxy_uri;
	guint status;
	gchar **proxies;

	source_uri = soup_uri_new (uri);
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	status = soup_proxy_uri_resolver_get_proxy_uri_sync (wrapper->soup_resolver,
							     source_uri,
							     cancellable,
							     &proxy_uri);
	G_GNUC_END_IGNORE_DEPRECATIONS;
	proxies = convert_response (source_uri, status, proxy_uri, error);
	soup_uri_free (source_uri);
	return proxies;
}

static void
soup_proxy_resolver_wrapper_class_init (SoupProxyResolverWrapperClass *static_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (static_class);

	object_class->finalize = soup_proxy_resolver_wrapper_finalize;
}

static void
soup_proxy_resolver_wrapper_interface_init (GProxyResolverInterface *proxy_resolver_interface)
{
	proxy_resolver_interface->lookup =
		soup_proxy_resolver_wrapper_lookup;
	proxy_resolver_interface->lookup_async =
		soup_proxy_resolver_wrapper_lookup_async;
	proxy_resolver_interface->lookup_finish =
		soup_proxy_resolver_wrapper_lookup_finish;
}

GProxyResolver *
soup_proxy_resolver_wrapper_new (SoupProxyURIResolver *soup_resolver)
{
	SoupProxyResolverWrapper *wrapper;

	wrapper = g_object_new (SOUP_TYPE_PROXY_RESOLVER_WRAPPER, NULL);
	wrapper->soup_resolver = g_object_ref (soup_resolver);
	return (GProxyResolver *)wrapper;
}
