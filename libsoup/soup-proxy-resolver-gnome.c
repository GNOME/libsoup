/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver-gnome.c: GNOME proxy resolution
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "soup-proxy-resolver-gnome.h"
#include "soup-proxy-uri-resolver.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

#include <gconf/gconf-client.h>
#include <proxy.h>

typedef enum {
	SOUP_PROXY_RESOLVER_GNOME_MODE_NONE,
	SOUP_PROXY_RESOLVER_GNOME_MODE_MANUAL,
	SOUP_PROXY_RESOLVER_GNOME_MODE_AUTO
} SoupProxyResolverGNOMEMode;

/* Since GConf is not thread-safe, making it annoying for us to deal
 * with, we make all of these static variables rather than instance
 * variables, so that we only have to deal with it once, rather than
 * per-resolver.
 */
G_LOCK_DEFINE_STATIC (resolver_gnome);
static SoupProxyResolverGNOMEMode proxy_mode;
static GConfClient *gconf_client;
static char *proxy_user, *proxy_password;

static pxProxyFactory *libproxy_factory;
static GThreadPool *libproxy_threadpool;

static void soup_proxy_resolver_gnome_interface_init (SoupProxyURIResolverInterface *proxy_resolver_interface);

G_DEFINE_TYPE_EXTENDED (SoupProxyResolverGNOME, soup_proxy_resolver_gnome, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE, NULL)
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_PROXY_URI_RESOLVER, soup_proxy_resolver_gnome_interface_init))

static void gconf_value_changed (GConfClient *client, const char *key,
				 GConfValue *value, gpointer user_data);
static void update_proxy_settings (void);

static void libproxy_threadpool_func (gpointer thread_data, gpointer user_data);

static void get_proxy_uri_async (SoupProxyURIResolver  *proxy_uri_resolver,
				 SoupURI               *uri,
				 GMainContext          *async_context,
				 GCancellable          *cancellable,
				 SoupProxyURIResolverCallback callback,
				 gpointer               user_data);
static guint get_proxy_uri_sync (SoupProxyURIResolver  *proxy_uri_resolver,
				 SoupURI               *uri,
				 GCancellable          *cancellable,
				 SoupURI              **proxy_uri);

typedef struct {
	GMutex *lock;
	GCond *cond;
} SoupProxyResolverGNOMEInitData;

static gboolean
init_gconf (gpointer user_data)
{
	SoupProxyResolverGNOMEInitData *id = user_data;

	if (id)
		g_mutex_lock (id->lock);

	/* resolver_gnome is locked */

	gconf_client = gconf_client_get_default ();

	gconf_client_add_dir (gconf_client, "/system/proxy",
			      GCONF_CLIENT_PRELOAD_RECURSIVE, NULL);
	gconf_client_add_dir (gconf_client, "/system/http_proxy",
			      GCONF_CLIENT_PRELOAD_RECURSIVE, NULL);
	g_signal_connect (gconf_client, "value_changed",
			  G_CALLBACK (gconf_value_changed),
			  NULL);
	update_proxy_settings ();

	if (id) {
		g_mutex_unlock (id->lock);
		g_cond_signal (id->cond);
	}
	return FALSE;
}

static void
soup_proxy_resolver_gnome_init (SoupProxyResolverGNOME *resolver_gnome)
{
	GMainContext *default_context;

	G_LOCK (resolver_gnome);
	if (!gconf_client) {
		/* GConf is not thread-safe, and we might be running
		 * in some random thread right now while other
		 * GConf-related activity is going on in the main
		 * thread. To prevent badness, we try to claim the
		 * default GMainContext; if we succeed, then either
		 * we're in the thread of the default GMainContext, or
		 * else there isn't currently any thread running the
		 * default GMainContext (meaning either the main loop
		 * hasn't been started yet, or else there is no main
		 * loop). Either way, it's safe to use GConf.
		 *
		 * If we can't manage to acquire the default
		 * GMainContext, then that means another thread
		 * already has it, so we use g_idle_add() to ask that
		 * thread to do the GConf initialization, and wait
		 * for that thread to finish.
		 */
		default_context = g_main_context_default ();
		if (g_main_context_acquire (default_context)) {
			init_gconf (NULL);
			g_main_context_release (default_context);
		} else {
			SoupProxyResolverGNOMEInitData id;

			id.lock = g_mutex_new ();
			id.cond = g_cond_new ();

			g_mutex_lock (id.lock);
			g_idle_add (init_gconf, &id);
			g_cond_wait (id.cond, id.lock);
			g_mutex_unlock (id.lock);

			g_cond_free (id.cond);
			g_mutex_free (id.lock);
		}
	}
	G_UNLOCK(resolver_gnome);
}

static void
soup_proxy_resolver_gnome_class_init (SoupProxyResolverGNOMEClass *gconf_class)
{
}

static void
soup_proxy_resolver_gnome_interface_init (SoupProxyURIResolverInterface *proxy_uri_resolver_interface)
{
	proxy_uri_resolver_interface->get_proxy_uri_async = get_proxy_uri_async;
	proxy_uri_resolver_interface->get_proxy_uri_sync = get_proxy_uri_sync;
}

#define SOUP_GCONF_PROXY_MODE           "/system/proxy/mode"
#define SOUP_GCONF_PROXY_AUTOCONFIG_URL "/system/proxy/autoconfig_url"
#define SOUP_GCONF_HTTP_PROXY_HOST      "/system/http_proxy/host"
#define SOUP_GCONF_HTTP_PROXY_PORT      "/system/http_proxy/port"
#define SOUP_GCONF_HTTP_USE_AUTH        "/system/http_proxy/use_authentication"
#define SOUP_GCONF_HTTP_PROXY_USER      "/system/http_proxy/authentication_user"
#define SOUP_GCONF_HTTP_PROXY_PASSWORD  "/system/http_proxy/authentication_password"
#define SOUP_GCONF_HTTPS_PROXY_HOST     "/system/proxy/secure_host"
#define SOUP_GCONF_HTTPS_PROXY_PORT     "/system/proxy/secure_port"
#define SOUP_GCONF_USE_SAME_PROXY       "/system/http_proxy/use_same_proxy"
#define SOUP_GCONF_PROXY_IGNORE_HOSTS   "/system/http_proxy/ignore_hosts"

static GConfEnumStringPair proxy_mode_map [] = {
	{ SOUP_PROXY_RESOLVER_GNOME_MODE_NONE,   "none"   },
	{ SOUP_PROXY_RESOLVER_GNOME_MODE_MANUAL, "manual" },
	{ SOUP_PROXY_RESOLVER_GNOME_MODE_AUTO,   "auto"   },
	{ 0, NULL }
};

static void
update_proxy_settings (void)
{
	char *mode, *http_proxy, *https_proxy = NULL, *no_proxy = NULL;
	GSList *ignore;

	/* resolver_gnome is locked */

	if (proxy_user) {
		g_free (proxy_user);
		proxy_user = NULL;
	}
	if (proxy_password) {
		memset (proxy_password, 0, strlen (proxy_password));
		g_free (proxy_password);
		proxy_password = NULL;
	}

	/* Get new settings */
	mode = gconf_client_get_string (
		gconf_client, SOUP_GCONF_PROXY_MODE, NULL);
	if (!mode || !gconf_string_to_enum (proxy_mode_map, mode,
					    (int *)&proxy_mode))
		proxy_mode = SOUP_PROXY_RESOLVER_GNOME_MODE_NONE;
	g_free (mode);

	if (proxy_mode == SOUP_PROXY_RESOLVER_GNOME_MODE_NONE) {
		if (libproxy_factory) {
			/* Unset anything we previously set */
			g_unsetenv ("PX_CONFIG_ORDER");
			g_unsetenv ("http_proxy");
			g_unsetenv ("https_proxy");
			g_unsetenv ("no_proxy");
		}
		return;
	} else if (proxy_mode == SOUP_PROXY_RESOLVER_GNOME_MODE_AUTO) {
		char *autoconfig_url;

		autoconfig_url = gconf_client_get_string (
			gconf_client, SOUP_GCONF_PROXY_AUTOCONFIG_URL, NULL);
		if (autoconfig_url && !strncmp (autoconfig_url, "http", 4))
			http_proxy = g_strconcat ("pac+", autoconfig_url, NULL);
		else
			http_proxy = g_strdup ("wpad://");
		g_free (autoconfig_url);
	} else /* SOUP_PROXY_RESOLVER_GNOME_MODE_MANUAL */ {
		char *host;
		guint port;

		host = gconf_client_get_string (
			gconf_client, SOUP_GCONF_HTTP_PROXY_HOST, NULL);
		if (!host || !*host) {
			g_free (host);
			proxy_mode = SOUP_PROXY_RESOLVER_GNOME_MODE_NONE;
			return;
		}
		port = gconf_client_get_int (
			gconf_client, SOUP_GCONF_HTTP_PROXY_PORT, NULL);

		if (port) {
			http_proxy = g_strdup_printf ("http://%s:%u",
						      host, port);
		} else
			http_proxy = g_strdup_printf ("http://%s", host);
		g_free (host);

		if (!gconf_client_get_bool (gconf_client, SOUP_GCONF_USE_SAME_PROXY, NULL)) {
			host = gconf_client_get_string (
				gconf_client, SOUP_GCONF_HTTPS_PROXY_HOST, NULL);
			port = gconf_client_get_int (
				gconf_client, SOUP_GCONF_HTTPS_PROXY_PORT, NULL);

			if (host && *host) {
				if (port) {
					https_proxy = g_strdup_printf (
						"http://%s:%u", host, port);
				} else {
					https_proxy = g_strdup_printf (
						"http://%s", host);
				}
			}
			g_free (host);
		}

		if (gconf_client_get_bool (gconf_client, SOUP_GCONF_HTTP_USE_AUTH, NULL)) {
			proxy_user = gconf_client_get_string (
				gconf_client, SOUP_GCONF_HTTP_PROXY_USER, NULL);
			proxy_password = gconf_client_get_string (
				gconf_client, SOUP_GCONF_HTTP_PROXY_PASSWORD, NULL);
		}
	}

	ignore = gconf_client_get_list (
		gconf_client, SOUP_GCONF_PROXY_IGNORE_HOSTS,
		GCONF_VALUE_STRING, NULL);
	if (ignore) {
		GString *ignore_list;
		GSList *i;

		ignore_list = g_string_new (NULL);
		for (i = ignore; i; i = i->next) {
			if (ignore_list->len)
				g_string_append_c (ignore_list, ',');
			g_string_append (ignore_list, i->data);
			g_free (i->data);
		}
		g_slist_free (ignore);
		no_proxy = g_string_free (ignore_list, FALSE);
	}

	g_setenv ("PX_CONFIG_ORDER", "envvar", TRUE);
	g_setenv ("http_proxy", http_proxy, TRUE);
	g_free (http_proxy);
	if (https_proxy) {
		g_setenv ("https_proxy", https_proxy, TRUE);
		g_free (https_proxy);
	} else
		g_unsetenv ("https_proxy");
	if (no_proxy) {
		g_setenv ("no_proxy", no_proxy, TRUE);
		g_free (no_proxy);
	} else
		g_unsetenv ("no_proxy");

	/* If we haven't created a proxy factory or thread pool yet,
	 * do so. If we already have one, we don't need to update
	 * anything, because it rechecks the environment variables
	 * every time.
	 */
	if (!libproxy_factory)
		libproxy_factory = px_proxy_factory_new ();

	if (proxy_mode == SOUP_PROXY_RESOLVER_GNOME_MODE_AUTO &&
	    !libproxy_threadpool) {
		libproxy_threadpool =
			g_thread_pool_new (libproxy_threadpool_func,
					   NULL, -1, FALSE, NULL);
	}
}

static void
gconf_value_changed (GConfClient *client, const char *key,
		     GConfValue *value, gpointer user_data)
{
	G_LOCK (resolver_gnome);
	update_proxy_settings ();
	G_UNLOCK (resolver_gnome);
}

static guint
get_proxy_for_uri (SoupURI *uri, SoupURI **proxy_uri)
{
	char *uristr, **proxies;
	gboolean got_proxy;
	int i;

	*proxy_uri = NULL;

	/* resolver_gnome is locked */

	uristr = soup_uri_to_string (uri, FALSE);
	proxies = px_proxy_factory_get_proxies (libproxy_factory, uristr);
	g_free (uristr);

	if (!proxies)
		return SOUP_STATUS_OK;

	got_proxy = FALSE;
	for (i = 0; proxies[i]; i++) {
		if (!strcmp (proxies[i], "direct://")) {
			got_proxy = TRUE;
			break;
		}
		if (strncmp (proxies[i], "http://", 7) == 0) {
			*proxy_uri = soup_uri_new (proxies[i]);
			got_proxy = TRUE;
			break;
		}
	}
	for (i = 0; proxies[i]; i++)
		free (proxies[i]);
	free (proxies);

	if (got_proxy) {
		if (*proxy_uri && proxy_user) {
			soup_uri_set_user (*proxy_uri, proxy_user);
			soup_uri_set_password (*proxy_uri, proxy_password);
		}

		return SOUP_STATUS_OK;
	} else
		return SOUP_STATUS_CANT_RESOLVE_PROXY;
}

typedef struct {
	SoupProxyURIResolver *proxy_uri_resolver;
	SoupURI *uri, *proxy_uri;
	GMainContext *async_context;
	GCancellable *cancellable;
	guint status;
	SoupProxyURIResolverCallback callback;
	gpointer user_data;
} SoupGNOMEAsyncData;

static gboolean
resolved_proxy (gpointer data)
{
	SoupGNOMEAsyncData *sgad = data;

	sgad->callback (sgad->proxy_uri_resolver, sgad->status,
			sgad->proxy_uri, sgad->user_data);
	g_object_unref (sgad->proxy_uri_resolver);
	if (sgad->uri)
		soup_uri_free (sgad->uri);
	if (sgad->async_context)
		g_main_context_unref (sgad->async_context);
	if (sgad->cancellable)
		g_object_unref (sgad->cancellable);
	if (sgad->proxy_uri)
		soup_uri_free (sgad->proxy_uri);
	g_slice_free (SoupGNOMEAsyncData, sgad);

	return FALSE;
}

static void
libproxy_threadpool_func (gpointer user_data, gpointer thread_data)
{
	SoupGNOMEAsyncData *sgad = user_data;

	/* We don't just call get_proxy_for_uri here, since it's
	 * possible that the proxy mode has changed...
	 */
	sgad->status = get_proxy_uri_sync (sgad->proxy_uri_resolver,
					   sgad->uri, sgad->cancellable,
					   &sgad->proxy_uri);
	soup_add_completion (sgad->async_context, resolved_proxy, sgad);
}

static void
get_proxy_uri_async (SoupProxyURIResolver  *proxy_uri_resolver,
		     SoupURI               *uri,
		     GMainContext          *async_context,
		     GCancellable          *cancellable,
		     SoupProxyURIResolverCallback callback,
		     gpointer               user_data)
{
	SoupGNOMEAsyncData *sgad;

	sgad = g_slice_new0 (SoupGNOMEAsyncData);
	sgad->proxy_uri_resolver = g_object_ref (proxy_uri_resolver);
	sgad->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	sgad->callback = callback;
	sgad->user_data = user_data;

	G_LOCK (resolver_gnome);
	switch (proxy_mode) {
	case SOUP_PROXY_RESOLVER_GNOME_MODE_NONE:
		sgad->proxy_uri = NULL;
		sgad->status = SOUP_STATUS_OK;
		break;

	case SOUP_PROXY_RESOLVER_GNOME_MODE_MANUAL:
		/* We know libproxy won't do PAC or WPAD in this case,
		 * so we can make a "blocking" call to it.
		 */
		sgad->status = get_proxy_for_uri (uri, &sgad->proxy_uri);
		break;

	case SOUP_PROXY_RESOLVER_GNOME_MODE_AUTO:
		/* FIXME: cancellable */
		sgad->uri = soup_uri_copy (uri);
		sgad->async_context = async_context ? g_main_context_ref (async_context) : NULL;
		g_thread_pool_push (libproxy_threadpool, sgad, NULL);
		G_UNLOCK (resolver_gnome);
		return;
	}
	G_UNLOCK (resolver_gnome);

	soup_add_completion (async_context, resolved_proxy, sgad);
}

static guint
get_proxy_uri_sync (SoupProxyURIResolver  *proxy_uri_resolver,
		    SoupURI               *uri,
		    GCancellable          *cancellable,
		    SoupURI              **proxy_uri)
{
	guint status;

	G_LOCK (resolver_gnome);
	if (proxy_mode == SOUP_PROXY_RESOLVER_GNOME_MODE_NONE) {
		*proxy_uri = NULL;
		status = SOUP_STATUS_OK;
	} else
		status = get_proxy_for_uri (uri, proxy_uri);
	G_UNLOCK (resolver_gnome);

	return status;
}
