/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-proxy-resolver-gconf.c: GConf-based proxy resolution
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-proxy-resolver-gconf.h"
#include "soup-address.h"
#include "soup-dns.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-session-feature.h"

#include <gconf/gconf-client.h>

typedef struct {
	GMutex *lock;
	GConfClient *gconf;

	SoupAddress *proxy_addr;
	char *user, *password;

	GSList *ignore_hosts;
} SoupProxyResolverGConfPrivate;
#define SOUP_PROXY_RESOLVER_GCONF_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_PROXY_RESOLVER_GCONF, SoupProxyResolverGConfPrivate))

static void soup_proxy_resolver_gconf_interface_init (SoupProxyResolverInterface *proxy_resolver_interface);

G_DEFINE_TYPE_EXTENDED (SoupProxyResolverGConf, soup_proxy_resolver_gconf, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE, NULL)
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_PROXY_RESOLVER, soup_proxy_resolver_gconf_interface_init))

static void gconf_value_changed (GConfClient *client, const char *key,
				 GConfValue *value, gpointer user_data);
static void update_proxy_settings (SoupProxyResolverGConfPrivate *priv);
static void free_proxy_settings (SoupProxyResolverGConfPrivate *priv);

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
soup_proxy_resolver_gconf_init (SoupProxyResolverGConf *resolver_gconf)
{
	SoupProxyResolverGConfPrivate *priv =
		SOUP_PROXY_RESOLVER_GCONF_GET_PRIVATE (resolver_gconf);

	priv->lock = g_mutex_new ();
	priv->gconf = gconf_client_get_default ();

	gconf_client_add_dir (priv->gconf, "/system/http_proxy",
			      GCONF_CLIENT_PRELOAD_RECURSIVE, NULL);
	g_signal_connect (priv->gconf, "value_changed",
			  G_CALLBACK (gconf_value_changed),
			  resolver_gconf);
	update_proxy_settings (priv);
}

static void
finalize (GObject *object)
{
	SoupProxyResolverGConfPrivate *priv =
		SOUP_PROXY_RESOLVER_GCONF_GET_PRIVATE (object);

	g_signal_handlers_disconnect_by_func (priv->gconf, gconf_value_changed,
					      object);
	free_proxy_settings (priv);
	g_object_unref (priv->gconf);
	g_mutex_free (priv->lock);

	G_OBJECT_CLASS (soup_proxy_resolver_gconf_parent_class)->finalize (object);
}

static void
soup_proxy_resolver_gconf_class_init (SoupProxyResolverGConfClass *gconf_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (gconf_class);

	g_type_class_add_private (gconf_class, sizeof (SoupProxyResolverGConfPrivate));

	object_class->finalize = finalize;
}

static void
soup_proxy_resolver_gconf_interface_init (SoupProxyResolverInterface *proxy_resolver_interface)
{
	proxy_resolver_interface->get_proxy_async = get_proxy_async;
	proxy_resolver_interface->get_proxy_sync = get_proxy_sync;
}

SoupProxyResolver *
soup_proxy_resolver_gconf_new (void)
{
	return g_object_new (SOUP_TYPE_PROXY_RESOLVER_GCONF, NULL);
}

static void
free_proxy_settings (SoupProxyResolverGConfPrivate *priv)
{
	GSList *l;

	if (priv->proxy_addr) {
		g_object_unref (priv->proxy_addr);
		priv->proxy_addr = NULL;
	}
	g_free (priv->user);
	priv->user = NULL;
	g_free (priv->password);
	priv->password = NULL;

	for (l = priv->ignore_hosts; l; l = l->next)
		g_free (l->data);
	g_slist_free (priv->ignore_hosts);
	priv->ignore_hosts = NULL;
}

#define SOUP_GCONF_PROXY_ENABLED      "/system/http_proxy/use_http_proxy"
#define SOUP_GCONF_PROXY_USE_AUTH     "/system/http_proxy/use_authentication"
#define SOUP_GCONF_PROXY_HOST         "/system/http_proxy/host"
#define SOUP_GCONF_PROXY_PORT         "/system/http_proxy/port"
#define SOUP_GCONF_PROXY_USER         "/system/http_proxy/authentication_user"
#define SOUP_GCONF_PROXY_PASSWORD     "/system/http_proxy/authentication_password"
#define SOUP_GCONF_PROXY_IGNORE_HOSTS "/system/http_proxy/ignore_hosts"

static void
update_proxy_settings (SoupProxyResolverGConfPrivate *priv)
{
	GSList *ignore_hosts, *i;
	char *host;
	guint port;

	if (!gconf_client_get_bool (priv->gconf, SOUP_GCONF_PROXY_ENABLED, NULL))
		return;

	host = gconf_client_get_string (
		priv->gconf, SOUP_GCONF_PROXY_HOST, NULL);
	if (!host)
		return;
	port = gconf_client_get_int (
		priv->gconf, SOUP_GCONF_PROXY_PORT, NULL);
	priv->proxy_addr = soup_address_new (host, port);
	g_free (host);

	if (gconf_client_get_bool (priv->gconf, SOUP_GCONF_PROXY_USE_AUTH, NULL)) {
		priv->user = gconf_client_get_string (
			priv->gconf, SOUP_GCONF_PROXY_USER, NULL);
		priv->password = gconf_client_get_string (
			priv->gconf, SOUP_GCONF_PROXY_PASSWORD, NULL);
	}

	ignore_hosts = gconf_client_get_list (
		priv->gconf, SOUP_GCONF_PROXY_IGNORE_HOSTS,
		GCONF_VALUE_STRING, NULL);
	for (i = ignore_hosts; i; i = i->next) {
		host = i->data;

		/* FIXME: not right. Need to handle addresses, masks */
		priv->ignore_hosts = g_slist_prepend (
			priv->ignore_hosts,
			g_ascii_strdown (host, -1));
		g_free (host);
	}
	g_slist_free (ignore_hosts);
}

static void
gconf_value_changed (GConfClient *client, const char *key,
		     GConfValue *value, gpointer user_data)
{
	SoupProxyResolverGConf *resolver_gconf = user_data;
	SoupProxyResolverGConfPrivate *priv =
		SOUP_PROXY_RESOLVER_GCONF_GET_PRIVATE (resolver_gconf);

	free_proxy_settings (priv);
	update_proxy_settings (priv);
}

static gboolean
message_has_ignored_address (SoupProxyResolverGConfPrivate *priv,
			     SoupMessage *msg)
{
	SoupAddress *addr;
	struct sockaddr *sockaddr;
	const char *name, *ignore_name;
	char *hostname;
	GSList *l;
	int len;

	if (!priv->ignore_hosts)
		return FALSE;

	addr = soup_message_get_address (msg);
	name = soup_address_get_name (addr);
	sockaddr = soup_address_get_sockaddr (addr, &len);
	g_return_val_if_fail (name != NULL && sockaddr != NULL, FALSE);

	hostname = g_ascii_strdown (name, -1);
	for (l = priv->ignore_hosts; l; l = l->next) {
		ignore_name = l->data;

		if (*ignore_name == '*') {
			if (g_str_has_suffix (hostname, ignore_name + 1)) {
				g_free (hostname);
				return TRUE;
			}
		} else if (strcmp (hostname, ignore_name) == 0) {
			g_free (hostname);
			return TRUE;
		}
	}
	g_free (hostname);

	return FALSE;
}

static SoupAddress *
get_proxy_for_message (SoupProxyResolver  *proxy_resolver,
		       SoupMessage        *msg)
{
	SoupProxyResolverGConfPrivate *priv =
		SOUP_PROXY_RESOLVER_GCONF_GET_PRIVATE (proxy_resolver);
	SoupAddress *addr;

	g_mutex_lock (priv->lock);

	if (!priv->proxy_addr || message_has_ignored_address (priv, msg)) {
		g_mutex_unlock (priv->lock);
		return NULL;
	}

	addr = g_object_ref (priv->proxy_addr);
	g_mutex_unlock (priv->lock);
	return addr;
}

typedef struct {
	SoupProxyResolver *proxy_resolver;
	SoupMessage *msg;
	SoupAddress *addr;
	SoupProxyResolverCallback callback;
	gpointer user_data;
} SoupGConfAsyncData;

static void
resolved_address (SoupAddress *addr, guint status, gpointer data)
{
	SoupGConfAsyncData *sgad = data;

	sgad->callback (sgad->proxy_resolver, sgad->msg,
			soup_status_proxify (status), addr,
			sgad->user_data);
	g_object_unref (sgad->proxy_resolver);
	g_object_unref (sgad->msg);
	if (addr)
		g_object_unref (addr);
	g_slice_free (SoupGConfAsyncData, sgad);
}

static gboolean
resolved_no_address (gpointer data)
{
	resolved_address (NULL, SOUP_STATUS_OK, data);
	return FALSE;
}

static void
get_proxy_async (SoupProxyResolver  *proxy_resolver,
		 SoupMessage        *msg,
		 GMainContext       *async_context,
		 GCancellable       *cancellable,
		 SoupProxyResolverCallback callback,
		 gpointer            user_data)
{
	SoupGConfAsyncData *sgad;

	sgad = g_slice_new0 (SoupGConfAsyncData);
	sgad->proxy_resolver = g_object_ref (proxy_resolver);
	sgad->msg = g_object_ref (msg);
	sgad->callback = callback;
	sgad->user_data = user_data;
	sgad->addr = get_proxy_for_message (proxy_resolver, msg);

	if (sgad->addr) {
		soup_address_resolve_async (sgad->addr, async_context,
					    cancellable, resolved_address,
					    sgad);
	} else
		soup_add_idle (async_context, resolved_no_address, sgad);
}

static guint
get_proxy_sync (SoupProxyResolver  *proxy_resolver,
		SoupMessage        *msg,
		GCancellable       *cancellable,
		SoupAddress       **addr)
{
	*addr = get_proxy_for_message (proxy_resolver, msg);
	if (*addr)
		return soup_status_proxify (soup_address_resolve_sync (*addr, cancellable));
	else
		return SOUP_STATUS_OK;
}
