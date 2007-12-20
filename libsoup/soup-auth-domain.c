/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-domain.c: HTTP Authentication Domain (server-side)
 *
 * Copyright (C) 2007 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-auth-domain.h"
#include "soup-message.h"
#include "soup-path-map.h"
#include "soup-uri.h"

enum {
	PROP_0,

	PROP_REALM,
	PROP_PROXY,
	PROP_ADD_PATH,
	PROP_REMOVE_PATH,
	PROP_FILTER,
	PROP_FILTER_DATA,

	LAST_PROP
};

typedef struct {
	char *realm;
	gboolean proxy;
	SoupAuthDomainFilter filter;
	gpointer filter_data;
	SoupPathMap *paths;
} SoupAuthDomainPrivate;

#define SOUP_AUTH_DOMAIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_AUTH_DOMAIN, SoupAuthDomainPrivate))

G_DEFINE_TYPE (SoupAuthDomain, soup_auth_domain, G_TYPE_OBJECT)

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_auth_domain_init (SoupAuthDomain *domain)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);

	priv->paths = soup_path_map_new (NULL);
}

static void
finalize (GObject *object)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (object);

	g_free (priv->realm);
	soup_path_map_free (priv->paths);

	G_OBJECT_CLASS (soup_auth_domain_parent_class)->finalize (object);
}

static void
soup_auth_domain_class_init (SoupAuthDomainClass *auth_domain_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_domain_class);

	g_type_class_add_private (auth_domain_class, sizeof (SoupAuthDomainPrivate));

	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	g_object_class_install_property (
		object_class, PROP_REALM,
		g_param_spec_string (SOUP_AUTH_DOMAIN_REALM,
				     "Realm",
				     "The realm of this auth domain",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_PROXY,
		g_param_spec_boolean (SOUP_AUTH_DOMAIN_PROXY,
				      "Proxy",
				      "Whether or not this is a proxy auth domain",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_ADD_PATH,
		g_param_spec_string (SOUP_AUTH_DOMAIN_ADD_PATH,
				     "Add a path",
				     "Add a path covered by this auth domain",
				     NULL,
				     G_PARAM_WRITABLE));
	g_object_class_install_property (
		object_class, PROP_REMOVE_PATH,
		g_param_spec_string (SOUP_AUTH_DOMAIN_REMOVE_PATH,
				     "Remove a path",
				     "Remove a path covered by this auth domain",
				     NULL,
				     G_PARAM_WRITABLE));
	g_object_class_install_property (
		object_class, PROP_FILTER,
		g_param_spec_pointer (SOUP_AUTH_DOMAIN_FILTER,
				      "Filter",
				      "A filter for deciding whether or not to require authentication",
				      G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_FILTER_DATA,
		g_param_spec_pointer (SOUP_AUTH_DOMAIN_FILTER_DATA,
				      "Filter data",
				      "Data to pass to filter",
				      G_PARAM_READWRITE));
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupAuthDomain *auth_domain = SOUP_AUTH_DOMAIN (object);
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_REALM:
		g_free (priv->realm);
		priv->realm = g_value_dup_string (value);
		break;
	case PROP_PROXY:
		priv->proxy = g_value_get_boolean (value);
		break;
	case PROP_ADD_PATH:
		soup_auth_domain_add_path (auth_domain,
					   g_value_get_string (value));
		break;
	case PROP_REMOVE_PATH:
		soup_auth_domain_remove_path (auth_domain,
					      g_value_get_string (value));
		break;
	case PROP_FILTER:
		priv->filter = g_value_get_pointer (value);
		break;
	case PROP_FILTER_DATA:
		priv->filter_data = g_value_get_pointer (value);
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_REALM:
		g_value_set_string (value, priv->realm);
		break;
	case PROP_PROXY:
		g_value_set_boolean (value, priv->proxy);
		break;
	case PROP_FILTER:
		g_value_set_pointer (value, priv->filter);
		break;
	case PROP_FILTER_DATA:
		g_value_set_pointer (value, priv->filter_data);
		break;
	default:
		break;
	}
}

void
soup_auth_domain_add_path (SoupAuthDomain *domain, const char *path)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);

	soup_path_map_add (priv->paths, path, GINT_TO_POINTER (TRUE));
}

void
soup_auth_domain_remove_path (SoupAuthDomain *domain, const char *path)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);

	soup_path_map_add (priv->paths, path, GINT_TO_POINTER (FALSE));
}

void
soup_auth_domain_set_filter (SoupAuthDomain *domain,
			     SoupAuthDomainFilter filter,
			     gpointer filter_data)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);

	priv->filter = filter;
	priv->filter_data = filter_data;
}

const char *
soup_auth_domain_get_realm (SoupAuthDomain *domain)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);

	return priv->realm;
}

gboolean
soup_auth_domain_covers (SoupAuthDomain *domain, SoupMessage *msg)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);
	const SoupURI *uri = soup_message_get_uri (msg);

	if (!soup_path_map_lookup (priv->paths, uri->path))
		return FALSE;
	else if (priv->filter && !priv->filter (domain, msg, priv->filter_data))
		return FALSE;
	else
		return TRUE;
}

char *
soup_auth_domain_accepts (SoupAuthDomain *domain, SoupMessage *msg)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);
	const char *header;

	header = soup_message_headers_find (msg->request_headers,
					    priv->proxy ?
					    "Proxy-Authorization" :
					    "Authorization");
	if (!header)
		return NULL;
	return SOUP_AUTH_DOMAIN_GET_CLASS (domain)->accepts (domain, msg, header);
}

void
soup_auth_domain_challenge (SoupAuthDomain *domain, SoupMessage *msg)
{
	SoupAuthDomainPrivate *priv = SOUP_AUTH_DOMAIN_GET_PRIVATE (domain);
	char *challenge;

	challenge = SOUP_AUTH_DOMAIN_GET_CLASS (domain)->challenge (domain, msg);
	soup_message_set_status (msg, priv->proxy ?
				 SOUP_STATUS_PROXY_UNAUTHORIZED :
				 SOUP_STATUS_UNAUTHORIZED);
	soup_message_headers_append (msg->response_headers,
				     priv->proxy ?
				     "Proxy-Authenticate" :
				     "WWW-Authenticate",
				     challenge);
	g_free (challenge);
}
