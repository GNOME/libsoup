/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-basic.c: HTTP Basic Authentication
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-auth-basic.h"
#include "soup-headers.h"
#include "soup-message.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-uri.h"

static void construct (SoupAuth *auth, const char *header);
static GSList *get_protection_space (SoupAuth *auth, const SoupUri *source_uri);
static const char *get_realm (SoupAuth *auth);
static void authenticate (SoupAuth *auth, const char *username, const char *password);
static gboolean invalidate (SoupAuth *auth);
static gboolean is_authenticated (SoupAuth *auth);
static char *get_authorization (SoupAuth *auth, SoupMessage *msg);

struct SoupAuthBasicPrivate {
	char *realm, *token;
};

#define PARENT_TYPE SOUP_TYPE_AUTH
static SoupAuthClass *parent_class;

static void
init (GObject *object)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (object);

	basic->priv = g_new0 (SoupAuthBasicPrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (object);

	g_free (basic->priv->realm);
	g_free (basic->priv->token);
	g_free (basic->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

	auth_class->scheme_name = "Basic";

	auth_class->construct = construct;
	auth_class->get_protection_space = get_protection_space;
	auth_class->get_realm = get_realm;
	auth_class->authenticate = authenticate;
	auth_class->invalidate = invalidate;
	auth_class->is_authenticated = is_authenticated;
	auth_class->get_authorization = get_authorization;

	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_auth_basic, SoupAuthBasic, class_init, init, PARENT_TYPE)


static void
construct (SoupAuth *auth, const char *header)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);
	GHashTable *tokens;

	header += sizeof ("Basic");

	tokens = soup_header_param_parse_list (header);
	if (!tokens)
		return;

	basic->priv->realm = soup_header_param_copy_token (tokens, "realm");
	soup_header_param_destroy_hash (tokens);
}

static GSList *
get_protection_space (SoupAuth *auth, const SoupUri *source_uri)
{
	char *space, *p;

	space = g_strdup (source_uri->path);

	/* Strip query and filename component */
	p = strrchr (space, '/');
	if (p && p != space && p[1])
		*p = '\0';

	return g_slist_prepend (NULL, space);
}

static const char *
get_realm (SoupAuth *auth)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);

	return basic->priv->realm;
}

static void
authenticate (SoupAuth *auth, const char *username, const char *password)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);
	char *user_pass;
	int len;

	g_return_if_fail (username != NULL);
	g_return_if_fail (password != NULL);

	user_pass = g_strdup_printf ("%s:%s", username, password);
	len = strlen (user_pass);

	basic->priv->token = soup_base64_encode (user_pass, len);

	memset (user_pass, 0, len);
	g_free (user_pass);
}

static gboolean
invalidate (SoupAuth *auth)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);

	g_free (basic->priv->token);
	basic->priv->token = NULL;

	return TRUE;
}

static gboolean
is_authenticated (SoupAuth *auth)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);

	return basic->priv->token != NULL;
}

static char *
get_authorization (SoupAuth *auth, SoupMessage *msg)
{
	SoupAuthBasic *basic = SOUP_AUTH_BASIC (auth);

	return g_strdup_printf ("Basic %s", basic->priv->token);
}
