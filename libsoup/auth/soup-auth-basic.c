/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
#include "soup.h"

struct _SoupAuthBasic {
	SoupAuth parent;
};

typedef struct {
	char *token;
} SoupAuthBasicPrivate;

/**
 * SoupAuthBasic:
 *
 * HTTP "Basic" authentication.
 *
 * [class@Session]s support this by default; if you want to disable
 * support for it, call [method@Session.remove_feature_by_type],
 * passing %SOUP_TYPE_AUTH_BASIC.
 *
 */

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupAuthBasic, soup_auth_basic, SOUP_TYPE_AUTH)

static void
soup_auth_basic_init (SoupAuthBasic *basic)
{
}

static void
soup_auth_basic_finalize (GObject *object)
{
	SoupAuthBasicPrivate *priv = soup_auth_basic_get_instance_private (SOUP_AUTH_BASIC (object));

	g_free (priv->token);

	G_OBJECT_CLASS (soup_auth_basic_parent_class)->finalize (object);
}

static gboolean
soup_auth_basic_update (SoupAuth *auth, SoupMessage *msg,
			GHashTable *auth_params)
{
	SoupAuthBasicPrivate *priv = soup_auth_basic_get_instance_private (SOUP_AUTH_BASIC (auth));

	/* If we're updating a pre-existing auth, the
	 * username/password must be bad now, so forget it.
	 * Other than that, there's nothing to do here.
	 */
	if (priv->token) {
		memset (priv->token, 0, strlen (priv->token));
		g_free (priv->token);
		priv->token = NULL;
	}

	return TRUE;
}

static GSList *
soup_auth_basic_get_protection_space (SoupAuth *auth, GUri *source_uri)
{
	char *space, *p;

	space = g_strdup (g_uri_get_path (source_uri));

	/* Strip filename component */
	p = strrchr (space, '/');
	if (p == space && p[1])
		p[1] = '\0';
	else if (p && p[1])
		*p = '\0';

	return g_slist_prepend (NULL, space);
}

static void
soup_auth_basic_authenticate (SoupAuth *auth, const char *username,
			      const char *password)
{
	SoupAuthBasicPrivate *priv = soup_auth_basic_get_instance_private (SOUP_AUTH_BASIC (auth));
	char *user_pass, *user_pass_latin1;
	int len;

	user_pass = g_strdup_printf ("%s:%s", username, password);
	user_pass_latin1 = g_convert (user_pass, -1, "ISO-8859-1", "UTF-8",
				      NULL, NULL, NULL);
	if (user_pass_latin1) {
		memset (user_pass, 0, strlen (user_pass));
		g_free (user_pass);
		user_pass = user_pass_latin1;
	}
	len = strlen (user_pass);

	if (priv->token) {
		memset (priv->token, 0, strlen (priv->token));
		g_free (priv->token);
	}
	priv->token = g_base64_encode ((guchar *)user_pass, len);

	memset (user_pass, 0, len);
	g_free (user_pass);
}

static gboolean
soup_auth_basic_is_authenticated (SoupAuth *auth)
{
	SoupAuthBasicPrivate *priv = soup_auth_basic_get_instance_private (SOUP_AUTH_BASIC (auth));

	return priv->token != NULL;
}

static char *
soup_auth_basic_get_authorization (SoupAuth *auth, SoupMessage *msg)
{
	SoupAuthBasicPrivate *priv = soup_auth_basic_get_instance_private (SOUP_AUTH_BASIC (auth));

	return g_strdup_printf ("Basic %s", priv->token);
}

static void
soup_auth_basic_class_init (SoupAuthBasicClass *auth_basic_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (auth_basic_class);
	GObjectClass *object_class = G_OBJECT_CLASS (auth_basic_class);

	auth_class->scheme_name = "Basic";
	auth_class->strength = 1;

	auth_class->update = soup_auth_basic_update;
	auth_class->get_protection_space = soup_auth_basic_get_protection_space;
	auth_class->authenticate = soup_auth_basic_authenticate;
	auth_class->is_authenticated = soup_auth_basic_is_authenticated;
	auth_class->get_authorization = soup_auth_basic_get_authorization;

	object_class->finalize = soup_auth_basic_finalize;
}
