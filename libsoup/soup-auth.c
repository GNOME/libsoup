/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth.c: HTTP Authentication framework
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-auth.h"
#include "soup-auth-basic.h"
#include "soup-auth-digest.h"

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);
}

SOUP_MAKE_TYPE (soup_auth, SoupAuth, class_init, NULL, PARENT_TYPE)


typedef struct {
	const char  *scheme;
	GType      (*type_func) (void);
	int          strength;
} AuthScheme; 

static AuthScheme known_auth_schemes [] = {
	{ "Basic",  soup_auth_basic_get_type,  0 },
	{ "Digest", soup_auth_digest_get_type, 3 },
	{ NULL }
};

SoupAuth *
soup_auth_new_from_header_list (const GSList *vals)
{
	char *header = NULL;
	AuthScheme *scheme = NULL, *iter;
	SoupAuth *auth = NULL;

	g_return_val_if_fail (vals != NULL, NULL);

	while (vals) {
		char *tryheader = vals->data;

		for (iter = known_auth_schemes; iter->scheme; iter++) {
			if (!g_strncasecmp (tryheader, iter->scheme, 
					    strlen (iter->scheme))) {
				if (!scheme || 
				    scheme->strength < iter->strength) {
					header = tryheader;
					scheme = iter;
				}

				break;
			}
		}

		vals = vals->next;
	}

	if (!scheme)
		return NULL;

	auth = g_object_new (scheme->type_func (), NULL);
	if (!auth)
		return NULL;

	SOUP_AUTH_GET_CLASS (auth)->construct (auth, header);
	return auth;
}

void
soup_auth_authenticate (SoupAuth *auth, const char *username, const char *password)
{
	g_return_if_fail (SOUP_IS_AUTH (auth));
	g_return_if_fail (username != NULL);
	g_return_if_fail (password != NULL);

	SOUP_AUTH_GET_CLASS (auth)->authenticate (auth, username, password);
}

const char *
soup_auth_get_scheme_name (SoupAuth *auth)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	return SOUP_AUTH_GET_CLASS (auth)->scheme_name;
}

const char *
soup_auth_get_realm (SoupAuth *auth)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	return SOUP_AUTH_GET_CLASS (auth)->get_realm (auth);
}

gboolean
soup_auth_is_authenticated (SoupAuth *auth)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), TRUE);

	return SOUP_AUTH_GET_CLASS (auth)->is_authenticated (auth);
}

char *
soup_auth_get_authorization (SoupAuth *auth, SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);
	g_return_val_if_fail (msg != NULL, NULL);

	return SOUP_AUTH_GET_CLASS (auth)->get_authorization (auth, msg);
}

GSList *
soup_auth_get_protection_space (SoupAuth *auth, const SoupUri *source_uri)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);
	g_return_val_if_fail (source_uri != NULL, NULL);

	return SOUP_AUTH_GET_CLASS (auth)->get_protection_space (auth, source_uri);
}

void
soup_auth_free_protection_space (SoupAuth *auth, GSList *space)
{
	GSList *s;

	for (s = space; s; s = s->next)
		g_free (s->data);
	g_slist_free (space);
}
