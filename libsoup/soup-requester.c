/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-requester.c:
 *
 * Copyright (C) 2010, Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "config.h"

#include <glib/gi18n.h>

#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "soup-requester.h"
#include "soup-request-data.h"
#include "soup-request-file.h"
#include "soup-request-http.h"
#include "soup-uri.h"

struct _SoupRequesterPrivate {
	GHashTable *request_types;
};

G_DEFINE_TYPE (SoupRequester, soup_requester, G_TYPE_OBJECT)

static void
soup_requester_init (SoupRequester *requester)
{
	requester->priv = G_TYPE_INSTANCE_GET_PRIVATE (requester,
						       SOUP_TYPE_REQUESTER,
						       SoupRequesterPrivate);

	requester->priv->request_types =
		g_hash_table_new_full (soup_str_case_hash,
				       soup_str_case_equal,
				       g_free, NULL);
	g_hash_table_insert (requester->priv->request_types, g_strdup ("file"),
			     GSIZE_TO_POINTER (SOUP_TYPE_REQUEST_FILE));
	g_hash_table_insert (requester->priv->request_types, g_strdup ("data"),
			     GSIZE_TO_POINTER (SOUP_TYPE_REQUEST_DATA));
	g_hash_table_insert (requester->priv->request_types, g_strdup ("http"),
			     GSIZE_TO_POINTER (SOUP_TYPE_REQUEST_HTTP));
	g_hash_table_insert (requester->priv->request_types, g_strdup ("https"),
			     GSIZE_TO_POINTER (SOUP_TYPE_REQUEST_HTTP));
}

static void
finalize (GObject *object)
{
	SoupRequester *requester = SOUP_REQUESTER (object);

	if (requester->priv->request_types)
		g_hash_table_destroy (requester->priv->request_types);

	G_OBJECT_CLASS (soup_requester_parent_class)->finalize (object);
}

static void
soup_requester_class_init (SoupRequesterClass *requester_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (requester_class);

	g_type_class_add_private (requester_class, sizeof (SoupRequesterPrivate));

	/* virtual method override */
	object_class->finalize = finalize;
}

SoupRequester *
soup_requester_new (void)
{
	return g_object_new (SOUP_TYPE_REQUESTER, NULL);
}

SoupRequest *
soup_requester_request (SoupRequester *requester, const char *uri_string,
			SoupSession *session, GError **error)
{
	SoupURI *uri;
	SoupRequest *req;

	uri = soup_uri_new (uri_string);
	if (!uri) {
		g_set_error (error, SOUP_REQUESTER_ERROR, SOUP_REQUESTER_ERROR_BAD_URI,
			     _("Could not parse URI '%s'"), uri_string);
		return NULL;
	}

	req = soup_requester_request_uri (requester, uri, session, error);
	soup_uri_free (uri);
	return req;
}

SoupRequest *
soup_requester_request_uri (SoupRequester *requester, SoupURI *uri,
			    SoupSession *session, GError **error)
{
	GType request_type;

	g_return_val_if_fail (SOUP_IS_REQUESTER (requester), NULL);

	request_type = (GType)GPOINTER_TO_SIZE (g_hash_table_lookup (requester->priv->request_types, uri->scheme));
	if (!request_type) {
		g_set_error (error, SOUP_REQUESTER_ERROR,
			     SOUP_REQUESTER_ERROR_UNSUPPORTED_URI_SCHEME,
			     _("Unsupported URI scheme '%s'"), uri->scheme);
		return NULL;
	}

	if (g_type_is_a (request_type, G_TYPE_INITABLE)) {
		return g_initable_new (request_type, NULL, error,
				       "uri", uri,
				       "session", session,
				       NULL);
	} else {
		return g_object_new (request_type,
				     "uri", uri,
				     "session", session,
				     NULL);
	}
}

/* RFC 2396, 3.1 */
static gboolean
soup_scheme_is_valid (const char *scheme)
{
	if (scheme == NULL ||
	    !g_ascii_isalpha (*scheme))
		return FALSE;

	scheme++;
	while (*scheme) {
		if (!g_ascii_isalpha (*scheme) &&
		    !g_ascii_isdigit (*scheme) &&
		    *scheme != '+' &&
		    *scheme != '-' &&
		    *scheme != '.')
			return FALSE;
		scheme++;
	}
	return TRUE;
}

void
soup_requester_add_protocol (SoupRequester *requester,
			     const char    *scheme,
			     GType          request_type)
{
	g_return_if_fail (SOUP_IS_REQUESTER (requester));
	g_return_if_fail (soup_scheme_is_valid (scheme));

	g_hash_table_insert (requester->priv->request_types, g_strdup (scheme),
			     GSIZE_TO_POINTER (request_type));
}

void
soup_requester_remove_protocol (SoupRequester *requester,
				       const char  *scheme)
{
	g_return_if_fail (SOUP_IS_REQUESTER (requester));
	g_return_if_fail (soup_scheme_is_valid (scheme));

	g_hash_table_remove (requester->priv->request_types, scheme);
}

GQuark
soup_requester_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_requester_error_quark");
	return error;
}
