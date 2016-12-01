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

#define LIBSOUP_USE_UNSTABLE_REQUEST_API

#include "soup-requester.h"
#include "soup.h"

G_GNUC_BEGIN_IGNORE_DEPRECATIONS

static SoupSessionFeatureInterface *soup_requester_default_feature_interface;
static void soup_requester_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

struct _SoupRequesterPrivate {
	SoupSession *session;
};

G_DEFINE_TYPE_WITH_CODE (SoupRequester, soup_requester, G_TYPE_OBJECT,
                         G_ADD_PRIVATE (SoupRequester)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_requester_session_feature_init))

static void
soup_requester_init (SoupRequester *requester)
{
	requester->priv = soup_requester_get_instance_private (requester);
}

static void
soup_requester_class_init (SoupRequesterClass *requester_class)
{
}

static void
soup_requester_attach (SoupSessionFeature *feature, SoupSession *session)
{
	SoupRequester *requester = SOUP_REQUESTER (feature);

	requester->priv->session = session;

	soup_requester_default_feature_interface->attach (feature, session);
}

static void
soup_requester_detach (SoupSessionFeature *feature, SoupSession *session)
{
	SoupRequester *requester = SOUP_REQUESTER (feature);

	requester->priv->session = NULL;

	soup_requester_default_feature_interface->detach (feature, session);
}

static gboolean
soup_requester_add_feature (SoupSessionFeature *feature, GType type)
{
	SoupRequester *requester = SOUP_REQUESTER (feature);

	if (!g_type_is_a (type, SOUP_TYPE_REQUEST))
		return FALSE;

	soup_session_add_feature_by_type (requester->priv->session, type);
	return TRUE;
}

static gboolean
soup_requester_remove_feature (SoupSessionFeature *feature, GType type)
{
	SoupRequester *requester = SOUP_REQUESTER (feature);

	if (!g_type_is_a (type, SOUP_TYPE_REQUEST))
		return FALSE;

	soup_session_remove_feature_by_type (requester->priv->session, type);
	return TRUE;
}

static gboolean
soup_requester_has_feature (SoupSessionFeature *feature, GType type)
{
	SoupRequester *requester = SOUP_REQUESTER (feature);

	if (!g_type_is_a (type, SOUP_TYPE_REQUEST))
		return FALSE;

	return soup_session_has_feature (requester->priv->session, type);
}

static void
soup_requester_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				     gpointer interface_data)
{
	soup_requester_default_feature_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = soup_requester_attach;
	feature_interface->detach = soup_requester_detach;
	feature_interface->add_feature = soup_requester_add_feature;
	feature_interface->remove_feature = soup_requester_remove_feature;
	feature_interface->has_feature = soup_requester_has_feature;
}

SoupRequester *
soup_requester_new (void)
{
	return g_object_new (SOUP_TYPE_REQUESTER, NULL);
}

static void
translate_error (GError *error)
{
	if (error->domain != SOUP_REQUEST_ERROR)
		return;

	error->domain = SOUP_REQUESTER_ERROR;
	if (error->code == SOUP_REQUEST_ERROR_BAD_URI)
		error->code = SOUP_REQUESTER_ERROR_BAD_URI;
	else if (error->code == SOUP_REQUEST_ERROR_UNSUPPORTED_URI_SCHEME)
		error->code = SOUP_REQUESTER_ERROR_UNSUPPORTED_URI_SCHEME;
	else
		g_warn_if_reached ();
}

/**
 * soup_requester_request:
 *
 * Return value: (transfer full):
 */
SoupRequest *
soup_requester_request (SoupRequester *requester, const char *uri_string,
			GError **error)
{
	SoupRequest *req;

	g_return_val_if_fail (SOUP_IS_REQUESTER (requester), NULL);

	req = soup_session_request (requester->priv->session,
				    uri_string, error);
	if (req || !error)
		return req;

	translate_error (*error);
	return NULL;
}

/**
 * soup_requester_request_uri:
 *
 * Return value: (transfer full):
 */
SoupRequest *
soup_requester_request_uri (SoupRequester *requester, SoupURI *uri,
			    GError **error)
{
	SoupRequest *req;

	g_return_val_if_fail (SOUP_IS_REQUESTER (requester), NULL);

	req = soup_session_request_uri (requester->priv->session,
					uri, error);
	if (req || !error)
		return req;

	translate_error (*error);
	return NULL;
}

GQuark
soup_requester_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_requester_error_quark");
	return error;
}

G_GNUC_END_IGNORE_DEPRECATIONS
