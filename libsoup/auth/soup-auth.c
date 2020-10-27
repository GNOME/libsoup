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
#include "soup.h"
#include "soup-connection-auth.h"
#include "soup-message-private.h"

/**
 * SECTION:soup-auth
 * @short_description: HTTP client-side authentication support
 * @see_also: #SoupSession
 *
 * #SoupAuth objects store the authentication data associated with a
 * given bit of web space. They are created automatically by
 * #SoupSession.
 **/

/**
 * SoupAuth:
 *
 * The abstract base class for handling authentication. Specific HTTP
 * Authentication mechanisms are implemented by its subclasses, but
 * applications never need to be aware of the specific subclasses
 * being used.
 **/

typedef struct {
        char *realm;
	char *authority;
	gboolean proxy;
	gboolean cancelled;
} SoupAuthPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (SoupAuth, soup_auth, G_TYPE_OBJECT)

enum {
	PROP_0,

	PROP_SCHEME_NAME,
	PROP_REALM,
	PROP_AUTHORITY,
	PROP_IS_FOR_PROXY,
	PROP_IS_AUTHENTICATED,
	PROP_IS_CANCELLED,

	LAST_PROP
};

static void
soup_auth_init (SoupAuth *auth)
{
}

static void
soup_auth_dispose (GObject *object)
{
	SoupAuth *auth = SOUP_AUTH (object);
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	if (!priv->cancelled && !soup_auth_is_authenticated (auth))
		soup_auth_cancel (auth);

	G_OBJECT_CLASS (soup_auth_parent_class)->dispose (object);
}

static void
soup_auth_finalize (GObject *object)
{
	SoupAuth *auth = SOUP_AUTH (object);
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_free (priv->realm);
	g_free (priv->authority);

	G_OBJECT_CLASS (soup_auth_parent_class)->finalize (object);
}

static void
soup_auth_set_property (GObject *object, guint prop_id,
			const GValue *value, GParamSpec *pspec)
{
	SoupAuth *auth = SOUP_AUTH (object);
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	switch (prop_id) {
	case PROP_REALM:
		g_free (priv->realm);
		priv->realm = g_value_dup_string (value);
		break;
	case PROP_AUTHORITY:
		g_free (priv->authority);
		priv->authority = g_value_dup_string (value);
		break;
	case PROP_IS_FOR_PROXY:
		priv->proxy = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_auth_get_property (GObject *object, guint prop_id,
			GValue *value, GParamSpec *pspec)
{
	SoupAuth *auth = SOUP_AUTH (object);
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	switch (prop_id) {
	case PROP_SCHEME_NAME:
		g_value_set_string (value, soup_auth_get_scheme_name (auth));
		break;
	case PROP_REALM:
		g_value_set_string (value, soup_auth_get_realm (auth));
		break;
	case PROP_AUTHORITY:
		g_value_set_string (value, soup_auth_get_authority (auth));
		break;
	case PROP_IS_FOR_PROXY:
		g_value_set_boolean (value, priv->proxy);
		break;
	case PROP_IS_AUTHENTICATED:
		g_value_set_boolean (value, soup_auth_is_authenticated (auth));
		break;
	case PROP_IS_CANCELLED:
		g_value_set_boolean (value, priv->cancelled);
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
auth_can_authenticate (SoupAuth *auth)
{
	return TRUE;
}

static void
soup_auth_class_init (SoupAuthClass *auth_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_class);

	auth_class->can_authenticate = auth_can_authenticate;

	object_class->dispose = soup_auth_dispose;
	object_class->finalize     = soup_auth_finalize;
	object_class->set_property = soup_auth_set_property;
	object_class->get_property = soup_auth_get_property;

	/* properties */
	/**
	 * SoupAuth:scheme-name:
         *
         * The authentication scheme name.
	 **/
	g_object_class_install_property (
		object_class, PROP_SCHEME_NAME,
		g_param_spec_string ("scheme-name",
				     "Scheme name",
				     "Authentication scheme name",
				     NULL,
				     G_PARAM_READABLE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupAuth:realm:
	 *
	 * The authentication realm.
	 **/
	g_object_class_install_property (
		object_class, PROP_REALM,
		g_param_spec_string ("realm",
				     "Realm",
				     "Authentication realm",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupAuth:authority:
	 *
	 * The authority (host:port) being authenticated to.
	 **/
	g_object_class_install_property (
		object_class, PROP_AUTHORITY,
		g_param_spec_string ("authority",
				     "Authority",
				     "Authentication authority",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupAuth:is-for-proxy:
	 *
	 * Whether or not the auth is for a proxy server.
	 **/
	g_object_class_install_property (
		object_class, PROP_IS_FOR_PROXY,
		g_param_spec_boolean ("is-for-proxy",
				      "For Proxy",
				      "Whether or not the auth is for a proxy server",
				      FALSE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SoupAuth:is-authenticated:
	 *
	 * Whether or not the auth has been authenticated.
	 **/
	g_object_class_install_property (
		object_class, PROP_IS_AUTHENTICATED,
		g_param_spec_boolean ("is-authenticated",
				      "Authenticated",
				      "Whether or not the auth is authenticated",
				      FALSE,
				      G_PARAM_READABLE |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SoupAuth:is-cancelled:
	 *
	 * An alias for the #SoupAuth:is-cancelled property.
	 * (Whether or not the auth has been cancelled.)
	 **/
	g_object_class_install_property (
		object_class, PROP_IS_CANCELLED,
		g_param_spec_boolean ("is-cancelled",
				      "Cancelled",
				      "Whether or not the auth is cancelled",
				      FALSE,
				      G_PARAM_READABLE |
				      G_PARAM_STATIC_STRINGS));
}

/**
 * soup_auth_new:
 * @type: the type of auth to create (a subtype of #SoupAuth)
 * @msg: the #SoupMessage the auth is being created for
 * @auth_header: the WWW-Authenticate/Proxy-Authenticate header
 *
 * Creates a new #SoupAuth of type @type with the information from
 * @msg and @auth_header.
 *
 * This is called by #SoupSession; you will normally not create auths
 * yourself.
 *
 * Return value: (nullable): the new #SoupAuth, or %NULL if it could
 * not be created
 **/
SoupAuth *
soup_auth_new (GType type, SoupMessage *msg, const char *auth_header)
{
	SoupAuth *auth;
	GHashTable *params;
	const char *scheme;
	SoupURI *uri;
	char *authority;

	g_return_val_if_fail (g_type_is_a (type, SOUP_TYPE_AUTH), NULL);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);
	g_return_val_if_fail (auth_header != NULL, NULL);

	uri = soup_message_get_uri_for_auth (msg);
	if (!uri)
		return NULL;

	authority = g_strdup_printf ("%s:%d", uri->host, uri->port);
	auth = g_object_new (type,
			     "is-for-proxy", (msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED),
			     "authority", authority,
			     NULL);
	g_free (authority);

	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	scheme = soup_auth_get_scheme_name (auth);
	if (g_ascii_strncasecmp (auth_header, scheme, strlen (scheme)) != 0) {
		g_object_unref (auth);
		return NULL;
	}

	params = soup_header_parse_param_list (auth_header + strlen (scheme));
	if (!params)
		params = g_hash_table_new (NULL, NULL);

	priv->realm = g_strdup (g_hash_table_lookup (params, "realm"));

	if (!SOUP_AUTH_GET_CLASS (auth)->update (auth, msg, params)) {
		g_object_unref (auth);
		auth = NULL;
	}
	soup_header_free_param_list (params);
	return auth;
}

/**
 * soup_auth_update:
 * @auth: a #SoupAuth
 * @msg: the #SoupMessage @auth is being updated for
 * @auth_header: the WWW-Authenticate/Proxy-Authenticate header
 *
 * Updates @auth with the information from @msg and @auth_header,
 * possibly un-authenticating it. As with soup_auth_new(), this is
 * normally only used by #SoupSession.
 *
 * Return value: %TRUE if @auth is still a valid (but potentially
 * unauthenticated) #SoupAuth. %FALSE if something about @auth_params
 * could not be parsed or incorporated into @auth at all.
 **/
gboolean
soup_auth_update (SoupAuth *auth, SoupMessage *msg, const char *auth_header)
{
	GHashTable *params;
	const char *scheme, *realm;
	gboolean was_authenticated, success;
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_return_val_if_fail (SOUP_IS_AUTH (auth), FALSE);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);
	g_return_val_if_fail (auth_header != NULL, FALSE);

	if (priv->cancelled)
		return FALSE;

	scheme = soup_auth_get_scheme_name (auth);
	if (g_ascii_strncasecmp (auth_header, scheme, strlen (scheme)) != 0)
		return FALSE;

	params = soup_header_parse_param_list (auth_header + strlen (scheme));
	if (!params)
		params = g_hash_table_new (NULL, NULL);

	realm = g_hash_table_lookup (params, "realm");
	if (realm && priv->realm && strcmp (realm, priv->realm) != 0) {
		soup_header_free_param_list (params);
		return FALSE;
	}

	was_authenticated = soup_auth_is_authenticated (auth);
	success = SOUP_AUTH_GET_CLASS (auth)->update (auth, msg, params);
	if (was_authenticated != soup_auth_is_authenticated (auth))
		g_object_notify (G_OBJECT (auth), "is-authenticated");
	soup_header_free_param_list (params);
	return success;
}

/**
 * soup_auth_authenticate:
 * @auth: a #SoupAuth
 * @username: the username provided by the user or client
 * @password: the password provided by the user or client
 *
 * Call this on an auth to authenticate it; normally this will cause
 * the auth's message to be requeued with the new authentication info.
 **/
void
soup_auth_authenticate (SoupAuth *auth, const char *username, const char *password)
{
	SoupAuthPrivate *priv;
	gboolean was_authenticated;

	g_return_if_fail (SOUP_IS_AUTH (auth));
	g_return_if_fail (username != NULL);
	g_return_if_fail (password != NULL);

	priv = soup_auth_get_instance_private (auth);
	if (priv->cancelled)
		return;

	was_authenticated = soup_auth_is_authenticated (auth);
	SOUP_AUTH_GET_CLASS (auth)->authenticate (auth, username, password);
	if (was_authenticated != soup_auth_is_authenticated (auth))
		g_object_notify (G_OBJECT (auth), "is-authenticated");
}

/**
 * soup_auth_cancel:
 * @auth: a #SoupAuth
 *
 * Call this on an auth to cancel it. You need to cancel an auth to complete
 * an asynchronous authenticate operation when no credentials are provided
 * (soup_auth_authenticate() is not called).
 * The #SoupAuth will be cancelled on dispose if it hans't been authenticated.
 */
void
soup_auth_cancel (SoupAuth *auth)
{
	SoupAuthPrivate *priv;

	g_return_if_fail (SOUP_IS_AUTH (auth));

	priv = soup_auth_get_instance_private (auth);
	if (priv->cancelled)
		return;

	priv->cancelled = TRUE;
	g_object_notify (G_OBJECT (auth), "is-cancelled");
}

/**
 * soup_auth_is_for_proxy:
 * @auth: a #SoupAuth
 *
 * Tests whether or not @auth is associated with a proxy server rather
 * than an "origin" server.
 *
 * Return value: %TRUE or %FALSE
 **/
gboolean
soup_auth_is_for_proxy (SoupAuth *auth)
{
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_return_val_if_fail (SOUP_IS_AUTH (auth), FALSE);

	return priv->proxy;
}

/**
 * soup_auth_get_scheme_name:
 * @auth: a #SoupAuth
 *
 * Returns @auth's scheme name. (Eg, "Basic", "Digest", or "NTLM")
 *
 * Return value: the scheme name
 **/
const char *
soup_auth_get_scheme_name (SoupAuth *auth)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	return SOUP_AUTH_GET_CLASS (auth)->scheme_name;
}

/**
 * soup_auth_get_authority:
 * @auth: a #SoupAuth
 *
 * Returns the authority (host:port) that @auth is associated with.
 *
 * Returns: the authority
 **/
const char *
soup_auth_get_authority (SoupAuth *auth)
{
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	return priv->authority;
}

/**
 * soup_auth_get_realm:
 * @auth: a #SoupAuth
 *
 * Returns @auth's realm. This is an identifier that distinguishes
 * separate authentication spaces on a given server, and may be some
 * string that is meaningful to the user. (Although it is probably not
 * localized.)
 *
 * Return value: the realm name
 **/
const char *
soup_auth_get_realm (SoupAuth *auth)
{
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	return priv->realm;
}

/**
 * soup_auth_get_info:
 * @auth: a #SoupAuth
 *
 * Gets an opaque identifier for @auth, for use as a hash key or the
 * like. #SoupAuth objects from the same server with the same
 * identifier refer to the same authentication domain (eg, the URLs
 * associated with them take the same usernames and passwords).
 *
 * Return value: the identifier
 **/
char *
soup_auth_get_info (SoupAuth *auth)
{
	SoupAuthPrivate *priv = soup_auth_get_instance_private (auth);

	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);

	if (SOUP_IS_CONNECTION_AUTH (auth))
		return g_strdup (SOUP_AUTH_GET_CLASS (auth)->scheme_name);
	else {
		return g_strdup_printf ("%s:%s",
					SOUP_AUTH_GET_CLASS (auth)->scheme_name,
					priv->realm);
	}
}

/**
 * soup_auth_is_authenticated:
 * @auth: a #SoupAuth
 *
 * Tests if @auth has been given a username and password
 *
 * Return value: %TRUE if @auth has been given a username and password
 **/
gboolean
soup_auth_is_authenticated (SoupAuth *auth)
{
	SoupAuthPrivate *priv;

	g_return_val_if_fail (SOUP_IS_AUTH (auth), TRUE);

	priv = soup_auth_get_instance_private (auth);
	if (priv->cancelled)
		return FALSE;

	return SOUP_AUTH_GET_CLASS (auth)->is_authenticated (auth);
}

/**
 * soup_auth_is_cancelled:
 * @auth: a #SoupAuth
 *
 * Tests if @auth has been cancelled
 *
 * Returns: %TRUE if @auth has been cancelled
 */
gboolean
soup_auth_is_cancelled (SoupAuth *auth)
{
 	SoupAuthPrivate *priv;

	g_return_val_if_fail (SOUP_IS_AUTH (auth), TRUE);

	priv = soup_auth_get_instance_private (auth);
	return priv->cancelled;
}

/**
 * soup_auth_get_authorization:
 * @auth: a #SoupAuth
 * @msg: the #SoupMessage to be authorized
 *
 * Generates an appropriate "Authorization" header for @msg. (The
 * session will only call this if soup_auth_is_authenticated()
 * returned %TRUE.)
 *
 * Return value: the "Authorization" header, which must be freed.
 **/
char *
soup_auth_get_authorization (SoupAuth *auth, SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);
	g_return_val_if_fail (msg != NULL, NULL);

	return SOUP_AUTH_GET_CLASS (auth)->get_authorization (auth, msg);
}

/**
 * soup_auth_is_ready:
 * @auth: a #SoupAuth
 * @msg: a #SoupMessage
 *
 * Tests if @auth is ready to make a request for @msg with. For most
 * auths, this is equivalent to soup_auth_is_authenticated(), but for
 * some auth types (eg, NTLM), the auth may be sendable (eg, as an
 * authentication request) even before it is authenticated.
 *
 * Return value: %TRUE if @auth is ready to make a request with.
 *
 * Since: 2.42
 **/
gboolean
soup_auth_is_ready (SoupAuth    *auth,
		    SoupMessage *msg)
{
	SoupAuthPrivate *priv;

	g_return_val_if_fail (SOUP_IS_AUTH (auth), TRUE);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), TRUE);

	priv = soup_auth_get_instance_private (auth);
	if (priv->cancelled)
		return FALSE;

	if (SOUP_AUTH_GET_CLASS (auth)->is_ready)
		return SOUP_AUTH_GET_CLASS (auth)->is_ready (auth, msg);
	else
		return SOUP_AUTH_GET_CLASS (auth)->is_authenticated (auth);
}

/**
 * soup_auth_can_authenticate:
 * @auth: a #SoupAuth
 *
 * Tests if @auth is able to authenticate by providing credentials to the
 * soup_auth_authenticate().
 *
 * Return value: %TRUE if @auth is able to accept credentials.
 *
 * Since: 2.54
 **/
gboolean
soup_auth_can_authenticate (SoupAuth *auth)
{
	SoupAuthPrivate *priv;

	g_return_val_if_fail (SOUP_IS_AUTH (auth), FALSE);

	priv = soup_auth_get_instance_private (auth);
	if (priv->cancelled)
		return FALSE;

	return SOUP_AUTH_GET_CLASS (auth)->can_authenticate (auth);
}

/**
 * soup_auth_get_protection_space:
 * @auth: a #SoupAuth
 * @source_uri: the URI of the request that @auth was generated in
 * response to.
 *
 * Returns a list of paths on the server which @auth extends over.
 * (All subdirectories of these paths are also assumed to be part
 * of @auth's protection space, unless otherwise discovered not to
 * be.)
 *
 * Return value: (element-type utf8) (transfer full): the list of
 * paths, which can be freed with soup_auth_free_protection_space().
 **/
GSList *
soup_auth_get_protection_space (SoupAuth *auth, SoupURI *source_uri)
{
	g_return_val_if_fail (SOUP_IS_AUTH (auth), NULL);
	g_return_val_if_fail (source_uri != NULL, NULL);

	return SOUP_AUTH_GET_CLASS (auth)->get_protection_space (auth, source_uri);
}

/**
 * soup_auth_free_protection_space: (skip)
 * @auth: a #SoupAuth
 * @space: the return value from soup_auth_get_protection_space()
 *
 * Frees @space.
 **/
void
soup_auth_free_protection_space (SoupAuth *auth, GSList *space)
{
	g_slist_free_full (space, g_free);
}
