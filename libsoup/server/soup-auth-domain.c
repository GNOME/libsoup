/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-auth-domain.c: HTTP Authentication Domain (server-side)
 *
 * Copyright (C) 2007 Novell, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-auth-domain-private.h"
#include "soup-message-headers-private.h"
#include "soup.h"
#include "soup-path-map.h"

/**
 * SoupAuthDomain:
 *
 * Server-side authentication.
 *
 * A [class@AuthDomain] manages authentication for all or part of a
 * [class@Server]. To make a server require authentication, first create
 * an appropriate subclass of [class@AuthDomain], and then add it to the
 * server with [method@Server.add_auth_domain].
 *
 * In order for an auth domain to have any effect, you must add one or more
 * paths to it (via [method@AuthDomain.add_path]). To require authentication for
 * all ordinary requests, add the path `"/"`. (Note that this does not include
 * the special `"*"` URI (eg, "OPTIONS *"), which must be added as a separate
 * path if you want to cover it.)
 *
 * If you need greater control over which requests should and shouldn't be
 * authenticated, add paths covering everything you *might* want authenticated,
 * and then use a filter ([method@AuthDomain.set_filter] to bypass
 * authentication for those requests that don't need it.
 **/

enum {
	PROP_0,

	PROP_REALM,
	PROP_PROXY,
	PROP_FILTER,
	PROP_FILTER_DATA,
	PROP_GENERIC_AUTH_CALLBACK,
	PROP_GENERIC_AUTH_DATA,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

typedef struct {
	char *realm;
	gboolean proxy;
	SoupPathMap *paths;

	SoupAuthDomainFilter filter;
	gpointer filter_data;
	GDestroyNotify filter_dnotify;

	SoupAuthDomainGenericAuthCallback auth_callback;
	gpointer auth_data;
	GDestroyNotify auth_dnotify;

} SoupAuthDomainPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (SoupAuthDomain, soup_auth_domain, G_TYPE_OBJECT)

static void
soup_auth_domain_init (SoupAuthDomain *domain)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	priv->paths = soup_path_map_new (NULL);
}

static void
soup_auth_domain_finalize (GObject *object)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (SOUP_AUTH_DOMAIN (object));

	g_free (priv->realm);
	soup_path_map_free (priv->paths);

	if (priv->filter_dnotify)
		priv->filter_dnotify (priv->filter_data);
	if (priv->auth_dnotify)
		priv->auth_dnotify (priv->auth_data);

	G_OBJECT_CLASS (soup_auth_domain_parent_class)->finalize (object);
}

static void
soup_auth_domain_set_property (GObject *object, guint prop_id,
			       const GValue *value, GParamSpec *pspec)
{
	SoupAuthDomain *auth_domain = SOUP_AUTH_DOMAIN (object);
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (auth_domain);

	switch (prop_id) {
	case PROP_REALM:
		g_free (priv->realm);
		priv->realm = g_value_dup_string (value);
		break;
	case PROP_PROXY:
		priv->proxy = g_value_get_boolean (value);
		break;
	case PROP_FILTER:
		priv->filter = g_value_get_pointer (value);
		break;
	case PROP_FILTER_DATA:
		if (priv->filter_dnotify) {
			priv->filter_dnotify (priv->filter_data);
			priv->filter_dnotify = NULL;
		}
		priv->filter_data = g_value_get_pointer (value);
		break;
	case PROP_GENERIC_AUTH_CALLBACK:
		priv->auth_callback = g_value_get_pointer (value);
		break;
	case PROP_GENERIC_AUTH_DATA:
		if (priv->auth_dnotify) {
			priv->auth_dnotify (priv->auth_data);
			priv->auth_dnotify = NULL;
		}
		priv->auth_data = g_value_get_pointer (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_auth_domain_get_property (GObject *object, guint prop_id,
			       GValue *value, GParamSpec *pspec)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (SOUP_AUTH_DOMAIN (object));

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
	case PROP_GENERIC_AUTH_CALLBACK:
		g_value_set_pointer (value, priv->auth_callback);
		break;
	case PROP_GENERIC_AUTH_DATA:
		g_value_set_pointer (value, priv->auth_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_auth_domain_class_init (SoupAuthDomainClass *auth_domain_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_domain_class);

	object_class->finalize = soup_auth_domain_finalize;
	object_class->set_property = soup_auth_domain_set_property;
	object_class->get_property = soup_auth_domain_get_property;

	/**
	 * SoupAuthDomain:realm: (attributes org.gtk.Property.get=soup_auth_domain_get_realm)
	 *
	 * The realm of this auth domain.
	 */
        properties[PROP_REALM] =
		g_param_spec_string ("realm",
				     "Realm",
				     "The realm of this auth domain",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupAuthDomain:proxy:
	 *
	 * Whether or not this is a proxy auth domain.
	 */
        properties[PROP_PROXY] =
		g_param_spec_boolean ("proxy",
				      "Proxy",
				      "Whether or not this is a proxy auth domain",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				      G_PARAM_STATIC_STRINGS);

	/**
	 * SoupAuthDomain:filter: (type SoupAuthDomainFilter) (attributes org.gtk.Property.set=soup_auth_domain_set_filter)
	 *
	 * The [callback@AuthDomainFilter] for the domain.
	 */
        properties[PROP_FILTER] =
		g_param_spec_pointer ("filter",
				      "Filter",
				      "A filter for deciding whether or not to require authentication",
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS);
	/**
	 * SoupAuthDomain:filter-data:
	 *
	 * Data to pass to the [callback@AuthDomainFilter].
	 **/
        properties[PROP_FILTER_DATA] =
		g_param_spec_pointer ("filter-data",
				      "Filter data",
				      "Data to pass to filter",
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS);
	/**
	 * SoupAuthDomain:generic-auth-callback: (type SoupAuthDomainGenericAuthCallback) (attributes org.gtk.Property.set=soup_auth_domain_set_generic_auth_callback)
	 *
	 * The [callback@AuthDomainGenericAuthCallback].
	 **/
        properties[PROP_GENERIC_AUTH_CALLBACK] =
		g_param_spec_pointer ("generic-auth-callback",
				      "Generic authentication callback",
				      "An authentication callback that can be used with any SoupAuthDomain subclass",
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS);
	/**
	 * SoupAuthDomain:generic-auth-data:
	 *
         * The data to pass to the [callback@AuthDomainGenericAuthCallback].
	 **/
        properties[PROP_GENERIC_AUTH_DATA] =
		g_param_spec_pointer ("generic-auth-data",
				      "Authentication callback data",
				      "Data to pass to auth callback",
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

/**
 * soup_auth_domain_add_path:
 * @domain: a #SoupAuthDomain
 * @path: the path to add to @domain
 *
 * Adds @path to @domain.
 *
 * Requests under @path on @domain's server will require authentication (unless
 * overridden by [method@AuthDomain.remove_path] or
 * [method@AuthDomain.set_filter]).
 **/
void
soup_auth_domain_add_path (SoupAuthDomain *domain, const char *path)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	/* "" should not match "*" */
	if (!*path)
		path = "/";

	soup_path_map_add (priv->paths, path, GINT_TO_POINTER (TRUE));
}

/**
 * soup_auth_domain_remove_path:
 * @domain: a #SoupAuthDomain
 * @path: the path to remove from @domain
 *
 * Removes @path from @domain.
 *
 * Requests under @path on @domain's server will NOT require
 * authentication.
 *
 * This is not simply an undo-er for [method@AuthDomain.add_path]; it
 * can be used to "carve out" a subtree that does not require
 * authentication inside a hierarchy that does. Note also that unlike
 * with [method@AuthDomain.add_path], this cannot be overridden by
 * adding a filter, as filters can only bypass authentication that
 * would otherwise be required, not require it where it would
 * otherwise be unnecessary.
 **/
void
soup_auth_domain_remove_path (SoupAuthDomain *domain, const char *path)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	/* "" should not match "*" */
	if (!*path)
		path = "/";

	soup_path_map_add (priv->paths, path, GINT_TO_POINTER (FALSE));
}

/**
 * SoupAuthDomainFilter:
 * @domain: a #SoupAuthDomain
 * @msg: a #SoupServerMessage
 * @user_data: the data passed to [method@AuthDomain.set_filter]
 *
 * The prototype for a [class@AuthDomain] filter.
 *
 * See [method@AuthDomain.set_filter] for details.
 *
 * Returns: %TRUE if @msg requires authentication, %FALSE if not.
 **/

/**
 * soup_auth_domain_set_filter: (attributes org.gtk.Method.set_property=filter)
 * @domain: a #SoupAuthDomain
 * @filter: the auth filter for @domain
 * @filter_data: data to pass to @filter
 * @dnotify: destroy notifier to free @filter_data when @domain
 *   is destroyed
 *
 * Adds @filter as an authentication filter to @domain.
 *
 * The filter gets a chance to bypass authentication for certain requests that
 * would otherwise require it. Eg, it might check the message's path in some way
 * that is too complicated to do via the other methods, or it might check the
 * message's method, and allow GETs but not PUTs.
 *
 * The filter function returns %TRUE if the request should still
 * require authentication, or %FALSE if authentication is unnecessary
 * for this request.
 *
 * To help prevent security holes, your filter should return %TRUE by
 * default, and only return %FALSE under specifically-tested
 * circumstances, rather than the other way around. Eg, in the example
 * above, where you want to authenticate PUTs but not GETs, you should
 * check if the method is GET and return %FALSE in that case, and then
 * return %TRUE for all other methods (rather than returning %TRUE for
 * PUT and %FALSE for all other methods). This way if it turned out
 * (now or later) that some paths supported additional methods besides
 * GET and PUT, those methods would default to being NOT allowed for
 * unauthenticated users.
 *
 * You can also set the filter by setting the SoupAuthDomain:filter
 * and [property@AuthDomain:filter-data properties], which can also be
 * used to set the filter at construct time.
 **/
void
soup_auth_domain_set_filter (SoupAuthDomain *domain,
			     SoupAuthDomainFilter filter,
			     gpointer        filter_data,
			     GDestroyNotify  dnotify)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	if (priv->filter_dnotify)
		priv->filter_dnotify (priv->filter_data);

	priv->filter = filter;
	priv->filter_data = filter_data;
	priv->filter_dnotify = dnotify;

	g_object_notify_by_pspec (G_OBJECT (domain), properties[PROP_FILTER]);
	g_object_notify_by_pspec (G_OBJECT (domain), properties[PROP_FILTER_DATA]);
}

/**
 * soup_auth_domain_get_realm: (attributes org.gtk.Method.get_property=realm)
 * @domain: a #SoupAuthDomain
 *
 * Gets the realm name associated with @domain.
 *
 * Returns: @domain's realm
 **/
const char *
soup_auth_domain_get_realm (SoupAuthDomain *domain)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	return priv->realm;
}

/**
 * SoupAuthDomainGenericAuthCallback:
 * @domain: a #SoupAuthDomain
 * @msg: the [class@ServerMessage] being authenticated
 * @username: the username from @msg
 * @user_data: the data passed to [method@AuthDomain.set_generic_auth_callback]
 *
 * The prototype for a [class@AuthDomain] generic authentication callback.
 *
 * The callback should look up the user's password, call
 * [method@AuthDomain.check_password], and use the return value from that method
 * as its own return value.
 *
 * In general, for security reasons, it is preferable to use the
 * auth-domain-specific auth callbacks (eg,
 * [callback@AuthDomainBasicAuthCallback] and
 * [callback@AuthDomainDigestAuthCallback]), because they don't require
 * keeping a cleartext password database. Most users will use the same
 * password for many different sites, meaning if any site with a
 * cleartext password database is compromised, accounts on other
 * servers might be compromised as well. For many of the cases where
 * [class@Server] is used, this is not really relevant, but it may still
 * be worth considering.
 *
 * Returns: %TRUE if @msg is authenticated, %FALSE if not.
 **/

/**
 * soup_auth_domain_set_generic_auth_callback: (attributes org.gtk.Method.get_property=generic-auth-callback)
 * @domain: a #SoupAuthDomain
 * @auth_callback: the auth callback
 * @auth_data: data to pass to @auth_callback
 * @dnotify: destroy notifier to free @auth_data when @domain
 *   is destroyed
 *
 * Sets @auth_callback as an authentication-handling callback for @domain.
 *
 * Whenever a request comes in to @domain which cannot be authenticated via a
 * domain-specific auth callback (eg, [callback@AuthDomainDigestAuthCallback]),
 * the generic auth callback will be invoked. See
 * [callback@AuthDomainGenericAuthCallback] for information on what the callback
 * should do.
 **/
void
soup_auth_domain_set_generic_auth_callback (SoupAuthDomain *domain,
					    SoupAuthDomainGenericAuthCallback auth_callback,
					    gpointer        auth_data,
					    GDestroyNotify  dnotify)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	if (priv->auth_dnotify)
		priv->auth_dnotify (priv->auth_data);

	priv->auth_callback = auth_callback;
	priv->auth_data = auth_data;
	priv->auth_dnotify = dnotify;

	g_object_notify_by_pspec (G_OBJECT (domain), properties[PROP_GENERIC_AUTH_CALLBACK]);
	g_object_notify_by_pspec (G_OBJECT (domain), properties[PROP_GENERIC_AUTH_DATA]);
}

gboolean
soup_auth_domain_try_generic_auth_callback (SoupAuthDomain    *domain,
					    SoupServerMessage *msg,
					    const char        *username)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);

	if (priv->auth_callback)
		return priv->auth_callback (domain, msg, username, priv->auth_data);
	else
		return FALSE;
}

/**
 * soup_auth_domain_check_password:
 * @domain: a #SoupAuthDomain
 * @msg: a #SoupServerMessage
 * @username: a username
 * @password: a password
 *
 * Checks if @msg authenticates to @domain via @username and
 * @password.
 *
 * This would normally be called from a
 * [callback@AuthDomainGenericAuthCallback].
 *
 * Returns: whether or not the message is authenticated
 **/
gboolean
soup_auth_domain_check_password (SoupAuthDomain    *domain,
				 SoupServerMessage *msg,
				 const char        *username,
				 const char        *password)
{
	return SOUP_AUTH_DOMAIN_GET_CLASS (domain)->check_password (domain, msg,
								    username,
								    password);
}

/**
 * soup_auth_domain_covers:
 * @domain: a #SoupAuthDomain
 * @msg: a #SoupServerMessage
 *
 * Checks if @domain requires @msg to be authenticated (according to
 * its paths and filter function).
 *
 * This does not actually look at whether @msg *is* authenticated, merely
 * whether or not it needs to be.
 *
 * This is used by [class@Server] internally and is probably of no use to
 * anyone else.
 *
 * Returns: %TRUE if @domain requires @msg to be authenticated
 **/
gboolean
soup_auth_domain_covers (SoupAuthDomain    *domain,
			 SoupServerMessage *msg)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);
	const char *path;

	if (!priv->proxy) {
		path = g_uri_get_path (soup_server_message_get_uri (msg));
		if (!soup_path_map_lookup (priv->paths, path))
			return FALSE;
	}

	if (priv->filter && !priv->filter (domain, msg, priv->filter_data))
		return FALSE;
	else
		return TRUE;
}

/**
 * soup_auth_domain_accepts:
 * @domain: a #SoupAuthDomain
 * @msg: a #SoupServerMessage
 *
 * Checks if @msg contains appropriate authorization for @domain to
 * accept it.
 *
 * Mirroring [method@AuthDomain.covers], this does not check whether or not
 * @domain *cares* if @msg is authorized.
 *
 * This is used by [class@Server] internally and is probably of no use to
 * anyone else.
 *
 * Returns: (nullable): the username that @msg has authenticated
 *   as, if in fact it has authenticated. %NULL otherwise.
 **/
char *
soup_auth_domain_accepts (SoupAuthDomain    *domain,
			  SoupServerMessage *msg)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);
	const char *header;

	header = soup_message_headers_get_one_common (soup_server_message_get_request_headers (msg),
                                                      priv->proxy ?
                                                      SOUP_HEADER_PROXY_AUTHORIZATION :
                                                      SOUP_HEADER_AUTHORIZATION);
	if (!header)
		return NULL;
	return SOUP_AUTH_DOMAIN_GET_CLASS (domain)->accepts (domain, msg, header);
}

/**
 * soup_auth_domain_challenge: (virtual challenge)
 * @domain: a #SoupAuthDomain
 * @msg: a #SoupServerMessage
 *
 * Adds a "WWW-Authenticate" or "Proxy-Authenticate" header to @msg.
 *
 * It requests that the client authenticate, and sets @msg's status accordingly.
 *
 * This is used by [class@Server] internally and is probably of no use to
 * anyone else.
 **/
void
soup_auth_domain_challenge (SoupAuthDomain    *domain,
			    SoupServerMessage *msg)
{
	SoupAuthDomainPrivate *priv = soup_auth_domain_get_instance_private (domain);
	char *challenge;

	challenge = SOUP_AUTH_DOMAIN_GET_CLASS (domain)->challenge (domain, msg);
	soup_server_message_set_status (msg, priv->proxy ?
					SOUP_STATUS_PROXY_UNAUTHORIZED :
					SOUP_STATUS_UNAUTHORIZED,
					NULL);
	soup_message_headers_append_common (soup_server_message_get_response_headers (msg),
                                            priv->proxy ?
                                            SOUP_HEADER_PROXY_AUTHENTICATE :
                                            SOUP_HEADER_WWW_AUTHENTICATE,
                                            challenge);
	g_free (challenge);
}
