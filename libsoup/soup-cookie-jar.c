/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar.c
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-cookie-jar.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup.h"

/**
 * SECTION:soup-cookie-jar
 * @short_description: Automatic cookie handling for SoupSession
 *
 * A #SoupCookieJar stores #SoupCookie<!-- -->s and arrange for them
 * to be sent with the appropriate #SoupMessage<!-- -->s.
 * #SoupCookieJar implements #SoupSessionFeature, so you can add a
 * cookie jar to a session with soup_session_add_feature() or
 * soup_session_add_feature_by_type().
 *
 * Note that the base #SoupCookieJar class does not support any form
 * of long-term cookie persistence.
 **/

enum {
	CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_READ_ONLY,
	PROP_ACCEPT_POLICY,

	LAST_PROP
};

typedef struct {
	gboolean constructed, read_only;
	GHashTable *domains, *serials;
	guint serial;
	SoupCookieJarAcceptPolicy accept_policy;
} SoupCookieJarPrivate;

static void soup_cookie_jar_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupCookieJar, soup_cookie_jar, G_TYPE_OBJECT,
                         G_ADD_PRIVATE (SoupCookieJar)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_cookie_jar_session_feature_init))

static void
soup_cookie_jar_init (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv = soup_cookie_jar_get_instance_private (jar);

	priv->domains = g_hash_table_new_full (soup_str_case_hash,
					       soup_str_case_equal,
					       g_free, NULL);
	priv->serials = g_hash_table_new (NULL, NULL);
	priv->accept_policy = SOUP_COOKIE_JAR_ACCEPT_ALWAYS;
}

static void
soup_cookie_jar_constructed (GObject *object)
{
	SoupCookieJarPrivate *priv =
		soup_cookie_jar_get_instance_private (SOUP_COOKIE_JAR (object));

	priv->constructed = TRUE;
}

static void
soup_cookie_jar_finalize (GObject *object)
{
	SoupCookieJarPrivate *priv =
		soup_cookie_jar_get_instance_private (SOUP_COOKIE_JAR (object));
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->domains);
	while (g_hash_table_iter_next (&iter, &key, &value))
		soup_cookies_free (value);
	g_hash_table_destroy (priv->domains);
	g_hash_table_destroy (priv->serials);

	G_OBJECT_CLASS (soup_cookie_jar_parent_class)->finalize (object);
}

static void
soup_cookie_jar_set_property (GObject *object, guint prop_id,
			      const GValue *value, GParamSpec *pspec)
{
	SoupCookieJarPrivate *priv =
		soup_cookie_jar_get_instance_private (SOUP_COOKIE_JAR (object));

	switch (prop_id) {
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	case PROP_ACCEPT_POLICY:
		priv->accept_policy = g_value_get_enum (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_cookie_jar_get_property (GObject *object, guint prop_id,
			      GValue *value, GParamSpec *pspec)
{
	SoupCookieJarPrivate *priv =
		soup_cookie_jar_get_instance_private (SOUP_COOKIE_JAR (object));

	switch (prop_id) {
	case PROP_READ_ONLY:
		g_value_set_boolean (value, priv->read_only);
		break;
	case PROP_ACCEPT_POLICY:
		g_value_set_enum (value, priv->accept_policy);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
soup_cookie_jar_real_is_persistent (SoupCookieJar *jar)
{
	return FALSE;
}

static void
soup_cookie_jar_class_init (SoupCookieJarClass *jar_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (jar_class);

	object_class->constructed = soup_cookie_jar_constructed;
	object_class->finalize = soup_cookie_jar_finalize;
	object_class->set_property = soup_cookie_jar_set_property;
	object_class->get_property = soup_cookie_jar_get_property;

	jar_class->is_persistent = soup_cookie_jar_real_is_persistent;

	/**
	 * SoupCookieJar::changed:
	 * @jar: the #SoupCookieJar
	 * @old_cookie: the old #SoupCookie value
	 * @new_cookie: the new #SoupCookie value
	 *
	 * Emitted when @jar changes. If a cookie has been added,
	 * @new_cookie will contain the newly-added cookie and
	 * @old_cookie will be %NULL. If a cookie has been deleted,
	 * @old_cookie will contain the to-be-deleted cookie and
	 * @new_cookie will be %NULL. If a cookie has been changed,
	 * @old_cookie will contain its old value, and @new_cookie its
	 * new value.
	 **/
	signals[CHANGED] =
		g_signal_new ("changed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupCookieJarClass, changed),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2, 
			      SOUP_TYPE_COOKIE | G_SIGNAL_TYPE_STATIC_SCOPE,
			      SOUP_TYPE_COOKIE | G_SIGNAL_TYPE_STATIC_SCOPE);

	/**
	 * SOUP_COOKIE_JAR_READ_ONLY:
	 *
	 * Alias for the #SoupCookieJar:read-only property. (Whether
	 * or not the cookie jar is read-only.)
	 **/
	g_object_class_install_property (
		object_class, PROP_READ_ONLY,
		g_param_spec_boolean (SOUP_COOKIE_JAR_READ_ONLY,
				      "Read-only",
				      "Whether or not the cookie jar is read-only",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				      G_PARAM_STATIC_STRINGS));

	/**
	 * SOUP_COOKIE_JAR_ACCEPT_POLICY:
	 *
	 * Alias for the #SoupCookieJar:accept-policy property.
	 *
	 * Since: 2.30
	 */
	/**
	 * SoupCookieJar:accept-policy:
	 *
	 * The policy the jar should follow to accept or reject cookies
	 *
	 * Since: 2.30
	 */
	g_object_class_install_property (
		object_class, PROP_ACCEPT_POLICY,
		g_param_spec_enum (SOUP_COOKIE_JAR_ACCEPT_POLICY,
				   "Accept-policy",
				   "The policy the jar should follow to accept or reject cookies",
				   SOUP_TYPE_COOKIE_JAR_ACCEPT_POLICY,
				   SOUP_COOKIE_JAR_ACCEPT_ALWAYS,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
}

/**
 * soup_cookie_jar_new:
 *
 * Creates a new #SoupCookieJar. The base #SoupCookieJar class does
 * not support persistent storage of cookies; use a subclass for that.
 *
 * Returns: a new #SoupCookieJar
 *
 * Since: 2.24
 **/
SoupCookieJar *
soup_cookie_jar_new (void) 
{
	return g_object_new (SOUP_TYPE_COOKIE_JAR, NULL);
}

/**
 * soup_cookie_jar_save:
 * @jar: a #SoupCookieJar
 *
 * This function exists for backward compatibility, but does not do
 * anything any more; cookie jars are saved automatically when they
 * are changed.
 *
 * Since: 2.24
 *
 * Deprecated: This is a no-op.
 */
void
soup_cookie_jar_save (SoupCookieJar *jar)
{
	/* Does nothing, obsolete */
}

static void
soup_cookie_jar_changed (SoupCookieJar *jar,
			 SoupCookie *old, SoupCookie *new)
{
	SoupCookieJarPrivate *priv = soup_cookie_jar_get_instance_private (jar);

	if (old && old != new)
		g_hash_table_remove (priv->serials, old);
	if (new) {
		priv->serial++;
		g_hash_table_insert (priv->serials, new, GUINT_TO_POINTER (priv->serial));
	}

	if (priv->read_only || !priv->constructed)
		return;

	g_signal_emit (jar, signals[CHANGED], 0, old, new);
}

static int
compare_cookies (gconstpointer a, gconstpointer b, gpointer jar)
{
	SoupCookie *ca = (SoupCookie *)a;
	SoupCookie *cb = (SoupCookie *)b;
	SoupCookieJarPrivate *priv = soup_cookie_jar_get_instance_private (jar);
	int alen, blen;
	guint aserial, bserial;

	/* "Cookies with longer path fields are listed before cookies
	 * with shorter path field."
	 */
	alen = ca->path ? strlen (ca->path) : 0;
	blen = cb->path ? strlen (cb->path) : 0;
	if (alen != blen)
		return blen - alen;

	/* "Among cookies that have equal length path fields, cookies
	 * with earlier creation dates are listed before cookies with
	 * later creation dates."
	 */
	aserial = GPOINTER_TO_UINT (g_hash_table_lookup (priv->serials, ca));
	bserial = GPOINTER_TO_UINT (g_hash_table_lookup (priv->serials, cb));
	return aserial - bserial;
}

static gboolean
cookie_is_valid_for_same_site_policy (SoupCookie *cookie,
                                      gboolean    is_safe_method,
                                      SoupURI    *uri,
                                      SoupURI    *top_level,
                                      SoupURI    *cookie_uri,
                                      gboolean    is_top_level_navigation,
                                      gboolean    for_http)
{
	SoupSameSitePolicy policy = soup_cookie_get_same_site_policy (cookie);

	if (policy == SOUP_SAME_SITE_POLICY_NONE)
		return TRUE;

	if (top_level == NULL)
		return TRUE;

	if (policy == SOUP_SAME_SITE_POLICY_LAX && is_top_level_navigation &&
	    (is_safe_method || for_http == FALSE))
		return TRUE;

	if (is_top_level_navigation && cookie_uri == NULL)
		return FALSE;

	return soup_host_matches_host (soup_uri_get_host (cookie_uri ? cookie_uri : top_level), soup_uri_get_host (uri));
}

static GSList *
get_cookies (SoupCookieJar *jar,
             SoupURI       *uri,
             SoupURI       *top_level,
             SoupURI       *site_for_cookies,
             gboolean       is_safe_method,
             gboolean       for_http,
             gboolean       is_top_level_navigation,
             gboolean       copy_cookies)
{
	SoupCookieJarPrivate *priv;
	GSList *cookies, *domain_cookies;
	char *domain, *cur, *next_domain;
	GSList *new_head, *cookies_to_remove = NULL, *p;

	priv = soup_cookie_jar_get_instance_private (jar);

	if (!uri->host || !uri->host[0])
		return NULL;

	/* The logic here is a little weird, but the plan is that if
	 * uri->host is "www.foo.com", we will end up looking up
	 * cookies for ".www.foo.com", "www.foo.com", ".foo.com", and
	 * ".com", in that order. (Logic stolen from Mozilla.)
	 */
	cookies = NULL;
	domain = cur = g_strdup_printf (".%s", uri->host);
	next_domain = domain + 1;
	do {
		new_head = domain_cookies = g_hash_table_lookup (priv->domains, cur);
		while (domain_cookies) {
			GSList *next = domain_cookies->next;
			SoupCookie *cookie = domain_cookies->data;

			if (cookie->expires && soup_date_is_past (cookie->expires)) {
				cookies_to_remove = g_slist_append (cookies_to_remove,
								    cookie);
				new_head = g_slist_delete_link (new_head, domain_cookies);
				g_hash_table_insert (priv->domains,
						     g_strdup (cur),
						     new_head);
			} else if (soup_cookie_applies_to_uri (cookie, uri) &&
			           cookie_is_valid_for_same_site_policy (cookie, is_safe_method, uri, top_level,
				                                         site_for_cookies, is_top_level_navigation,
									 for_http) &&
				   (for_http || !cookie->http_only))
				cookies = g_slist_append (cookies, copy_cookies ? soup_cookie_copy (cookie) : cookie);

			domain_cookies = next;
		}
		cur = next_domain;
		if (cur)
			next_domain = strchr (cur + 1, '.');
	} while (cur);
	g_free (domain);

	for (p = cookies_to_remove; p; p = p->next) {
		SoupCookie *cookie = p->data;

		soup_cookie_jar_changed (jar, cookie, NULL);
		soup_cookie_free (cookie);
	}
	g_slist_free (cookies_to_remove);

	return g_slist_sort_with_data (cookies, compare_cookies, jar);
}

/**
 * soup_cookie_jar_get_cookies:
 * @jar: a #SoupCookieJar
 * @uri: a #SoupURI
 * @for_http: whether or not the return value is being passed directly
 * to an HTTP operation
 *
 * Retrieves (in Cookie-header form) the list of cookies that would
 * be sent with a request to @uri.
 *
 * If @for_http is %TRUE, the return value will include cookies marked
 * "HttpOnly" (that is, cookies that the server wishes to keep hidden
 * from client-side scripting operations such as the JavaScript
 * document.cookies property). Since #SoupCookieJar sets the Cookie
 * header itself when making the actual HTTP request, you should
 * almost certainly be setting @for_http to %FALSE if you are calling
 * this.
 *
 * Return value: (nullable): the cookies, in string form, or %NULL if
 * there are no cookies for @uri.
 *
 * Since: 2.24
 **/
char *
soup_cookie_jar_get_cookies (SoupCookieJar *jar, SoupURI *uri,
			     gboolean for_http)
{
	GSList *cookies;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);
	g_return_val_if_fail (uri != NULL, NULL);

	cookies = get_cookies (jar, uri, NULL, NULL, TRUE, for_http, FALSE, FALSE);

	if (cookies) {
		char *result = soup_cookies_to_cookie_header (cookies);
		g_slist_free (cookies);

		if (!*result) {
			g_free (result);
			result = NULL;
		}
		return result;
	} else
		return NULL;
}

/**
 * soup_cookie_jar_get_cookie_list:
 * @jar: a #SoupCookieJar
 * @uri: a #SoupURI
 * @for_http: whether or not the return value is being passed directly
 * to an HTTP operation
 *
 * Retrieves the list of cookies that would be sent with a request to @uri
 * as a #GSList of #SoupCookie objects.
 *
 * If @for_http is %TRUE, the return value will include cookies marked
 * "HttpOnly" (that is, cookies that the server wishes to keep hidden
 * from client-side scripting operations such as the JavaScript
 * document.cookies property). Since #SoupCookieJar sets the Cookie
 * header itself when making the actual HTTP request, you should
 * almost certainly be setting @for_http to %FALSE if you are calling
 * this.
 *
 * Return value: (transfer full) (element-type Soup.Cookie): a #GSList
 * with the cookies in the @jar that would be sent with a request to @uri.
 *
 * Since: 2.40
 **/
GSList *
soup_cookie_jar_get_cookie_list (SoupCookieJar *jar, SoupURI *uri, gboolean for_http)
{
	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);
	g_return_val_if_fail (uri != NULL, NULL);

	return get_cookies (jar, uri, NULL, NULL, TRUE, for_http, FALSE, TRUE);
}

/**
 * soup_cookie_jar_get_cookie_list_with_same_site_info:
 * @jar: a #SoupCookieJar
 * @uri: a #SoupURI
 * @top_level: (nullable): a #SoupURI for the top level document
 * @site_for_cookies: (nullable): a #SoupURI indicating the origin to get cookies for
 * @for_http: whether or not the return value is being passed directly
 * to an HTTP operation
 * @is_safe_method: if the HTTP method is safe, as defined by RFC 7231, ignored when @for_http is %FALSE
 * @is_top_level_navigation: whether or not the HTTP request is part of
 * top level navigation
 *
 * This is an extended version of soup_cookie_jar_get_cookie_list() that
 * provides more information required to use SameSite cookies. See the
 * [SameSite cookies spec](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00)
 * for more detailed information.
 *
 * Return value: (transfer full) (element-type Soup.Cookie): a #GSList
 * with the cookies in the @jar that would be sent with a request to @uri.
 *
 * Since: 2.70
 */
GSList *
soup_cookie_jar_get_cookie_list_with_same_site_info (SoupCookieJar *jar,
                                                     SoupURI       *uri,
                                                     SoupURI       *top_level,
                                                     SoupURI       *site_for_cookies,
                                                     gboolean       for_http,
                                                     gboolean       is_safe_method,
                                                     gboolean       is_top_level_navigation)
{
	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);
	g_return_val_if_fail (uri != NULL, NULL);

	return get_cookies (jar,  uri, top_level, site_for_cookies, is_safe_method, for_http, is_top_level_navigation, TRUE);
}

static const char *
normalize_cookie_domain (const char *domain)
{
	/* Trim any leading dot if present to transform the cookie
         * domain into a valid hostname.
         */
	if (domain != NULL && domain[0] == '.')
		return domain + 1;
	return domain;
}

static gboolean
incoming_cookie_is_third_party (SoupCookieJar            *jar,
				SoupCookie               *cookie,
				SoupURI                  *first_party,
				SoupCookieJarAcceptPolicy policy)
{
	SoupCookieJarPrivate *priv;
	const char *normalized_cookie_domain;
	const char *cookie_base_domain;
	const char *first_party_base_domain;

	if (policy != SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY &&
	    policy != SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY)
		return FALSE;

	if (first_party == NULL || first_party->host == NULL)
		return TRUE;

	normalized_cookie_domain = normalize_cookie_domain (cookie->domain);
	cookie_base_domain = soup_tld_get_base_domain (normalized_cookie_domain, NULL);
	if (cookie_base_domain == NULL)
		cookie_base_domain = cookie->domain;

	first_party_base_domain = soup_tld_get_base_domain (first_party->host, NULL);
	if (first_party_base_domain == NULL)
		first_party_base_domain = first_party->host;

	if (soup_host_matches_host (cookie_base_domain, first_party_base_domain))
		return FALSE;

	if (policy == SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY)
		return TRUE;

	/* Now we know the cookie's base domain and the first party's base domain
	 * are different, but for SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY
	 * policy we want to grandfather in any domain that's already in the jar.
	 * That is, we never want to block cookies from domains the user has
	 * previously visited directly.
	 */
	priv = soup_cookie_jar_get_instance_private (jar);
	return !g_hash_table_lookup (priv->domains, cookie->domain);
}

/**
 * soup_cookie_jar_add_cookie_full:
 * @jar: a #SoupCookieJar
 * @cookie: (transfer full): a #SoupCookie
 * @uri: (nullable): the URI setting the cookie
 * @first_party: (nullable): the URI for the main document
 *
 * Adds @cookie to @jar, emitting the 'changed' signal if we are modifying
 * an existing cookie or adding a valid new cookie ('valid' means
 * that the cookie's expire date is not in the past).
 *
 * @first_party will be used to reject cookies coming from third party
 * resources in case such a security policy is set in the @jar.
 *
 * @uri will be used to reject setting or overwriting secure cookies
 * from insecure origins. %NULL is treated as secure.
 * 
 * @cookie will be 'stolen' by the jar, so don't free it afterwards.
 *
 * Since: 2.68
 **/
void
soup_cookie_jar_add_cookie_full (SoupCookieJar *jar, SoupCookie *cookie, SoupURI *uri, SoupURI *first_party)
{
	SoupCookieJarPrivate *priv;
	GSList *old_cookies, *oc, *last = NULL;
	SoupCookie *old_cookie;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (cookie != NULL);

	/* Never accept cookies for public domains. */
	if (!g_hostname_is_ip_address (cookie->domain) &&
	    soup_tld_domain_is_public_suffix (cookie->domain)) {
		soup_cookie_free (cookie);
		return;
	}

	priv = soup_cookie_jar_get_instance_private (jar);

        if (first_party != NULL) {
                if (priv->accept_policy == SOUP_COOKIE_JAR_ACCEPT_NEVER ||
                    incoming_cookie_is_third_party (jar, cookie, first_party, priv->accept_policy)) {
                        soup_cookie_free (cookie);
                        return;
                }
        }

	/* Cannot set a secure cookie over http */
	if (uri != NULL && !soup_uri_is_https (uri, NULL) && soup_cookie_get_secure (cookie)) {
		soup_cookie_free (cookie);
		return;
	}

	old_cookies = g_hash_table_lookup (priv->domains, cookie->domain);
	for (oc = old_cookies; oc; oc = oc->next) {
		old_cookie = oc->data;
		if (!strcmp (cookie->name, old_cookie->name) &&
		    !g_strcmp0 (cookie->path, old_cookie->path)) {
			if (soup_cookie_get_secure (oc->data) && uri != NULL && !soup_uri_is_https (uri, NULL)) {
				/* We do not allow overwriting secure cookies from an insecure origin
				 * https://tools.ietf.org/html/draft-ietf-httpbis-cookie-alone-01
				 */
				soup_cookie_free (cookie);
			} else if (cookie->expires && soup_date_is_past (cookie->expires)) {
				/* The new cookie has an expired date,
				 * this is the way the the server has
				 * of telling us that we have to
				 * remove the cookie.
				 */
				old_cookies = g_slist_delete_link (old_cookies, oc);
				g_hash_table_insert (priv->domains,
						     g_strdup (cookie->domain),
						     old_cookies);
				soup_cookie_jar_changed (jar, old_cookie, NULL);
				soup_cookie_free (old_cookie);
				soup_cookie_free (cookie);
			} else {
				oc->data = cookie;
				soup_cookie_jar_changed (jar, old_cookie, cookie);
				soup_cookie_free (old_cookie);
			}

			return;
		}
		last = oc;
	}

	/* The new cookie is... a new cookie */
	if (cookie->expires && soup_date_is_past (cookie->expires)) {
		soup_cookie_free (cookie);
		return;
	}

	if (last)
		last->next = g_slist_append (NULL, cookie);
	else {
		old_cookies = g_slist_append (NULL, cookie);
		g_hash_table_insert (priv->domains, g_strdup (cookie->domain),
				     old_cookies);
	}

	soup_cookie_jar_changed (jar, NULL, cookie);
}

/**
 * soup_cookie_jar_add_cookie:
 * @jar: a #SoupCookieJar
 * @cookie: (transfer full): a #SoupCookie
 *
 * Adds @cookie to @jar, emitting the 'changed' signal if we are modifying
 * an existing cookie or adding a valid new cookie ('valid' means
 * that the cookie's expire date is not in the past).
 *
 * @cookie will be 'stolen' by the jar, so don't free it afterwards.
 *
 * Since: 2.26
 **/
void
soup_cookie_jar_add_cookie (SoupCookieJar *jar, SoupCookie *cookie)
{
	soup_cookie_jar_add_cookie_full (jar, cookie, NULL, NULL);
}

/**
 * soup_cookie_jar_add_cookie_with_first_party:
 * @jar: a #SoupCookieJar
 * @first_party: the URI for the main document
 * @cookie: (transfer full): a #SoupCookie
 *
 * Adds @cookie to @jar, emitting the 'changed' signal if we are modifying
 * an existing cookie or adding a valid new cookie ('valid' means
 * that the cookie's expire date is not in the past).
 *
 * @first_party will be used to reject cookies coming from third party
 * resources in case such a security policy is set in the @jar.
 *
 * @cookie will be 'stolen' by the jar, so don't free it afterwards.
 *
 * For secure cookies to work properly you may want to use
 * soup_cookie_jar_add_cookie_full().
 *
 * Since: 2.40
 **/
void
soup_cookie_jar_add_cookie_with_first_party (SoupCookieJar *jar, SoupURI *first_party, SoupCookie *cookie)
{
	g_return_if_fail (first_party != NULL);

	soup_cookie_jar_add_cookie_full (jar, cookie, NULL, first_party);
}

/**
 * soup_cookie_jar_set_cookie:
 * @jar: a #SoupCookieJar
 * @uri: the URI setting the cookie
 * @cookie: the stringified cookie to set
 *
 * Adds @cookie to @jar, exactly as though it had appeared in a
 * Set-Cookie header returned from a request to @uri.
 *
 * Keep in mind that if the #SoupCookieJarAcceptPolicy set is either
 * %SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY or
 * %SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY you'll need to use
 * soup_cookie_jar_set_cookie_with_first_party(), otherwise the jar
 * will have no way of knowing if the cookie is being set by a third
 * party or not.
 *
 * Since: 2.24
 **/
void
soup_cookie_jar_set_cookie (SoupCookieJar *jar, SoupURI *uri,
			    const char *cookie)
{
	SoupCookie *soup_cookie;
	SoupCookieJarPrivate *priv;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (uri != NULL);
	g_return_if_fail (cookie != NULL);

	if (!uri->host)
		return;

	priv = soup_cookie_jar_get_instance_private (jar);
	if (priv->accept_policy == SOUP_COOKIE_JAR_ACCEPT_NEVER)
		return;

	g_return_if_fail (priv->accept_policy != SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY &&
			  priv->accept_policy != SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY);

	soup_cookie = soup_cookie_parse (cookie, uri);
	if (soup_cookie) {
		/* will steal or free soup_cookie */
		soup_cookie_jar_add_cookie_full (jar, soup_cookie, uri, NULL);
	}
}

/**
 * soup_cookie_jar_set_cookie_with_first_party:
 * @jar: a #SoupCookieJar
 * @uri: the URI setting the cookie
 * @first_party: the URI for the main document
 * @cookie: the stringified cookie to set
 *
 * Adds @cookie to @jar, exactly as though it had appeared in a
 * Set-Cookie header returned from a request to @uri. @first_party
 * will be used to reject cookies coming from third party resources in
 * case such a security policy is set in the @jar.
 *
 * Since: 2.30
 **/
void
soup_cookie_jar_set_cookie_with_first_party (SoupCookieJar *jar,
					     SoupURI *uri,
					     SoupURI *first_party,
					     const char *cookie)
{
	SoupCookie *soup_cookie;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (uri != NULL);
	g_return_if_fail (first_party != NULL);
	g_return_if_fail (cookie != NULL);

	if (!uri->host)
		return;

	soup_cookie = soup_cookie_parse (cookie, uri);
	if (soup_cookie) {
		soup_cookie_jar_add_cookie_full (jar, soup_cookie, uri, first_party);
	}
}

static void
process_set_cookie_header (SoupMessage *msg, gpointer user_data)
{
	SoupCookieJar *jar = user_data;
	SoupCookieJarPrivate *priv = soup_cookie_jar_get_instance_private (jar);
	GSList *new_cookies, *nc;
	SoupURI *first_party, *uri;

	if (priv->accept_policy == SOUP_COOKIE_JAR_ACCEPT_NEVER)
		return;

	new_cookies = soup_cookies_from_response (msg);
	first_party = soup_message_get_first_party (msg);
	uri = soup_message_get_uri (msg);
	for (nc = new_cookies; nc; nc = nc->next) {		
		soup_cookie_jar_add_cookie_full (jar, g_steal_pointer (&nc->data), uri, first_party);
	}
	g_slist_free (new_cookies);
}

static void
msg_starting_cb (SoupMessage *msg, gpointer feature)
{
	SoupCookieJar *jar = SOUP_COOKIE_JAR (feature);
	GSList *cookies;

	cookies = soup_cookie_jar_get_cookie_list_with_same_site_info (jar, soup_message_get_uri (msg),
	                                                               soup_message_get_first_party (msg),
							               soup_message_get_site_for_cookies (msg),
								       TRUE,
							               SOUP_METHOD_IS_SAFE (msg->method),
							               soup_message_get_is_top_level_navigation (msg));
	if (cookies != NULL) {
		char *cookie_header = soup_cookies_to_cookie_header (cookies);
		soup_message_headers_replace (msg->request_headers, "Cookie", cookie_header);
		g_free (cookie_header);
		g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
	} else {
		soup_message_headers_remove (msg->request_headers, "Cookie");
	}
}

static void
soup_cookie_jar_request_queued (SoupSessionFeature *feature,
				SoupSession *session,
				SoupMessage *msg)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (msg_starting_cb),
			  feature);

	soup_message_add_header_handler (msg, "got-headers",
					 "Set-Cookie",
					 G_CALLBACK (process_set_cookie_header),
					 feature);
        soup_message_add_status_code_handler (msg, "got-informational",
                                              SOUP_STATUS_SWITCHING_PROTOCOLS,
                                              G_CALLBACK (process_set_cookie_header),
                                              feature);
}

static void
soup_cookie_jar_request_unqueued (SoupSessionFeature *feature,
				  SoupSession *session,
				  SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, process_set_cookie_header, feature);
}

static void
soup_cookie_jar_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				      gpointer interface_data)
{
	feature_interface->request_queued = soup_cookie_jar_request_queued;
	feature_interface->request_unqueued = soup_cookie_jar_request_unqueued;
}

/**
 * soup_cookie_jar_all_cookies:
 * @jar: a #SoupCookieJar
 *
 * Constructs a #GSList with every cookie inside the @jar.
 * The cookies in the list are a copy of the original, so
 * you have to free them when you are done with them.
 *
 * Return value: (transfer full) (element-type Soup.Cookie): a #GSList
 * with all the cookies in the @jar.
 *
 * Since: 2.26
 **/
GSList *
soup_cookie_jar_all_cookies (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv;
	GHashTableIter iter;
	GSList *l = NULL;
	gpointer key, value;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);

	priv = soup_cookie_jar_get_instance_private (jar);

	g_hash_table_iter_init (&iter, priv->domains);

	while (g_hash_table_iter_next (&iter, &key, &value)) {
		GSList *p, *cookies = value;
		for (p = cookies; p; p = p->next)
			l = g_slist_prepend (l, soup_cookie_copy (p->data));
	}

	return l;
}

/**
 * soup_cookie_jar_delete_cookie:
 * @jar: a #SoupCookieJar
 * @cookie: a #SoupCookie
 *
 * Deletes @cookie from @jar, emitting the 'changed' signal.
 *
 * Since: 2.26
 **/
void
soup_cookie_jar_delete_cookie (SoupCookieJar *jar,
			       SoupCookie    *cookie)
{
	SoupCookieJarPrivate *priv;
	GSList *cookies, *p;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (cookie != NULL);

	priv = soup_cookie_jar_get_instance_private (jar);

	cookies = g_hash_table_lookup (priv->domains, cookie->domain);
	if (cookies == NULL)
		return;

	for (p = cookies; p; p = p->next ) {
		SoupCookie *c = (SoupCookie*)p->data;
		if (soup_cookie_equal (cookie, c)) {
			cookies = g_slist_delete_link (cookies, p);
			g_hash_table_insert (priv->domains,
					     g_strdup (cookie->domain),
					     cookies);
			soup_cookie_jar_changed (jar, c, NULL);
			soup_cookie_free (c);
			return;
		}
	}
}

/**
 * SoupCookieJarAcceptPolicy:
 * @SOUP_COOKIE_JAR_ACCEPT_ALWAYS: accept all cookies unconditionally.
 * @SOUP_COOKIE_JAR_ACCEPT_NEVER: reject all cookies unconditionally.
 * @SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY: accept all cookies set by
 * the main document loaded in the application using libsoup. An
 * example of the most common case, web browsers, would be: If
 * http://www.example.com is the page loaded, accept all cookies set
 * by example.com, but if a resource from http://www.third-party.com
 * is loaded from that page reject any cookie that it could try to
 * set. For libsoup to be able to tell apart first party cookies from
 * the rest, the application must call soup_message_set_first_party()
 * on each outgoing #SoupMessage, setting the #SoupURI of the main
 * document. If no first party is set in a message when this policy is
 * in effect, cookies will be assumed to be third party by default.
 * @SOUP_COOKIE_JAR_ACCEPT_GRANDFATHERED_THIRD_PARTY: accept all cookies
 * set by the main document loaded in the application using libsoup, and
 * from domains that have previously set at least one cookie when loaded
 * as the main document. An example of the most common case, web browsers,
 * would be: if http://www.example.com is the page loaded, accept all
 * cookies set by example.com, but if a resource from http://www.third-party.com
 * is loaded from that page, reject any cookie that it could try to
 * set unless it already has a cookie in the cookie jar. For libsoup to
 * be able to tell apart first party cookies from the rest, the
 * application must call soup_message_set_first_party() on each outgoing
 * #SoupMessage, setting the #SoupURI of the main document. If no first
 * party is set in a message when this policy is in effect, cookies will
 * be assumed to be third party by default. Since 2.72.
 *
 * The policy for accepting or rejecting cookies returned in
 * responses.
 *
 * Since: 2.30
 */

/**
 * soup_cookie_jar_get_accept_policy:
 * @jar: a #SoupCookieJar
 *
 * Gets @jar's #SoupCookieJarAcceptPolicy
 *
 * Returns: the #SoupCookieJarAcceptPolicy set in the @jar
 *
 * Since: 2.30
 **/
SoupCookieJarAcceptPolicy
soup_cookie_jar_get_accept_policy (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), SOUP_COOKIE_JAR_ACCEPT_ALWAYS);

	priv = soup_cookie_jar_get_instance_private (jar);
	return priv->accept_policy;
}

/**
 * soup_cookie_jar_set_accept_policy:
 * @jar: a #SoupCookieJar
 * @policy: a #SoupCookieJarAcceptPolicy
 * 
 * Sets @policy as the cookie acceptance policy for @jar.
 *
 * Since: 2.30
 **/
void
soup_cookie_jar_set_accept_policy (SoupCookieJar *jar,
				   SoupCookieJarAcceptPolicy policy)
{
	SoupCookieJarPrivate *priv;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));

	priv = soup_cookie_jar_get_instance_private (jar);

	if (priv->accept_policy != policy) {
		priv->accept_policy = policy;
		g_object_notify (G_OBJECT (jar), SOUP_COOKIE_JAR_ACCEPT_POLICY);
	}
}

/**
 * soup_cookie_jar_is_persistent:
 * @jar: a #SoupCookieJar
 *
 * Gets whether @jar stores cookies persistenly.
 *
 * Returns: %TRUE if @jar storage is persistent or %FALSE otherwise.
 *
 * Since: 2.40
 **/
gboolean
soup_cookie_jar_is_persistent (SoupCookieJar *jar)
{
	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), FALSE);

	return SOUP_COOKIE_JAR_GET_CLASS (jar)->is_persistent (jar);
}
