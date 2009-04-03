/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cookie-jar.c
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "soup-cookie.h"
#include "soup-cookie-jar.h"
#include "soup-date.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

/**
 * SECTION:soup-cookie-jar
 * @short_description: Automatic cookie handling for #SoupSession
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

static void soup_cookie_jar_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);
static void request_queued (SoupSessionFeature *feature, SoupSession *session,
			    SoupMessage *msg);
static void request_started (SoupSessionFeature *feature, SoupSession *session,
			     SoupMessage *msg, SoupSocket *socket);
static void request_unqueued (SoupSessionFeature *feature, SoupSession *session,
			      SoupMessage *msg);

G_DEFINE_TYPE_WITH_CODE (SoupCookieJar, soup_cookie_jar, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_cookie_jar_session_feature_init))

enum {
	CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_READ_ONLY,

	LAST_PROP
};

typedef struct {
	gboolean constructed, read_only;
	GHashTable *domains;
} SoupCookieJarPrivate;
#define SOUP_COOKIE_JAR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_COOKIE_JAR, SoupCookieJarPrivate))

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_cookie_jar_init (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

	priv->domains = g_hash_table_new_full (g_str_hash, g_str_equal,
					       g_free, NULL);
}

static void
constructed (GObject *object)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (object);

	priv->constructed = TRUE;
}

static void
finalize (GObject *object)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (object);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->domains);
	while (g_hash_table_iter_next (&iter, &key, &value))
		soup_cookies_free (value);
	g_hash_table_destroy (priv->domains);

	G_OBJECT_CLASS (soup_cookie_jar_parent_class)->finalize (object);
}

static void
soup_cookie_jar_class_init (SoupCookieJarClass *jar_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (jar_class);

	g_type_class_add_private (jar_class, sizeof (SoupCookieJarPrivate));

	object_class->constructed = constructed;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/**
	 * SoupCookieJar::changed
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
			      soup_marshal_NONE__BOXED_BOXED,
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
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static void
soup_cookie_jar_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				      gpointer interface_data)
{
	feature_interface->request_queued = request_queued;
	feature_interface->request_started = request_started;
	feature_interface->request_unqueued = request_unqueued;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupCookieJarPrivate *priv =
		SOUP_COOKIE_JAR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_READ_ONLY:
		priv->read_only = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupCookieJarPrivate *priv =
		SOUP_COOKIE_JAR_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_READ_ONLY:
		g_value_set_boolean (value, priv->read_only);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
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

void
soup_cookie_jar_save (SoupCookieJar *jar)
{
	/* Does nothing, obsolete */
}

static void
soup_cookie_jar_changed (SoupCookieJar *jar,
			 SoupCookie *old, SoupCookie *new)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

	if (priv->read_only || !priv->constructed)
		return;

	g_signal_emit (jar, signals[CHANGED], 0, old, new);
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
 * Return value: the cookies, in string form, or %NULL if there are no
 * cookies for @uri.
 *
 * Since: 2.24
 **/
char *
soup_cookie_jar_get_cookies (SoupCookieJar *jar, SoupURI *uri,
			     gboolean for_http)
{
	SoupCookieJarPrivate *priv;
	GSList *cookies, *domain_cookies;
	char *domain, *cur, *next_domain, *result;
	GSList *new_head, *cookies_to_remove = NULL, *p;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);
	priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

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
				   (for_http || !cookie->http_only))
				cookies = g_slist_append (cookies, cookie);

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

	if (cookies) {
		/* FIXME: sort? */
		result = soup_cookies_to_cookie_header (cookies);
		g_slist_free (cookies);
		return result;
	} else
		return NULL;
}

/**
 * soup_cookie_jar_add_cookie:
 * @jar: a #SoupCookieJar
 * @cookie: a #SoupCookie
 *
 * Adds @cookie to @jar, emitting the 'changed' signal if we are modifying
 * an existing cookie or adding a valid new cookie ('valid' means
 * that the cookie's expire date is not in the past).
 *
 * @cookie will be 'stolen' by the jar, so don't free it afterwards.
 *
 * Since: 2.24
 **/
void
soup_cookie_jar_add_cookie (SoupCookieJar *jar, SoupCookie *cookie)
{
	SoupCookieJarPrivate *priv;
	GSList *old_cookies, *oc, *prev = NULL;
	SoupCookie *old_cookie;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (cookie != NULL);

	priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);
	old_cookies = g_hash_table_lookup (priv->domains, cookie->domain);
	for (oc = old_cookies; oc; oc = oc->next) {
		old_cookie = oc->data;
		if (!strcmp (cookie->name, old_cookie->name) &&
		    !g_strcmp0 (cookie->path, old_cookie->path)) {
			if (cookie->expires && soup_date_is_past (cookie->expires)) {
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
		prev = oc;
	}

	/* The new cookie is... a new cookie */
	if (cookie->expires && soup_date_is_past (cookie->expires)) {
		soup_cookie_free (cookie);
		return;
	}

	if (prev)
		prev = g_slist_append (prev, cookie);
	else {
		old_cookies = g_slist_append (NULL, cookie);
		g_hash_table_insert (priv->domains, g_strdup (cookie->domain),
				     old_cookies);
	}

	soup_cookie_jar_changed (jar, NULL, cookie);
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
 * Since: 2.24
 **/
void
soup_cookie_jar_set_cookie (SoupCookieJar *jar, SoupURI *uri,
			    const char *cookie)
{
	SoupCookie *soup_cookie;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (cookie != NULL);

	soup_cookie = soup_cookie_parse (cookie, uri);
	if (soup_cookie) {
		/* will steal or free soup_cookie */
		soup_cookie_jar_add_cookie (jar, soup_cookie);
	}
}

static void
process_set_cookie_header (SoupMessage *msg, gpointer user_data)
{
	SoupCookieJar *jar = user_data;
	GSList *new_cookies, *nc;

	new_cookies = soup_cookies_from_response (msg);
	for (nc = new_cookies; nc; nc = nc->next)
		soup_cookie_jar_add_cookie (jar, nc->data);
	g_slist_free (new_cookies);
}

static void
request_queued (SoupSessionFeature *feature, SoupSession *session,
		SoupMessage *msg)
{
	soup_message_add_header_handler (msg, "got-headers",
					 "Set-Cookie",
					 G_CALLBACK (process_set_cookie_header),
					 feature);
}

static void
request_started (SoupSessionFeature *feature, SoupSession *session,
		 SoupMessage *msg, SoupSocket *socket)
{
	SoupCookieJar *jar = SOUP_COOKIE_JAR (feature);
	char *cookies;

	cookies = soup_cookie_jar_get_cookies (jar, soup_message_get_uri (msg), TRUE);
	if (cookies) {
		soup_message_headers_replace (msg->request_headers,
					      "Cookie", cookies);
		g_free (cookies);
	} else
		soup_message_headers_remove (msg->request_headers, "Cookie");
}

static void
request_unqueued (SoupSessionFeature *feature, SoupSession *session,
		  SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, process_set_cookie_header, feature);
}

/**
 * soup_cookie_jar_all_cookies:
 * @jar: a #SoupCookieJar
 *
 * Constructs a #GSList with every cookie inside the @jar.
 * The cookies in the list are a copy of the original, so
 * you have to free them when you are done with them.
 *
 * Return value: a #GSList with all the cookies in the @jar.
 *
 * Since: 2.24
 **/
GSList *
soup_cookie_jar_all_cookies (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv;
	GHashTableIter iter;
	GSList *l = NULL;
	gpointer key, value;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);

	priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

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
 * Since: 2.24
 **/
void
soup_cookie_jar_delete_cookie (SoupCookieJar *jar,
			       SoupCookie    *cookie)
{
	SoupCookieJarPrivate *priv;
	GSList *cookies, *p;
	char *domain;

	g_return_if_fail (SOUP_IS_COOKIE_JAR (jar));
	g_return_if_fail (cookie != NULL);

	priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

	domain = g_strdup (cookie->domain);

	cookies = g_hash_table_lookup (priv->domains, domain);
	if (cookies == NULL)
		return;

	for (p = cookies; p; p = p->next ) {
		SoupCookie *c = (SoupCookie*)p->data;
		if (soup_cookie_equal (cookie, c)) {
			cookies = g_slist_delete_link (cookies, p);
			g_hash_table_insert (priv->domains,
					     domain,
					     cookies);
			soup_cookie_jar_changed (jar, c, NULL);
			soup_cookie_free (c);
			return;
		}
	}
}
