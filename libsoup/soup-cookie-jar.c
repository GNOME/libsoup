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
#include "soup-message.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

/**
 * SECTION:soup-cookie-jar
 * @short_description: 
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

typedef struct {
	GHashTable *domains;
} SoupCookieJarPrivate;
#define SOUP_COOKIE_JAR_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_COOKIE_JAR, SoupCookieJarPrivate))

static void
soup_cookie_jar_init (SoupCookieJar *jar)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

	priv->domains = g_hash_table_new_full (g_str_hash, g_str_equal,
					       g_free, NULL);
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

	object_class->finalize = finalize;
}

static void
soup_cookie_jar_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				      gpointer interface_data)
{
	feature_interface->request_queued = request_queued;
	feature_interface->request_started = request_started;
	feature_interface->request_unqueued = request_unqueued;
}

/**
 * soup_cookie_jar_new:
 *
 * Creates a new #SoupCookieJar.
 *
 * Returns: a new #SoupCookieJar
 **/
SoupCookieJar *
soup_cookie_jar_new (void) 
{
	return g_object_new (SOUP_TYPE_COOKIE_JAR, NULL);
}

/**
 * soup_cookie_jar_save:
 * @jar: a SoupCookieJar
 *
 * Tells @jar to save the state of its (non-session) cookies to some
 * sort of permanent storage.
 **/
void
soup_cookie_jar_save (SoupCookieJar *jar)
{
	if (SOUP_COOKIE_JAR_GET_CLASS (jar)->save)
		SOUP_COOKIE_JAR_GET_CLASS (jar)->save (jar);
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
 **/
char *
soup_cookie_jar_get_cookies (SoupCookieJar *jar, SoupURI *uri,
			     gboolean for_http)
{
	SoupCookieJarPrivate *priv;
	GSList *cookies, *domain_cookies;
	char *domain, *cur, *next, *result;

	g_return_val_if_fail (SOUP_IS_COOKIE_JAR (jar), NULL);
	priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);

	/* The logic here is a little weird, but the plan is that if
	 * uri->host is "www.foo.com", we will end up looking up
	 * cookies for ".www.foo.com", "www.foo.com", ".foo.com", and
	 * ".com", in that order. (Logic stolen from Mozilla.)
	 */
	cookies = NULL;
	domain = cur = g_strdup_printf (".%s", uri->host);
	next = domain + 1;
	do {
		domain_cookies = g_hash_table_lookup (priv->domains, cur);
		while (domain_cookies) {
			SoupCookie *cookie = domain_cookies->data;

			if (soup_cookie_applies_to_uri (cookie, uri) &&
			    (for_http || !cookie->http_only))
				cookies = g_slist_append (cookies, cookie);
			domain_cookies = domain_cookies->next;
		}
		cur = next;
		if (cur)
			next = strchr (cur + 1, '.');
	} while (cur);
	g_free (domain);

	if (cookies) {
		/* FIXME: sort? */
		result = soup_cookies_to_cookie_header (cookies);
		g_slist_free (cookies);
		return result;
	} else
		return NULL;
}

static GSList *
get_cookies_for_domain (SoupCookieJar *jar, const char *domain)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);
	GSList *cookies, *orig_cookies, *c;
	SoupCookie *cookie;

	cookies = g_hash_table_lookup (priv->domains, domain);
	c = orig_cookies = cookies;
	while (c) {
		cookie = c->data;
		c = c->next;
		if (cookie->expires && soup_date_is_past (cookie->expires)) {
			cookies = g_slist_remove (cookies, cookie);
			soup_cookie_free (cookie);
		}
	}

	if (cookies != orig_cookies)
		g_hash_table_insert (priv->domains, g_strdup (domain), cookies);
	return cookies;
}

static void
set_cookie (SoupCookieJar *jar, SoupCookie *cookie)
{
	SoupCookieJarPrivate *priv = SOUP_COOKIE_JAR_GET_PRIVATE (jar);
	GSList *old_cookies, *oc, *prev = NULL;
	SoupCookie *old_cookie;

	old_cookies = get_cookies_for_domain (jar, cookie->domain);
	for (oc = old_cookies; oc; oc = oc->next) {
		old_cookie = oc->data;
		if (!strcmp (cookie->name, old_cookie->name)) {
			/* The new cookie is a replacement for an old
			 * cookie. It might be pre-expired, but we
			 * don't worry about that here;
			 * get_cookies_for_domain() will delete it
			 * later.
			 */
			soup_cookie_free (old_cookie);
			oc->data = cookie;
			return;
		}
		prev = oc;
	}

	/* The new cookie is... a new cookie */
	if (cookie->expires && soup_date_is_past (cookie->expires))
		soup_cookie_free (cookie);
	else if (prev)
		prev = g_slist_append (prev, cookie);
	else {
		old_cookies = g_slist_append (NULL, cookie);
		g_hash_table_insert (priv->domains, g_strdup (cookie->domain),
				     old_cookies);
	}
}

/**
 * soup_cookie_jar_set_cookie:
 * @jar: a #SoupCookieJar
 * @uri: the URI setting the cookie
 * @cookie: the stringified cookie to set
 *
 * Adds @cookie to @jar, exactly as though it had appeared in a
 * Set-Cookie header returned from a request to @uri.
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
		set_cookie (jar, soup_cookie);
		/* set_cookie will steal or free soup_cookie */
	}
}

static void
process_set_cookie_header (SoupMessage *msg, gpointer user_data)
{
	SoupCookieJar *jar = user_data;
	GSList *new_cookies, *nc;

	new_cookies = soup_cookies_from_response (msg);
	for (nc = new_cookies; nc; nc = nc->next)
		set_cookie (jar, nc->data);
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
	soup_message_headers_replace (msg->request_headers,
				      "Cookie", cookies);
	g_free (cookies);
}

static void
request_unqueued (SoupSessionFeature *feature, SoupSession *session,
		  SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, process_set_cookie_header, feature);
}

