/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-cookie.c
 *
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-cookie.h"
#include "soup-date-utils-private.h"
#include "soup-message-headers-private.h"
#include "soup-misc.h"
#include "soup-uri-utils-private.h"
#include "soup.h"

/**
 * SoupCookie:
 *
 * Implements HTTP cookies, as described by
 * [RFC 6265](http://tools.ietf.org/html/rfc6265.txt).
 *
 * To have a [class@Session] handle cookies for your appliction
 * automatically, use a [class@CookieJar].
 *
 * @name and @value will be set for all cookies. If the cookie is
 * generated from a string that appears to have no name, then @name
 * will be the empty string.
 *
 * @domain and @path give the host or domain, and path within that
 * host/domain, to restrict this cookie to. If @domain starts with
 * ".", that indicates a domain (which matches the string after the
 * ".", or any hostname that has @domain as a suffix). Otherwise, it
 * is a hostname and must match exactly.
 *
 * @expires will be non-%NULL if the cookie uses either the original
 * "expires" attribute, or the newer "max-age" attribute. If @expires
 * is %NULL, it indicates that neither "expires" nor "max-age" was
 * specified, and the cookie expires at the end of the session.
 * 
 * If @http_only is set, the cookie should not be exposed to untrusted
 * code (eg, javascript), so as to minimize the danger posed by
 * cross-site scripting attacks.
 **/

struct _SoupCookie {
	char      *name;
	char      *value;
	char      *domain;
	char      *path;
	GDateTime *expires;
	gboolean   secure;
	gboolean   http_only;
	SoupSameSitePolicy same_site_policy;
};

G_DEFINE_BOXED_TYPE (SoupCookie, soup_cookie, soup_cookie_copy, soup_cookie_free)

/**
 * soup_cookie_copy:
 * @cookie: a #SoupCookie
 *
 * Copies @cookie.
 *
 * Returns: a copy of @cookie
 **/
SoupCookie *
soup_cookie_copy (SoupCookie *cookie)
{
	SoupCookie *copy = g_slice_new0 (SoupCookie);

	copy->name = g_strdup (cookie->name);
	copy->value = g_strdup (cookie->value);
	copy->domain = g_strdup (cookie->domain);
	copy->path = g_strdup (cookie->path);
	if (cookie->expires)
		copy->expires = g_date_time_ref (cookie->expires);
	copy->secure = cookie->secure;
	copy->http_only = cookie->http_only;
	copy->same_site_policy = cookie->same_site_policy;

	return copy;
}

/**
 * soup_cookie_domain_matches:
 * @cookie: a #SoupCookie
 * @host: a URI
 *
 * Checks if the @cookie's domain and @host match.
 *
 * The domains match if @cookie should be sent when making a request to @host,
 * or that @cookie should be accepted when receiving a response from @host.
 * 
 * Returns: %TRUE if the domains match, %FALSE otherwise
 **/
gboolean
soup_cookie_domain_matches (SoupCookie *cookie, const char *host)
{
	g_return_val_if_fail (cookie != NULL, FALSE);
	g_return_val_if_fail (host != NULL, FALSE);

	return soup_host_matches_host (cookie->domain, host);
}

static inline gboolean
is_white_space (char c)
{
	return (c == ' ' || c == '\t');
}

static inline const char *
skip_lws (const char *s)
{
	while (is_white_space (*s))
		s++;
	return s;
}

static inline const char *
unskip_lws (const char *s, const char *start)
{
	while (s > start && is_white_space (*(s - 1)))
		s--;
	return s;
}

#define is_attr_ender(ch) ((ch) == '\0' || (ch) == ';' || (ch) == ',' || (ch) == '=')
#define is_value_ender(ch) ((ch) == '\0' || (ch) == ';')

static char *
parse_value (const char **val_p, gboolean copy)
{
	const char *start, *end, *p;
	char *value;

	p = *val_p;
	if (*p == '=')
		p++;
	start = skip_lws (p);
	for (p = start; !is_value_ender (*p); p++)
		;
	end = unskip_lws (p, start);

	if (copy)
		value = g_strndup (start, end - start);
	else
		value = NULL;

	*val_p = p;
	return value;
}

static GDateTime *
parse_date (const char **val_p)
{
	char *value;
	GDateTime *date;

	value = parse_value (val_p, TRUE);
	date = soup_date_time_new_from_http_string (value);
	g_free (value);
	return date;
}

#define MAX_AGE_CAP_IN_SECONDS 31536000  // 1 year
#define MAX_ATTRIBUTE_SIZE 1024

static SoupCookie *
parse_one_cookie (const char *header, GUri *origin)
{
	const char *start, *end, *p;
	gboolean has_value;
	SoupCookie *cookie;

	cookie = g_slice_new0 (SoupCookie);
	soup_cookie_set_same_site_policy (cookie, SOUP_SAME_SITE_POLICY_LAX);

	/* Parse the NAME */
	start = skip_lws (header);
	for (p = start; !is_attr_ender (*p); p++)
		;
	if (*p == '=') {
		end = unskip_lws (p, start);
		cookie->name = g_strndup (start, end - start);
	} else {
		/* No NAME; Set cookie->name to "" and then rewind to
		 * re-parse the string as a VALUE.
		 */
		cookie->name = g_strdup ("");
		p = start;
	}

	/* Parse the VALUE */
	cookie->value = parse_value (&p, TRUE);

        if (!*cookie->name && !*cookie->value) {
            soup_cookie_free (cookie);
            return NULL;
        }

	if (strlen (cookie->name) + strlen (cookie->value) > 4096) {
		soup_cookie_free (cookie);
		return NULL;
	}

	/* Parse attributes */
	while (*p == ';') {
		start = skip_lws (p + 1);
		for (p = start; !is_attr_ender (*p); p++)
			;
		end = unskip_lws (p, start);

		has_value = (*p == '=');
#define MATCH_NAME(name) ((end - start == strlen (name)) && !g_ascii_strncasecmp (start, name, end - start))

		if (MATCH_NAME ("domain") && has_value) {
                        char *new_domain = parse_value (&p, TRUE);
                        if (strlen (new_domain) > MAX_ATTRIBUTE_SIZE) {
                            g_free (new_domain);
                            continue;
                        }
			g_free (cookie->domain);
			cookie->domain = g_steal_pointer (&new_domain);
			if (!*cookie->domain) {
				g_free (cookie->domain);
				cookie->domain = NULL;
			}
		} else if (MATCH_NAME ("expires") && has_value) {
			g_clear_pointer (&cookie->expires, g_date_time_unref);
			cookie->expires = parse_date (&p);
		} else if (MATCH_NAME ("httponly")) {
			cookie->http_only = TRUE;
			if (has_value)
				parse_value (&p, FALSE);
		} else if (MATCH_NAME ("max-age") && has_value) {
			char *max_age_str = parse_value (&p, TRUE), *mae;
                        if (strlen (max_age_str) > MAX_ATTRIBUTE_SIZE) {
                            g_free (max_age_str);
                            continue;
                        }
			long max_age = strtol (max_age_str, &mae, 10);
			if (!*mae) {
				if (max_age < 0)
					max_age = 0;
				if (max_age > MAX_AGE_CAP_IN_SECONDS)
					max_age = MAX_AGE_CAP_IN_SECONDS;
				soup_cookie_set_max_age (cookie, max_age);
			}
			g_free (max_age_str);
		} else if (MATCH_NAME ("path") && has_value) {
                        char *new_path = parse_value (&p, TRUE);
                        if (strlen (new_path) > MAX_ATTRIBUTE_SIZE) {
                            g_free (new_path);
                            continue;
                        }
			g_free (cookie->path);
			cookie->path = g_steal_pointer (&new_path);
			if (*cookie->path != '/') {
				g_free (cookie->path);
				cookie->path = NULL;
			}
		} else if (MATCH_NAME ("secure")) {
			cookie->secure = TRUE;
			if (has_value)
				parse_value (&p, FALSE);
		} else if (MATCH_NAME ("samesite")) {
			if (has_value) {
				char *policy = parse_value (&p, TRUE);
				if (g_ascii_strcasecmp (policy, "None") == 0)
					soup_cookie_set_same_site_policy (cookie, SOUP_SAME_SITE_POLICY_NONE);
				else if (g_ascii_strcasecmp (policy, "Strict") == 0)
					soup_cookie_set_same_site_policy (cookie, SOUP_SAME_SITE_POLICY_STRICT);
				/* There is an explicit "Lax" value which is the default */
				g_free (policy);
			}
			/* Note that earlier versions of the same-site RFC treated invalid values as strict but
			   the latest revision assigns invalid SameSite values to Lax. */
		} else {
			/* Ignore unknown attributes, but we still have
			 * to skip over the value.
			 */
			if (has_value)
				parse_value (&p, FALSE);
		}
	}

	if (cookie->domain) {
		/* Domain must have at least one '.' (not counting an
		 * initial one. (We check this now, rather than
		 * bailing out sooner, because we don't want to force
		 * any cookies after this one in the Set-Cookie header
		 * to be discarded.)
		 */
		if (!strchr (cookie->domain + 1, '.')) {
			soup_cookie_free (cookie);
			return NULL;
		}

		/* If the domain string isn't an IP addr, and doesn't
		 * start with a '.', prepend one.
		 */
		if (!g_hostname_is_ip_address (cookie->domain) &&
		    cookie->domain[0] != '.') {
			char *tmp = g_strdup_printf (".%s", cookie->domain);
			g_free (cookie->domain);
			cookie->domain = tmp;
		}
	}

	if (origin) {
		/* Sanity-check domain */
		if (cookie->domain) {
			if (!soup_cookie_domain_matches (cookie, g_uri_get_host (origin))) {
				soup_cookie_free (cookie);
				return NULL;
			}
		} else
			cookie->domain = g_strdup (g_uri_get_host (origin));

		/* The original cookie spec didn't say that pages
		 * could only set cookies for paths they were under.
		 * RFC 2109 adds that requirement, but some sites
		 * depend on the old behavior
		 * (https://bugzilla.mozilla.org/show_bug.cgi?id=156725#c20).
		 * So we don't check the path.
		 */

		if (!cookie->path) {
                        GUri *normalized_origin = soup_uri_copy_with_normalized_flags (origin);
			char *slash;
                        const char *origin_path = g_uri_get_path (normalized_origin);

			slash = strrchr (origin_path, '/');
			if (!slash || slash == origin_path)
				cookie->path = g_strdup ("/");
			else {
				cookie->path = g_strndup (origin_path,
							  slash - origin_path);
			}

                        g_uri_unref (normalized_origin);
		}

	} else if (!cookie->path) {
		cookie->path = g_strdup ("/");
	}

	return cookie;
}

static SoupCookie *
cookie_new_internal (const char *name, const char *value,
		     const char *domain, const char *path,
		     int max_age)
{
	SoupCookie *cookie;

	cookie = g_slice_new0 (SoupCookie);
	cookie->name = g_strdup (name);
	cookie->value = g_strdup (value);
	cookie->domain = g_strdup (domain);
	cookie->path = g_strdup (path);
	soup_cookie_set_max_age (cookie, max_age);
	cookie->same_site_policy = SOUP_SAME_SITE_POLICY_LAX;

	return cookie;
}

/**
 * soup_cookie_new:
 * @name: cookie name
 * @value: cookie value
 * @domain: cookie domain or hostname
 * @path: cookie path, or %NULL
 * @max_age: max age of the cookie, or -1 for a session cookie
 *
 * Creates a new [struct@Cookie] with the given attributes.
 *
 * Use [method@Cookie.set_secure] and [method@Cookie.set_http_only] if you
 * need to set those attributes on the returned cookie.
 *
 * If @domain starts with ".", that indicates a domain (which matches
 * the string after the ".", or any hostname that has @domain as a
 * suffix). Otherwise, it is a hostname and must match exactly.
 *
 * @max_age is used to set the "expires" attribute on the cookie; pass
 * -1 to not include the attribute (indicating that the cookie expires
 * with the current session), 0 for an already-expired cookie, or a
 * lifetime in seconds. You can use the constants
 * %SOUP_COOKIE_MAX_AGE_ONE_HOUR, %SOUP_COOKIE_MAX_AGE_ONE_DAY,
 * %SOUP_COOKIE_MAX_AGE_ONE_WEEK and %SOUP_COOKIE_MAX_AGE_ONE_YEAR (or
 * multiples thereof) to calculate this value. (If you really care
 * about setting the exact time that the cookie will expire, use
 * [method@Cookie.set_expires].)
 *
 * As of version 3.4.0 the default value of a cookie's same-site-policy
 * is %SOUP_SAME_SITE_POLICY_LAX.
 *
 * Returns: a new #SoupCookie.
 **/
SoupCookie *
soup_cookie_new (const char *name, const char *value,
		 const char *domain, const char *path,
		 int max_age)
{
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	/* We ought to return if domain is NULL too, but this used to
	 * do be incorrectly documented as legal, and it wouldn't
	 * break anything as long as you called
	 * soup_cookie_set_domain() immediately after. So we warn but
	 * don't return, to discourage that behavior but not actually
	 * break anyone doing it.
	 */
	g_warn_if_fail (domain != NULL);

	return cookie_new_internal (name, value, domain, path, max_age);
}

/**
 * soup_cookie_parse:
 * @header: a cookie string (eg, the value of a Set-Cookie header)
 * @origin: (nullable): origin of the cookie
 *
 * Parses @header and returns a [struct@Cookie].
 *
 * If @header contains multiple cookies, only the first one will be parsed.
 *
 * If @header does not have "path" or "domain" attributes, they will
 * be defaulted from @origin. If @origin is %NULL, path will default
 * to "/", but domain will be left as %NULL. Note that this is not a
 * valid state for a [struct@Cookie], and you will need to fill in some
 * appropriate string for the domain if you want to actually make use
 * of the cookie.
 *
 * As of version 3.4.0 the default value of a cookie's same-site-policy
 * is %SOUP_SAME_SITE_POLICY_LAX.
 *
 * Returns: (nullable): a new #SoupCookie, or %NULL if it could
 *   not be parsed, or contained an illegal "domain" attribute for a
 *   cookie originating from @origin.
 **/
SoupCookie *
soup_cookie_parse (const char *cookie, GUri *origin)
{
        g_return_val_if_fail (cookie != NULL, NULL);
        g_return_val_if_fail (origin == NULL || g_uri_get_host (origin) != NULL, NULL);

	return parse_one_cookie (cookie, origin);
}

/**
 * soup_cookie_get_name:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's name.
 *
 * Returns: @cookie's name
 **/
const char *
soup_cookie_get_name (SoupCookie *cookie)
{
	return cookie->name;
}

/**
 * soup_cookie_set_name:
 * @cookie: a #SoupCookie
 * @name: the new name
 *
 * Sets @cookie's name to @name.
 **/
void
soup_cookie_set_name (SoupCookie *cookie, const char *name)
{
	g_free (cookie->name);
	cookie->name = g_strdup (name);
}

/**
 * soup_cookie_get_value:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's value.
 *
 * Returns: @cookie's value
 **/
const char *
soup_cookie_get_value (SoupCookie *cookie)
{
	return cookie->value;
}

/**
 * soup_cookie_set_value:
 * @cookie: a #SoupCookie
 * @value: the new value
 *
 * Sets @cookie's value to @value.
 **/
void
soup_cookie_set_value (SoupCookie *cookie, const char *value)
{
	g_free (cookie->value);
	cookie->value = g_strdup (value);
}

/**
 * soup_cookie_get_domain:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's domain.
 *
 * Returns: @cookie's domain
 **/
const char *
soup_cookie_get_domain (SoupCookie *cookie)
{
	return cookie->domain;
}

/**
 * soup_cookie_set_domain:
 * @cookie: a #SoupCookie
 * @domain: the new domain
 *
 * Sets @cookie's domain to @domain.
 **/
void
soup_cookie_set_domain (SoupCookie *cookie, const char *domain)
{
	g_free (cookie->domain);
	cookie->domain = g_strdup (domain);
}

/**
 * soup_cookie_get_path:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's path.
 *
 * Returns: @cookie's path
 **/
const char *
soup_cookie_get_path (SoupCookie *cookie)
{
	return cookie->path;
}

/**
 * soup_cookie_set_path:
 * @cookie: a #SoupCookie
 * @path: the new path
 *
 * Sets @cookie's path to @path.
 **/
void
soup_cookie_set_path (SoupCookie *cookie, const char *path)
{
	g_free (cookie->path);
	cookie->path = g_strdup (path);
}

/**
 * soup_cookie_set_max_age:
 * @cookie: a #SoupCookie
 * @max_age: the new max age
 *
 * Sets @cookie's max age to @max_age.
 *
 * If @max_age is -1, the cookie is a session cookie, and will expire at the end
 * of the client's session. Otherwise, it is the number of seconds until the
 * cookie expires. You can use the constants %SOUP_COOKIE_MAX_AGE_ONE_HOUR,
 * %SOUP_COOKIE_MAX_AGE_ONE_DAY, %SOUP_COOKIE_MAX_AGE_ONE_WEEK and
 * %SOUP_COOKIE_MAX_AGE_ONE_YEAR (or multiples thereof) to calculate this value.
 * (A value of 0 indicates that the cookie should be considered
 * already-expired.)
 *
 * This sets the same property as [method@Cookie.set_expires].
 **/
void
soup_cookie_set_max_age (SoupCookie *cookie, int max_age)
{
	if (cookie->expires)
		g_date_time_unref (cookie->expires);

	if (max_age == -1)
		cookie->expires = NULL;
	else if (max_age == 0) {
		/* Use a date way in the past, to protect against
		 * clock skew.
		 */
		cookie->expires = g_date_time_new_from_unix_utc (0);
	} else {
                GDateTime *now = g_date_time_new_now_utc ();
                cookie->expires = g_date_time_add_seconds (now, max_age);
                g_date_time_unref (now);
        }
}

/**
 * SOUP_COOKIE_MAX_AGE_ONE_HOUR:
 *
 * A constant corresponding to 1 hour.
 *
 * For use with [ctor@Cookie.new] and [method@Cookie.set_max_age].
 **/
/**
 * SOUP_COOKIE_MAX_AGE_ONE_DAY:
 *
 * A constant corresponding to 1 day.
 *
 * For use with [ctor@Cookie.new] and [method@Cookie.set_max_age].
 **/
/**
 * SOUP_COOKIE_MAX_AGE_ONE_WEEK:
 *
 * A constant corresponding to 1 week.
 *
 * For use with [ctor@Cookie.new] and [method@Cookie.set_max_age].
 **/
/**
 * SOUP_COOKIE_MAX_AGE_ONE_YEAR:
 *
 * A constant corresponding to 1 year.
 *
 * For use with [ctor@Cookie.new] and [method@Cookie.set_max_age].
 **/

/**
 * soup_cookie_get_expires:
 * @cookie: a #GDateTime
 *
 * Gets @cookie's expiration time.
 *
 * Returns: (nullable) (transfer none): @cookie's expiration time, which is
 *   owned by @cookie and should not be modified or freed.
 **/
GDateTime *
soup_cookie_get_expires (SoupCookie *cookie)
{
	return cookie->expires;
}

/**
 * soup_cookie_set_expires:
 * @cookie: a #SoupCookie
 * @expires: the new expiration time, or %NULL
 *
 * Sets @cookie's expiration time to @expires.
 *
 * If @expires is %NULL, @cookie will be a session cookie and will expire at the
 * end of the client's session.
 *
 * (This sets the same property as [method@Cookie.set_max_age].)
 **/
void
soup_cookie_set_expires (SoupCookie *cookie, GDateTime *expires)
{
	if (cookie->expires)
		g_date_time_unref (cookie->expires);

	if (expires)
		cookie->expires = g_date_time_ref (expires);
	else
		cookie->expires = NULL;
}

/**
 * soup_cookie_get_secure:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's secure attribute.
 *
 * Returns: @cookie's secure attribute
 **/
gboolean
soup_cookie_get_secure (SoupCookie *cookie)
{
	return cookie->secure;
}

/**
 * soup_cookie_set_secure:
 * @cookie: a #SoupCookie
 * @secure: the new value for the secure attribute
 *
 * Sets @cookie's secure attribute to @secure.
 *
 * If %TRUE, @cookie will only be transmitted from the client to the server over
 * secure (https) connections.
 **/
void
soup_cookie_set_secure (SoupCookie *cookie, gboolean secure)
{
	cookie->secure = secure;
}

/**
 * soup_cookie_get_http_only:
 * @cookie: a #SoupCookie
 *
 * Gets @cookie's HttpOnly attribute.
 *
 * Returns: @cookie's HttpOnly attribute
 **/
gboolean
soup_cookie_get_http_only (SoupCookie *cookie)
{
	return cookie->http_only;
}

/**
 * soup_cookie_set_http_only:
 * @cookie: a #SoupCookie
 * @http_only: the new value for the HttpOnly attribute
 *
 * Sets @cookie's HttpOnly attribute to @http_only.
 *
 * If %TRUE, @cookie will be marked as "http only", meaning it should not be
 * exposed to web page scripts or other untrusted code.
 **/
void
soup_cookie_set_http_only (SoupCookie *cookie, gboolean http_only)
{
	cookie->http_only = http_only;
}

static void
serialize_cookie (SoupCookie *cookie, GString *header, gboolean set_cookie)
{
	SoupSameSitePolicy same_site_policy;

	if (!*cookie->name && !*cookie->value)
		return;

	if (header->len) {
		if (set_cookie)
			g_string_append (header, ", ");
		else
			g_string_append (header, "; ");
	}

	if (set_cookie || *cookie->name) {
		g_string_append (header, cookie->name);
		g_string_append (header, "=");
	}
	g_string_append (header, cookie->value);
	if (!set_cookie)
		return;

	if (cookie->expires) {
		char *timestamp;
		timestamp = soup_date_time_to_string (cookie->expires,
						      SOUP_DATE_COOKIE);
                if (timestamp) {
                        g_string_append (header, "; expires=");
                        g_string_append (header, timestamp);
                        g_free (timestamp);
                }
	}
	if (cookie->path) {
		g_string_append (header, "; path=");
		g_string_append (header, cookie->path);
	}
	if (cookie->domain) {
		g_string_append (header, "; domain=");
		g_string_append (header, cookie->domain);
	}

	same_site_policy = soup_cookie_get_same_site_policy (cookie);
	if (same_site_policy != SOUP_SAME_SITE_POLICY_NONE) {
		g_string_append (header, "; SameSite=");
		if (same_site_policy == SOUP_SAME_SITE_POLICY_LAX)
			g_string_append (header, "Lax");
		else
			g_string_append (header, "Strict");
	}
	if (cookie->secure)
		g_string_append (header, "; secure");
	if (cookie->http_only)
		g_string_append (header, "; HttpOnly");
}

/**
 * soup_cookie_set_same_site_policy:
 * @cookie: a #SoupCookie
 * @policy: a #SoupSameSitePolicy
 *
 * When used in conjunction with
 * [method@CookieJar.get_cookie_list_with_same_site_info] this sets the policy
 * of when this cookie should be exposed.
 **/
void
soup_cookie_set_same_site_policy (SoupCookie         *cookie,
                                  SoupSameSitePolicy  policy)
{
	switch (policy) {
	case SOUP_SAME_SITE_POLICY_NONE:
	case SOUP_SAME_SITE_POLICY_STRICT:
	case SOUP_SAME_SITE_POLICY_LAX:
                cookie->same_site_policy = policy;
		break;
	default:
		g_return_if_reached ();
	}
}

/**
 * soup_cookie_get_same_site_policy:
 * @cookie: a #SoupCookie
 *
 * Returns the same-site policy for this cookie.
 *
 * Returns: a #SoupSameSitePolicy
 **/
SoupSameSitePolicy
soup_cookie_get_same_site_policy (SoupCookie *cookie)
{
        return cookie->same_site_policy;
}

/**
 * soup_cookie_to_set_cookie_header:
 * @cookie: a #SoupCookie
 *
 * Serializes @cookie in the format used by the Set-Cookie header.
 *
 * i.e. for sending a cookie from a [class@Server] to a client.
 *
 * Returns: the header
 **/
char *
soup_cookie_to_set_cookie_header (SoupCookie *cookie)
{
	GString *header = g_string_new (NULL);

	serialize_cookie (cookie, header, TRUE);
	return g_string_free (header, FALSE);
}

/**
 * soup_cookie_to_cookie_header:
 * @cookie: a #SoupCookie
 *
 * Serializes @cookie in the format used by the Cookie header (ie, for
 * returning a cookie from a [class@Session] to a server).
 *
 * Returns: the header
 **/
char *
soup_cookie_to_cookie_header (SoupCookie *cookie)
{
	GString *header = g_string_new (NULL);

	serialize_cookie (cookie, header, FALSE);
	return g_string_free (header, FALSE);
}

/**
 * soup_cookie_free:
 * @cookie: a #SoupCookie
 *
 * Frees @cookie.
 **/
void
soup_cookie_free (SoupCookie *cookie)
{
	g_return_if_fail (cookie != NULL);

	g_free (cookie->name);
	g_free (cookie->value);
	g_free (cookie->domain);
	g_free (cookie->path);
	g_clear_pointer (&cookie->expires, g_date_time_unref);

	g_dataset_destroy (cookie);
	g_slice_free (SoupCookie, cookie);
}

/**
 * soup_cookies_from_response:
 * @msg: a #SoupMessage containing a "Set-Cookie" response header
 *
 * Parses @msg's Set-Cookie response headers and returns a [struct@GLib.SList]
 * of `SoupCookie`s.
 *
 * Cookies that do not specify "path" or "domain" attributes will have their
 * values defaulted from @msg.
 *
 * Returns: (element-type SoupCookie) (transfer full): a #GSList of
 *   `SoupCookie`s, which can be freed with [method@Cookie.free].
 **/
GSList *
soup_cookies_from_response (SoupMessage *msg)
{
	GUri *origin;
	const char *name, *value;
	SoupCookie *cookie;
	GSList *cookies = NULL;
	SoupMessageHeadersIter iter;

	origin = soup_message_get_uri (msg);

	/* We have to use soup_message_headers_iter rather than
	 * soup_message_headers_get_list() since Set-Cookie isn't
	 * properly mergeable/unmergeable.
	 */
	soup_message_headers_iter_init (&iter, soup_message_get_response_headers (msg));
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		if (g_ascii_strcasecmp (name, "Set-Cookie") != 0)
			continue;

		cookie = parse_one_cookie (value, origin);
		if (cookie)
			cookies = g_slist_prepend (cookies, cookie);
	}
	return g_slist_reverse (cookies);
}

/**
 * soup_cookies_from_request:
 * @msg: a #SoupMessage containing a "Cookie" request header
 *
 * Parses @msg's Cookie request header and returns a [struct@GLib.SList] of
 * `SoupCookie`s.
 *
 * As the "Cookie" header, unlike "Set-Cookie", only contains cookie names and
 * values, none of the other [struct@Cookie] fields will be filled in. (Thus, you
 * can't generally pass a cookie returned from this method directly to
 * [func@cookies_to_response].)
 *
 * Returns: (element-type SoupCookie) (transfer full): a #GSList of
 *   `SoupCookie`s, which can be freed with [method@Cookie.free].
 **/
GSList *
soup_cookies_from_request (SoupMessage *msg)
{
	SoupCookie *cookie;
	GSList *cookies = NULL;
	GHashTable *params;
	GHashTableIter iter;
	gpointer name, value;
	const char *header;

	header = soup_message_headers_get_one_common (soup_message_get_request_headers (msg), SOUP_HEADER_COOKIE);
	if (!header)
		return NULL;

	params = soup_header_parse_semi_param_list (header);
	g_hash_table_iter_init (&iter, params);
	while (g_hash_table_iter_next (&iter, &name, &value)) {
		if (name && value) {
			cookie = cookie_new_internal (name, value,
						      NULL, NULL, 0);
			cookies = g_slist_prepend (cookies, cookie);
		}
	}
	soup_header_free_param_list (params);

	return g_slist_reverse (cookies);
}

/**
 * soup_cookies_to_response:
 * @cookies: (element-type SoupCookie): a #GSList of [struct@Cookie]
 * @msg: a #SoupMessage
 *
 * Appends a "Set-Cookie" response header to @msg for each cookie in
 * @cookies.
 *
 * This is in addition to any other "Set-Cookie" headers
 * @msg may already have.
 **/
void
soup_cookies_to_response (GSList *cookies, SoupMessage *msg)
{
	GString *header;

	header = g_string_new (NULL);
	while (cookies) {
		serialize_cookie (cookies->data, header, TRUE);
		soup_message_headers_append_common (soup_message_get_response_headers (msg),
                                                    SOUP_HEADER_SET_COOKIE, header->str);
		g_string_truncate (header, 0);
		cookies = cookies->next;
	}
	g_string_free (header, TRUE);
}

/**
 * soup_cookies_to_request:
 * @cookies: (element-type SoupCookie): a #GSList of [struct@Cookie]
 * @msg: a #SoupMessage
 *
 * Adds the name and value of each cookie in @cookies to @msg's
 * "Cookie" request.
 *
 * If @msg already has a "Cookie" request header, these cookies will be appended
 * to the cookies already present. Be careful that you do not append the same
 * cookies twice, eg, when requeuing a message.
 **/
void
soup_cookies_to_request (GSList *cookies, SoupMessage *msg)
{
	GString *header;

	header = g_string_new (soup_message_headers_get_one_common (soup_message_get_request_headers (msg),
                                                                    SOUP_HEADER_COOKIE));
	while (cookies) {
		serialize_cookie (cookies->data, header, FALSE);
		cookies = cookies->next;
	}
	soup_message_headers_replace_common (soup_message_get_request_headers (msg),
                                             SOUP_HEADER_COOKIE, header->str);
	g_string_free (header, TRUE);
}

/**
 * soup_cookies_free: (skip)
 * @cookies: (element-type SoupCookie): a #GSList of [struct@Cookie]
 *
 * Frees @cookies.
 **/
void
soup_cookies_free (GSList *cookies)
{
	g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
}

/**
 * soup_cookies_to_cookie_header:
 * @cookies: (element-type SoupCookie): a #GSList of [struct@Cookie]
 *
 * Serializes a [struct@GLib.SList] of [struct@Cookie] into a string suitable for
 * setting as the value of the "Cookie" header.
 *
 * Returns: the serialization of @cookies
 **/
char *
soup_cookies_to_cookie_header (GSList *cookies)
{
	GString *str;

	g_return_val_if_fail (cookies != NULL, NULL);

	str = g_string_new (NULL);
	while (cookies) {
		serialize_cookie (cookies->data, str, FALSE);
		cookies = cookies->next;
	}

	return g_string_free (str, FALSE);
}

/**
 * soup_cookie_applies_to_uri:
 * @cookie: a #SoupCookie
 * @uri: a #GUri
 *
 * Tests if @cookie should be sent to @uri.
 *
 * (At the moment, this does not check that @cookie's domain matches
 * @uri, because it assumes that the caller has already done that.
 * But don't rely on that; it may change in the future.)
 *
 * Returns: %TRUE if @cookie should be sent to @uri, %FALSE if not
 **/
gboolean
soup_cookie_applies_to_uri (SoupCookie *cookie, GUri *uri)
{
	int plen;

        g_return_val_if_fail (cookie != NULL, FALSE);
        g_return_val_if_fail (uri != NULL, FALSE);

	if (cookie->secure && !soup_uri_is_https (uri))
		return FALSE;

	if (cookie->expires && soup_date_time_is_past (cookie->expires))
		return FALSE;

	plen = strlen (cookie->path);
	if (plen == 0)
		return TRUE;

        GUri *normalized_uri = soup_uri_copy_with_normalized_flags (uri);
        const char *uri_path = g_uri_get_path (normalized_uri);
	if (strncmp (cookie->path, uri_path, plen) != 0 ||
	    (cookie->path[plen - 1] != '/' && uri_path[plen] &&
             uri_path[plen] != '/')) {
                     g_uri_unref (normalized_uri);
                     return FALSE;
        }

        g_uri_unref (normalized_uri);
	return TRUE;
}

/**
 * soup_cookie_equal:
 * @cookie1: a #SoupCookie
 * @cookie2: a #SoupCookie
 *
 * Tests if @cookie1 and @cookie2 are equal.
 *
 * Note that currently, this does not check that the cookie domains
 * match. This may change in the future.
 *
 * Returns: whether the cookies are equal.
 */
gboolean
soup_cookie_equal (SoupCookie *cookie1, SoupCookie *cookie2)
{
	g_return_val_if_fail (cookie1, FALSE);
	g_return_val_if_fail (cookie2, FALSE);

	return (!strcmp (cookie1->name, cookie2->name) &&
		!strcmp (cookie1->value, cookie2->value) &&
		!g_strcmp0 (cookie1->path, cookie2->path));
}
