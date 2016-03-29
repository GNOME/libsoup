/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-hsts-policy.c
 *
 * Copyright (C) 2016 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-hsts-policy.h"
#include "soup.h"

/**
 * SECTION:soup-hsts-policy
 * @short_description: HTTP Strict Transport Security policies
 * @see_also: #SoupHstsEnforcer
 *
 * #SoupHstsPolicy implements HTTP policies, as described by <ulink
 * url="http://tools.ietf.org/html/rfc6797">RFC 6797</ulink>.
 *
 * To have a #SoupSession handle HSTS policies for your appliction
 * automatically, use a #SoupHstsEnforcer.
 **/

/**
 * SoupHstsPolicy:
 * @domain: the "domain" attribute, or else the hostname that the
 * policy came from.
 * @expires: the policy expiration time, or %NULL for a session policy
 * @include_sub_domains: %TRUE if the policy applies on sub domains
 *
 * An HTTP Strict Transport Security policy.
 *
 * @domain give the host or domain that this policy belongs to and applies
 * on.
 *
 * @expires will be non-%NULL if the policy has been set by the host and
 * hence has an expiry time. If @expires is %NULL, it indicates that the
 * policy is a session policy set by the user agent.
 * 
 * If @include_sub_domains is set, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Since: 2.54
 **/

G_DEFINE_BOXED_TYPE (SoupHstsPolicy, soup_hsts_policy, soup_hsts_policy_copy, soup_hsts_policy_free)

/**
 * soup_hsts_policy_copy:
 * @policy: a #SoupHstsPolicy
 *
 * Copies @policy.
 *
 * Return value: a copy of @policy
 *
 * Since: 2.54
 **/
SoupHstsPolicy *
soup_hsts_policy_copy (SoupHstsPolicy *policy)
{
	SoupHstsPolicy *copy = g_slice_new0 (SoupHstsPolicy);

	copy->domain = g_strdup (policy->domain);
	copy->expires = policy->expires ? soup_date_copy(policy->expires)
					: NULL;
	copy->include_sub_domains = policy->include_sub_domains;

	return copy;
}

/**
 * soup_hsts_policy_equal:
 * @policy1: a #SoupCookie
 * @policy2: a #SoupCookie
 *
 * Tests if @policy1 and @policy2 are equal.
 *
 * Note that currently, this does not check that the cookie domains
 * match. This may change in the future.
 *
 * Return value: whether the cookies are equal.
 *
 * Since: 2.24
 */
gboolean
soup_hsts_policy_equal (SoupHstsPolicy *policy1, SoupHstsPolicy *policy2)
{
	g_return_val_if_fail (policy1, FALSE);
	g_return_val_if_fail (policy2, FALSE);

	if (strcmp (policy1->domain, policy2->domain))
		return FALSE;

	if (policy1->include_sub_domains != policy2->include_sub_domains)
		return FALSE;

	if ((policy1->expires && !policy2->expires) ||
	    (!policy1->expires && policy2->expires))
		return FALSE;

	if (policy1->expires && policy2->expires &&
	    soup_date_to_time_t (policy1->expires) !=
	    soup_date_to_time_t (policy2->expires))
		return FALSE;

	return TRUE;
}

static inline const char *
skip_lws (const char *s)
{
	while (g_ascii_isspace (*s))
		s++;
	return s;
}

static inline const char *
unskip_lws (const char *s, const char *start)
{
	while (s > start && g_ascii_isspace (*(s - 1)))
		s--;
	return s;
}

#define is_attr_ender(ch) ((ch) < ' ' || (ch) == ';' || (ch) == ',' || (ch) == '=')
#define is_value_ender(ch) ((ch) < ' ' || (ch) == ';')

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

static SoupHstsPolicy *
parse_one_policy (const char *header, SoupURI *origin)
{
	const char *start, *end, *p;
	gboolean has_value;
	long max_age = -1;
	gboolean include_sub_domains = FALSE;

	g_return_val_if_fail (origin == NULL || origin->host, NULL);

	p = start = skip_lws (header);

	/* Parse directives */
	do {
		if (*p == ';')
			p++;

		start = skip_lws (p);
		for (p = start; !is_attr_ender (*p); p++)
			;
		end = unskip_lws (p, start);

		has_value = (*p == '=');
#define MATCH_NAME(name) ((end - start == strlen (name)) && !g_ascii_strncasecmp (start, name, end - start))

		if (MATCH_NAME ("max-age") && has_value) {
			char *max_age_str, *max_age_end;

			/* Repeated directives make the policy invalid. */
			if (max_age >= 0)
				goto fail;

			max_age_str = parse_value (&p, TRUE);
			max_age = strtol (max_age_str, &max_age_end, 10);
			g_free (max_age_str);

			if (*max_age_end == '\0') {
				/* Invalid 'max-age' directive makes the policy invalid. */
				if (max_age < 0)
					goto fail;
			}
		} else if (MATCH_NAME ("includeSubDomains")) {
			/* Repeated directives make the policy invalid. */
			if (include_sub_domains)
				goto fail;

			/* The 'includeSubDomains' directive can't have a value. */
			if (has_value)
				goto fail;

			include_sub_domains = TRUE;
		} else {
			/* Unknown directives must be skipped. */
			if (has_value)
				parse_value (&p, FALSE);
		}
	} while (*p == ';');

	/* No 'max-age' directive makes the policy invalid. */
	if (max_age < 0)
		goto fail;

	return soup_hsts_policy_new_with_max_age (origin->host, max_age,
						  include_sub_domains);

fail:
	return NULL;
}

/**
 * Return value: %TRUE if the hostname is suitable for an HSTS host, %FALSE
 * otherwise.
 **/
static gboolean
is_hostname_valid (const char *hostname)
{
	if (!hostname)
		return FALSE;

	/* Hostnames must have at least one '.'
	 */
	if (!strchr (hostname, '.'))
		return FALSE;

	/* IP addresses are not valid hostnames, only domain names are.
	 */
	if (g_hostname_is_ip_address (hostname))
		return FALSE;

	/* The hostname should be a valid domain name.
	 */
	return TRUE;
}

/**
 * soup_hsts_policy_new:
 * @domain: policy domain or hostname
 * @expires: (transfer full): the expiry date of the policy
 * @include_sub_domains: %TRUE if the policy applies on sub domains
 *
 * Creates a new #SoupHstsPolicy with the given attributes.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * @expires is the date and time when the policy should be considered
 * expired.
 *
 * If @include_sub_domains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Return value: a new #SoupHstsPolicy.
 *
 * Since: 2.54
 **/
SoupHstsPolicy *
soup_hsts_policy_new (const char *domain, SoupDate *expires,
		      gboolean include_sub_domains)
{
	SoupHstsPolicy *policy;

	g_return_val_if_fail (is_hostname_valid (domain), NULL);

	policy = g_slice_new0 (SoupHstsPolicy);
	policy->domain = g_strdup (domain);
	policy->expires = expires;
	policy->include_sub_domains = include_sub_domains;

	return policy;
}

/**
 * soup_hsts_policy_new_with_max_age:
 * @domain: policy domain or hostname
 * @max_age: max age of the policy
 * @include_sub_domains: %TRUE if the policy applies on sub domains
 *
 * Creates a new #SoupHstsPolicy with the given attributes.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * @max_age is used to set the "expires" attribute on the policy; pass
 * SOUP_HSTS_POLICY_MAX_AGE_PAST for an already-expired policy, or a
 * lifetime in seconds.
 *
 * If @include_sub_domains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Return value: a new #SoupHstsPolicy.
 *
 * Since: 2.54
 **/
SoupHstsPolicy *
soup_hsts_policy_new_with_max_age (const char *domain, int max_age,
				   gboolean include_sub_domains)
{
	SoupDate *expires;
	SoupHstsPolicy *policy;

	g_return_val_if_fail (is_hostname_valid (domain), NULL);
	g_return_val_if_fail (max_age >= 0, NULL);

	if (max_age == SOUP_HSTS_POLICY_MAX_AGE_PAST) {
		/* Use a date way in the past, to protect against
		 * clock skew.
		 */
		expires = soup_date_new (1970, 1, 1, 0, 0, 0);
	} else
		expires = soup_date_new_from_now (max_age);

	policy = soup_hsts_policy_new (domain, expires, include_sub_domains);

	if (!policy)
		soup_date_free (expires);

	return policy;
}

/**
 * soup_hsts_policy_new_permanent:
 * @domain: policy domain or hostname
 * @include_sub_domains: %TRUE if the policy applies on sub domains
 *
 * Creates a new #SoupHstsPolicy with the given attributes.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * If @include_sub_domains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Return value: a new #SoupHstsPolicy.
 *
 * Since: 2.54
 **/
SoupHstsPolicy *
soup_hsts_policy_new_permanent (const char *domain,
				gboolean include_sub_domains)
{
	return soup_hsts_policy_new (domain, NULL, include_sub_domains);
}

/**
 * soup_hsts_policy_new_from_response:
 * @msg: a #SoupMessage containing a "Strict-Transport-Security" response
 * header
 *
 * Parses @msg's first "Strict-Transport-Security" response header and
 * returns a #SoupHstsPolicy, or %NULL if no valid
 * "Strict-Transport-Security" response header was found.
 *
 * Return value: (nullable): a new #SoupHstsPolicy, or %NULL if no valid
 * "Strict-Transport-Security" response header was found.
 *
 * Since: 2.54
 **/
SoupHstsPolicy *
soup_hsts_policy_new_from_response (SoupMessage *msg)
{
	SoupURI *origin;
	const char *name, *value;
	SoupMessageHeadersIter iter;

	soup_message_headers_iter_init (&iter, msg->response_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		if (g_ascii_strcasecmp (name, "Strict-Transport-Security") != 0)
			continue;

		origin = soup_message_get_uri (msg);
		return parse_one_policy (value, origin);
	}

	return NULL;
}

/**
 * soup_hsts_policy_get_domain:
 * @policy: a #SoupHstsPolicy
 *
 * Gets @policy's domain.
 *
 * Return value: @policy's domain.
 *
 * Since: 2.54
 **/
const char *
soup_hsts_policy_get_domain (SoupHstsPolicy *policy)
{
	return policy->domain;
}

/**
 * soup_hsts_policy_is_expired:
 * @policy: a #SoupHstsPolicy
 *
 * Gets whether @policy is expired.
 *
 * Permanent policies never expire.
 *
 * Return value: whether @policy is expired.
 *
 * Since: 2.54
 **/
gboolean
soup_hsts_policy_is_expired (SoupHstsPolicy *policy)
{
	return policy->expires && soup_date_is_past (policy->expires);
}

/**
 * soup_hsts_policy_includes_sub_domains:
 * @policy: a #SoupHstsPolicy
 *
 * Gets whether @policy include its sub-domains.
 *
 * Return value: whether @policy include its sub-domains.
 *
 * Since: 2.54
 **/
gboolean
soup_hsts_policy_includes_sub_domains (SoupHstsPolicy *policy)
{
	return policy->include_sub_domains;
}

/**
 * soup_hsts_policy_is_permanent:
 * @policy: a #SoupHstsPolicy
 *
 * Gets whether @policy is permanent (not expirable).
 *
 * A permanent policy never expires and should not be saved by a persistent
 * #SoupHstsEnforcer so the user agent can control them.
 *
 * Return value: whether @policy is permanent.
 *
 * Since: 2.54
 **/
gboolean
soup_hsts_policy_is_permanent (SoupHstsPolicy *policy)
{
	return !policy->expires;
}

/**
 * soup_hsts_policy_free:
 * @policy: a #SoupHstsPolicy
 *
 * Frees @policy.
 *
 * Since: 2.54
 **/
void
soup_hsts_policy_free (SoupHstsPolicy *policy)
{
	g_return_if_fail (policy != NULL);

	g_free (policy->domain);
	g_clear_pointer (&policy->expires, soup_date_free);

	g_slice_free (SoupHstsPolicy, policy);
}
