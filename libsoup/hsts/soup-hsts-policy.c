/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-hsts-policy.c: HSTS policy structure
 *
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "soup-hsts-policy.h"
#include "soup-date-utils-private.h"
#include "soup.h"

/**
 * SoupHSTSPolicy:
 *
 * [struct@HSTSPolicy] implements HTTP policies, as described by
 * [RFC 6797](http://tools.ietf.org/html/rfc6797).
 *
 * @domain represents the host that this policy applies to. The domain
 * must be IDNA-canonicalized. [ctor@HSTSPolicy.new] and related methods
 * will do this for you.
 *
 * @max_age contains the 'max-age' value from the Strict Transport
 * Security header and indicates the time to live of this policy,
 * in seconds.
 *
 * @expires will be non-%NULL if the policy has been set by the host and
 * hence has an expiry time. If @expires is %NULL, it indicates that the
 * policy is a permanent session policy set by the user agent.
 *
 * If @include_subdomains is %TRUE, the Strict Transport Security policy
 * must also be enforced on subdomains of @domain.
 **/

struct _SoupHSTSPolicy {
	char                 *domain;
	unsigned long         max_age;
	GDateTime            *expires;
	gboolean              include_subdomains;
};

G_DEFINE_BOXED_TYPE (SoupHSTSPolicy, soup_hsts_policy, soup_hsts_policy_copy, soup_hsts_policy_free)

/**
 * soup_hsts_policy_copy:
 * @policy: a #SoupHSTSPolicy
 *
 * Copies @policy.
 *
 * Returns: (transfer full): a copy of @policy
 **/
SoupHSTSPolicy *
soup_hsts_policy_copy (SoupHSTSPolicy *policy)
{
	SoupHSTSPolicy *copy = g_slice_new0 (SoupHSTSPolicy);

	copy->domain = g_strdup (policy->domain);
	copy->max_age = policy->max_age;
	copy->expires = policy->expires ?
		g_date_time_ref (policy->expires) : NULL;
	copy->include_subdomains = policy->include_subdomains;

	return copy;
}

/**
 * soup_hsts_policy_equal:
 * @policy1: a #SoupHSTSPolicy
 * @policy2: a #SoupHSTSPolicy
 *
 * Tests if @policy1 and @policy2 are equal.
 *
 * Returns: whether the policies are equal.
 */
gboolean
soup_hsts_policy_equal (SoupHSTSPolicy *policy1, SoupHSTSPolicy *policy2)
{
	g_return_val_if_fail (policy1, FALSE);
	g_return_val_if_fail (policy2, FALSE);

	if (strcmp (policy1->domain, policy2->domain))
		return FALSE;

	if (policy1->include_subdomains != policy2->include_subdomains)
		return FALSE;

	if (policy1->max_age != policy2->max_age)
		return FALSE;

	if ((policy1->expires && !policy2->expires) ||
	    (!policy1->expires && policy2->expires))
		return FALSE;

	if (policy1->expires && policy2->expires &&
	    !g_date_time_equal (policy1->expires, policy2->expires))
		return FALSE;

	return TRUE;
}

/*
 * Returns: %TRUE if the hostname is suitable for an HSTS host, %FALSE
 * otherwise. Suitable hostnames are any that is not an IP address.
 */
static gboolean
is_hostname_valid (const char *hostname)
{
	/* IP addresses are not valid hostnames, only domain names are. */
	return hostname && !g_hostname_is_ip_address (hostname);
}

/**
 * soup_hsts_policy_new:
 * @domain: policy domain or hostname
 * @max_age: max age of the policy
 * @include_subdomains: %TRUE if the policy applies on subdomains
 *
 * Creates a new [struct@HSTSPolicy] with the given attributes.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * @max_age is used to set the "expires" attribute on the policy; pass
 * %SOUP_HSTS_POLICY_MAX_AGE_PAST for an already-expired policy, or a
 * lifetime in seconds.
 *
 * If @include_subdomains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Returns: a new #SoupHSTSPolicy.
 **/
SoupHSTSPolicy *
soup_hsts_policy_new (const char *domain,
		      unsigned long max_age,
		      gboolean include_subdomains)
{
	GDateTime *expires;
        SoupHSTSPolicy *policy;

	if (max_age == SOUP_HSTS_POLICY_MAX_AGE_PAST) {
		/* Use a date way in the past, to protect against
		 * clock skew.
		 */
                expires = g_date_time_new_from_unix_utc (0);
	} else {
                GDateTime *now = g_date_time_new_now_utc ();
                expires = g_date_time_add_seconds (now, max_age);
                g_date_time_unref (now);
        }

	policy = soup_hsts_policy_new_full (domain, max_age, expires, include_subdomains);

        g_date_time_unref (expires);

        return policy;
}

/**
 * soup_hsts_policy_new_full:
 * @domain: policy domain or hostname
 * @max_age: max age of the policy
 * @expires: the date of expiration of the policy or %NULL for a permanent policy
 * @include_subdomains: %TRUE if the policy applies on subdomains
 *
 * Full version of [ctor@HSTSPolicy.new], to use with an existing
 * expiration date.
 *
 * See [ctor@HSTSPolicy.new] for details.
 *
 * Returns: a new #SoupHSTSPolicy.
 **/
SoupHSTSPolicy *
soup_hsts_policy_new_full (const char *domain,
			   unsigned long max_age,
			   GDateTime *expires,
			   gboolean include_subdomains)
{
	SoupHSTSPolicy *policy;

	g_return_val_if_fail (is_hostname_valid (domain), NULL);

	policy = g_slice_new0 (SoupHSTSPolicy);

	if (g_hostname_is_ascii_encoded (domain)) {
		policy->domain = g_hostname_to_unicode (domain);
		if (!policy->domain) {
			g_slice_free (SoupHSTSPolicy, policy);
			return NULL;
		}
	} else {
		policy->domain = g_strdup (domain);
	}

	policy->max_age = max_age;
	policy->expires = expires ? g_date_time_ref (expires) : NULL;
	policy->include_subdomains = include_subdomains;

	return policy;
}

/**
 * soup_hsts_policy_new_session_policy:
 * @domain: policy domain or hostname
 * @include_subdomains: %TRUE if the policy applies on sub domains
 *
 * Creates a new session [struct@HSTSPolicy] with the given attributes.
 *
 * A session policy is a policy that is valid during the lifetime of
 * the [class@HSTSEnforcer] it is added to. Contrary to regular policies,
 * it has no expiration date and is not stored in persistent
 * enforcers. These policies are useful for user-agent to load their
 * own or user-defined rules.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * If @include_subdomains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Returns: a new #SoupHSTSPolicy.
 **/
SoupHSTSPolicy *
soup_hsts_policy_new_session_policy (const char *domain,
				     gboolean include_subdomains)
{
	SoupHSTSPolicy *policy;

	policy = soup_hsts_policy_new_full (domain, 0, NULL, include_subdomains);

	return policy;
}

/**
 * soup_hsts_policy_new_from_response:
 * @msg: a #SoupMessage
 *
 * Parses @msg's first "Strict-Transport-Security" response header and
 * returns a [struct@HSTSPolicy].
 *
 * Returns: (nullable): a new #SoupHSTSPolicy, or %NULL if no valid
 *   "Strict-Transport-Security" response header was found.
 **/
SoupHSTSPolicy *
soup_hsts_policy_new_from_response (SoupMessage *msg)
{
	SoupMessageHeadersIter iter;
	const char *name, *value;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	soup_message_headers_iter_init (&iter, soup_message_get_response_headers (msg));
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		GUri *uri;
		GHashTable *params;
		const char *max_age_str;
		char *endptr;
		unsigned long max_age;
		gboolean include_subdomains;
		gpointer include_subdomains_value = NULL;
		SoupHSTSPolicy *policy = NULL;

		if (g_ascii_strcasecmp (name, "Strict-Transport-Security") != 0)
			continue;

		uri = soup_message_get_uri (msg);

		params = soup_header_parse_semi_param_list_strict (value);

		if (!params)
			return NULL;

		max_age_str = g_hash_table_lookup (params, "max-age");

		if (!max_age_str)
			goto out;
		max_age = strtoul (max_age_str, &endptr, 10);
		if (*endptr != '\0')
			goto out;

		include_subdomains = g_hash_table_lookup_extended (params, "includeSubDomains", NULL,
								   &include_subdomains_value);
		/* includeSubdomains shouldn't have a value. */
		if (include_subdomains_value)
			goto out;

		policy = soup_hsts_policy_new (g_uri_get_host (uri), max_age, include_subdomains);
	out:
		soup_header_free_param_list (params);
		return policy;
	}

	return NULL;
}

/**
 * soup_hsts_policy_get_domain:
 * @policy: a #SoupHSTSPolicy
 *
 * Gets @policy's domain.
 *
 * Returns: (transfer none): @policy's domain.
 **/
const char *
soup_hsts_policy_get_domain (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, NULL);

	return policy->domain;
}

/**
 * soup_hsts_policy_is_expired:
 * @policy: a #SoupHSTSPolicy
 *
 * Gets whether @policy is expired.
 *
 * Permanent policies never expire.
 *
 * Returns: %TRUE if @policy is expired, %FALSE otherwise.
 **/
gboolean
soup_hsts_policy_is_expired (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, TRUE);

	return policy->expires && soup_date_time_is_past (policy->expires);
}

/**
 * soup_hsts_policy_includes_subdomains:
 * @policy: a #SoupHSTSPolicy
 *
 * Gets whether @policy include its subdomains.
 *
 * Returns: %TRUE if @policy includes subdomains, %FALSE otherwise.
 **/
gboolean
soup_hsts_policy_includes_subdomains (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, FALSE);

	return policy->include_subdomains;
}

/**
 * soup_hsts_policy_is_session_policy:
 * @policy: a #SoupHSTSPolicy
 *
 * Gets whether @policy is a non-permanent, non-expirable session policy.
 *
 * See [ctor@HSTSPolicy.new_session_policy] for details.
 *
 * Returns: %TRUE if @policy is permanent, %FALSE otherwise
 **/
gboolean
soup_hsts_policy_is_session_policy (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, FALSE);

	return !policy->expires;
}

/**
 * soup_hsts_policy_get_expires:
 * @policy: a #SoupHSTSPolicy
 *
 * Returns the expiration date for @policy.
 *
 * Returns: A #GDateTime or %NULL if unset
 */
GDateTime *
soup_hsts_policy_get_expires (SoupHSTSPolicy *policy)
{
        g_return_val_if_fail (policy != NULL, NULL);

        return policy->expires;
}

/**
 * soup_hsts_policy_get_max_age:
 * @policy: a #SoupHSTSPolicy
 *
 * Returns the max age for @policy.
 *
 * Returns: Max age in seconds
 */
gulong
soup_hsts_policy_get_max_age (SoupHSTSPolicy *policy)
{
        g_return_val_if_fail (policy != NULL, 0);

        return policy->max_age;
}

/**
 * soup_hsts_policy_free:
 * @policy: (transfer full): a #SoupHSTSPolicy
 *
 * Frees @policy.
 **/
void
soup_hsts_policy_free (SoupHSTSPolicy *policy)
{
	g_return_if_fail (policy != NULL);

	g_free (policy->domain);
	g_clear_pointer (&policy->expires, g_date_time_unref);
	g_slice_free (SoupHSTSPolicy, policy);
}
