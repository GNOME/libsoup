/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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
#include "soup.h"

/**
 * SECTION:soup-hsts-policy
 * @short_description: HTTP Strict Transport Security policies
 * @see_also: #SoupHSTSEnforcer
 *
 * #SoupHSTSPolicy implements HTTP policies, as described by <ulink
 * url="http://tools.ietf.org/html/rfc6797">RFC 6797</ulink>.
 *
 * To have a #SoupSession handle HSTS policies for your appliction
 * automatically, use a #SoupHSTSEnforcer.
 **/

/**
 * SoupHSTSPolicy:
 * @domain: The domain or hostname that the policy applies to
 * @max_age: The maximum age, in seconds, that the policy is valid
 * @expires: the policy expiration time, or %NULL for a permanent session policy
 * @include_subdomains: %TRUE if the policy applies on subdomains
 *
 * An HTTP Strict Transport Security policy.
 *
 * @domain represents the host that this policy applies to. The domain
 * must be IDNA-canonicalized. soup_hsts_policy_new() and related methods
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
 *
 * Since: 2.68
 **/

G_DEFINE_BOXED_TYPE (SoupHSTSPolicy, soup_hsts_policy, soup_hsts_policy_copy, soup_hsts_policy_free)

/**
 * soup_hsts_policy_copy:
 * @policy: a #SoupHSTSPolicy
 *
 * Copies @policy.
 *
 * Returns: (transfer full): a copy of @policy
 *
 * Since: 2.68
 **/
SoupHSTSPolicy *
soup_hsts_policy_copy (SoupHSTSPolicy *policy)
{
	SoupHSTSPolicy *copy = g_slice_new0 (SoupHSTSPolicy);

	copy->domain = g_strdup (policy->domain);
	copy->max_age = policy->max_age;
	copy->expires = policy->expires ?
		soup_date_copy (policy->expires) : NULL;
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
 *
 * Since: 2.68
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
	    soup_date_to_time_t (policy1->expires) !=
	    soup_date_to_time_t (policy2->expires))
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
 * Creates a new #SoupHSTSPolicy with the given attributes.
 *
 * @domain is a domain on which the strict transport security policy
 * represented by this object must be enforced.
 *
 * @max_age is used to set the "expires" attribute on the policy; pass
 * SOUP_HSTS_POLICY_MAX_AGE_PAST for an already-expired policy, or a
 * lifetime in seconds.
 *
 * If @include_subdomains is %TRUE, the strict transport security policy
 * must also be enforced on all subdomains of @domain.
 *
 * Returns: a new #SoupHSTSPolicy.
 *
 * Since: 2.68
 **/
SoupHSTSPolicy *
soup_hsts_policy_new (const char *domain,
		      unsigned long max_age,
		      gboolean include_subdomains)
{
	SoupDate *expires;

	if (max_age == SOUP_HSTS_POLICY_MAX_AGE_PAST) {
		/* Use a date way in the past, to protect against
		 * clock skew.
		 */
		expires = soup_date_new (1970, 1, 1, 0, 0, 0);
	} else
		expires = soup_date_new_from_now (max_age);

	return soup_hsts_policy_new_full (domain, max_age, expires, include_subdomains);
}

/**
 * soup_hsts_policy_new_full:
 * @domain: policy domain or hostname
 * @max_age: max age of the policy
 * @expires: the date of expiration of the policy or %NULL for a permanent policy
 * @include_subdomains: %TRUE if the policy applies on subdomains
 *
 * Full version of #soup_hsts_policy_new(), to use with an existing
 * expiration date. See #soup_hsts_policy_new() for details.
 *
 * Returns: a new #SoupHSTSPolicy.
 *
 * Since: 2.68
 **/
SoupHSTSPolicy *
soup_hsts_policy_new_full (const char *domain,
			   unsigned long max_age,
			   SoupDate *expires,
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
	policy->expires = expires;
	policy->include_subdomains = include_subdomains;

	return policy;
}

/**
 * soup_hsts_policy_new_session_policy:
 * @domain: policy domain or hostname
 * @include_subdomains: %TRUE if the policy applies on sub domains
 *
 * Creates a new session #SoupHSTSPolicy with the given attributes.
 * A session policy is a policy that is valid during the lifetime of
 * the #SoupHSTSEnforcer it is added to. Contrary to regular policies,
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
 *
 * Since: 2.68
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
 * returns a #SoupHSTSPolicy.
 *
 * Returns: (nullable): a new #SoupHSTSPolicy, or %NULL if no valid
 * "Strict-Transport-Security" response header was found.
 *
 * Since: 2.68
 **/
SoupHSTSPolicy *
soup_hsts_policy_new_from_response (SoupMessage *msg)
{
	SoupMessageHeadersIter iter;
	const char *name, *value;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	soup_message_headers_iter_init (&iter, msg->response_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		SoupURI *uri;
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

		policy = soup_hsts_policy_new (uri->host, max_age, include_subdomains);
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
 *
 * Since: 2.68
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
 * Gets whether @policy is expired. Permanent policies never
 * expire.
 *
 * Returns: %TRUE if @policy is expired, %FALSE otherwise.
 *
 * Since: 2.68
 **/
gboolean
soup_hsts_policy_is_expired (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, TRUE);

	return policy->expires && soup_date_is_past (policy->expires);
}

/**
 * soup_hsts_policy_includes_subdomains:
 * @policy: a #SoupHSTSPolicy
 *
 * Gets whether @policy include its subdomains.
 *
 * Returns: %TRUE if @policy includes subdomains, %FALSE otherwise.
 *
 * Since: 2.68
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
 * see soup_hsts_policy_new_session_policy() for details.
 *
 * Returns: %TRUE if @policy is permanent, %FALSE otherwise
 *
 * Since: 2.68
 **/
gboolean
soup_hsts_policy_is_session_policy (SoupHSTSPolicy *policy)
{
	g_return_val_if_fail (policy != NULL, FALSE);

	return !policy->expires;
}

/**
 * soup_hsts_policy_free:
 * @policy: (transfer full): a #SoupHSTSPolicy
 *
 * Frees @policy.
 *
 * Since: 2.68
 **/
void
soup_hsts_policy_free (SoupHSTSPolicy *policy)
{
	g_return_if_fail (policy != NULL);

	g_free (policy->domain);
	g_clear_pointer (&policy->expires, soup_date_free);
	g_slice_free (SoupHSTSPolicy, policy);
}
