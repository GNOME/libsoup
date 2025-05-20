/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-tld.c
 *
 * Copyright (C) 2012 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>
#include <libpsl.h>

#include "soup-tld.h"
#include "soup.h"

static const char *soup_tld_get_base_domain_internal (const char *hostname,
						      GError    **error);

/**
 * soup_tld_get_base_domain:
 * @hostname: a hostname
 * @error: return location for a #GError, or %NULL to ignore
 *   errors. See [error@TLDError] for the available error codes
 *
 * Finds the base domain for a given @hostname
 *
 * The base domain is composed by the top level domain (such as .org, .com,
 * .co.uk, etc) plus the second level domain, for example for
 * myhost.mydomain.com it will return mydomain.com.
 *
 * Note that %NULL will be returned for private URLs (those not ending
 * with any well known TLD) because choosing a base domain for them
 * would be totally arbitrary.
 *
 * Prior to libsoup 2.46, this function required that @hostname be in
 * UTF-8 if it was an IDN. From 2.46 on, the name can be in either
 * UTF-8 or ASCII format (and the return value will be in the same
 * format).
 *
 * Returns: a pointer to the start of the base domain in @hostname. If
 *   an error occurs, %NULL will be returned and @error set.
 **/
const char *
soup_tld_get_base_domain (const char *hostname, GError **error)
{
	g_return_val_if_fail (hostname, NULL);

	return soup_tld_get_base_domain_internal (hostname, error);
}

static psl_ctx_t *
soup_psl_context (void)
{
	static psl_ctx_t *psl = NULL;

	if (!psl)
		psl = psl_latest (NULL);

	return psl;
}

/**
 * soup_tld_domain_is_public_suffix:
 * @domain: a domain name
 *
 * Looks whether the @domain passed as argument is a public domain
 * suffix (.org, .com, .co.uk, etc) or not.
 *
 * Prior to libsoup 2.46, this function required that @domain be in
 * UTF-8 if it was an IDN. From 2.46 on, the name can be in either
 * UTF-8 or ASCII format.
 *
 * Returns: %TRUE if it is a public domain, %FALSE otherwise.
 **/
gboolean
soup_tld_domain_is_public_suffix (const char *domain)
{
	const psl_ctx_t* psl = soup_psl_context ();

	g_return_val_if_fail (domain, FALSE);

	if (!psl) {
		g_warning ("soup-tld: There is no public-suffix data available.");
		return FALSE;
	}

	return psl_is_public_suffix2 (psl, domain, PSL_TYPE_ANY | PSL_TYPE_NO_STAR_RULE);
}

/**
 * SOUP_TLD_ERROR:
 *
 * The #GError domain for soup-tld-related errors.
 */
/**
 * SoupTLDError:
 * @SOUP_TLD_ERROR_INVALID_HOSTNAME: A hostname was syntactically
 *   invalid.
 * @SOUP_TLD_ERROR_IS_IP_ADDRESS: The passed-in "hostname" was
 *   actually an IP address (and thus has no base domain or
 *   public suffix).
 * @SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS: The passed-in hostname
 *   did not have enough components. Eg, calling
 *   [func@tld_get_base_domain] on <literal>"co.uk"</literal>.
 * @SOUP_TLD_ERROR_NO_BASE_DOMAIN: The passed-in hostname has
 *   no recognized public suffix.
 * @SOUP_TLD_ERROR_NO_PSL_DATA: The Public Suffix List was not
 *   available.
 *
 * Error codes for %SOUP_TLD_ERROR.
 */

G_DEFINE_QUARK (soup-tld-error-quark, soup_tld_error)

static const char *
soup_tld_get_base_domain_internal (const char *hostname, GError **error)
{
	char *utf8_hostname = NULL;
	const psl_ctx_t* psl = soup_psl_context ();
	const char *registrable_domain, *unregistrable_domain;

	if (!psl) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_NO_PSL_DATA,
				     _("No public-suffix list available."));
		return NULL;
	}

	/* Valid hostnames neither start with a dot nor have more than one
	 * dot together.
	 */
	if (*hostname == '.') {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_INVALID_HOSTNAME,
				     _("Invalid hostname"));
		return NULL;
	}

	if (g_hostname_is_ip_address (hostname)) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_IS_IP_ADDRESS,
				     _("Hostname is an IP address"));
		return NULL;
	}

	if (g_hostname_is_ascii_encoded (hostname)) {
		utf8_hostname = g_hostname_to_unicode (hostname);
		if (!utf8_hostname) {
			g_set_error_literal (error, SOUP_TLD_ERROR,
					     SOUP_TLD_ERROR_INVALID_HOSTNAME,
					     _("Invalid hostname"));
			return NULL;
		}
		g_free (utf8_hostname);
	}

	/* Fetch the domain portion of the hostname and check whether
	 * it's a public domain. */
	unregistrable_domain = psl_unregistrable_domain (psl, hostname);
	if (!psl_is_public_suffix2 (psl, unregistrable_domain, PSL_TYPE_ANY | PSL_TYPE_NO_STAR_RULE)) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_NO_BASE_DOMAIN,
				     _("Hostname has no base domain"));
		return NULL;
	}

	registrable_domain = psl_registrable_domain (psl, hostname);
	if (!registrable_domain) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS,
				     _("Not enough domains"));
		return NULL;
	}

	return registrable_domain;
}
