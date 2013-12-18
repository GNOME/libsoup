/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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

#include "soup-tld.h"
#include "soup.h"
#include "soup-tld-private.h"

/**
 * SECTION:soup-tld
 * @short_description: Top-Level Domain Utilities
 *
 * These functions can be used to parse hostnames to attempt to determine
 * what part of the name belongs to the domain owner, and what part is
 * simply a "public suffix" such as ".com".
 */

static void soup_tld_ensure_rules_hash_table (void);
static const char *soup_tld_get_base_domain_internal (const char *hostname,
						      guint       additional_domains,
						      GError    **error);

static GHashTable *rules = NULL;
static SoupTLDEntry tld_entries[] = {
#include "tld_data.inc"
};

/* Stores the entries data in a hash table to ease and speed up
 * searches.
 */
static void
soup_tld_ensure_rules_hash_table (void)
{
	static gsize init = 0;

	if (g_once_init_enter (&init)) {
		int i;

		rules = g_hash_table_new (g_str_hash, g_str_equal);
		for (i = 0; i < G_N_ELEMENTS (tld_entries); ++i)
			g_hash_table_insert (rules, tld_entries[i].domain,
					     &(tld_entries[i].flags));
		g_once_init_leave (&init, 1);
	}
}

/**
 * soup_tld_get_base_domain:
 * @hostname: a hostname
 * @error: return location for a #GError, or %NULL to ignore
 *   errors. See #SoupTLDError for the available error codes
 *
 * Finds the base domain for a given @hostname. The base domain is
 * composed by the top level domain (such as .org, .com, .co.uk, etc)
 * plus the second level domain, for example for myhost.mydomain.com
 * it will return mydomain.com.
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
 * an error occurs, %NULL will be returned and @error set.
 *
 * Since: 2.40
 **/
const char *
soup_tld_get_base_domain (const char *hostname, GError **error)
{
	g_return_val_if_fail (hostname, NULL);

	return soup_tld_get_base_domain_internal (hostname, 1, error);
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
 * UTF-8 or ASCII format (and the return value will be in the same
 * format).
 *
 * Returns: %TRUE if it is a public domain, %FALSE otherwise.
 *
 * Since: 2.40
 **/
gboolean
soup_tld_domain_is_public_suffix (const char *domain)
{
	const char *base_domain;
	GError *error = NULL;

	g_return_val_if_fail (domain, FALSE);

	/* Skip the leading '.' if present */
	if (*domain == '.' && !*(++domain))
		g_return_val_if_reached (FALSE);

	base_domain = soup_tld_get_base_domain_internal (domain, 0, &error);
	if (g_strcmp0 (domain, base_domain)) {
		g_clear_error (&error);
		return FALSE;
	}

	if (g_error_matches (error, SOUP_TLD_ERROR, SOUP_TLD_ERROR_NO_BASE_DOMAIN)) {
		g_error_free (error);
		return FALSE;
	}

	if (g_error_matches (error, SOUP_TLD_ERROR, SOUP_TLD_ERROR_IS_IP_ADDRESS) ||
	    g_error_matches (error, SOUP_TLD_ERROR, SOUP_TLD_ERROR_INVALID_HOSTNAME)) {
		g_error_free (error);
		g_return_val_if_reached (FALSE);
	}

	g_clear_error (&error);

	return TRUE;
}

/**
 * SOUP_TLD_ERROR:
 *
 * The #GError domain for soup-tld-related errors.
 *
 * Since: 2.40
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
 *   soup_tld_get_base_domain() on <literal>"co.uk"</literal>.
 * @SOUP_TLD_ERROR_NO_BASE_DOMAIN: The passed-in hostname has
 *   no recognized public suffix.
 *
 * Error codes for %SOUP_TLD_ERROR.
 *
 * Since: 2.40
 */

GQuark
soup_tld_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_tld_error_quark");
	return error;
}

static const char *
soup_tld_get_base_domain_internal (const char *hostname, guint additional_domains, GError **error)
{
	char *prev_domain, *cur_domain, *next_dot;
	gint add_domains;
	const char *orig_hostname = NULL, *tld;
	char *utf8_hostname = NULL;

	soup_tld_ensure_rules_hash_table ();

	if (g_hostname_is_ip_address (hostname)) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_IS_IP_ADDRESS,
				     _("Hostname is an IP address"));
		return NULL;
	}

	if (g_hostname_is_ascii_encoded (hostname)) {
		orig_hostname = hostname;
		hostname = utf8_hostname = g_hostname_to_unicode (hostname);
		if (!hostname) {
			g_set_error_literal (error, SOUP_TLD_ERROR,
					     SOUP_TLD_ERROR_INVALID_HOSTNAME,
					     _("Invalid hostname"));
			return NULL;
		}
	}

	cur_domain = (char *) hostname;
	tld = cur_domain;
	prev_domain = NULL;
	/* Process matching rules from longest to shortest. Logic
	 * based on Mozilla's implementation of nsEffectiveTLDService.
	 */
	while (TRUE) {
		char *orig_domain;
		gboolean domain_found;
		int *flags;

		/* Valid hostnames neither start with a dot nor have more than one
		 * dot together.
		 */
		if (*cur_domain == '.') {
			g_set_error_literal (error, SOUP_TLD_ERROR,
					     SOUP_TLD_ERROR_INVALID_HOSTNAME,
					     _("Invalid hostname"));
			g_free (utf8_hostname);
			return NULL;
		}

		next_dot = strchr (cur_domain, '.');
		domain_found = g_hash_table_lookup_extended (rules, cur_domain, (gpointer *) &orig_domain, (gpointer *) &flags);
		/* We compare the keys just to be sure that we haven't hit a collision */
		if (domain_found && !strncmp (orig_domain, cur_domain, strlen (orig_domain))) {
			if (*flags & SOUP_TLD_RULE_MATCH_ALL) {
				/* If we match a *. rule and there were no previous exceptions
				 * nor previous domains then treat it as an exact match.
				 */
				tld = prev_domain ? prev_domain : cur_domain;
				break;
			} else if (*flags == SOUP_TLD_RULE_NORMAL) {
				tld = cur_domain;
				break;
			} else if (*flags & SOUP_TLD_RULE_EXCEPTION) {
				tld = next_dot + 1;
				break;
			}
		}

		/* If we hit the top and haven't matched yet, then it
		 * has no public suffix.
		 */
		if (!next_dot) {
			g_set_error_literal (error, SOUP_TLD_ERROR,
					     SOUP_TLD_ERROR_NO_BASE_DOMAIN,
					     _("Hostname has no base domain"));
			g_free (utf8_hostname);
			return NULL;
		}

		prev_domain = cur_domain;
		cur_domain = next_dot + 1;
	}

	if (orig_hostname) {
		int dots;
		const char *p;

		/* Count the number of dots that appear after tld in
		 * utf8_hostname, and then find the corresponding spot
		 * in orig_hostname;
		 */
		for (p = tld, dots = 0; *p; p++) {
			if (*p == '.')
				dots++;
		}

		for (p = orig_hostname + strlen (orig_hostname); p > orig_hostname; p--) {
			if (*(p - 1) == '.') {
				if (dots)
					dots--;
				else
					break;
			}
		}
		/* It's not possible for utf8_hostname to have had
		 * more dots than orig_hostname.
		 */
		g_assert (dots == 0);

		tld = p;
		g_free (utf8_hostname);
		hostname = orig_hostname;
	}

	/* Include the additional number of domains requested. */
	add_domains = additional_domains;
	while (tld != hostname) {
		if (*(--tld) == '.' && (!(add_domains--))) {
			++add_domains;
			++tld;
			break;
		}
	}

	/* If additional_domains > 0 then we haven't found enough additional domains. */
	if (add_domains) {
		g_set_error_literal (error, SOUP_TLD_ERROR,
				     SOUP_TLD_ERROR_NOT_ENOUGH_DOMAINS,
				     _("Not enough domains"));
		return NULL;
	}

	return tld;
}
