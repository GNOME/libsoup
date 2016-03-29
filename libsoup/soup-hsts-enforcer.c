/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-hsts-enforcer.c: HTTP Strict Transport Security implementation
 *
 * Copyright (C) 2016 Igalia S.L.
 */

/* TODO Use only internationalized domain names */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "soup-hsts-enforcer.h"
#include "soup-hsts-enforcer-private.h"
#include "soup.h"

/**
 * SECTION:soup-hsts-enforcer
 * @short_description: Automatic HSTS enforcing for SoupSession
 *
 * A #SoupHstsEnforcer stores HSTS policies and enforce them when
 * required.
 * #SoupHstsEnforcer implements #SoupSessionFeature, so you can add a
 * HSTS enforcer to a session with soup_session_add_feature() or
 * soup_session_add_feature_by_type().
 *
 * When the #SoupSession the #SoupHstsEnforcer is attached to sends a
 * message, the #SoupHstsEnforcer will ask for a redirection to HTTPS if
 * the destination is a known HSTS host and is contacted over an insecure
 * transport protocol (HTTP).
 *
 * Note that the base #SoupHstsEnforcer class does not support any form
 * of long-term HSTS policy persistence.
 **/

static void soup_hsts_enforcer_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupHstsEnforcer, soup_hsts_enforcer, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_hsts_enforcer_session_feature_init))

enum {
	CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GHashTable *host_policies;
	GHashTable *session_policies;
} SoupHstsEnforcerPrivate;
#define SOUP_HSTS_ENFORCER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HSTS_ENFORCER, SoupHstsEnforcerPrivate))

static void
soup_hsts_enforcer_init (SoupHstsEnforcer *hsts_enforcer)
{
	SoupHstsEnforcerPrivate *priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);

	priv->host_policies = g_hash_table_new_full (soup_str_case_hash,
						soup_str_case_equal,
						g_free, NULL);

	priv->session_policies = g_hash_table_new_full (soup_str_case_hash,
							soup_str_case_equal,
							g_free, NULL);
}

static void
soup_hsts_enforcer_finalize (GObject *object)
{
	SoupHstsEnforcerPrivate *priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (object);
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init (&iter, priv->host_policies);
	while (g_hash_table_iter_next (&iter, &key, &value))
		soup_hsts_policy_free (value);
	g_hash_table_destroy (priv->host_policies);

	g_hash_table_iter_init (&iter, priv->session_policies);
	while (g_hash_table_iter_next (&iter, &key, &value))
		soup_hsts_policy_free (value);
	g_hash_table_destroy (priv->session_policies);

	G_OBJECT_CLASS (soup_hsts_enforcer_parent_class)->finalize (object);
}

static gboolean
soup_hsts_enforcer_real_is_persistent (SoupHstsEnforcer *hsts_enforcer)
{
	return FALSE;
}

static void
soup_hsts_enforcer_class_init (SoupHstsEnforcerClass *hsts_enforcer_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (hsts_enforcer_class);

	g_type_class_add_private (hsts_enforcer_class, sizeof (SoupHstsEnforcerPrivate));

	object_class->finalize = soup_hsts_enforcer_finalize;

	hsts_enforcer_class->is_persistent = soup_hsts_enforcer_real_is_persistent;

	/**
	 * SoupHstsEnforcer::changed:
	 * @hsts_enforcer: the #SoupHstsEnforcer
	 * @old_policy: the old #SoupHstsPolicy value
	 * @new_policy: the new #SoupHstsPolicy value
	 *
	 * Emitted when @hsts_enforcer changes. If a policy has been added,
	 * @new_policy will contain the newly-added policy and
	 * @old_policy will be %NULL. If a policy has been deleted,
	 * @old_policy will contain the to-be-deleted policy and
	 * @new_policy will be %NULL. If a policy has been changed,
	 * @old_policy will contain its old value, and @new_policy its
	 * new value.
	 **/
	signals[CHANGED] =
		g_signal_new ("changed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupHstsEnforcerClass, changed),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      SOUP_TYPE_HSTS_POLICY | G_SIGNAL_TYPE_STATIC_SCOPE,
			      SOUP_TYPE_HSTS_POLICY | G_SIGNAL_TYPE_STATIC_SCOPE);
}

/**
 * soup_hsts_enforcer_new:
 *
 * Creates a new #SoupHstsEnforcer. The base #SoupHstsEnforcer class does
 * not support persistent storage of HSTS policies; use a subclass for
 * that.
 *
 * Returns: a new #SoupHstsEnforcer
 *
 * Since: 2.54
 **/
SoupHstsEnforcer *
soup_hsts_enforcer_new (void)
{
	return g_object_new (SOUP_TYPE_HSTS_ENFORCER, NULL);
}

static void
soup_hsts_enforcer_changed (SoupHstsEnforcer *hsts_enforcer,
			    SoupHstsPolicy *old, SoupHstsPolicy *new)
{
	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));

	g_assert_true (old || new);

	g_signal_emit (hsts_enforcer, signals[CHANGED], 0, old, new);
}

static void
soup_hsts_enforcer_remove_expired_host_policies (SoupHstsEnforcer *hsts_enforcer)
{
	SoupHstsEnforcerPrivate *priv;
	SoupHstsPolicy *policy;
	GList *domains, *p;
	const char *domain;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);

	/* Remove all the expired policies as soon as one is encountered as required by the RFC. */
	domains = g_hash_table_get_keys (priv->host_policies);
	for (p = domains; p; p = p->next ) {
		domain = (const char *) p->data;
		policy = g_hash_table_lookup (priv->host_policies, domain);
		if (policy && soup_hsts_policy_is_expired (policy)) {
			g_hash_table_remove (priv->host_policies, domain);
			soup_hsts_enforcer_changed (hsts_enforcer, policy, NULL);
			soup_hsts_policy_free (policy);
		}
	}
	g_list_free (domains);
}

static void
soup_hsts_enforcer_remove_host_policy (SoupHstsEnforcer *hsts_enforcer,
				       const gchar *domain)
{
	SoupHstsEnforcerPrivate *priv;
	SoupHstsPolicy *policy;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));
	g_return_if_fail (domain != NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);

	policy = g_hash_table_lookup (priv->host_policies, domain);

	g_assert_nonnull (policy);

	g_hash_table_remove (priv->host_policies, domain);
	soup_hsts_enforcer_changed (hsts_enforcer, policy, NULL);
	soup_hsts_policy_free (policy);

	soup_hsts_enforcer_remove_expired_host_policies (hsts_enforcer);
}

static void
soup_hsts_enforcer_replace_policy (SoupHstsEnforcer *hsts_enforcer,
				   SoupHstsPolicy *new_policy)
{
	SoupHstsEnforcerPrivate *priv;
	GHashTable *policies;
	SoupHstsPolicy *old_policy;
	const gchar *domain;
	gboolean is_permanent;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));
	g_return_if_fail (new_policy != NULL);

	g_assert_false (soup_hsts_policy_is_expired (new_policy));

	domain = soup_hsts_policy_get_domain (new_policy);
	is_permanent = soup_hsts_policy_is_permanent (new_policy);

	g_return_if_fail (domain != NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);
	policies = is_permanent ? priv->session_policies :
				  priv->host_policies;

	old_policy = g_hash_table_lookup (policies, domain);

	g_assert_nonnull (old_policy);

	g_hash_table_remove (policies, domain);
	g_hash_table_insert (policies, g_strdup (domain), new_policy);
	if (!is_permanent && !soup_hsts_policy_equal (old_policy, new_policy))
		soup_hsts_enforcer_changed (hsts_enforcer, old_policy, new_policy);
	soup_hsts_policy_free (old_policy);

	soup_hsts_enforcer_remove_expired_host_policies (hsts_enforcer);
}

static void
soup_hsts_enforcer_insert_policy (SoupHstsEnforcer *hsts_enforcer,
				  SoupHstsPolicy *policy)
{
	SoupHstsEnforcerPrivate *priv;
	GHashTable *policies;
	const gchar *domain;
	gboolean is_permanent;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));
	g_return_if_fail (policy != NULL);

	g_assert_false (soup_hsts_policy_is_expired (policy));

	domain = soup_hsts_policy_get_domain (policy);
	is_permanent = soup_hsts_policy_is_permanent (policy);

	g_return_if_fail (domain != NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);
	policies = is_permanent ? priv->session_policies :
				  priv->host_policies;

	g_assert_false (g_hash_table_contains (policies, domain));

	g_hash_table_insert (policies, g_strdup (domain), policy);
	if (!is_permanent)
		soup_hsts_enforcer_changed (hsts_enforcer, NULL, policy);
}

/**
 * soup_hsts_enforcer_set_policy:
 * @hsts_enforcer: a #SoupHstsEnforcer
 * @policy: (transfer full): the policy of the HSTS host
 *
 * Sets @domain's HSTS policy to @policy. If @policy is expired, any
 * existing HSTS policy for this host will be removed instead. If a policy
 * exited for this host, it will be replaced. Otherwise, the new policy
 * will be inserted.
 *
 * This steals @policy.
 *
 * Since: 2.54
 **/
void
soup_hsts_enforcer_set_policy (SoupHstsEnforcer *hsts_enforcer,
			       SoupHstsPolicy *policy)
{
	SoupHstsEnforcerPrivate *priv;
	GHashTable *policies;
	const gchar *domain;
	gboolean is_permanent;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));
	g_return_if_fail (policy != NULL);

	domain = soup_hsts_policy_get_domain (policy);
	is_permanent = soup_hsts_policy_is_permanent (policy);

	g_return_if_fail (domain != NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);
	policies = is_permanent ? priv->session_policies :
				  priv->host_policies;

	if (!is_permanent && soup_hsts_policy_is_expired (policy)) {
		soup_hsts_enforcer_remove_host_policy (hsts_enforcer, domain);
		soup_hsts_policy_free (policy);
		return;
	}

	if (g_hash_table_contains (policies, domain))
		soup_hsts_enforcer_replace_policy (hsts_enforcer, policy);
	else
		soup_hsts_enforcer_insert_policy (hsts_enforcer, policy);
}

static SoupHstsPolicy *
soup_hsts_enforcer_get_host_policy (SoupHstsEnforcer *hsts_enforcer,
				    const gchar *domain)
{
	SoupHstsEnforcerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), NULL);
	g_return_val_if_fail (domain != NULL, NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);

	return g_hash_table_lookup (priv->host_policies, domain);
}

static SoupHstsPolicy *
soup_hsts_enforcer_get_session_policy (SoupHstsEnforcer *hsts_enforcer,
				       const gchar *domain)
{
	SoupHstsEnforcerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), NULL);
	g_return_val_if_fail (domain != NULL, NULL);

	priv = SOUP_HSTS_ENFORCER_GET_PRIVATE (hsts_enforcer);

	return g_hash_table_lookup (priv->session_policies, domain);
}

/**
 * soup_hsts_enforcer_set_session_policy:
 * @hsts_enforcer: a #SoupHstsEnforcer
 * @domain: policy domain or hostname
 * @include_sub_domains: %TRUE if the policy applies on sub domains
 *
 * Sets a session policy@domain's HSTS policy to @policy. If @policy is expired, any
 * existing HSTS policy for this host will be removed instead. If a policy
 * exited for this host, it will be replaced. Otherwise, the new policy
 * will be inserted.
 *
 * Since: 2.54
 **/
void
soup_hsts_enforcer_set_session_policy (SoupHstsEnforcer *hsts_enforcer,
				       const char *domain,
				       gboolean include_sub_domains)
{
	SoupHstsPolicy *policy;

	g_return_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer));
	g_return_if_fail (domain != NULL);

	policy = soup_hsts_policy_new_permanent (domain, include_sub_domains);
	soup_hsts_enforcer_set_policy (hsts_enforcer, policy);
}

static gboolean
soup_hsts_enforcer_is_valid_host (SoupHstsEnforcer *hsts_enforcer,
				  const gchar *domain)
{
	SoupHstsPolicy *policy;

	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);

	if (soup_hsts_enforcer_get_session_policy (hsts_enforcer, domain))
		return TRUE;

	policy = soup_hsts_enforcer_get_host_policy (hsts_enforcer, domain);
	if (policy)
		return !soup_hsts_policy_is_expired (policy);

	return FALSE;
}

static gboolean
soup_hsts_enforcer_host_includes_sub_domains (SoupHstsEnforcer *hsts_enforcer,
					      const gchar *domain)
{
	SoupHstsPolicy *policy;
	gboolean include_sub_domains = FALSE;

	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);

	policy = soup_hsts_enforcer_get_session_policy (hsts_enforcer, domain);
	if (policy)
		include_sub_domains |= soup_hsts_policy_includes_sub_domains (policy);

	policy = soup_hsts_enforcer_get_host_policy (hsts_enforcer, domain);
	if (policy)
		include_sub_domains |= soup_hsts_policy_includes_sub_domains (policy);

	return include_sub_domains;
}

static inline const gchar*
super_domain_of (const gchar *domain)
{
	const gchar *iter = domain;

	g_return_val_if_fail (domain != NULL, NULL);

	for (; *iter != '\0' && *iter != '.' ; iter++);
	for (; *iter == '.' ; iter++);

	if (*iter == '\0')
		return NULL;

	return iter;
}

static gboolean
soup_hsts_enforcer_must_enforce_secure_transport (SoupHstsEnforcer *hsts_enforcer,
						  const gchar *domain)
{
	const gchar *super_domain = domain;

	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), FALSE);
	g_return_val_if_fail (domain != NULL, FALSE);

	if (soup_hsts_enforcer_is_valid_host (hsts_enforcer, domain))
		return TRUE;

	while ((super_domain = super_domain_of (super_domain)) != NULL) {
		if (soup_hsts_enforcer_host_includes_sub_domains (hsts_enforcer, super_domain) &&
		    soup_hsts_enforcer_is_valid_host (hsts_enforcer, super_domain))
			return TRUE;
	}

	return FALSE;
}

/* Processes the 'Strict-Transport-Security' field of a message's response header. */
static void
soup_hsts_enforcer_process_sts_header (SoupHstsEnforcer *hsts_enforcer,
				       SoupMessage *msg)
{
	SoupHstsPolicy *policy;
	SoupURI *uri;

	g_return_if_fail (hsts_enforcer != NULL);
	g_return_if_fail (msg != NULL);

	/* TODO if connection error or warnings received, do nothing. */

	/* TODO if header received on hazardous connection, do nothing. */

	uri = soup_message_get_uri (msg);

	g_return_if_fail (uri != NULL);

	policy = soup_hsts_policy_new_from_response (msg);

	g_return_if_fail (policy != NULL);

	soup_hsts_enforcer_set_policy (hsts_enforcer, policy);
}

/* Enforces HTTPS when demanded. */
static gboolean
soup_hsts_enforcer_should_redirect_to_https (SoupHstsEnforcer *hsts_enforcer,
					     SoupMessage *msg)
{
	SoupURI *uri;
	const gchar *domain;

	g_return_val_if_fail (hsts_enforcer != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	uri = soup_message_get_uri (msg);

	g_return_val_if_fail (uri != NULL, FALSE);

	// HSTS secures only HTTP connections.
	if (uri->scheme != SOUP_URI_SCHEME_HTTP)
		return FALSE;

	domain = soup_uri_get_host (uri);

	g_return_val_if_fail (domain != NULL, FALSE);

	return soup_hsts_enforcer_must_enforce_secure_transport (hsts_enforcer, domain);
}

static void
redirect_to_https (SoupMessage *msg)
{
	SoupURI *src_uri, *dst_uri;
	char *dst;

	src_uri = soup_message_get_uri (msg);

	dst_uri = soup_uri_copy (src_uri);
	soup_uri_set_scheme (dst_uri, SOUP_URI_SCHEME_HTTPS);
	dst = soup_uri_to_string (dst_uri, FALSE);
	soup_uri_free (dst_uri);

	soup_message_set_redirect (msg, 301, dst);
	g_free (dst);
}

static void
process_sts_header (SoupMessage *msg, gpointer user_data)
{
	SoupHstsEnforcer *hsts_enforcer = SOUP_HSTS_ENFORCER (user_data);

	g_return_if_fail (hsts_enforcer != NULL);
	g_return_if_fail (msg != NULL);

	soup_hsts_enforcer_process_sts_header (hsts_enforcer, msg);
}

static void
soup_hsts_enforcer_request_queued (SoupSessionFeature *feature,
				   SoupSession *session,
				   SoupMessage *msg)
{
	SoupHstsEnforcer *hsts_enforcer = SOUP_HSTS_ENFORCER (feature);
	SoupURI *uri;
	const char *scheme;

	g_return_if_fail (hsts_enforcer != NULL);
	g_return_if_fail (msg != NULL);

	uri = soup_message_get_uri (msg);

	g_return_if_fail (uri != NULL);

	scheme = soup_uri_get_scheme (uri);

	if (scheme == SOUP_URI_SCHEME_HTTP) {
		if (soup_hsts_enforcer_should_redirect_to_https (hsts_enforcer, msg))
			redirect_to_https (msg);
	}
	else if (scheme == SOUP_URI_SCHEME_HTTPS) {
		soup_message_add_header_handler (msg, "got-headers",
						 "Strict-Transport-Security",
						 G_CALLBACK (process_sts_header),
						 hsts_enforcer);
	}
}

static void
soup_hsts_enforcer_request_unqueued (SoupSessionFeature *feature,
				     SoupSession *session,
				     SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, process_sts_header, feature);
}

static void
soup_hsts_enforcer_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					 gpointer interface_data)
{
	feature_interface->request_queued = soup_hsts_enforcer_request_queued;
	feature_interface->request_unqueued = soup_hsts_enforcer_request_unqueued;
}

/**
 * soup_hsts_enforcer_is_persistent:
 * @hsts_enforcer: a #SoupHstsEnforcer
 *
 * Gets whether @hsts_enforcer stores policies persistenly.
 *
 * Returns: %TRUE if @hsts_enforcer storage is persistent or %FALSE otherwise.
 *
 * Since: 2.54
 **/
gboolean
soup_hsts_enforcer_is_persistent (SoupHstsEnforcer *hsts_enforcer)
{
	g_return_val_if_fail (SOUP_IS_HSTS_ENFORCER (hsts_enforcer), FALSE);

	return SOUP_HSTS_ENFORCER_GET_CLASS (hsts_enforcer)->is_persistent (hsts_enforcer);
}
