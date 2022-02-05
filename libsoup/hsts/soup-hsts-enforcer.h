/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_HSTS_ENFORCER (soup_hsts_enforcer_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupHSTSEnforcer, soup_hsts_enforcer, SOUP, HSTS_ENFORCER, GObject)

/**
 * SoupHSTSEnforcerClass:
 * @parent_class: The parent class.
 * @is_persistent: The @is_persistent function advertises whether the enforcer is persistent or
 * whether changes made to it will be lost when the underlying [class@Session] is finished.
 * @has_valid_policy: The @has_valid_policy function is called to check whether there is a valid
 * policy for the given domain. This method should return %TRUE for #SoupHSTSEnforcer to
 * change the scheme of the #GUri in the #SoupMessage to HTTPS. Implementations might want to
 * chain up to the @has_valid_policy in the parent class to check, for instance, for runtime
 * policies.
 * @changed: The class closure for the #SoupHSTSEnforcer::changed signal.
 *
 * Class structure for #SoupHSTSEnforcer.
 **/
struct _SoupHSTSEnforcerClass {
	GObjectClass parent_class;

	gboolean (*is_persistent) (SoupHSTSEnforcer *hsts_enforcer);
	gboolean (*has_valid_policy) (SoupHSTSEnforcer *hsts_enforcer, const char *domain);

	/* signals */
	void (*changed) (SoupHSTSEnforcer *enforcer,
			 SoupHSTSPolicy	  *old_policy,
			 SoupHSTSPolicy	  *new_policy);

        /* <private> */
	gpointer padding[4];
};

SOUP_AVAILABLE_IN_ALL
SoupHSTSEnforcer *soup_hsts_enforcer_new			   (void);
SOUP_AVAILABLE_IN_ALL
gboolean	  soup_hsts_enforcer_is_persistent		   (SoupHSTSEnforcer *hsts_enforcer);
SOUP_AVAILABLE_IN_ALL
gboolean	  soup_hsts_enforcer_has_valid_policy		   (SoupHSTSEnforcer *hsts_enforcer,
								    const char	     *domain);
SOUP_AVAILABLE_IN_ALL
void		  soup_hsts_enforcer_set_session_policy		   (SoupHSTSEnforcer *hsts_enforcer,
								    const char	     *domain,
								    gboolean	      include_subdomains);
SOUP_AVAILABLE_IN_ALL
void		  soup_hsts_enforcer_set_policy			   (SoupHSTSEnforcer *hsts_enforcer,
								    SoupHSTSPolicy   *policy);

SOUP_AVAILABLE_IN_ALL
GList            *soup_hsts_enforcer_get_domains                   (SoupHSTSEnforcer *hsts_enforcer,
								    gboolean          session_policies);

SOUP_AVAILABLE_IN_ALL
GList            *soup_hsts_enforcer_get_policies                  (SoupHSTSEnforcer *hsts_enforcer,
								    gboolean          session_policies);

G_END_DECLS
