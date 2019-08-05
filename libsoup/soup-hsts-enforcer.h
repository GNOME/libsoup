/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#ifndef __SOUP_HSTS_ENFORCER_H__
#define __SOUP_HSTS_ENFORCER_H__ 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_HSTS_ENFORCER		   (soup_hsts_enforcer_get_type ())
#define SOUP_HSTS_ENFORCER(obj)		   (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HSTS_ENFORCER, SoupHSTSEnforcer))
#define SOUP_HSTS_ENFORCER_CLASS(klass)	   (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HSTS_ENFORCER, SoupHSTSEnforcerClass))
#define SOUP_IS_HSTS_ENFORCER(obj)	   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER))
#define SOUP_IS_HSTS_ENFORCER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER))
#define SOUP_HSTS_ENFORCER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HSTS_ENFORCER, SoupHSTSEnforcerClass))

typedef struct _SoupHSTSEnforcerPrivate SoupHSTSEnforcerPrivate;

struct _SoupHSTSEnforcer {
	GObject parent;

	SoupHSTSEnforcerPrivate *priv;
};

/**
 * SoupHSTSEnforcerClass:
 * @parent_class: The parent class.
 * @is_persistent: The @is_persistent function advertises whether the enforcer is persistent or
 * whether changes made to it will be lost when the underlying #SoupSession is finished.
 * @has_valid_policy: The @has_valid_policy function is called to check whether there is a valid
 * policy for the given domain. This method should return %TRUE for #SoupHSTSEnforcer to
 * change the scheme of the #SoupURI in the #SoupMessage to HTTPS. Implementations might want to
 * chain up to the @has_valid_policy in the parent class to check, for instance, for runtime
 * policies.
 * @changed: the class closure for the #SoupHSTSEnforcer::changed signal.
 **/
typedef struct {
	GObjectClass parent_class;

	gboolean (*is_persistent) (SoupHSTSEnforcer *hsts_enforcer);
	gboolean (*has_valid_policy) (SoupHSTSEnforcer *hsts_enforcer, const char *domain);

	/* signals */
	void (*changed) (SoupHSTSEnforcer *enforcer,
			 SoupHSTSPolicy	  *old_policy,
			 SoupHSTSPolicy	  *new_policy);

	void (*hsts_enforced) (SoupHSTSEnforcer *enforcer,
			       SoupMessage      *message);

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
	void (*_libsoup_reserved4) (void);
} SoupHSTSEnforcerClass;

SOUP_AVAILABLE_IN_2_68
GType		  soup_hsts_enforcer_get_type			   (void);
SOUP_AVAILABLE_IN_2_68
SoupHSTSEnforcer *soup_hsts_enforcer_new			   (void);
SOUP_AVAILABLE_IN_2_68
gboolean	  soup_hsts_enforcer_is_persistent		   (SoupHSTSEnforcer *hsts_enforcer);
SOUP_AVAILABLE_IN_2_68
gboolean	  soup_hsts_enforcer_has_valid_policy		   (SoupHSTSEnforcer *hsts_enforcer,
								    const char	     *domain);
SOUP_AVAILABLE_IN_2_68
void		  soup_hsts_enforcer_set_session_policy		   (SoupHSTSEnforcer *hsts_enforcer,
								    const char	     *domain,
								    gboolean	      include_subdomains);
SOUP_AVAILABLE_IN_2_68
void		  soup_hsts_enforcer_set_policy			   (SoupHSTSEnforcer *hsts_enforcer,
								    SoupHSTSPolicy   *policy);

SOUP_AVAILABLE_IN_2_68
GList            *soup_hsts_enforcer_get_domains                   (SoupHSTSEnforcer *hsts_enforcer,
								    gboolean          session_policies);

SOUP_AVAILABLE_IN_2_68
GList            *soup_hsts_enforcer_get_policies                  (SoupHSTSEnforcer *hsts_enforcer,
								    gboolean          session_policies);

G_END_DECLS

#endif /* __SOUP_HSTS_ENFORCER_H__ */
