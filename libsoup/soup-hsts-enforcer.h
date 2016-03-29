/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016 Igalia S.L.
 */

#ifndef SOUP_HSTS_ENFORCER_H
#define SOUP_HSTS_ENFORCER_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_HSTS_ENFORCER            (soup_hsts_enforcer_get_type ())
#define SOUP_HSTS_ENFORCER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HSTS_ENFORCER, SoupHstsEnforcer))
#define SOUP_HSTS_ENFORCER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HSTS_ENFORCER, SoupHstsEnforcerClass))
#define SOUP_IS_HSTS_ENFORCER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER))
#define SOUP_IS_HSTS_ENFORCER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HSTS_ENFORCER))
#define SOUP_HSTS_ENFORCER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HSTS_ENFORCER, SoupHstsEnforcerClass))

struct _SoupHstsEnforcer {
	GObject parent;

};

typedef struct {
	GObjectClass parent_class;

	gboolean (*is_persistent) (SoupHstsEnforcer *hsts_enforcer);

	/* signals */
	void (*changed) (SoupHstsEnforcer *jar,
			 SoupHstsPolicy   *old_policy,
			 SoupHstsPolicy   *new_policy);

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
} SoupHstsEnforcerClass;

SOUP_AVAILABLE_IN_2_54
GType             soup_hsts_enforcer_get_type                      (void);
SOUP_AVAILABLE_IN_2_54
SoupHstsEnforcer *soup_hsts_enforcer_new                           (void);
SOUP_AVAILABLE_IN_2_54
gboolean          soup_hsts_enforcer_is_persistent                 (SoupHstsEnforcer *hsts_enforcer);

SOUP_AVAILABLE_IN_2_54
void              soup_hsts_enforcer_set_session_policy            (SoupHstsEnforcer *hsts_enforcer,
								    const char       *domain,
								    gboolean          include_sub_domains);
G_END_DECLS

#endif /* SOUP_HSTS_ENFORCER_H */
