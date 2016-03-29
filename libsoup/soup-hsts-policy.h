/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016 Igalia S.L.
 */

#ifndef SOUP_HSTS_POLICY_H
#define SOUP_HSTS_POLICY_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

struct _SoupHstsPolicy {
	char                 *domain;
	SoupDate             *expires;
	gboolean              include_sub_domains;
};

SOUP_AVAILABLE_IN_2_54
GType soup_hsts_policy_get_type (void);
#define SOUP_TYPE_HSTS_POLICY (soup_hsts_policy_get_type())

#define SOUP_HSTS_POLICY_MAX_AGE_PAST (0)

SOUP_AVAILABLE_IN_2_54
SoupHstsPolicy *soup_hsts_policy_new		(const char *domain,
						 SoupDate   *expiry_date,
						 gboolean    include_sub_domains);
SOUP_AVAILABLE_IN_2_54
SoupHstsPolicy *soup_hsts_policy_new_with_max_age	(const char *domain,
							 int         max_age,
							 gboolean    include_sub_domains);
SOUP_AVAILABLE_IN_2_54
SoupHstsPolicy *soup_hsts_policy_new_permanent		(const char *domain,
							 gboolean    include_sub_domains);
SOUP_AVAILABLE_IN_2_54
SoupHstsPolicy *soup_hsts_policy_new_from_response	(SoupMessage *msg);

SOUP_AVAILABLE_IN_2_54
SoupHstsPolicy *soup_hsts_policy_copy           (SoupHstsPolicy *policy);
SOUP_AVAILABLE_IN_2_54
gboolean soup_hsts_policy_equal                 (SoupHstsPolicy *policy1,
                                                 SoupHstsPolicy *policy2);

SOUP_AVAILABLE_IN_2_54
const char *soup_hsts_policy_get_domain         (SoupHstsPolicy *policy);
SOUP_AVAILABLE_IN_2_54
gboolean    soup_hsts_policy_is_expired         (SoupHstsPolicy *policy);
SOUP_AVAILABLE_IN_2_54
gboolean    soup_hsts_policy_includes_sub_domains       (SoupHstsPolicy *policy);
SOUP_AVAILABLE_IN_2_54
gboolean    soup_hsts_policy_is_permanent       (SoupHstsPolicy *policy);

SOUP_AVAILABLE_IN_2_54
void        soup_hsts_policy_free               (SoupHstsPolicy *policy);

G_END_DECLS

#endif /* SOUP_HSTS_POLICY_H */
