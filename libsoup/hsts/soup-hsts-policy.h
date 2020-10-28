/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

typedef struct _SoupHSTSPolicy SoupHSTSPolicy;

SOUP_AVAILABLE_IN_2_68
GType		 soup_hsts_policy_get_type (void);
#define SOUP_TYPE_HSTS_POLICY (soup_hsts_policy_get_type())

#define SOUP_HSTS_POLICY_MAX_AGE_PAST (0)

SOUP_AVAILABLE_IN_2_68
SoupHSTSPolicy  *soup_hsts_policy_new			(const char	*domain,
							 unsigned long	 max_age,
							 gboolean	 include_subdomains);
SOUP_AVAILABLE_IN_2_68
SoupHSTSPolicy  *soup_hsts_policy_new_full		(const char	*domain,
							 unsigned long	 max_age,
							 GDateTime	*expires,
							 gboolean	 include_subdomains);
SOUP_AVAILABLE_IN_2_68
SoupHSTSPolicy  *soup_hsts_policy_new_session_policy	(const char	*domain,
							 gboolean	 include_subdomains);
SOUP_AVAILABLE_IN_2_68
SoupHSTSPolicy  *soup_hsts_policy_new_from_response	(SoupMessage	*msg);

SOUP_AVAILABLE_IN_2_68
SoupHSTSPolicy  *soup_hsts_policy_copy			(SoupHSTSPolicy *policy);
SOUP_AVAILABLE_IN_2_68
gboolean	 soup_hsts_policy_equal			(SoupHSTSPolicy *policy1,
							 SoupHSTSPolicy *policy2);
SOUP_AVAILABLE_IN_2_68
const char	*soup_hsts_policy_get_domain		(SoupHSTSPolicy *policy);
SOUP_AVAILABLE_IN_2_68
gboolean	 soup_hsts_policy_is_expired		(SoupHSTSPolicy *policy);
SOUP_AVAILABLE_IN_2_68
gboolean	 soup_hsts_policy_includes_subdomains 	(SoupHSTSPolicy *policy);
SOUP_AVAILABLE_IN_2_68
gboolean	 soup_hsts_policy_is_session_policy	(SoupHSTSPolicy *policy);

SOUP_AVAILABLE_IN_2_68
void		 soup_hsts_policy_free			(SoupHSTSPolicy *policy);

SOUP_AVAILABLE_IN_ALL
GDateTime       *soup_hsts_policy_get_expires           (SoupHSTSPolicy *policy);

SOUP_AVAILABLE_IN_ALL
gulong           soup_hsts_policy_get_max_age           (SoupHSTSPolicy *policy);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (SoupHSTSPolicy, soup_hsts_policy_free)

G_END_DECLS
