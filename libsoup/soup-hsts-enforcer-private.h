/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2016, 2017, 2018 Igalia S.L.
 * Copyright (C) 2017, 2018 Metrological Group B.V.
 */

#ifndef SOUP_HSTS_ENFORCER_PRIVATE_H
#define SOUP_HSTS_ENFORCER_PRIVATE_H 1

#include <libsoup/soup-types.h>

void soup_hsts_enforcer_set_policy (SoupHSTSEnforcer  *hsts_enforcer,
				    SoupHSTSPolicy    *policy);

#endif /* SOUP_HSTS_ENFORCER_PRIVATE_H */
