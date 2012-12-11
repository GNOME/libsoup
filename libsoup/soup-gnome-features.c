/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-gnome-features.c: GNOME-specific features
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-gnome-features.h"

GType
soup_gnome_features_2_26_get_type (void)
{
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	return SOUP_TYPE_PROXY_RESOLVER_GNOME;
	G_GNUC_END_IGNORE_DEPRECATIONS;
}

