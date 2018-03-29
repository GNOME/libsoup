/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __SOUP_GNOME_FEATURES_H__
#define __SOUP_GNOME_FEATURES_H__ 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

SOUP_AVAILABLE_IN_2_26
SOUP_DEPRECATED_IN_2_42_FOR(SoupSession:proxy-resolver)
GType soup_proxy_resolver_gnome_get_type (void);
#define SOUP_TYPE_PROXY_RESOLVER_GNOME (soup_proxy_resolver_gnome_get_type ())

SOUP_AVAILABLE_IN_2_26
SOUP_DEPRECATED_IN_2_42
GType soup_gnome_features_2_26_get_type (void);
#define SOUP_TYPE_GNOME_FEATURES_2_26 (soup_gnome_features_2_26_get_type ())

SOUP_AVAILABLE_IN_2_28
SOUP_DEPRECATED_IN_2_28
GType soup_password_manager_gnome_get_type (void);
#define SOUP_TYPE_PASSWORD_MANAGER_GNOME (soup_password_manager_gnome_get_type ())

G_END_DECLS

#endif /* __SOUP_GNOME_FEATURES_H__ */
