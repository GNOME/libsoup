/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cached-resolver.h:
 *
 * Copyright (C) 2019 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#pragma once

#include <gio/gio.h>
#include "soup-version.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHED_RESOVLER (soup_cached_resolver_get_type())
G_DECLARE_FINAL_TYPE (SoupCachedResolver, soup_cached_resolver, SOUP, CACHED_RESOLVER, GResolver)

SOUP_AVAILABLE_IN_2_66
void soup_cached_resolver_ensure_default (void);

SOUP_AVAILABLE_IN_2_66
SoupCachedResolver *soup_cached_resolver_new (GResolver *wrapped_resolver);

G_END_DECLS
