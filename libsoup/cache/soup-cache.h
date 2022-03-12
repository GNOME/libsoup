/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-cache.h:
 *
 * Copyright (C) 2009, 2010 Igalia, S.L.
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

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHE (soup_cache_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupCache, soup_cache, SOUP, CACHE, GObject)

typedef enum {
	SOUP_CACHE_CACHEABLE = (1 << 0),
	SOUP_CACHE_UNCACHEABLE = (1 << 1),
	SOUP_CACHE_INVALIDATES = (1 << 2),
	SOUP_CACHE_VALIDATES = (1 << 3)
} SoupCacheability;

typedef enum {
	SOUP_CACHE_SINGLE_USER,
	SOUP_CACHE_SHARED
} SoupCacheType;

struct _SoupCacheClass {
	GObjectClass parent_class;

	/* methods */
	SoupCacheability (*get_cacheability) (SoupCache   *cache,
					      SoupMessage *msg);
        gpointer padding[4];
};

SOUP_AVAILABLE_IN_ALL
SoupCache *soup_cache_new          (const char    *cache_dir,
				    SoupCacheType  cache_type);
SOUP_AVAILABLE_IN_ALL
void       soup_cache_flush        (SoupCache     *cache);
SOUP_AVAILABLE_IN_ALL
void       soup_cache_clear        (SoupCache     *cache);

SOUP_AVAILABLE_IN_ALL
void       soup_cache_dump         (SoupCache     *cache);
SOUP_AVAILABLE_IN_ALL
void       soup_cache_load         (SoupCache     *cache);

SOUP_AVAILABLE_IN_ALL
void       soup_cache_set_max_size (SoupCache     *cache,
				    guint          max_size);
SOUP_AVAILABLE_IN_ALL
guint      soup_cache_get_max_size (SoupCache     *cache);

G_END_DECLS
