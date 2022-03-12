/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-cache-private.h:
 *
 * Copyright (C) 2010 Igalia, S.L.
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

#include "cache/soup-cache.h"
#include "soup-message.h"

G_BEGIN_DECLS

typedef enum {
	SOUP_CACHE_RESPONSE_FRESH,
	SOUP_CACHE_RESPONSE_NEEDS_VALIDATION,
	SOUP_CACHE_RESPONSE_STALE
} SoupCacheResponse;

SoupCacheResponse  soup_cache_has_response                    (SoupCache   *cache,
							       SoupMessage *msg);
GInputStream      *soup_cache_send_response                   (SoupCache   *cache,
							       SoupMessage *msg);
SoupCacheability   soup_cache_get_cacheability                (SoupCache   *cache,
							       SoupMessage *msg);
SoupMessage       *soup_cache_generate_conditional_request    (SoupCache   *cache,
							       SoupMessage *original);
void               soup_cache_cancel_conditional_request      (SoupCache   *cache,
							       SoupMessage *msg);
void               soup_cache_update_from_conditional_request (SoupCache   *cache,
							       SoupMessage *msg);

G_END_DECLS
