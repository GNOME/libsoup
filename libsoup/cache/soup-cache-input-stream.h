/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-cache-input-stream.h - Header for SoupCacheInputStream
 */

#pragma once

#include "soup-filter-input-stream.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHE_INPUT_STREAM		(soup_cache_input_stream_get_type())
G_DECLARE_FINAL_TYPE (SoupCacheInputStream, soup_cache_input_stream, SOUP, CACHE_INPUT_STREAM, SoupFilterInputStream)

GInputStream *soup_cache_input_stream_new (GInputStream *base_stream,
					   GFile        *file);

G_END_DECLS
