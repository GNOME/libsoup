/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2015 Igalia S.L.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CACHE_CLIENT_INPUT_STREAM            (soup_cache_client_input_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupCacheClientInputStream, soup_cache_client_input_stream, SOUP, CACHE_CLIENT_INPUT_STREAM, GFilterInputStream)

GInputStream *soup_cache_client_input_stream_new (GInputStream *base_stream);

G_END_DECLS
