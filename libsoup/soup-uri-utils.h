/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

/* 
 * Copyright 1999-2002 Ximian, Inc.
 */


#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

SOUP_AVAILABLE_IN_ALL
GBytes     *soup_uri_decode_data_uri       (const char *uri,
					    char      **content_type);

SOUP_AVAILABLE_IN_ALL
gboolean soup_uri_equal (GUri *uri1, GUri *uri2);

SOUP_AVAILABLE_IN_ALL
GUri       *soup_uri_copy_with_query_from_form   (GUri       *uri,
                                                  GHashTable *form);

SOUP_AVAILABLE_IN_ALL
GUri       *soup_uri_copy_with_query_from_fields (GUri       *uri,
                                                  const char *first_field,
                                                  ...) G_GNUC_NULL_TERMINATED;

SOUP_AVAILABLE_IN_ALL
int          soup_uri_get_port_with_default      (GUri       *uri);

#define SOUP_HTTP_URI_FLAGS (G_URI_FLAGS_HAS_PASSWORD | G_URI_FLAGS_ENCODED_PATH | G_URI_FLAGS_ENCODED_QUERY | G_URI_FLAGS_ENCODED_FRAGMENT | G_URI_FLAGS_SCHEME_NORMALIZE)

G_END_DECLS
