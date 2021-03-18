/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/* 
 * Copyright 1999-2002 Ximian, Inc.
 */


#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

typedef enum {
	SOUP_URI_NONE,
	SOUP_URI_SCHEME,
	SOUP_URI_USER,
	SOUP_URI_PASSWORD,
	SOUP_URI_AUTH_PARAMS,
	SOUP_URI_HOST,
	SOUP_URI_PORT,
	SOUP_URI_PATH,
	SOUP_URI_QUERY,
	SOUP_URI_FRAGMENT
} SoupURIComponent;

SOUP_AVAILABLE_IN_ALL
GBytes     *soup_uri_decode_data_uri       (const char *uri,
					    char      **content_type);

SOUP_AVAILABLE_IN_ALL
gboolean soup_uri_equal (GUri *uri1, GUri *uri2);


SOUP_AVAILABLE_IN_ALL
GUri       *soup_uri_copy (GUri *uri,
			   SoupURIComponent first_component,
			   ...);

#define SOUP_HTTP_URI_FLAGS (G_URI_FLAGS_HAS_PASSWORD | G_URI_FLAGS_ENCODED_PATH | G_URI_FLAGS_ENCODED_QUERY | G_URI_FLAGS_ENCODED_FRAGMENT | G_URI_FLAGS_SCHEME_NORMALIZE)

G_END_DECLS
