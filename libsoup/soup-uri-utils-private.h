/* 
 * Copyright 1999-2002 Ximian, Inc.
 * Copyright 2020 Igalia, S.L.
 */


#pragma once

#include "soup-uri-utils.h"

G_BEGIN_DECLS

gboolean     soup_uri_is_http               (GUri       *uri);

gboolean     soup_uri_is_https              (GUri       *uri);

gboolean     soup_uri_uses_default_port     (GUri       *uri);

char        *soup_uri_get_path_and_query    (GUri       *uri);

GUri        *soup_uri_copy_host             (GUri       *uri);

guint        soup_uri_host_hash             (gconstpointer key);

gboolean     soup_uri_host_equal            (gconstpointer v1, gconstpointer v2);

GUri        *soup_uri_copy_with_normalized_flags (GUri  *uri);

char        *soup_uri_get_host_for_headers  (GUri       *uri);

#define SOUP_URI_IS_VALID(x) ((x) && g_uri_get_host(x) && g_uri_get_host(x)[0])

G_END_DECLS
