/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011 Igalia, S.L.
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef __SOUP_MISC_PRIVATE_H__
#define __SOUP_MISC_PRIVATE_H__ 1

#include "soup-message-headers.h"

char *soup_uri_decoded_copy (const char *str, int length, int *decoded_length);
char *soup_uri_to_string_internal (SoupURI *uri, gboolean just_path_and_query,
				   gboolean include_password, gboolean force_port);
gboolean soup_uri_is_http (SoupURI *uri, char **aliases);
gboolean soup_uri_is_https (SoupURI *uri, char **aliases);

/* At some point it might be possible to mark additional methods
 * safe or idempotent...
 */
#define SOUP_METHOD_IS_SAFE(method) (method == SOUP_METHOD_GET || \
				     method == SOUP_METHOD_HEAD || \
				     method == SOUP_METHOD_OPTIONS || \
				     method == SOUP_METHOD_PROPFIND || \
				     method == SOUP_METHOD_TRACE)

#define SOUP_METHOD_IS_IDEMPOTENT(method) (method == SOUP_METHOD_GET || \
					   method == SOUP_METHOD_HEAD || \
					   method == SOUP_METHOD_OPTIONS || \
					   method == SOUP_METHOD_PROPFIND || \
					   method == SOUP_METHOD_TRACE || \
					   method == SOUP_METHOD_PUT || \
					   method == SOUP_METHOD_DELETE)

GSource *soup_add_completion_reffed (GMainContext   *async_context,
				     GSourceFunc     function,
				     gpointer        data,
				     GDestroyNotify  dnotify);

guint soup_message_headers_get_ranges_internal (SoupMessageHeaders  *hdrs,
						goffset              total_length,
						gboolean             check_satisfiable,
						SoupRange          **ranges,
						int                 *length);

SoupAddress *soup_address_new_from_gsockaddr (GSocketAddress *addr);

gboolean           soup_host_matches_host    (const gchar *host,
					      const gchar *compare_with);

#endif /* __SOUP_MISC_PRIVATE_H__ */
