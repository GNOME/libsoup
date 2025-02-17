/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_MISC_H__
#define __SOUP_MISC_H__ 1

#include "soup-types.h"
#include "soup-message.h"
#include "soup-message-headers.h"

G_BEGIN_DECLS

/* Non-default-GMainContext operations */
void               soup_add_completion	     (GMainContext *async_context,
					      GSourceFunc   function,
					      gpointer      data);
GSource           *soup_add_completion_reffed (GMainContext   *async_context,
                                               GSourceFunc     function,
                                               gpointer        data,
                                               GDestroyNotify  dnotify);
GSource           *soup_add_timeout          (GMainContext *async_context,
					      guint         interval,
					      GSourceFunc   function,
					      gpointer      data);
GMainContext      *soup_thread_default_context (void);

/* Misc utils */

guint              soup_str_case_hash        (gconstpointer key);
gboolean           soup_str_case_equal       (gconstpointer v1,
					      gconstpointer v2);

/* character classes */

extern const char soup_char_attributes[];
#define SOUP_CHAR_URI_PERCENT_ENCODED 0x01
#define SOUP_CHAR_URI_GEN_DELIMS      0x02
#define SOUP_CHAR_URI_SUB_DELIMS      0x04
#define SOUP_CHAR_HTTP_SEPARATOR      0x08
#define SOUP_CHAR_HTTP_CTL            0x10

#define soup_char_is_uri_percent_encoded(ch) (soup_char_attributes[(guchar)(ch)] & SOUP_CHAR_URI_PERCENT_ENCODED)
#define soup_char_is_uri_gen_delims(ch)      (soup_char_attributes[(guchar)(ch)] & SOUP_CHAR_URI_GEN_DELIMS)
#define soup_char_is_uri_sub_delims(ch)      (soup_char_attributes[(guchar)(ch)] & SOUP_CHAR_URI_SUB_DELIMS)
#define soup_char_is_uri_unreserved(ch)      (!(soup_char_attributes[(guchar)(ch)] & (SOUP_CHAR_URI_PERCENT_ENCODED | SOUP_CHAR_URI_GEN_DELIMS | SOUP_CHAR_URI_SUB_DELIMS)))
#define soup_char_is_token(ch)               (!(soup_char_attributes[(guchar)(ch)] & (SOUP_CHAR_HTTP_SEPARATOR | SOUP_CHAR_HTTP_CTL)))

/* At some point it might be possible to mark additional methods
 * safe or idempotent...
 */
#define SOUP_METHOD_IS_SAFE(method) ((method) == SOUP_METHOD_GET || \
				     (method) == SOUP_METHOD_HEAD || \
				     (method) == SOUP_METHOD_OPTIONS || \
				     (method) == SOUP_METHOD_PROPFIND || \
				     (method) == SOUP_METHOD_TRACE)

#define SOUP_METHOD_IS_IDEMPOTENT(method) ((method) == SOUP_METHOD_GET || \
					   (method) == SOUP_METHOD_HEAD || \
					   (method) == SOUP_METHOD_OPTIONS || \
					   (method) == SOUP_METHOD_PROPFIND || \
					   (method) == SOUP_METHOD_TRACE || \
					   (method) == SOUP_METHOD_PUT || \
					   (method) == SOUP_METHOD_DELETE)

guint soup_message_headers_get_ranges_internal (SoupMessageHeaders  *hdrs,
						goffset              total_length,
						gboolean             check_satisfiable,
						SoupRange          **ranges,
						int                 *length);

gboolean           soup_host_matches_host    (const gchar *host,
					      const gchar *compare_with);

gchar *soup_get_accept_languages_from_system (void);

const char *soup_http_version_to_string (SoupHTTPVersion version);

G_END_DECLS

#endif /* __SOUP_MISC_H__ */
