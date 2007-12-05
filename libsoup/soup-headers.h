/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifndef SOUP_HEADERS_H
#define SOUP_HEADERS_H 1

#include <glib.h>
#include <libsoup/soup-message.h>

G_BEGIN_DECLS

/* HTTP Header Parsing */

guint       soup_headers_parse_request      (const char          *str,
					     int                  len,
					     SoupMessageHeaders  *req_headers,
					     char               **req_method,
					     char               **req_path,
					     SoupHTTPVersion     *ver);

gboolean    soup_headers_parse_status_line  (const char          *status_line,
					     SoupHTTPVersion     *ver,
					     guint               *status_code,
					     char               **reason_phrase);

gboolean    soup_headers_parse_response     (const char          *str,
					     int                  len,
					     SoupMessageHeaders  *headers,
					     SoupHTTPVersion     *ver,
					     guint               *status_code,
					     char               **reason_phrase);

/* HTTP parameterized header parsing */

char       *soup_header_param_decode_token  (char            **in);

GHashTable *soup_header_param_parse_list    (const char       *header);

char       *soup_header_param_copy_token    (GHashTable       *tokens, 
					     char             *t);

void        soup_header_param_destroy_hash  (GHashTable       *table);

G_END_DECLS

#endif /*SOUP_HEADERS_H*/
