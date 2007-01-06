/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifndef SOUP_HEADERS_H
#define SOUP_HEADERS_H 1

#include <glib.h>
#include <libsoup/soup-message.h>

/* HTTP Header Parsing */

gboolean    soup_headers_parse_request      (const char       *str, 
					     int               len, 
					     GHashTable       *dest, 
					     char            **req_method,
					     char            **req_path,
					     SoupHttpVersion  *ver);

gboolean    soup_headers_parse_status_line  (const char        *status_line,
					     SoupHttpVersion  *ver,
					     guint            *status_code,
					     char            **reason_phrase);

gboolean    soup_headers_parse_response     (const char       *str, 
					     int               len, 
					     GHashTable       *dest,
					     SoupHttpVersion  *ver,
					     guint            *status_code,
					     char            **reason_phrase);

/* HTTP parameterized header parsing */

char       *soup_header_param_decode_token  (char            **in);

GHashTable *soup_header_param_parse_list    (const char       *header);

char       *soup_header_param_copy_token    (GHashTable       *tokens, 
					     char             *t);

void        soup_header_param_destroy_hash  (GHashTable       *table);

#endif /*SOUP_HEADERS_H*/
