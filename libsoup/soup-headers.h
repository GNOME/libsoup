/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-headers.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_HEADERS_H
#define SOUP_HEADERS_H 1

#include <glib.h>

gboolean soup_parse_request_headers  (gchar       *str, 
				      gint         len, 
				      GHashTable  *dest, 
				      gchar      **req_method,
				      gchar      **req_path);

gboolean soup_parse_response_headers (gchar       *str, 
				      gint         len, 
				      GHashTable  *dest, 
				      guint       *status_code,
				      gchar      **status_phrase);

#endif /*SOUP_HEADERS_H*/
