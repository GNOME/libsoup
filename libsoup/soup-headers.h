/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-headers.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef SOUP_HEADERS_H
#define SOUP_HEADERS_H 1

#include <glib.h>
#include <libsoup/soup-message.h>

/* HTTP Header Parsing */

gboolean       soup_headers_parse_request  (gchar            *str, 
					    gint              len, 
					    GHashTable       *dest, 
					    gchar           **req_method,
					    gchar           **req_path,
					    SoupHttpVersion  *ver);

gboolean       soup_headers_parse_response (gchar            *str, 
					    gint              len, 
					    GHashTable       *dest,
					    SoupHttpVersion  *ver,
					    guint            *status_code,
					    gchar           **status_phrase);

#endif /*SOUP_HEADERS_H*/
