/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* url-util.h : utility functions to parse URLs */

/* 
 * Copyright 1999-2002 Ximian, Inc.
 */


#ifndef  SOUP_URI_H
#define  SOUP_URI_H 1

#include <glib.h>

typedef enum {
	SOUP_PROTOCOL_HTTP = 1,
	SOUP_PROTOCOL_HTTPS,
	SOUP_PROTOCOL_SMTP,
	SOUP_PROTOCOL_SOCKS4,
	SOUP_PROTOCOL_SOCKS5,
	SOUP_PROTOCOL_FILE
} SoupProtocol;

typedef struct {
	SoupProtocol        protocol;

	gchar              *user;
	gchar              *authmech;
	gchar              *passwd;

	gchar              *host;
	gint                port;

	gchar              *path;
	gchar              *querystring;
} SoupUri;

SoupUri *soup_uri_new       (const gchar   *uri_string);

gchar   *soup_uri_to_string (const SoupUri *uri, 
			     gboolean       show_password);

SoupUri *soup_uri_copy      (const SoupUri *uri);

gboolean soup_uri_equal     (const SoupUri *uri1, 
			     const SoupUri *uri2);

void     soup_uri_free      (SoupUri       *uri);

void     soup_uri_set_auth  (SoupUri       *uri, 
			     const gchar   *user, 
			     const gchar   *passwd, 
			     const gchar   *authmech);

#endif /*SOUP_URI_H*/
