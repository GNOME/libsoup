/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* url-util.h : utility functions to parse URLs */

/* 
 * Author : 
 *  Bertrand Guiheneuf <bertrand@helixcode.com>
 *
 * Copyright 1999, 2000 HelixCode (http://www.helixcode.com)
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */


#ifndef  SOUP_URI_H
#define  SOUP_URI_H 1

#include <glib.h>

typedef enum {
	SOUP_PROTOCOL_HTTP = 1,
	SOUP_PROTOCOL_HTTPS,
	SOUP_PROTOCOL_SMTP,
	SOUP_PROTOCOL_SOCKS4,
	SOUP_PROTOCOL_SOCKS5
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
	gchar             **query_elems;
} SoupUri;

SoupUri *soup_uri_new       (const gchar   *uri_string);

gchar   *soup_uri_to_string (const SoupUri *uri, 
			     gboolean       show_password);

SoupUri *soup_uri_copy      (const SoupUri *uri);

void     soup_uri_free      (SoupUri       *uri);

void     soup_uri_set_auth  (SoupUri       *uri, 
			     const gchar   *user, 
			     const gchar   *passwd, 
			     const gchar   *authmech);

#endif /*SOUP_URI_H*/
