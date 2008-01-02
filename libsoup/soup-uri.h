/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

/* 
 * Copyright 1999-2002 Ximian, Inc.
 */


#ifndef  SOUP_URI_H
#define  SOUP_URI_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

struct SoupURI {
	const char *scheme;

	char       *user;
	char       *password;

	char       *host;
	guint       port;

	char       *path;
	char       *query;

	char       *fragment;
};

GType     soup_uri_get_type          (void);
#define SOUP_TYPE_URI (soup_uri_get_type ())

SoupURI  *soup_uri_new_with_base     (SoupURI    *base,
				      const char *uri_string);
SoupURI  *soup_uri_new               (const char *uri_string);

char     *soup_uri_to_string         (SoupURI    *uri, 
				      gboolean    just_path);

SoupURI  *soup_uri_copy              (SoupURI    *uri);

gboolean  soup_uri_equal             (SoupURI    *uri1, 
				      SoupURI    *uri2);

void      soup_uri_free              (SoupURI    *uri);

char     *soup_uri_encode            (const char *part,
				      const char *escape_extra);
gboolean  soup_uri_decode            (char       *part);
gboolean  soup_uri_normalize         (char       *part,
				      const char *unescape_extra);

gboolean  soup_uri_uses_default_port (SoupURI    *uri);
gboolean  soup_uri_is_https          (SoupURI    *uri);

G_END_DECLS

#endif /*SOUP_URI_H*/
