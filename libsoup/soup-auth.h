/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth.h: Authentication schemes
 *
 * Authors:
 *      Joe Shaw (joe@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef SOUP_AUTH_H
#define SOUP_AUTH_H 1

#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-misc.h>

typedef struct _SoupAuth SoupAuth;
struct _SoupAuth {
	SoupAuthType  type;
	gchar        *realm;

	gboolean (*compare_func) (SoupAuth      *a, 
				  SoupAuth      *b);

	void     (*parse_func)   (SoupAuth      *auth,
				  const gchar   *header);

	void     (*init_func)    (SoupAuth      *auth, 
				  const SoupUri *uri);

	char    *(*auth_func)    (SoupAuth      *auth, 
				  SoupMessage   *message);

	void     (*free_func)    (SoupAuth      *auth);
};

SoupAuth *soup_auth_lookup                 (SoupContext   *ctx);

void      soup_auth_set_context            (SoupAuth      *auth,
					    SoupContext   *ctx);

SoupAuth *soup_auth_new_from_header_list   (const SoupUri *uri,
					    const GSList  *header);

void      soup_auth_initialize             (SoupAuth      *auth,
					    const SoupUri *uri);

void      soup_auth_free                   (SoupAuth      *auth);

gchar    *soup_auth_authorize              (SoupAuth      *auth, 
					    SoupMessage   *msg);

gboolean  soup_auth_invalidates_prior      (SoupAuth      *new_auth, 
					    SoupAuth      *old_auth);

#endif /* SOUP_AUTH_H */
