/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth.h: Authentication schemes
 *
 * Authors:
 *      Joe Shaw (joe@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifndef SOUP_AUTH_H
#define SOUP_AUTH_H 1

#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-misc.h>

typedef   enum _SoupAuthStatus SoupAuthStatus;
typedef struct _SoupAuth       SoupAuth;

struct _SoupAuth {
	SoupAuthType    type;
	char           *realm;
	gboolean        authenticated;

	void     (*parse_func)      (SoupAuth      *auth,
				     const gchar   *header);

	void     (*init_func)       (SoupAuth      *auth, 
				     const SoupUri *uri);

	gboolean (*invalidate_func) (SoupAuth      *auth);

	char    *(*auth_func)       (SoupAuth      *auth, 
				     SoupMessage   *message);

	GSList  *(*pspace_func)     (SoupAuth      *auth,
				     const SoupUri *source_uri);

	void     (*free_func)       (SoupAuth      *auth);
};

SoupAuth   *soup_auth_new_from_header_list  (const SoupUri *uri,
					     const GSList  *header);

SoupAuth   *soup_auth_new_ntlm              (void);

void        soup_auth_initialize            (SoupAuth      *auth,
					     const SoupUri *uri);

gboolean    soup_auth_invalidate            (SoupAuth      *auth);

void        soup_auth_free                  (SoupAuth      *auth);

gchar      *soup_auth_authorize             (SoupAuth      *auth, 
					     SoupMessage   *msg);

GSList     *soup_auth_get_protection_space  (SoupAuth      *auth,
					     const SoupUri *source_uri);
void        soup_auth_free_protection_space (SoupAuth      *auth,
					     GSList        *space);


#endif /* SOUP_AUTH_H */
