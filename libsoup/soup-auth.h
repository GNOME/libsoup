/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifndef SOUP_AUTH_H
#define SOUP_AUTH_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-headers.h>

#define SOUP_TYPE_AUTH            (soup_auth_get_type ())
#define SOUP_AUTH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_AUTH, SoupAuth))
#define SOUP_AUTH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH, SoupAuthClass))
#define SOUP_IS_AUTH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_AUTH))
#define SOUP_IS_AUTH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_AUTH))
#define SOUP_AUTH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH, SoupAuthClass))

typedef struct {
	GObject parent;

	char *realm;
} SoupAuth;

typedef struct {
	GObjectClass parent_class;

	const char *scheme_name;

	void         (*construct)            (SoupAuth      *auth,
					      GHashTable    *auth_params);

	GSList *     (*get_protection_space) (SoupAuth      *auth,
					      const SoupUri *source_uri);

	void         (*authenticate)         (SoupAuth      *auth,
					      const char    *username,
					      const char    *password);
	gboolean     (*is_authenticated)     (SoupAuth      *auth);

	char *       (*get_authorization)    (SoupAuth      *auth,
					      SoupMessage   *msg);
} SoupAuthClass;

GType       soup_auth_get_type              (void);


SoupAuth   *soup_auth_new_from_headers      (SoupMessageHeaders *hdrs,
					     const char    *header_name);

const char *soup_auth_get_scheme_name       (SoupAuth      *auth);
const char *soup_auth_get_realm             (SoupAuth      *auth);
char       *soup_auth_get_info              (SoupAuth      *auth);

void        soup_auth_authenticate          (SoupAuth      *auth,
					     const char    *username,
					     const char    *password);
gboolean    soup_auth_is_authenticated      (SoupAuth      *auth);

char       *soup_auth_get_authorization     (SoupAuth      *auth, 
					     SoupMessage   *msg);

GSList     *soup_auth_get_protection_space  (SoupAuth      *auth,
					     const SoupUri *source_uri);
void        soup_auth_free_protection_space (SoupAuth      *auth,
					     GSList        *space);

#endif /* SOUP_AUTH_H */
