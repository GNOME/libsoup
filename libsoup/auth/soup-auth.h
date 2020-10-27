/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-headers.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH (soup_auth_get_type())
SOUP_AVAILABLE_IN_2_4
G_DECLARE_DERIVABLE_TYPE (SoupAuth, soup_auth, SOUP, AUTH, GObject)

struct _SoupAuthClass {
	GObjectClass parent_class;

	const char  *scheme_name;
	guint        strength;

	gboolean     (*update)               (SoupAuth      *auth,
					      SoupMessage   *msg,
					      GHashTable    *auth_header);

	GSList *     (*get_protection_space) (SoupAuth      *auth,
					      SoupURI       *source_uri);

	void         (*authenticate)         (SoupAuth      *auth,
					      const char    *username,
					      const char    *password);
	gboolean     (*is_authenticated)     (SoupAuth      *auth);

	char *       (*get_authorization)    (SoupAuth      *auth,
					      SoupMessage   *msg);

	gboolean     (*is_ready)             (SoupAuth      *auth,
					      SoupMessage   *msg);

	gboolean     (*can_authenticate)     (SoupAuth      *auth);

	gpointer padding[6];
};

SOUP_AVAILABLE_IN_2_4
SoupAuth   *soup_auth_new                   (GType          type,
					     SoupMessage   *msg,
					     const char    *auth_header);
SOUP_AVAILABLE_IN_2_4
gboolean    soup_auth_update                (SoupAuth      *auth,
					     SoupMessage   *msg,
					     const char    *auth_header);

SOUP_AVAILABLE_IN_2_4
gboolean    soup_auth_is_for_proxy          (SoupAuth      *auth);
SOUP_AVAILABLE_IN_2_4
const char *soup_auth_get_scheme_name       (SoupAuth      *auth);
SOUP_AVAILABLE_IN_2_4
const char *soup_auth_get_host              (SoupAuth      *auth);
SOUP_AVAILABLE_IN_2_4
const char *soup_auth_get_realm             (SoupAuth      *auth);
SOUP_AVAILABLE_IN_2_4
char       *soup_auth_get_info              (SoupAuth      *auth);

SOUP_AVAILABLE_IN_2_4
void        soup_auth_authenticate          (SoupAuth      *auth,
					     const char    *username,
					     const char    *password);
SOUP_AVAILABLE_IN_2_4
gboolean    soup_auth_is_authenticated      (SoupAuth      *auth);
SOUP_AVAILABLE_IN_2_42
gboolean    soup_auth_is_ready              (SoupAuth      *auth,
					     SoupMessage   *msg);
SOUP_AVAILABLE_IN_2_54
gboolean    soup_auth_can_authenticate      (SoupAuth      *auth);

SOUP_AVAILABLE_IN_2_4
char       *soup_auth_get_authorization     (SoupAuth      *auth, 
					     SoupMessage   *msg);

SOUP_AVAILABLE_IN_2_4
GSList     *soup_auth_get_protection_space  (SoupAuth      *auth,
					     SoupURI       *source_uri);
SOUP_AVAILABLE_IN_2_4
void        soup_auth_free_protection_space (SoupAuth      *auth,
					     GSList        *space);

SOUP_AVAILABLE_IN_2_54
gboolean    soup_auth_negotiate_supported   (void);

G_END_DECLS
