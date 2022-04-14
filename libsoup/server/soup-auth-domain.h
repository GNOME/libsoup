/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH_DOMAIN (soup_auth_domain_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupAuthDomain, soup_auth_domain, SOUP, AUTH_DOMAIN, GObject)

struct _SoupAuthDomainClass {
	GObjectClass parent_class;

	char *   (*accepts)        (SoupAuthDomain    *domain,
				    SoupServerMessage *msg,
				    const char        *header);
	char *   (*challenge)      (SoupAuthDomain    *domain,
				    SoupServerMessage *msg);
	gboolean (*check_password) (SoupAuthDomain    *domain,
				    SoupServerMessage *msg,
				    const char        *username,
				    const char        *password);
	gpointer padding[6];
};

typedef gboolean (*SoupAuthDomainFilter) (SoupAuthDomain    *domain,
					  SoupServerMessage *msg,
					  gpointer           user_data);

typedef gboolean (*SoupAuthDomainGenericAuthCallback) (SoupAuthDomain    *domain,
						       SoupServerMessage *msg,
						       const char        *username,
						       gpointer           user_data);

SOUP_AVAILABLE_IN_ALL
void        soup_auth_domain_add_path    (SoupAuthDomain       *domain,
					  const char           *path);
SOUP_AVAILABLE_IN_ALL
void        soup_auth_domain_remove_path (SoupAuthDomain       *domain,
					  const char           *path);

SOUP_AVAILABLE_IN_ALL
void        soup_auth_domain_set_filter  (SoupAuthDomain       *domain,
					  SoupAuthDomainFilter  filter,
					  gpointer              filter_data,
					  GDestroyNotify        dnotify);

SOUP_AVAILABLE_IN_ALL
const char *soup_auth_domain_get_realm   (SoupAuthDomain       *domain);

SOUP_AVAILABLE_IN_ALL
void        soup_auth_domain_set_generic_auth_callback (SoupAuthDomain *domain,
							SoupAuthDomainGenericAuthCallback auth_callback,
							gpointer        auth_data,
							GDestroyNotify  dnotify);
SOUP_AVAILABLE_IN_ALL
gboolean    soup_auth_domain_check_password (SoupAuthDomain    *domain,
					     SoupServerMessage *msg,
					     const char        *username,
					     const char        *password);

SOUP_AVAILABLE_IN_ALL
gboolean    soup_auth_domain_covers      (SoupAuthDomain       *domain,
					  SoupServerMessage    *msg);
SOUP_AVAILABLE_IN_ALL
char       *soup_auth_domain_accepts     (SoupAuthDomain       *domain,
					  SoupServerMessage    *msg);
SOUP_AVAILABLE_IN_ALL
void        soup_auth_domain_challenge   (SoupAuthDomain       *domain,
					  SoupServerMessage    *msg);

G_END_DECLS
