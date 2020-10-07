/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#pragma once

#include "soup-auth-domain.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH_DOMAIN_BASIC (soup_auth_domain_basic_get_type ())
SOUP_AVAILABLE_IN_2_4
G_DECLARE_FINAL_TYPE (SoupAuthDomainBasic, soup_auth_domain_basic, SOUP, AUTH_DOMAIN_BASIC, SoupAuthDomain)

#define SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK "auth-callback"
#define SOUP_AUTH_DOMAIN_BASIC_AUTH_DATA     "auth-data"

SOUP_AVAILABLE_IN_2_4
SoupAuthDomain *soup_auth_domain_basic_new (const char *optname1,
					    ...) G_GNUC_NULL_TERMINATED;

typedef	gboolean (*SoupAuthDomainBasicAuthCallback) (SoupAuthDomain *domain,
						     SoupMessage    *msg,
						     const char     *username,
						     const char     *password,
						     gpointer        user_data);

SOUP_AVAILABLE_IN_2_4
void      soup_auth_domain_basic_set_auth_callback  (SoupAuthDomain *domain,
						     SoupAuthDomainBasicAuthCallback callback,
						     gpointer        user_data,
						     GDestroyNotify  dnotify);

G_END_DECLS
