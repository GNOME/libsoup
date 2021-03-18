/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#pragma once

#include "soup-auth-domain.h"

G_BEGIN_DECLS

#define SOUP_TYPE_AUTH_DOMAIN_DIGEST (soup_auth_domain_digest_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupAuthDomainDigest, soup_auth_domain_digest, SOUP, AUTH_DOMAIN_DIGEST, SoupAuthDomain)

SOUP_AVAILABLE_IN_ALL
SoupAuthDomain *soup_auth_domain_digest_new (const char *optname1,
					    ...) G_GNUC_NULL_TERMINATED;

typedef	char * (*SoupAuthDomainDigestAuthCallback) (SoupAuthDomain    *domain,
						    SoupServerMessage *msg,
						    const char        *username,
						    gpointer           user_data);

SOUP_AVAILABLE_IN_ALL
void    soup_auth_domain_digest_set_auth_callback  (SoupAuthDomain *domain,
						    SoupAuthDomainDigestAuthCallback callback,
						    gpointer        user_data,
						    GDestroyNotify  dnotify);

SOUP_AVAILABLE_IN_ALL
char   *soup_auth_domain_digest_encode_password    (const char     *username,
						    const char     *realm,
						    const char     *password);

G_END_DECLS
