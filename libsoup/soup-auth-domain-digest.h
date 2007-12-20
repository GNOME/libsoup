/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#ifndef SOUP_AUTH_DOMAIN_DIGEST_H
#define SOUP_AUTH_DOMAIN_DIGEST_H 1

#include <libsoup/soup-auth-domain.h>

#define SOUP_TYPE_AUTH_DOMAIN_DIGEST            (soup_auth_domain_digest_get_type ())
#define SOUP_AUTH_DOMAIN_DIGEST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_AUTH_DOMAIN_DIGEST, SoupAuthDomainDigest))
#define SOUP_AUTH_DOMAIN_DIGEST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_DOMAIN_DIGEST, SoupAuthDomainDigestClass))
#define SOUP_IS_AUTH_DOMAIN_DIGEST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_AUTH_DOMAIN_DIGEST))
#define SOUP_IS_AUTH_DOMAIN_DIGEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_AUTH_DOMAIN_DIGEST))
#define SOUP_AUTH_DOMAIN_DIGEST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_DOMAIN_DIGEST, SoupAuthDomainDigestClass))

typedef struct {
	SoupAuthDomain parent;

} SoupAuthDomainDigest;

typedef struct {
	SoupAuthDomainClass parent_class;

	/* signals */
	gboolean (*get_auth_info) (SoupAuthDomainDigest *domain,
				   SoupMessage *msg,
				   const char *username,
				   char hex_urp[33]);

} SoupAuthDomainDigestClass;

GType soup_auth_domain_digest_get_type (void);

SoupAuthDomain *soup_auth_domain_digest_new (const char *optname1,
					    ...) G_GNUC_NULL_TERMINATED;

void soup_auth_domain_digest_compute_hex_urp (const char *username,
					      const char *realm,
					      const char *password,
					      char        hex_urp[33]);

#endif /* SOUP_AUTH_DOMAIN_DIGEST_H */
