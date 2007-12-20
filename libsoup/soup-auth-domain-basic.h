/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#ifndef SOUP_AUTH_DOMAIN_BASIC_H
#define SOUP_AUTH_DOMAIN_BASIC_H 1

#include <libsoup/soup-auth-domain.h>

#define SOUP_TYPE_AUTH_DOMAIN_BASIC            (soup_auth_domain_basic_get_type ())
#define SOUP_AUTH_DOMAIN_BASIC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_AUTH_DOMAIN_BASIC, SoupAuthDomainBasic))
#define SOUP_AUTH_DOMAIN_BASIC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_DOMAIN_BASIC, SoupAuthDomainBasicClass))
#define SOUP_IS_AUTH_DOMAIN_BASIC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_AUTH_DOMAIN_BASIC))
#define SOUP_IS_AUTH_DOMAIN_BASIC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_AUTH_DOMAIN_BASIC))
#define SOUP_AUTH_DOMAIN_BASIC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_DOMAIN_BASIC, SoupAuthDomainBasicClass))

typedef struct {
	SoupAuthDomain parent;

} SoupAuthDomainBasic;

typedef struct {
	SoupAuthDomainClass parent_class;

	/* signals */
	gboolean (*authenticate) (SoupAuthDomainBasic *domain,
				  SoupMessage *msg,
				  const char *username,
				  const char *password);

} SoupAuthDomainBasicClass;

GType soup_auth_domain_basic_get_type (void);

SoupAuthDomain *soup_auth_domain_basic_new (const char *optname1,
					    ...) G_GNUC_NULL_TERMINATED;

#endif /* SOUP_AUTH_DOMAIN_BASIC_H */
