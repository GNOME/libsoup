/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_AUTH_DIGEST_H
#define SOUP_AUTH_DIGEST_H 1

#include "soup-auth.h"

#define SOUP_TYPE_AUTH_DIGEST            (soup_auth_digest_get_type ())
#define SOUP_AUTH_DIGEST(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_AUTH_DIGEST, SoupAuthDigest))
#define SOUP_AUTH_DIGEST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_DIGEST, SoupAuthDigestClass))
#define SOUP_IS_AUTH_DIGEST(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_AUTH_DIGEST))
#define SOUP_IS_AUTH_DIGEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_AUTH_DIGEST))
#define SOUP_AUTH_DIGEST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_DIGEST, SoupAuthDigestClass))

typedef struct SoupAuthDigestPrivate SoupAuthDigestPrivate;

typedef struct {
	SoupAuth parent;

	SoupAuthDigestPrivate *priv;
} SoupAuthDigest;

typedef struct {
	SoupAuthClass parent_class;

} SoupAuthDigestClass;

GType soup_auth_digest_get_type (void);

#endif /*SOUP_AUTH_DIGEST_H*/
