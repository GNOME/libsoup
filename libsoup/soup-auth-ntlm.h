/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-ntlm-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_AUTH_NTLM_H
#define SOUP_AUTH_NTLM_H 1

#include "soup-auth.h"

#define SOUP_TYPE_AUTH_NTLM            (soup_auth_ntlm_get_type ())
#define SOUP_AUTH_NTLM(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLM))
#define SOUP_AUTH_NTLM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLMClass))
#define SOUP_IS_AUTH_NTLM(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_AUTH_NTLM))
#define SOUP_IS_AUTH_NTLM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_AUTH_NTLM))
#define SOUP_AUTH_NTLM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLMClass))

typedef struct SoupAuthNTLMPrivate SoupAuthNTLMPrivate;

typedef struct {
	SoupAuth parent;

	SoupAuthNTLMPrivate *priv;
} SoupAuthNTLM;

typedef struct {
	SoupAuthClass  parent_class;

} SoupAuthNTLMClass;

GType     soup_auth_ntlm_get_type (void);

SoupAuth *soup_auth_ntlm_new      (void);

#endif /*SOUP_AUTH_NTLM_H*/
