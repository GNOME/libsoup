/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-ntlm-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_CONNECTION_NTLM_H
#define SOUP_CONNECTION_NTLM_H 1

#include "soup-connection.h"

#define SOUP_TYPE_CONNECTION_NTLM            (soup_connection_ntlm_get_type ())
#define SOUP_CONNECTION_NTLM(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_CONNECTION_NTLM, SoupConnectionNTLM))
#define SOUP_CONNECTION_NTLM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONNECTION_NTLM, SoupConnectionNTLMClass))
#define SOUP_IS_CONNECTION_NTLM(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_CONNECTION_NTLM))
#define SOUP_IS_CONNECTION_NTLM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_CONNECTION_NTLM))
#define SOUP_CONNECTION_NTLM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONNECTION_NTLM, SoupConnectionNTLMClass))

typedef struct SoupConnectionNTLMPrivate SoupConnectionNTLMPrivate;

typedef struct {
	SoupConnection parent;

	SoupConnectionNTLMPrivate *priv;
} SoupConnectionNTLM;

typedef struct {
	SoupConnectionClass  parent_class;

} SoupConnectionNTLMClass;

GType soup_connection_ntlm_get_type (void);

#endif /*SOUP_CONNECTION_NTLM_H*/
