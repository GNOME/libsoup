/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifndef __SOUP_AUTH_NTLM_H__
#define __SOUP_AUTH_NTLM_H__ 1

#include "soup-connection-auth.h"

#define SOUP_AUTH_NTLM(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLM))
#define SOUP_AUTH_NTLM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLMClass))
#define SOUP_IS_AUTH_NTLM(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_AUTH_NTLM))
#define SOUP_IS_AUTH_NTLM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_AUTH_NTLM))
#define SOUP_AUTH_NTLM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_AUTH_NTLM, SoupAuthNTLMClass))

typedef struct {
	SoupConnectionAuth parent;

} SoupAuthNTLM;

typedef struct {
	SoupConnectionAuthClass parent_class;

} SoupAuthNTLMClass;

#endif /* __SOUP_AUTH_NTLM_H__ */
