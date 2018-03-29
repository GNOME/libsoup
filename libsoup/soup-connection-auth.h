/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef __SOUP_CONNECTION_AUTH_H__
#define __SOUP_CONNECTION_AUTH_H__ 1

#include <libsoup/soup-auth.h>

G_BEGIN_DECLS

#define SOUP_TYPE_CONNECTION_AUTH            (soup_connection_auth_get_type ())
#define SOUP_CONNECTION_AUTH(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuth))
#define SOUP_CONNECTION_AUTH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthClass))
#define SOUP_IS_CONNECTION_AUTH(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_CONNECTION_AUTH))
#define SOUP_IS_CONNECTION_AUTH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_CONNECTION_AUTH))
#define SOUP_CONNECTION_AUTH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthClass))

typedef struct SoupConnectionAuthPrivate SoupConnectionAuthPrivate;

typedef struct {
	SoupAuth parent;

	SoupConnectionAuthPrivate *priv;
} SoupConnectionAuth;

typedef struct {
	SoupAuthClass parent_class;

	gpointer  (*create_connection_state)      (SoupConnectionAuth *auth);
	void      (*free_connection_state)        (SoupConnectionAuth *auth,
						   gpointer            conn);

	gboolean  (*update_connection)            (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   const char         *auth_header,
						   gpointer            conn);
	char     *(*get_connection_authorization) (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   gpointer            conn);
	gboolean  (*is_connection_ready)          (SoupConnectionAuth *auth,
						   SoupMessage        *msg,
						   gpointer            conn);
} SoupConnectionAuthClass;

GType soup_connection_auth_get_type (void);

SOUP_AVAILABLE_IN_2_58
gpointer	soup_connection_auth_get_connection_state_for_message
						(SoupConnectionAuth *auth,
						 SoupMessage *message);
G_END_DECLS

#endif /* __SOUP_CONNECTION_AUTH_H__ */
