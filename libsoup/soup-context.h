/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_CONTEXT_H
#define SOUP_CONTEXT_H 1

#include <libsoup/soup-types.h>

#define SOUP_TYPE_CONTEXT            (soup_context_get_type ())
#define SOUP_CONTEXT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CONTEXT, SoupContext))
#define SOUP_CONTEXT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONTEXT, SoupContextClass))
#define SOUP_IS_CONTEXT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CONTEXT))
#define SOUP_IS_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_CONTEXT))
#define SOUP_CONTEXT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONTEXT, SoupContextClass))

typedef struct SoupContextPrivate SoupContextPrivate;

struct SoupContext {
	GObject parent;

	SoupContextPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

} SoupContextClass;

GType soup_context_get_type (void);


typedef void (*SoupConnectCallbackFn) (SoupContext    *ctx,
				       guint           status,
				       SoupConnection *conn, 
				       gpointer        user_data);

typedef gpointer SoupConnectId;

SoupContext   *soup_context_get               (const char           *uri);

SoupContext   *soup_context_from_uri          (const SoupUri        *suri);

SoupConnectId  soup_context_get_connection    (SoupContext          *ctx,
					       SoupConnectCallbackFn cb,
					       gpointer              user_data);

void           soup_context_cancel_connect    (SoupConnectId         tag);

const SoupUri *soup_context_get_uri           (SoupContext          *ctx);


void           soup_context_preauthenticate   (SoupContext          *ctx,
					       const char           *header);
					  

void           soup_connection_purge_idle     (void);


#endif /*SOUP_CONTEXT_H*/
