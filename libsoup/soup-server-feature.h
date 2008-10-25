/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_SERVER_FEATURE_H
#define SOUP_SERVER_FEATURE_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER_FEATURE            (soup_server_feature_get_type ())
#define SOUP_SERVER_FEATURE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SERVER_FEATURE, SoupServerFeature))
#define SOUP_SERVER_FEATURE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SERVER_FEATURE, SoupServerFeatureInterface))
#define SOUP_IS_SERVER_FEATURE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SERVER_FEATURE))
#define SOUP_IS_SERVER_FEATURE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_SERVER_FEATURE))
#define SOUP_SERVER_FEATURE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), SOUP_TYPE_SERVER_FEATURE, SoupServerFeatureInterface))

typedef struct {
	GTypeInterface parent;

	/* methods */
	void (*attach) (SoupServerFeature *feature,
			SoupServer        *server);
	void (*detach) (SoupServerFeature *feature,
			SoupServer        *server);

	void (*request_started)  (SoupServerFeature *feature,
				  SoupServer        *server,
				  SoupMessage       *msg,
				  SoupClientContext *context);
	void (*request_read)     (SoupServerFeature *feature,
				  SoupServer        *server,
				  SoupMessage       *msg,
				  SoupClientContext *context);
	void (*request_finished) (SoupServerFeature *feature,
				  SoupServer        *server,
				  SoupMessage       *msg,
				  SoupClientContext *context);
	void (*request_aborted)  (SoupServerFeature *feature,
				  SoupServer        *server,
				  SoupMessage       *msg,
				  SoupClientContext *context);

} SoupServerFeatureInterface;

SOUP_AVAILABLE_IN_2_46
GType soup_server_feature_get_type (void);

SOUP_AVAILABLE_IN_2_46
void soup_server_feature_attach (SoupServerFeature *feature,
				 SoupServer        *server);
SOUP_AVAILABLE_IN_2_46
void soup_server_feature_detach (SoupServerFeature *feature,
				 SoupServer        *server);

G_END_DECLS

#endif /* SOUP_SERVER_FEATURE_H */
