/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SESSION_FEATURE (soup_session_feature_get_type ())
SOUP_AVAILABLE_IN_2_24
G_DECLARE_INTERFACE (SoupSessionFeature, soup_session_feature, SOUP, SESSION_FEATURE, GObject)

struct _SoupSessionFeatureInterface {
	GTypeInterface parent;

	/* methods */
	void     (*attach)           (SoupSessionFeature *feature,
				      SoupSession        *session);
	void     (*detach)           (SoupSessionFeature *feature,
				      SoupSession        *session);

	void     (*request_queued)   (SoupSessionFeature *feature,
				      SoupMessage        *msg);
	void     (*request_unqueued) (SoupSessionFeature *feature,
				      SoupMessage        *msg);

	gboolean (*add_feature)      (SoupSessionFeature *feature,
				      GType               type);
	gboolean (*remove_feature)   (SoupSessionFeature *feature,
				      GType               type);
	gboolean (*has_feature)      (SoupSessionFeature *feature,
				      GType               type);

};

SOUP_AVAILABLE_IN_2_24
void     soup_session_feature_attach         (SoupSessionFeature *feature,
					      SoupSession        *session);
SOUP_AVAILABLE_IN_2_24
void     soup_session_feature_detach         (SoupSessionFeature *feature,
					      SoupSession        *session);

SOUP_AVAILABLE_IN_ALL
void     soup_session_feature_request_queued (SoupSessionFeature *feature,
					      SoupMessage        *msg);
SOUP_AVAILABLE_IN_ALL
void     soup_session_feature_request_unqueued (SoupSessionFeature *feature,
						SoupMessage        *msg);

SOUP_AVAILABLE_IN_2_34
gboolean soup_session_feature_add_feature    (SoupSessionFeature *feature,
					      GType               type);
SOUP_AVAILABLE_IN_2_34
gboolean soup_session_feature_remove_feature (SoupSessionFeature *feature,
					      GType               type);
SOUP_AVAILABLE_IN_2_34
gboolean soup_session_feature_has_feature    (SoupSessionFeature *feature,
					      GType               type);

G_END_DECLS
