/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#pragma once

#include "soup-session-feature.h"

G_BEGIN_DECLS

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

void     soup_session_feature_attach         (SoupSessionFeature *feature,
					      SoupSession        *session);
void     soup_session_feature_detach         (SoupSessionFeature *feature,
					      SoupSession        *session);
void     soup_session_feature_request_queued (SoupSessionFeature *feature,
					      SoupMessage        *msg);
void     soup_session_feature_request_unqueued (SoupSessionFeature *feature,
						SoupMessage        *msg);
gboolean soup_session_feature_add_feature    (SoupSessionFeature *feature,
					      GType               type);
gboolean soup_session_feature_remove_feature (SoupSessionFeature *feature,
					      GType               type);
gboolean soup_session_feature_has_feature    (SoupSessionFeature *feature,
					      GType               type);

G_END_DECLS
