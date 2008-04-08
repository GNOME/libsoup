/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session-feature.c: Miscellaneous session feature-provider interface
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-session-feature.h"

static void soup_session_feature_interface_init (SoupSessionFeatureInterface *interface);

static void attach (SoupSessionFeature *feature, SoupSession *session);
static void detach (SoupSessionFeature *feature, SoupSession *session);

GType
soup_session_feature_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;
  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      GType g_define_type_id =
        g_type_register_static_simple (G_TYPE_INTERFACE,
                                       g_intern_static_string ("SoupSessionFeature"),
                                       sizeof (SoupSessionFeatureInterface),
                                       (GClassInitFunc)soup_session_feature_interface_init,
                                       0,
                                       (GInstanceInitFunc)NULL,
                                       (GTypeFlags) 0);
      g_type_interface_add_prerequisite (g_define_type_id, G_TYPE_OBJECT);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }
  return g_define_type_id__volatile;
}

static void
soup_session_feature_interface_init (SoupSessionFeatureInterface *interface)
{
	interface->attach = attach;
	interface->detach = detach;
}

static void
weak_notify_unref (gpointer feature, GObject *ex_object)
{
	g_object_unref (feature);
}

static void
request_queued (SoupSession *session, SoupMessage *msg, gpointer feature)
{
	SOUP_SESSION_FEATURE_GET_CLASS (feature)->
		request_queued (feature, session, msg);
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket, gpointer feature)
{
	SOUP_SESSION_FEATURE_GET_CLASS (feature)->
		request_started (feature, session, msg, socket);
}

static void
request_unqueued (SoupSession *session, SoupMessage *msg, gpointer feature)
{
	SOUP_SESSION_FEATURE_GET_CLASS (feature)->
		request_unqueued (feature, session, msg);
}

static void
attach (SoupSessionFeature *feature, SoupSession *session)
{
	g_object_weak_ref (G_OBJECT (session),
			   weak_notify_unref, g_object_ref (feature));

	if (SOUP_SESSION_FEATURE_GET_CLASS (feature)->request_queued) {
		g_signal_connect (session, "request_queued",
				  G_CALLBACK (request_queued), feature);
	}

	if (SOUP_SESSION_FEATURE_GET_CLASS (feature)->request_started) {
		g_signal_connect (session, "request_started",
				  G_CALLBACK (request_started), feature);
	}

	if (SOUP_SESSION_FEATURE_GET_CLASS (feature)->request_unqueued) {
		g_signal_connect (session, "request_unqueued",
				  G_CALLBACK (request_unqueued), feature);
	}
}

/**
 * soup_session_feature_attach:
 * @feature: a #SoupSessionFeature
 * @session: a #SoupSession
 *
 * Adds @feature to @session.
 **/
void
soup_session_feature_attach (SoupSessionFeature *feature,
			     SoupSession        *session)
{
	SOUP_SESSION_FEATURE_GET_CLASS (feature)->attach (feature, session);
}

static void
detach (SoupSessionFeature *feature, SoupSession *session)
{
	g_object_weak_unref (G_OBJECT (session), weak_notify_unref, feature);

	g_signal_handlers_disconnect_by_func (session, request_queued, feature);
	g_signal_handlers_disconnect_by_func (session, request_started, feature);
	g_signal_handlers_disconnect_by_func (session, request_unqueued, feature);

	g_object_unref (feature);
}

/**
 * soup_session_feature_detach:
 * @feature: a #SoupSessionFeature
 * @session: a #SoupSession
 *
 * Removes @feature from @session.
 *
 * Return value: success or failure
 **/
void
soup_session_feature_detach (SoupSessionFeature *feature,
			     SoupSession        *session)
{
	SOUP_SESSION_FEATURE_GET_CLASS (feature)->detach (feature, session);
}
