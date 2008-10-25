/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server-feature.c: Miscellaneous server feature-provider interface
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-server-feature.h"

/**
 * SECTION:soup-server-feature
 * @short_description: Interface for miscellaneous server features
 *
 * #SoupServerFeature is the interface used by classes that extend
 * the functionality of a #SoupServer.
 *
 * See soup_server_add_feature(), etc, to add a feature to a server.
 **/

/**
 * SoupServerFeature:
 *
 * The interface implemented by objects that implement features for
 * #SoupServer.
 **/

static void soup_server_feature_interface_init (SoupServerFeatureInterface *interface);

static void attach (SoupServerFeature *feature, SoupServer *server);
static void detach (SoupServerFeature *feature, SoupServer *server);

GType
soup_server_feature_get_type (void)
{
  static volatile gsize g_define_type_id__volatile = 0;
  if (g_once_init_enter (&g_define_type_id__volatile))
    {
      GType g_define_type_id =
        g_type_register_static_simple (G_TYPE_INTERFACE,
                                       g_intern_static_string ("SoupServerFeature"),
                                       sizeof (SoupServerFeatureInterface),
                                       (GClassInitFunc)soup_server_feature_interface_init,
                                       0,
                                       (GInstanceInitFunc)NULL,
                                       (GTypeFlags) 0);
      g_type_interface_add_prerequisite (g_define_type_id, G_TYPE_OBJECT);
      g_once_init_leave (&g_define_type_id__volatile, g_define_type_id);
    }
  return g_define_type_id__volatile;
}

static void
soup_server_feature_interface_init (SoupServerFeatureInterface *interface)
{
	interface->attach = attach;
	interface->detach = detach;
}

static void
request_started (SoupServer *server, SoupMessage *msg,
		 SoupClientContext *context, gpointer feature)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->
		request_started (feature, server, msg, context);
}

static void
request_read (SoupServer *server, SoupMessage *msg,
	      SoupClientContext *context, gpointer feature)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->
		request_started (feature, server, msg, context);
}

static void
request_finished (SoupServer *server, SoupMessage *msg,
		  SoupClientContext *context, gpointer feature)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->
		request_started (feature, server, msg, context);
}

static void
request_aborted (SoupServer *server, SoupMessage *msg,
		 SoupClientContext *context, gpointer feature)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->
		request_started (feature, server, msg, context);
}

static void
attach (SoupServerFeature *feature, SoupServer *server)
{
	if (SOUP_SERVER_FEATURE_GET_CLASS (feature)->request_started) {
		g_signal_connect (server, "request_started",
				  G_CALLBACK (request_started), feature);
	}
	if (SOUP_SERVER_FEATURE_GET_CLASS (feature)->request_read) {
		g_signal_connect (server, "request_read",
				  G_CALLBACK (request_read), feature);
	}
	if (SOUP_SERVER_FEATURE_GET_CLASS (feature)->request_finished) {
		g_signal_connect (server, "request_finished",
				  G_CALLBACK (request_finished), feature);
	}
	if (SOUP_SERVER_FEATURE_GET_CLASS (feature)->request_aborted) {
		g_signal_connect (server, "request_aborted",
				  G_CALLBACK (request_aborted), feature);
	}
}

void
soup_server_feature_attach (SoupServerFeature *feature,
			    SoupServer        *server)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->attach (feature, server);
}

static void
detach (SoupServerFeature *feature, SoupServer *server)
{
	g_signal_handlers_disconnect_by_func (server, request_started, feature);
	g_signal_handlers_disconnect_by_func (server, request_read, feature);
	g_signal_handlers_disconnect_by_func (server, request_finished, feature);
	g_signal_handlers_disconnect_by_func (server, request_aborted, feature);
}

void
soup_server_feature_detach (SoupServerFeature *feature,
			    SoupServer        *server)
{
	SOUP_SERVER_FEATURE_GET_CLASS (feature)->detach (feature, server);
}
