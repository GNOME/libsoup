/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension-manager.c
 *
 * Copyright (C) 2019 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-websocket-extension-manager.h"
#include "soup-headers.h"
#include "soup-session-feature-private.h"
#include "soup-websocket.h"
#include "soup-websocket-extension.h"
#include "soup-websocket-extension-deflate.h"
#include "soup-websocket-extension-manager-private.h"

/**
 * SoupWebsocketExtensionManager:
 *
 * SoupWebsocketExtensionManager is the [iface@SessionFeature] that handles WebSockets
 * extensions for a [class@Session].
 *
 * A [class@WebsocketExtensionManager] is added to the session by default, and normally
 * you don't need to worry about it at all. However, if you want to
 * disable WebSocket extensions, you can remove the feature from the
 * session with [method@Session.remove_feature_by_type] or disable it on
 * individual requests with [method@Message.disable_feature].
 **/

/**
 * SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER:
 *
 * The #GType of [class@WebsocketExtensionManager]; you can use this with
 * [method@Session.remove_feature_by_type] or
 * [method@Message.disable_feature].
 */

static void soup_websocket_extension_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

struct _SoupWebsocketExtensionManager {
	GObject parent;
};

typedef struct {
        GPtrArray *extension_types;
} SoupWebsocketExtensionManagerPrivate;

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupWebsocketExtensionManager, soup_websocket_extension_manager, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupWebsocketExtensionManager)
                               G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
                                                      soup_websocket_extension_manager_session_feature_init))

static void
soup_websocket_extension_manager_init (SoupWebsocketExtensionManager *manager)
{
        SoupWebsocketExtensionManagerPrivate *priv = soup_websocket_extension_manager_get_instance_private (manager);

        priv->extension_types = g_ptr_array_new_with_free_func ((GDestroyNotify)g_type_class_unref);

        /* Use permessage-deflate extension by default */
        soup_session_feature_add_feature (SOUP_SESSION_FEATURE (manager), SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE);
}

static void
soup_websocket_extension_manager_finalize (GObject *object)
{
        SoupWebsocketExtensionManagerPrivate *priv;

        priv = soup_websocket_extension_manager_get_instance_private (SOUP_WEBSOCKET_EXTENSION_MANAGER (object));
        g_ptr_array_free (priv->extension_types, TRUE);

        G_OBJECT_CLASS (soup_websocket_extension_manager_parent_class)->finalize (object);
}

static void
soup_websocket_extension_manager_class_init (SoupWebsocketExtensionManagerClass *websocket_extension_manager_class)
{
        GObjectClass *object_class = G_OBJECT_CLASS (websocket_extension_manager_class);

        object_class->finalize = soup_websocket_extension_manager_finalize;
}

static gboolean
soup_websocket_extension_manager_add_feature (SoupSessionFeature *feature, GType type)
{
        SoupWebsocketExtensionManagerPrivate *priv;

        if (!g_type_is_a (type, SOUP_TYPE_WEBSOCKET_EXTENSION))
                return FALSE;

        priv = soup_websocket_extension_manager_get_instance_private (SOUP_WEBSOCKET_EXTENSION_MANAGER (feature));
        g_ptr_array_add (priv->extension_types, g_type_class_ref (type));

        return TRUE;
}

static gboolean
soup_websocket_extension_manager_remove_feature (SoupSessionFeature *feature, GType type)
{
        SoupWebsocketExtensionManagerPrivate *priv;
        SoupWebsocketExtensionClass *extension_class;
        guint i;

        if (!g_type_is_a (type, SOUP_TYPE_WEBSOCKET_EXTENSION))
                return FALSE;

        priv = soup_websocket_extension_manager_get_instance_private (SOUP_WEBSOCKET_EXTENSION_MANAGER (feature));
        extension_class = g_type_class_peek (type);

        for (i = 0; i < priv->extension_types->len; i++) {
                if (priv->extension_types->pdata[i] == (gpointer)extension_class) {
                        g_ptr_array_remove_index (priv->extension_types, i);
                        return TRUE;
                }
        }

        return FALSE;
}

static gboolean
soup_websocket_extension_manager_has_feature (SoupSessionFeature *feature, GType type)
{
        SoupWebsocketExtensionManagerPrivate *priv;
        SoupWebsocketExtensionClass *extension_class;
        guint i;

        if (!g_type_is_a (type, SOUP_TYPE_WEBSOCKET_EXTENSION))
                return FALSE;

        priv = soup_websocket_extension_manager_get_instance_private (SOUP_WEBSOCKET_EXTENSION_MANAGER (feature));
        extension_class = g_type_class_peek (type);

        for (i = 0; i < priv->extension_types->len; i++) {
                if (priv->extension_types->pdata[i] == (gpointer)extension_class)
                        return TRUE;
        }

        return FALSE;
}

static void
soup_websocket_extension_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface,
                                                       gpointer                     interface_data)
{
        feature_interface->add_feature = soup_websocket_extension_manager_add_feature;
        feature_interface->remove_feature = soup_websocket_extension_manager_remove_feature;
        feature_interface->has_feature = soup_websocket_extension_manager_has_feature;
}

GPtrArray *
soup_websocket_extension_manager_get_supported_extensions (SoupWebsocketExtensionManager *manager)
{
        SoupWebsocketExtensionManagerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION_MANAGER (manager), NULL);

        priv = soup_websocket_extension_manager_get_instance_private (manager);
        return priv->extension_types;
}
