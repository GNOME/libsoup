/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension-manager.h
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

#ifndef __SOUP_WEBSOCKET_EXTENSION_MANAGER_H__
#define __SOUP_WEBSOCKET_EXTENSION_MANAGER_H__ 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER            (soup_websocket_extension_manager_get_type ())
#define SOUP_WEBSOCKET_EXTENSION_MANAGER(object)         (G_TYPE_CHECK_INSTANCE_CAST ((object), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER, SoupWebsocketExtensionManager))
#define SOUP_IS_WEBSOCKET_EXTENSION_MANAGER(object)      (G_TYPE_CHECK_INSTANCE_TYPE ((object), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER))
#define SOUP_WEBSOCKET_EXTENSION_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER, SoupWebsocketExtensionManagerClass))
#define SOUP_IS_WEBSOCKET_EXTENSION_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER))
#define SOUP_WEBSOCKET_EXTENSION_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER, SoupWebsocketExtensionManagerClass))

typedef struct {
	GObject parent;
} SoupWebsocketExtensionManager;

typedef struct {
	GObjectClass parent_class;
} SoupWebsocketExtensionManagerClass;

SOUP_AVAILABLE_IN_2_68
GType soup_websocket_extension_manager_get_type (void);

G_END_DECLS

#endif /* __SOUP_WEBSOCKET_EXTENSION_MANAGER_H__ */
