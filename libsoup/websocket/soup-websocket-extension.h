/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension.h
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

#pragma once

#include "soup-types.h"
#include "soup-websocket.h"

G_BEGIN_DECLS

#define SOUP_TYPE_WEBSOCKET_EXTENSION (soup_websocket_extension_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupWebsocketExtension, soup_websocket_extension, SOUP, WEBSOCKET_EXTENSION, GObject)

struct _SoupWebsocketExtensionClass {
	GObjectClass parent_class;

	const char  *name;

	gboolean (* configure)                (SoupWebsocketExtension     *extension,
					       SoupWebsocketConnectionType connection_type,
					       GHashTable                 *params,
					       GError                    **error);

	char    *(* get_request_params)       (SoupWebsocketExtension     *extension);

	char    *(* get_response_params)      (SoupWebsocketExtension     *extension);

	GBytes  *(* process_outgoing_message) (SoupWebsocketExtension     *extension,
					       guint8                     *header,
					       GBytes                     *payload,
					       GError                    **error);

	GBytes  *(* process_incoming_message) (SoupWebsocketExtension     *extension,
					       guint8                     *header,
					       GBytes                     *payload,
                                               GError                    **error);

        /* <private> */
	gpointer padding[6];
};

SOUP_AVAILABLE_IN_ALL
gboolean                 soup_websocket_extension_configure                (SoupWebsocketExtension     *extension,
									    SoupWebsocketConnectionType connection_type,
									    GHashTable                 *params,
									    GError                    **error);
SOUP_AVAILABLE_IN_ALL
char                    *soup_websocket_extension_get_request_params       (SoupWebsocketExtension     *extension);

SOUP_AVAILABLE_IN_ALL
char                    *soup_websocket_extension_get_response_params      (SoupWebsocketExtension     *extension);

SOUP_AVAILABLE_IN_ALL
GBytes                  *soup_websocket_extension_process_outgoing_message (SoupWebsocketExtension     *extension,
									    guint8                     *header,
									    GBytes                     *payload,
									    GError                    **error);
SOUP_AVAILABLE_IN_ALL
GBytes                  *soup_websocket_extension_process_incoming_message (SoupWebsocketExtension     *extension,
									    guint8                     *header,
									    GBytes                     *payload,
									    GError                    **error);

G_END_DECLS
