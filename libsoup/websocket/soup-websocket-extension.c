/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension.c
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

#include "soup-websocket-extension.h"

/**
 * SoupWebsocketExtension:
 *
 * A WebSocket extension
 *
 * [class@WebsocketExtension] is the base class for WebSocket extension objects.
 */

/**
 * SoupWebsocketExtensionClass:
 * @name: the name of the extension
 * @parent_class: the parent class
 * @configure: called to configure the extension with the given parameters
 * @get_request_params: called by the client to build the request header.
 *    It should include the parameters string starting with ';'
 * @get_response_params: called by the server to build the response header.
 *    It should include the parameters string starting with ';'
 * @process_outgoing_message: called to process the payload data of a message
 *    before it's sent. Reserved bits of the header should be changed.
 * @process_incoming_message: called to process the payload data of a message
 *    after it's received. Reserved bits of the header should be cleared.
 *
 * The class structure for the [class@WebsocketExtension].
 */

G_DEFINE_ABSTRACT_TYPE (SoupWebsocketExtension, soup_websocket_extension, G_TYPE_OBJECT)

static void
soup_websocket_extension_init (SoupWebsocketExtension *extension)
{
}

static void
soup_websocket_extension_class_init (SoupWebsocketExtensionClass *auth_class)
{
}

/**
 * soup_websocket_extension_configure:
 * @extension: a #SoupWebsocketExtension
 * @connection_type: either %SOUP_WEBSOCKET_CONNECTION_CLIENT or %SOUP_WEBSOCKET_CONNECTION_SERVER
 * @params: (nullable): the parameters
 * @error: return location for a #GError
 *
 * Configures @extension with the given @params.
 *
 * Returns: %TRUE if extension could be configured with the given parameters, or %FALSE otherwise
 */
gboolean
soup_websocket_extension_configure (SoupWebsocketExtension     *extension,
				    SoupWebsocketConnectionType connection_type,
				    GHashTable                 *params,
				    GError                    **error)
{
	SoupWebsocketExtensionClass *klass;

	g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION (extension), FALSE);
	g_return_val_if_fail (connection_type != SOUP_WEBSOCKET_CONNECTION_UNKNOWN, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	klass = SOUP_WEBSOCKET_EXTENSION_GET_CLASS (extension);
	if (!klass->configure)
		return TRUE;

	return klass->configure (extension, connection_type, params, error);
}

/**
 * soup_websocket_extension_get_request_params:
 * @extension: a #SoupWebsocketExtension
 *
 * Get the parameters strings to be included in the request header.
 *
 * If the extension doesn't include any parameter in the request, this function
 * returns %NULL.
 *
 * Returns: (nullable) (transfer full): a new allocated string with the parameters
 */
char *
soup_websocket_extension_get_request_params (SoupWebsocketExtension *extension)
{
	SoupWebsocketExtensionClass *klass;

        g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION (extension), NULL);

	klass = SOUP_WEBSOCKET_EXTENSION_GET_CLASS (extension);
        if (!klass->get_request_params)
                return NULL;

        return klass->get_request_params (extension);
}

/**
 * soup_websocket_extension_get_response_params:
 * @extension: a #SoupWebsocketExtension
 *
 * Get the parameters strings to be included in the response header.
 *
 * If the extension doesn't include any parameter in the response, this function
 * returns %NULL.
 *
 * Returns: (nullable) (transfer full): a new allocated string with the parameters
 */
char *
soup_websocket_extension_get_response_params (SoupWebsocketExtension *extension)
{
	SoupWebsocketExtensionClass *klass;

	g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION (extension), NULL);

	klass = SOUP_WEBSOCKET_EXTENSION_GET_CLASS (extension);
	if (!klass->get_response_params)
		return NULL;

	return klass->get_response_params (extension);
}

/**
 * soup_websocket_extension_process_outgoing_message:
 * @extension: a #SoupWebsocketExtension
 * @header: (inout): the message header
 * @payload: (transfer full): the payload data
 * @error: return location for a #GError
 *
 * Process a message before it's sent.
 *
 * If the payload isn't changed the given @payload is just returned, otherwise
 * [method@Glib.Bytes.unref] is called on the given @payload and a new
 * [struct@GLib.Bytes] is returned with the new data.
 *
 * Extensions using reserved bits of the header will change them in @header.
 *
 * Returns: (transfer full): the message payload data, or %NULL in case of error
 */
GBytes *
soup_websocket_extension_process_outgoing_message (SoupWebsocketExtension *extension,
						   guint8                 *header,
						   GBytes                 *payload,
						   GError                **error)
{
	SoupWebsocketExtensionClass *klass;

        g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION (extension), NULL);
	g_return_val_if_fail (header != NULL, NULL);
	g_return_val_if_fail (payload != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        klass = SOUP_WEBSOCKET_EXTENSION_GET_CLASS (extension);
	if (!klass->process_outgoing_message)
		return payload;

	return klass->process_outgoing_message (extension, header, payload, error);
}

/**
 * soup_websocket_extension_process_incoming_message:
 * @extension: a #SoupWebsocketExtension
 * @header: (inout): the message header
 * @payload: (transfer full): the payload data
 * @error: return location for a #GError
 *
 * Process a message after it's received.
 *
 * If the payload isn't changed the given @payload is just returned, otherwise
 * [method@GLib.Bytes.unref] is called on the given @payload and a new
 * [struct@GLib.Bytes] is returned with the new data.
 *
 * Extensions using reserved bits of the header will reset them in @header.
 *
 * Returns: (transfer full): the message payload data, or %NULL in case of error
 */
GBytes *
soup_websocket_extension_process_incoming_message (SoupWebsocketExtension *extension,
						   guint8                 *header,
						   GBytes                 *payload,
						   GError                **error)
{
	SoupWebsocketExtensionClass *klass;

        g_return_val_if_fail (SOUP_IS_WEBSOCKET_EXTENSION (extension), NULL);
	g_return_val_if_fail (header != NULL, NULL);
	g_return_val_if_fail (payload != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        klass = SOUP_WEBSOCKET_EXTENSION_GET_CLASS (extension);
	if (!klass->process_incoming_message)
		return payload;

	return klass->process_incoming_message (extension, header, payload, error);
}
