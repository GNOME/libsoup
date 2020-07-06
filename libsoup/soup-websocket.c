/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket.c: This file was originally part of Cockpit.
 *
 * Copyright 2013, 2014 Red Hat, Inc.
 *
 * Cockpit is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * Cockpit is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <glib/gi18n-lib.h>

#include "soup-websocket.h"
#include "soup-headers.h"
#include "soup-message-private.h"
#include "soup-websocket-extension.h"

#define FIXED_DIGEST_LEN 20

/**
 * SECTION:soup-websocket
 * @short_description: The WebSocket Protocol
 * @see_also: soup_session_websocket_connect_async(),
 *   soup_server_add_websocket_handler()
 *
 * #SoupWebsocketConnection provides support for the <ulink
 * url="http://tools.ietf.org/html/rfc6455">WebSocket</ulink> protocol.
 *
 * To connect to a WebSocket server, create a #SoupSession and call
 * soup_session_websocket_connect_async(). To accept WebSocket
 * connections, create a #SoupServer and add a handler to it with
 * soup_server_add_websocket_handler().
 *
 * (Lower-level support is available via
 * soup_websocket_client_prepare_handshake() and
 * soup_websocket_client_verify_handshake(), for handling the client
 * side of the WebSocket handshake, and
 * soup_websocket_server_process_handshake() for handling the server
 * side.)
 *
 * #SoupWebsocketConnection handles the details of WebSocket
 * communication. You can use soup_websocket_connection_send_text()
 * and soup_websocket_connection_send_binary() to send data, and the
 * #SoupWebsocketConnection::message signal to receive data.
 * (#SoupWebsocketConnection currently only supports asynchronous
 * I/O.)
 *
 * Since: 2.50
 */

/**
 * SOUP_WEBSOCKET_ERROR:
 *
 * A #GError domain for WebSocket-related errors. Used with
 * #SoupWebsocketError.
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketError:
 * @SOUP_WEBSOCKET_ERROR_FAILED: a generic error
 * @SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET: attempted to handshake with a
 *   server that does not appear to understand WebSockets.
 * @SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE: the WebSocket handshake failed
 *   because some detail was invalid (eg, incorrect accept key).
 * @SOUP_WEBSOCKET_ERROR_BAD_ORIGIN: the WebSocket handshake failed
 *   because the "Origin" header was not an allowed value.
 *
 * WebSocket-related errors.
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketConnectionType:
 * @SOUP_WEBSOCKET_CONNECTION_UNKNOWN: unknown/invalid connection
 * @SOUP_WEBSOCKET_CONNECTION_CLIENT: a client-side connection
 * @SOUP_WEBSOCKET_CONNECTION_SERVER: a server-side connection
 *
 * The type of a #SoupWebsocketConnection.
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketDataType:
 * @SOUP_WEBSOCKET_DATA_TEXT: UTF-8 text
 * @SOUP_WEBSOCKET_DATA_BINARY: binary data
 *
 * The type of data contained in a #SoupWebsocketConnection::message
 * signal.
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketCloseCode:
 * @SOUP_WEBSOCKET_CLOSE_NORMAL: a normal, non-error close
 * @SOUP_WEBSOCKET_CLOSE_GOING_AWAY: the client/server is going away
 * @SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR: a protocol error occurred
 * @SOUP_WEBSOCKET_CLOSE_UNSUPPORTED_DATA: the endpoint received data
 *   of a type that it does not support.
 * @SOUP_WEBSOCKET_CLOSE_NO_STATUS: reserved value indicating that
 *   no close code was present; must not be sent.
 * @SOUP_WEBSOCKET_CLOSE_ABNORMAL: reserved value indicating that
 *   the connection was closed abnormally; must not be sent.
 * @SOUP_WEBSOCKET_CLOSE_BAD_DATA: the endpoint received data that
 *   was invalid (eg, non-UTF-8 data in a text message).
 * @SOUP_WEBSOCKET_CLOSE_POLICY_VIOLATION: generic error code
 *   indicating some sort of policy violation.
 * @SOUP_WEBSOCKET_CLOSE_TOO_BIG: the endpoint received a message
 *   that is too big to process.
 * @SOUP_WEBSOCKET_CLOSE_NO_EXTENSION: the client is closing the
 *   connection because the server failed to negotiate a required
 *   extension.
 * @SOUP_WEBSOCKET_CLOSE_SERVER_ERROR: the server is closing the
 *   connection because it was unable to fulfill the request.
 * @SOUP_WEBSOCKET_CLOSE_TLS_HANDSHAKE: reserved value indicating that
 *   the TLS handshake failed; must not be sent.
 *
 * Pre-defined close codes that can be passed to
 * soup_websocket_connection_close() or received from
 * soup_websocket_connection_get_close_code(). (However, other codes
 * are also allowed.)
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketState:
 * @SOUP_WEBSOCKET_STATE_OPEN: the connection is ready to send messages
 * @SOUP_WEBSOCKET_STATE_CLOSING: the connection is in the process of
 *   closing down; messages may be received, but not sent
 * @SOUP_WEBSOCKET_STATE_CLOSED: the connection is completely closed down
 *
 * The state of the WebSocket connection.
 *
 * Since: 2.50
 */

GQuark
soup_websocket_error_get_quark (void)
{
	return g_quark_from_static_string ("web-socket-error-quark");
}

static gboolean
validate_key (const char *key)
{
	guchar buf[18];
	int state = 0;
	guint save = 0;

	/* The spec requires us to check that the key is "a
	 * base64-encoded value that, when decoded, is 16 bytes in
	 * length".
	 */
	if (strlen (key) != 24)
		return FALSE;
	if (g_base64_decode_step (key, 24, buf, &state, &save) != 16)
		return FALSE;
	return TRUE;
}

static char *
compute_accept_key (const char *key)
{
	gsize digest_len = FIXED_DIGEST_LEN;
	guchar digest[FIXED_DIGEST_LEN];
	GChecksum *checksum;

	if (!key)
		return NULL;

	checksum = g_checksum_new (G_CHECKSUM_SHA1);
	g_return_val_if_fail (checksum != NULL, NULL);

	g_checksum_update (checksum, (guchar *)key, -1);

	/* magic from: http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17 */
	g_checksum_update (checksum, (guchar *)"258EAFA5-E914-47DA-95CA-C5AB0DC85B11", -1);

	g_checksum_get_digest (checksum, digest, &digest_len);
	g_checksum_free (checksum);

	g_assert (digest_len == FIXED_DIGEST_LEN);

	return g_base64_encode (digest, digest_len);
}

static gboolean
choose_subprotocol (SoupMessage  *msg,
		    const char  **server_protocols,
		    const char  **chosen_protocol)
{
	const char *client_protocols_str;
	char **client_protocols;
	int i, j;

	if (chosen_protocol)
		*chosen_protocol = NULL;

	if (!server_protocols)
		return TRUE;

	client_protocols_str = soup_message_headers_get_one (msg->request_headers,
							     "Sec-Websocket-Protocol");
	if (!client_protocols_str)
		return TRUE;

	client_protocols = g_strsplit_set (client_protocols_str, ", ", -1);
	if (!client_protocols || !client_protocols[0]) {
		g_strfreev (client_protocols);
		return TRUE;
	}

	for (i = 0; server_protocols[i] != NULL; i++) {
		for (j = 0; client_protocols[j] != NULL; j++) {
			if (g_str_equal (server_protocols[i], client_protocols[j])) {
				g_strfreev (client_protocols);
				if (chosen_protocol)
					*chosen_protocol = server_protocols[i];
				return TRUE;
			}
		}
	}

	g_strfreev (client_protocols);
	return FALSE;
}

/**
 * soup_websocket_client_prepare_handshake:
 * @msg: a #SoupMessage
 * @origin: (allow-none): the "Origin" header to set
 * @protocols: (allow-none) (array zero-terminated=1): list of
 *   protocols to offer
 *
 * Adds the necessary headers to @msg to request a WebSocket
 * handshake. The message body and non-WebSocket-related headers are
 * not modified.
 *
 * Use soup_websocket_client_prepare_handshake_with_extensions() if you
 * want to include "Sec-WebSocket-Extensions" header in the request.
 *
 * This is a low-level function; if you use
 * soup_session_websocket_connect_async() to create a WebSocket
 * connection, it will call this for you.
 *
 * Since: 2.50
 */
void
soup_websocket_client_prepare_handshake (SoupMessage  *msg,
					 const char   *origin,
					 char        **protocols)
{
	soup_websocket_client_prepare_handshake_with_extensions (msg, origin, protocols, NULL);
}

/**
 * soup_websocket_client_prepare_handshake_with_extensions:
 * @msg: a #SoupMessage
 * @origin: (nullable): the "Origin" header to set
 * @protocols: (nullable) (array zero-terminated=1): list of
 *   protocols to offer
 * @supported_extensions: (nullable) (element-type GObject.TypeClass): list
 *   of supported extension types
 *
 * Adds the necessary headers to @msg to request a WebSocket
 * handshake including supported WebSocket extensions.
 * The message body and non-WebSocket-related headers are
 * not modified.
 *
 * This is a low-level function; if you use
 * soup_session_websocket_connect_async() to create a WebSocket
 * connection, it will call this for you.
 *
 * Since: 2.68
 */
void
soup_websocket_client_prepare_handshake_with_extensions (SoupMessage *msg,
                                                         const char  *origin,
                                                         char       **protocols,
                                                         GPtrArray   *supported_extensions)
{
	guint32 raw[4];
	char *key;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	soup_message_headers_replace (msg->request_headers, "Upgrade", "websocket");
	soup_message_headers_append (msg->request_headers, "Connection", "Upgrade");

	raw[0] = g_random_int ();
	raw[1] = g_random_int ();
	raw[2] = g_random_int ();
	raw[3] = g_random_int ();
	key = g_base64_encode ((const guchar *)raw, sizeof (raw));
	soup_message_headers_replace (msg->request_headers, "Sec-WebSocket-Key", key);
	g_free (key);

	soup_message_headers_replace (msg->request_headers, "Sec-WebSocket-Version", "13");

	if (origin)
		soup_message_headers_replace (msg->request_headers, "Origin", origin);

	if (protocols) {
		char *protocols_str;

		protocols_str = g_strjoinv (", ", protocols);
		soup_message_headers_replace (msg->request_headers,
					      "Sec-WebSocket-Protocol", protocols_str);
		g_free (protocols_str);
	}

	if (supported_extensions && supported_extensions->len > 0) {
		guint i;
		GString *extensions;

		extensions = g_string_new (NULL);

		for (i = 0; i < supported_extensions->len; i++) {
			SoupWebsocketExtensionClass *extension_class = (SoupWebsocketExtensionClass *)supported_extensions->pdata[i];

			if (soup_message_is_feature_disabled (msg, G_TYPE_FROM_CLASS (extension_class)))
				continue;

			if (i != 0)
				extensions = g_string_append (extensions, ", ");
			extensions = g_string_append (extensions, extension_class->name);

			if (extension_class->get_request_params) {
				SoupWebsocketExtension *websocket_extension;
				gchar *params;

				websocket_extension = g_object_new (G_TYPE_FROM_CLASS (extension_class), NULL);
				params = soup_websocket_extension_get_request_params (websocket_extension);
				if (params) {
					extensions = g_string_append (extensions, params);
					g_free (params);
				}
				g_object_unref (websocket_extension);
			}
		}

		if (extensions->len > 0) {
			soup_message_headers_replace (msg->request_headers,
						      "Sec-WebSocket-Extensions",
						      extensions->str);
		} else {
			soup_message_headers_remove (msg->request_headers,
						     "Sec-WebSocket-Extensions");
		}
		g_string_free (extensions, TRUE);
	}
}

/**
 * soup_websocket_server_check_handshake:
 * @msg: #SoupMessage containing the client side of a WebSocket handshake
 * @origin: (allow-none): expected Origin header
 * @protocols: (allow-none) (array zero-terminated=1): allowed WebSocket
 *   protocols.
 * @error: return location for a #GError
 *
 * Examines the method and request headers in @msg and determines
 * whether @msg contains a valid handshake request.
 *
 * If @origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted.
 *
 * Requests containing "Sec-WebSocket-Extensions" header will be
 * accepted even if the header is not valid. To check a request
 * with extensions you need to use
 * soup_websocket_server_check_handshake_with_extensions() and provide
 * the list of supported extension types.
 *
 * Normally soup_websocket_server_process_handshake() will take care
 * of this for you, and if you use soup_server_add_websocket_handler()
 * to handle accepting WebSocket connections, it will call that for
 * you. However, this function may be useful if you need to perform
 * more complicated validation; eg, accepting multiple different Origins,
 * or handling different protocols depending on the path.
 *
 * Returns: %TRUE if @msg contained a valid WebSocket handshake,
 *   %FALSE and an error if not.
 *
 * Since: 2.50
 */
gboolean
soup_websocket_server_check_handshake (SoupMessage  *msg,
				       const char   *expected_origin,
				       char        **protocols,
				       GError      **error)
{
	return soup_websocket_server_check_handshake_with_extensions (msg, expected_origin, protocols, NULL, error);
}

static gboolean
websocket_extension_class_equal (gconstpointer a,
                                 gconstpointer b)
{
        return g_str_equal (((const SoupWebsocketExtensionClass *)a)->name, (const char *)b);
}

static GHashTable *
extract_extension_names_from_request (SoupMessage *msg)
{
        const char *extensions;
        GSList *extension_list, *l;
        GHashTable *return_value = NULL;

        extensions = soup_message_headers_get_list (msg->request_headers, "Sec-WebSocket-Extensions");
        if (!extensions || !*extensions)
                return NULL;

        extension_list = soup_header_parse_list (extensions);
        for (l = extension_list; l != NULL; l = g_slist_next (l)) {
                char *extension = (char *)l->data;
                char *p, *end;

                while (g_ascii_isspace (*extension))
                        extension++;

                if (!*extension)
                        continue;

                p = strstr (extension, ";");
                end = p ? p : extension + strlen (extension);
                while (end > extension && g_ascii_isspace (*(end - 1)))
                        end--;
                *end = '\0';

                if (!return_value)
                        return_value = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
                g_hash_table_add (return_value, g_strdup (extension));
        }

        soup_header_free_list (extension_list);

        return return_value;
}

static gboolean
process_extensions (SoupMessage *msg,
                    const char  *extensions,
                    gboolean     is_server,
                    GPtrArray   *supported_extensions,
                    GList      **accepted_extensions,
                    GError     **error)
{
        GSList *extension_list, *l;
        GHashTable *requested_extensions = NULL;

        if (!supported_extensions || supported_extensions->len == 0) {
                if (is_server)
                        return TRUE;

                g_set_error_literal (error,
                                     SOUP_WEBSOCKET_ERROR,
                                     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                                     _("Server requested unsupported extension"));
                return FALSE;
        }

        if (!is_server)
                requested_extensions = extract_extension_names_from_request (msg);

        extension_list = soup_header_parse_list (extensions);
        for (l = extension_list; l != NULL; l = g_slist_next (l)) {
                char *extension = (char *)l->data;
                char *p, *end;
                guint index;
                GHashTable *params = NULL;
                SoupWebsocketExtension *websocket_extension;

                while (g_ascii_isspace (*extension))
                        extension++;

                if (!*extension) {
                        g_set_error (error,
                                     SOUP_WEBSOCKET_ERROR,
                                     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                                     is_server ?
                                     _("Incorrect WebSocket “%s” header") :
                                     _("Server returned incorrect “%s” key"),
                                     "Sec-WebSocket-Extensions");
                        if (accepted_extensions)
                                g_list_free_full (*accepted_extensions, g_object_unref);
                        g_clear_pointer (&requested_extensions, g_hash_table_destroy);
                        soup_header_free_list (extension_list);

                        return FALSE;
                }

                p = strstr (extension, ";");
                end = p ? p : extension + strlen (extension);
                while (end > extension && g_ascii_isspace (*(end - 1)))
                        end--;
                *end = '\0';

                if (requested_extensions && !g_hash_table_contains (requested_extensions, extension)) {
                        g_set_error_literal (error,
                                             SOUP_WEBSOCKET_ERROR,
                                             SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                                             _("Server requested unsupported extension"));
                        if (accepted_extensions)
                                g_list_free_full (*accepted_extensions, g_object_unref);
                        g_clear_pointer (&requested_extensions, g_hash_table_destroy);
                        soup_header_free_list (extension_list);

                        return FALSE;
                }

                if (!g_ptr_array_find_with_equal_func (supported_extensions, extension, websocket_extension_class_equal, &index)) {
                        if (is_server)
                                continue;

                        g_set_error_literal (error,
                                             SOUP_WEBSOCKET_ERROR,
                                             SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                                             _("Server requested unsupported extension"));
                        if (accepted_extensions)
                                g_list_free_full (*accepted_extensions, g_object_unref);
                        g_clear_pointer (&requested_extensions, g_hash_table_destroy);
                        soup_header_free_list (extension_list);

                        return FALSE;
                }

                /* If we are just checking headers in server side
                 * and there's no parameters, it's enough to know
                 * the extension is supported.
                 */
                if (is_server && !accepted_extensions && !p)
                        continue;

                websocket_extension = g_object_new (G_TYPE_FROM_CLASS (supported_extensions->pdata[index]), NULL);
                if (accepted_extensions)
                        *accepted_extensions = g_list_prepend (*accepted_extensions, websocket_extension);

                if (p) {
                        params = soup_header_parse_semi_param_list_strict (p + 1);
                        if (!params) {
                                g_set_error (error,
                                             SOUP_WEBSOCKET_ERROR,
                                             SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                                             is_server ?
                                             _("Duplicated parameter in “%s” WebSocket extension header") :
                                             _("Server returned a duplicated parameter in “%s” WebSocket extension header"),
                                             extension);
                                if (accepted_extensions)
                                        g_list_free_full (*accepted_extensions, g_object_unref);
                                else
                                        g_object_unref (websocket_extension);
                                g_clear_pointer (&requested_extensions, g_hash_table_destroy);
                                soup_header_free_list (extension_list);

                                return FALSE;
                        }
                }

                if (!soup_websocket_extension_configure (websocket_extension,
                                                         is_server ? SOUP_WEBSOCKET_CONNECTION_SERVER : SOUP_WEBSOCKET_CONNECTION_CLIENT,
                                                         params,
                                                         error)) {
                        g_clear_pointer (&params, g_hash_table_destroy);
                        if (accepted_extensions)
                                g_list_free_full (*accepted_extensions, g_object_unref);
                        else
                                g_object_unref (websocket_extension);
                        g_clear_pointer (&requested_extensions, g_hash_table_destroy);
                        soup_header_free_list (extension_list);

                        return FALSE;
                }
                g_clear_pointer (&params, g_hash_table_destroy);
                if (!accepted_extensions)
                        g_object_unref (websocket_extension);
        }

        soup_header_free_list (extension_list);
        g_clear_pointer (&requested_extensions, g_hash_table_destroy);

        if (accepted_extensions)
                *accepted_extensions = g_list_reverse (*accepted_extensions);

        return TRUE;
}

/**
 * soup_websocket_server_check_handshake_with_extensions:
 * @msg: #SoupMessage containing the client side of a WebSocket handshake
 * @origin: (nullable): expected Origin header
 * @protocols: (nullable) (array zero-terminated=1): allowed WebSocket
 *   protocols.
 * @supported_extensions: (nullable) (element-type GObject.TypeClass): list
 *   of supported extension types
 * @error: return location for a #GError
 *
 * Examines the method and request headers in @msg and determines
 * whether @msg contains a valid handshake request.
 *
 * If @origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted. If @supported_extensions is non-%NULL, then
 * only requests containing valid supported extensions in
 * "Sec-WebSocket-Extensions" header will be accepted.
 *
 * Normally soup_websocket_server_process_handshake_with_extensioins()
 * will take care of this for you, and if you use
 * soup_server_add_websocket_handler() to handle accepting WebSocket
 * connections, it will call that for you. However, this function may
 * be useful if you need to perform more complicated validation; eg,
 * accepting multiple different Origins, or handling different protocols
 * depending on the path.
 *
 * Returns: %TRUE if @msg contained a valid WebSocket handshake,
 *   %FALSE and an error if not.
 *
 * Since: 2.68
 */
gboolean
soup_websocket_server_check_handshake_with_extensions (SoupMessage  *msg,
                                                       const char   *expected_origin,
                                                       char        **protocols,
                                                       GPtrArray   *supported_extensions,
                                                       GError      **error)
{
	const char *origin;
	const char *key;
	const char *extensions;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);

	if (msg->method != SOUP_METHOD_GET) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
				     _("WebSocket handshake expected"));
		return FALSE;
	}

	if (!soup_message_headers_header_equals (msg->request_headers, "Upgrade", "websocket") ||
	    !soup_message_headers_header_contains (msg->request_headers, "Connection", "upgrade")) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
				     _("WebSocket handshake expected"));
		return FALSE;
	}

	if (!soup_message_headers_header_equals (msg->request_headers, "Sec-WebSocket-Version", "13")) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Unsupported WebSocket version"));
		return FALSE;
	}

	key = soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Key");
	if (key == NULL || !validate_key (key)) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Invalid WebSocket key"));
		return FALSE;
	}

	if (expected_origin) {
		origin = soup_message_headers_get_one (msg->request_headers, "Origin");
		if (!origin || g_ascii_strcasecmp (origin, expected_origin) != 0) {
			g_set_error (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_ORIGIN,
				     _("Incorrect WebSocket “%s” header"), "Origin");
			return FALSE;
		}
	}

	if (!choose_subprotocol (msg, (const char **) protocols, NULL)) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Unsupported WebSocket subprotocol"));
		return FALSE;
	}

	extensions = soup_message_headers_get_list (msg->request_headers, "Sec-WebSocket-Extensions");
	if (extensions && *extensions) {
		if (!process_extensions (msg, extensions, TRUE, supported_extensions, NULL, error))
			return FALSE;
	}

	return TRUE;
}

#define RESPONSE_FORBIDDEN "<html><head><title>400 Forbidden</title></head>\r\n" \
	"<body>Received invalid WebSocket request</body></html>\r\n"

static void
respond_handshake_forbidden (SoupMessage *msg)
{
	soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
	soup_message_headers_append (msg->response_headers, "Connection", "close");
	soup_message_set_response (msg, "text/html", SOUP_MEMORY_COPY,
				   RESPONSE_FORBIDDEN, strlen (RESPONSE_FORBIDDEN));
}

#define RESPONSE_BAD "<html><head><title>400 Bad Request</title></head>\r\n" \
	"<body>Received invalid WebSocket request: %s</body></html>\r\n"

static void
respond_handshake_bad (SoupMessage *msg, const char *why)
{
	char *text;

	text = g_strdup_printf (RESPONSE_BAD, why);
	soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
	soup_message_headers_append (msg->response_headers, "Connection", "close");
	soup_message_set_response (msg, "text/html", SOUP_MEMORY_TAKE,
				   text, strlen (text));
}

/**
 * soup_websocket_server_process_handshake:
 * @msg: #SoupMessage containing the client side of a WebSocket handshake
 * @expected_origin: (allow-none): expected Origin header
 * @protocols: (allow-none) (array zero-terminated=1): allowed WebSocket
 *   protocols.
 *
 * Examines the method and request headers in @msg and (assuming @msg
 * contains a valid handshake request), fills in the handshake
 * response.
 *
 * If @expected_origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted.
 *
 * Requests containing "Sec-WebSocket-Extensions" header will be
 * accepted even if the header is not valid. To process a request
 * with extensions you need to use
 * soup_websocket_server_process_handshake_with_extensions() and provide
 * the list of supported extension types.
 *
 * This is a low-level function; if you use
 * soup_server_add_websocket_handler() to handle accepting WebSocket
 * connections, it will call this for you.
 *
 * Returns: %TRUE if @msg contained a valid WebSocket handshake
 *   request and was updated to contain a handshake response. %FALSE if not.
 *
 * Since: 2.50
 */
gboolean
soup_websocket_server_process_handshake (SoupMessage  *msg,
					 const char   *expected_origin,
					 char        **protocols)
{
	return soup_websocket_server_process_handshake_with_extensions (msg, expected_origin, protocols, NULL, NULL);
}

/**
 * soup_websocket_server_process_handshake_with_extensions:
 * @msg: #SoupMessage containing the client side of a WebSocket handshake
 * @expected_origin: (nullable): expected Origin header
 * @protocols: (nullable) (array zero-terminated=1): allowed WebSocket
 *   protocols.
 * @supported_extensions: (nullable) (element-type GObject.TypeClass): list
 *   of supported extension types
 * @accepted_extensions: (out) (optional) (element-type SoupWebsocketExtension): a
 *   #GList of #SoupWebsocketExtension objects
 *
 * Examines the method and request headers in @msg and (assuming @msg
 * contains a valid handshake request), fills in the handshake
 * response.
 *
 * If @expected_origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted. If @supported_extensions is non-%NULL, then
 * only requests containing valid supported extensions in
 * "Sec-WebSocket-Extensions" header will be accepted. The accepted extensions
 * will be returned in @accepted_extensions parameter if non-%NULL.
 *
 * This is a low-level function; if you use
 * soup_server_add_websocket_handler() to handle accepting WebSocket
 * connections, it will call this for you.
 *
 * Returns: %TRUE if @msg contained a valid WebSocket handshake
 *   request and was updated to contain a handshake response. %FALSE if not.
 *
 * Since: 2.68
 */
gboolean
soup_websocket_server_process_handshake_with_extensions (SoupMessage  *msg,
                                                         const char   *expected_origin,
                                                         char        **protocols,
                                                         GPtrArray    *supported_extensions,
                                                         GList       **accepted_extensions)
{
	const char *chosen_protocol = NULL;
	const char *key;
	const char *extensions;
	char *accept_key;
	GError *error = NULL;

	g_return_val_if_fail (accepted_extensions == NULL || *accepted_extensions == NULL, FALSE);

	if (!soup_websocket_server_check_handshake_with_extensions (msg, expected_origin, protocols, supported_extensions, &error)) {
		if (g_error_matches (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_ORIGIN))
			respond_handshake_forbidden (msg);
		else
			respond_handshake_bad (msg, error->message);
		g_error_free (error);
		return FALSE;
	}

	soup_message_set_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS);
	soup_message_headers_replace (msg->response_headers, "Upgrade", "websocket");
	soup_message_headers_append (msg->response_headers, "Connection", "Upgrade");

	key = soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Key");
	accept_key = compute_accept_key (key);
	soup_message_headers_append (msg->response_headers, "Sec-WebSocket-Accept", accept_key);
	g_free (accept_key);

	choose_subprotocol (msg, (const char **) protocols, &chosen_protocol);
	if (chosen_protocol)
		soup_message_headers_append (msg->response_headers, "Sec-WebSocket-Protocol", chosen_protocol);

	extensions = soup_message_headers_get_list (msg->request_headers, "Sec-WebSocket-Extensions");
	if (extensions && *extensions) {
		GList *websocket_extensions = NULL;
		GList *l;

		process_extensions (msg, extensions, TRUE, supported_extensions, &websocket_extensions, NULL);
		if (websocket_extensions) {
			GString *response_extensions;

			response_extensions = g_string_new (NULL);

			for (l = websocket_extensions; l && l->data; l = g_list_next (l)) {
				SoupWebsocketExtension *websocket_extension;
				gchar *params;

				websocket_extension = (SoupWebsocketExtension *)l->data;
				if (response_extensions->len > 0)
					response_extensions = g_string_append (response_extensions, ", ");
				response_extensions = g_string_append (response_extensions, SOUP_WEBSOCKET_EXTENSION_GET_CLASS (websocket_extension)->name);
				params = soup_websocket_extension_get_response_params (websocket_extension);
				if (params) {
					response_extensions = g_string_append (response_extensions, params);
					g_free (params);
				}
			}

			if (response_extensions->len > 0) {
				soup_message_headers_replace (msg->response_headers,
							      "Sec-WebSocket-Extensions",
							      response_extensions->str);
			} else {
				soup_message_headers_remove (msg->response_headers,
							     "Sec-WebSocket-Extensions");
			}
			g_string_free (response_extensions, TRUE);

			if (accepted_extensions)
				*accepted_extensions = websocket_extensions;
			else
				g_list_free_full (websocket_extensions, g_object_unref);
		}
	}

	return TRUE;
}

/**
 * soup_websocket_client_verify_handshake:
 * @msg: #SoupMessage containing both client and server sides of a
 *   WebSocket handshake
 * @error: return location for a #GError
 *
 * Looks at the response status code and headers in @msg and
 * determines if they contain a valid WebSocket handshake response
 * (given the handshake request in @msg's request headers).
 *
 * If the response contains the "Sec-WebSocket-Extensions" header,
 * the handshake will be considered invalid. You need to use
 * soup_websocket_client_verify_handshake_with_extensions() to handle
 * responses with extensions.
 *
 * This is a low-level function; if you use
 * soup_session_websocket_connect_async() to create a WebSocket
 * connection, it will call this for you.
 *
 * Returns: %TRUE if @msg contains a completed valid WebSocket
 *   handshake, %FALSE and an error if not.
 *
 * Since: 2.50
 */
gboolean
soup_websocket_client_verify_handshake (SoupMessage  *msg,
					GError      **error)
{
	return soup_websocket_client_verify_handshake_with_extensions (msg, NULL, NULL, error);
}

/**
 * soup_websocket_client_verify_handshake_with_extensions:
 * @msg: #SoupMessage containing both client and server sides of a
 *   WebSocket handshake
 * @supported_extensions: (nullable) (element-type GObject.TypeClass): list
 *   of supported extension types
 * @accepted_extensions: (out) (optional) (element-type SoupWebsocketExtension): a
 *   #GList of #SoupWebsocketExtension objects
 * @error: return location for a #GError
 *
 * Looks at the response status code and headers in @msg and
 * determines if they contain a valid WebSocket handshake response
 * (given the handshake request in @msg's request headers).
 *
 * If @supported_extensions is non-%NULL, extensions included in the
 * response "Sec-WebSocket-Extensions" are verified too. Accepted
 * extensions are returned in @accepted_extensions parameter if non-%NULL.
 *
 * This is a low-level function; if you use
 * soup_session_websocket_connect_async() to create a WebSocket
 * connection, it will call this for you.
 *
 * Returns: %TRUE if @msg contains a completed valid WebSocket
 *   handshake, %FALSE and an error if not.
 *
 * Since: 2.68
 */
gboolean
soup_websocket_client_verify_handshake_with_extensions (SoupMessage *msg,
                                                        GPtrArray   *supported_extensions,
                                                        GList      **accepted_extensions,
                                                        GError     **error)
{
	const char *protocol, *request_protocols, *extensions, *accept_key;
	char *expected_accept_key;
	gboolean key_ok;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);
	g_return_val_if_fail (accepted_extensions == NULL || *accepted_extensions == NULL, FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (msg->status_code == SOUP_STATUS_BAD_REQUEST) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Server rejected WebSocket handshake"));
		return FALSE;
	}

	if (msg->status_code != SOUP_STATUS_SWITCHING_PROTOCOLS) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
				     _("Server ignored WebSocket handshake"));
		return FALSE;
	}

	if (!soup_message_headers_header_equals (msg->response_headers, "Upgrade", "websocket") ||
	    !soup_message_headers_header_contains (msg->response_headers, "Connection", "upgrade")) {
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
				     _("Server ignored WebSocket handshake"));
		return FALSE;
	}

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	if (protocol) {
		request_protocols = soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Protocol");
		if (!request_protocols ||
		    !soup_header_contains (request_protocols, protocol)) {
			g_set_error_literal (error,
					     SOUP_WEBSOCKET_ERROR,
					     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
					     _("Server requested unsupported protocol"));
			return FALSE;
		}
	}

	extensions = soup_message_headers_get_list (msg->response_headers, "Sec-WebSocket-Extensions");
	if (extensions && *extensions) {
		if (!process_extensions (msg, extensions, FALSE, supported_extensions, accepted_extensions, error))
			return FALSE;
	}

	accept_key = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Accept");
	expected_accept_key = compute_accept_key (soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Key"));
	key_ok = (accept_key && expected_accept_key &&
		  !g_ascii_strcasecmp (accept_key, expected_accept_key));
	g_free (expected_accept_key);
	if (!key_ok) {
		g_set_error (error,
			     SOUP_WEBSOCKET_ERROR,
			     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
			     _("Server returned incorrect “%s” key"),
			     "Sec-WebSocket-Accept");
		return FALSE;
	}

	return TRUE;
}
