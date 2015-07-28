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
#include "soup-message.h"

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
	guint32 raw[4];
	char *key;

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
	const char *origin;
	const char *key;

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
				     _("Incorrect WebSocket \"%s\" header"), "Origin");
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
	const char *chosen_protocol = NULL;
	const char *key;
	char *accept_key;
	GError *error = NULL;

	if (!soup_websocket_server_check_handshake (msg, expected_origin, protocols, &error)) {
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
	const char *protocol, *request_protocols, *extensions, *accept_key;
	char *expected_accept_key;
	gboolean key_ok;

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
		g_set_error_literal (error,
				     SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
				     _("Server requested unsupported extension"));
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
			     _("Server returned incorrect \"%s\" key"),
			     "Sec-WebSocket-Accept");
		return FALSE;
	}

	return TRUE;
}
