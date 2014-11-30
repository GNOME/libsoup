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

/**
 * SoupWebsocketState:
 * @SOUP_WEBSOCKET_STATE_CONNECTING: the WebSocket is not yet ready to send messages
 * @SOUP_WEBSOCKET_STATE_OPEN: the Websocket is ready to send messages
 * @SOUP_WEBSOCKET_STATE_CLOSING: the Websocket is in the process of closing down, no further messages sent
 * @SOUP_WEBSOCKET_STATE_CLOSED: the Websocket is completely closed down
 *
 * The WebSocket is in the %SOUP_WEBSOCKET_STATE_CONNECTING state during initial
 * connection setup, and handshaking. If the handshake or connection fails it
 * can go directly to the %SOUP_WEBSOCKET_STATE_CLOSED state from here.
 *
 * Once the WebSocket handshake completes successfully it will be in the
 * %SOUP_WEBSOCKET_STATE_OPEN state. During this state, and only during this state
 * can WebSocket messages be sent.
 *
 * WebSocket messages can be received during either the %SOUP_WEBSOCKET_STATE_OPEN
 * or %SOUP_WEBSOCKET_STATE_CLOSING states.
 *
 * The WebSocket goes into the %SOUP_WEBSOCKET_STATE_CLOSING state once it has
 * successfully sent a close request to the peer. If we had not yet received
 * an earlier close request from the peer, then the WebSocket waits for a
 * response to the close request (until a timeout).
 *
 * Once actually closed completely down the WebSocket state is
 * %SOUP_WEBSOCKET_STATE_CLOSED. No communication is possible during this state.
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
	gsize digest_len = 20;
	guchar digest[digest_len];
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

	g_assert (digest_len == 20);

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
 * @origin: (allow-none): expected Origin header
 * @protocols: (allow-none) (array zero-terminated=1): allowed WebSocket
 *   protocols.
 * @error: return location for a #GError
 *
 * Examines the method and request headers in @msg and (assuming @msg
 * contains a valid handshake request), fills in the handshake
 * response.
 *
 * If @origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted.
 *
 * Returns: %TRUE if @msg contained a valid WebSocket handshake
 *   request and was updated to contain a handshake response. %FALSE
 *   and an error if not.
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
