/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * This file was originally part of Cockpit.
 *
 * Copyright (C) 2013 Red Hat, Inc.
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
 * along with Cockpit; If not, see <http://www.gnu.org/licenses/>.
 */

#include "test-utils.h"

#include <zlib.h>

typedef struct {
	GSocket *listener;
	gushort port;

	SoupSession *session;
	SoupMessage *msg;
	SoupWebsocketConnection *client;
	GError *client_error;

	SoupServer *soup_server;
	SoupWebsocketConnection *server;

	gboolean no_server;
	GIOStream *raw_server;

	gboolean enable_extensions;
	gboolean disable_deflate_in_message;

	GList *initial_cookies;

	GMutex mutex;
} Test;

#define WAIT_UNTIL(cond)					\
	G_STMT_START						\
	while (!(cond)) g_main_context_iteration (NULL, TRUE);	\
	G_STMT_END

static void
on_error_not_reached (SoupWebsocketConnection *ws,
                      GError *error,
                      gpointer user_data)
{
	/* At this point we know this will fail, but is informative */
	g_assert_no_error (error);
}

static void
on_error_copy (SoupWebsocketConnection *ws,
               GError *error,
               gpointer user_data)
{
	GError **copy = user_data;
	g_assert (*copy == NULL);
	*copy = g_error_copy (error);
}

static void
setup_listener (Test *test)
{
	GSocketAddress *addr;
	GError *error = NULL;

	test->listener = g_socket_new (G_SOCKET_FAMILY_IPV4,
				       G_SOCKET_TYPE_STREAM,
				       G_SOCKET_PROTOCOL_TCP,
				       &error);
	g_assert_no_error (error);

	addr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_assert_no_error (error);

	g_socket_bind (test->listener, addr, TRUE, &error);
	g_assert_no_error (error);
	g_object_unref (addr);

	addr = g_socket_get_local_address (test->listener, &error);
	g_assert_no_error (error);

	test->port = g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr));
	g_object_unref (addr);

	g_socket_listen (test->listener, &error);
	g_assert_no_error (error);
}

static void
direct_connection_complete (GObject *object,
			    GAsyncResult *result,
			    gpointer user_data)
{
	Test *test = user_data;
	GSocketConnection *conn;
	SoupURI *uri;
	GError *error = NULL;
	GList *extensions = NULL;

	conn = g_socket_client_connect_to_host_finish (G_SOCKET_CLIENT (object),
						       result, &error);
	g_assert_no_error (error);

	uri = soup_uri_new ("http://127.0.0.1/");
	if (test->enable_extensions) {
		SoupWebsocketExtension *extension;

		extension = g_object_new (SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE, NULL);
		g_assert_true (soup_websocket_extension_configure (extension,
								   SOUP_WEBSOCKET_CONNECTION_CLIENT,
								   NULL, NULL));
		extensions = g_list_prepend (extensions, extension);
	}
	test->client = soup_websocket_connection_new_with_extensions (G_IO_STREAM (conn), uri,
								      SOUP_WEBSOCKET_CONNECTION_CLIENT,
								      NULL, NULL,
								      extensions);
	soup_uri_free (uri);
	g_object_unref (conn);
}

static gboolean
got_connection (GSocket *listener,
		GIOCondition cond,
		gpointer user_data)
{
	Test *test = user_data;
	GSocket *sock;
	GSocketConnection *conn;
	SoupURI *uri;
	GList *extensions = NULL;
	GError *error = NULL;

	sock = g_socket_accept (listener, NULL, &error);
	g_assert_no_error (error);

	conn = g_socket_connection_factory_create_connection (sock);
	g_assert (conn != NULL);
	g_object_unref (sock);

	if (test->no_server)
		test->raw_server = G_IO_STREAM (conn);
	else {
		uri = soup_uri_new ("http://127.0.0.1/");
		if (test->enable_extensions) {
			SoupWebsocketExtension *extension;

			extension = g_object_new (SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE, NULL);
			g_assert_true (soup_websocket_extension_configure (extension,
									   SOUP_WEBSOCKET_CONNECTION_SERVER,
									   NULL, NULL));
			extensions = g_list_prepend (extensions, extension);
		}
		test->server = soup_websocket_connection_new_with_extensions (G_IO_STREAM (conn), uri,
									      SOUP_WEBSOCKET_CONNECTION_SERVER,
									      NULL, NULL,
									      extensions);
		soup_uri_free (uri);
		g_object_unref (conn);
	}

	return FALSE;
}

static void
setup_direct_connection (Test *test,
			 gconstpointer data)
{
	GSocketClient *client;
	GSource *listen_source;

	setup_listener (test);

	client = g_socket_client_new ();
	g_socket_client_connect_to_host_async (client, "127.0.0.1", test->port,
					       NULL, direct_connection_complete, test);

	listen_source = g_socket_create_source (test->listener, G_IO_IN, NULL);
	g_source_set_callback (listen_source, (GSourceFunc) got_connection, test, NULL);
	g_source_attach (listen_source, NULL);

	while (test->client == NULL || (test->server == NULL && test->raw_server == NULL))
 		g_main_context_iteration (NULL, TRUE);
	
	g_source_destroy (listen_source);
	g_source_unref (listen_source);
	g_object_unref (client);
}

static void
setup_direct_connection_with_extensions (Test *test,
					 gconstpointer data)
{
	test->enable_extensions = TRUE;
	setup_direct_connection (test, data);
}

static void
setup_half_direct_connection (Test *test,
			      gconstpointer data)
{
	test->no_server = TRUE;
	setup_direct_connection (test, data);
}

static void
setup_half_direct_connection_with_extensions (Test *test,
					      gconstpointer data)
{
	test->no_server = TRUE;
	setup_direct_connection_with_extensions (test, data);
}

static void
teardown_direct_connection (Test *test,
			    gconstpointer data)
{
	g_clear_object (&test->listener);
	g_clear_object (&test->client);
	g_clear_object (&test->server);
	g_clear_object (&test->raw_server);
}

static void
setup_soup_server (Test *test,
		   const char *origin,
		   const char **protocols,
		   SoupServerWebsocketCallback callback,
		   gpointer user_data)
{
	GError *error = NULL;

	setup_listener (test);

	test->soup_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	if (!test->enable_extensions)
		soup_server_remove_websocket_extension (test->soup_server, SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE);
	soup_server_listen_socket (test->soup_server, test->listener, 0, &error);
	g_assert_no_error (error);

	soup_server_add_websocket_handler (test->soup_server, "/unix",
					   origin, (char **) protocols,
					   callback, user_data, NULL);
}

static void
client_connect (Test *test,
		const char *origin,
		const char **protocols,
		GAsyncReadyCallback callback,
		gpointer user_data)
{
	char *url;
	SoupCookieJar *jar;
	GList *l;

	test->session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	if (test->enable_extensions)
		soup_session_add_feature_by_type (test->session, SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER);

	jar = soup_cookie_jar_new ();
	soup_cookie_jar_set_accept_policy (jar, SOUP_COOKIE_JAR_ACCEPT_NO_THIRD_PARTY);
	soup_session_add_feature (test->session, SOUP_SESSION_FEATURE (jar));
	for (l = test->initial_cookies; l; l = g_list_next (l))
		soup_cookie_jar_add_cookie (jar, (SoupCookie *)l->data);
	g_clear_pointer (&test->initial_cookies, g_list_free);
	g_object_unref (jar);

	url = g_strdup_printf ("ws://127.0.0.1:%u/unix", test->port);
	test->msg = soup_message_new ("GET", url);
	if (test->disable_deflate_in_message)
		soup_message_disable_feature (test->msg, SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE);
	g_free (url);

	soup_session_websocket_connect_async (test->session, test->msg,
					      origin, (char **) protocols,
					      NULL, callback, user_data);
}

static void
got_server_connection (SoupServer              *server,
		       SoupWebsocketConnection *connection,
		       const char              *path,
		       SoupClientContext       *client,
		       gpointer                 user_data)
{
	Test *test = user_data;

	test->server = g_object_ref (connection);
}

static void
got_client_connection (GObject *object,
		       GAsyncResult *result,
		       gpointer user_data)
{
	Test *test = user_data;

	test->client = soup_session_websocket_connect_finish (SOUP_SESSION (object),
							      result, &test->client_error);
}

static void
setup_soup_connection (Test *test,
		       gconstpointer data)
{
	setup_soup_server (test, NULL, NULL, got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);
}

static void
setup_soup_connection_with_extensions (Test *test,
				       gconstpointer data)
{
	test->enable_extensions = TRUE;
	setup_soup_connection (test, data);
}

static void
teardown_soup_connection (Test *test,
			  gconstpointer data)
{
	teardown_direct_connection (test, data);

	g_clear_object (&test->msg);
	g_clear_error (&test->client_error);
	g_clear_pointer (&test->session, soup_test_session_abort_unref);
	g_clear_pointer (&test->soup_server, soup_test_server_quit_unref);
}


static void
on_text_message (SoupWebsocketConnection *ws,
                 SoupWebsocketDataType type,
                 GBytes *message,
                 gpointer user_data)
{
	GBytes **receive = user_data;

	g_assert_cmpint (type, ==, SOUP_WEBSOCKET_DATA_TEXT);
	g_assert (*receive == NULL);
	g_assert (message != NULL);

	*receive = g_bytes_ref (message);
}

static void
on_binary_message (SoupWebsocketConnection *ws,
		   SoupWebsocketDataType type,
		   GBytes *message,
		   gpointer user_data)
{
	GBytes **receive = user_data;

	g_assert_cmpint (type, ==, SOUP_WEBSOCKET_DATA_BINARY);
	g_assert (*receive == NULL);
	g_assert (message != NULL);

	*receive = g_bytes_ref (message);
}

static void
on_close_set_flag (SoupWebsocketConnection *ws,
                   gpointer user_data)
{
	gboolean *flag = user_data;

	g_assert (*flag == FALSE);

	*flag = TRUE;
}


static void
test_handshake (Test *test,
                gconstpointer data)
{
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_OPEN);
	if (test->enable_extensions) {
		GList *extensions = soup_websocket_connection_get_extensions (test->client);

		g_assert_nonnull (extensions);
		g_assert_cmpuint (g_list_length (extensions), ==, 1);
		g_assert (SOUP_IS_WEBSOCKET_EXTENSION_DEFLATE (extensions->data));
	} else {
		g_assert_null (soup_websocket_connection_get_extensions (test->client));
	}

	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_OPEN);
	if (test->enable_extensions) {
                GList *extensions = soup_websocket_connection_get_extensions (test->server);

                g_assert_nonnull (extensions);
                g_assert_cmpuint (g_list_length (extensions), ==, 1);
                g_assert (SOUP_IS_WEBSOCKET_EXTENSION_DEFLATE (extensions->data));
        } else {
		g_assert_null (soup_websocket_connection_get_extensions (test->server));
	}

}

static void
websocket_server_request_started (SoupServer *server, SoupMessage *msg,
				  SoupClientContext *client, gpointer user_data)
{
	soup_message_headers_append (msg->response_headers, "Sec-WebSocket-Extensions", "x-foo");
}

static void
request_unqueued (SoupSession *session,
		  SoupMessage *msg,
                  gpointer data)
{
	Test *test = data;

	if (test->msg == msg)
		g_clear_object (&test->msg);
}


static void
test_handshake_unsupported_extension (Test *test,
				      gconstpointer data)
{
	char *url;

	setup_listener (test);
	test->soup_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_listen_socket (test->soup_server, test->listener, 0, NULL);
	g_signal_connect (test->soup_server, "request-started",
			  G_CALLBACK (websocket_server_request_started),
			  NULL);
	soup_server_add_websocket_handler (test->soup_server, "/unix", NULL, NULL,
					   got_server_connection, test, NULL);

	test->session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	g_signal_connect (test->session, "request-unqueued",
			  G_CALLBACK (request_unqueued),
			  test);
        url = g_strdup_printf ("ws://127.0.0.1:%u/unix", test->port);
        test->msg = soup_message_new ("GET", url);
        g_free (url);

	soup_session_websocket_connect_async (test->session, test->msg, NULL, NULL, NULL,
					      got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->msg == NULL);
	g_assert_error (test->client_error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE);
}

#define TEST_STRING "this is a test"
#define TEST_STRING_WITH_NULL "this is\0 a test"

static void
test_send_client_to_server (Test *test,
                            gconstpointer data)
{
	GBytes *sent;
	GBytes *received = NULL;
	const char *contents;
	gsize len;

	g_signal_connect (test->server, "message", G_CALLBACK (on_text_message), &received);

	soup_websocket_connection_send_text (test->client, TEST_STRING);

	WAIT_UNTIL (received != NULL);

	/* Received messages should be null terminated (outside of len) */
	contents = g_bytes_get_data (received, &len);
	g_assert_cmpstr (contents, ==, TEST_STRING);
	g_assert_cmpint (len, ==, strlen (TEST_STRING));
	g_clear_pointer (&received, g_bytes_unref);

	sent = g_bytes_new_static (TEST_STRING_WITH_NULL, sizeof (TEST_STRING_WITH_NULL));
	soup_websocket_connection_send_message (test->client, SOUP_WEBSOCKET_DATA_TEXT, sent);

	WAIT_UNTIL (received != NULL);

	g_assert (g_bytes_equal (sent, received));
	g_clear_pointer (&sent, g_bytes_unref);
	g_clear_pointer (&received, g_bytes_unref);
}

static void
test_send_server_to_client (Test *test,
                            gconstpointer data)
{
	GBytes *sent;
	GBytes *received = NULL;
	const char *contents;
	gsize len;

	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	soup_websocket_connection_send_text (test->server, TEST_STRING);

	WAIT_UNTIL (received != NULL);

	/* Received messages should be null terminated (outside of len) */
	contents = g_bytes_get_data (received, &len);
	g_assert_cmpstr (contents, ==, TEST_STRING);
	g_assert_cmpint (len, ==, strlen (TEST_STRING));
	g_clear_pointer (&received, g_bytes_unref);

	sent = g_bytes_new_static (TEST_STRING_WITH_NULL, sizeof (TEST_STRING_WITH_NULL));
        soup_websocket_connection_send_message (test->server, SOUP_WEBSOCKET_DATA_TEXT, sent);

        WAIT_UNTIL (received != NULL);

        g_assert (g_bytes_equal (sent, received));
        g_clear_pointer (&sent, g_bytes_unref);
        g_clear_pointer (&received, g_bytes_unref);
}

static void
test_send_big_packets (Test *test,
                       gconstpointer data)
{
	GBytes *sent = NULL;
	GBytes *received = NULL;

	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	sent = g_bytes_new_take (g_strnfill (400, '!'), 400);
	soup_websocket_connection_send_text (test->server, g_bytes_get_data (sent, NULL));
	WAIT_UNTIL (received != NULL);
	g_assert (g_bytes_equal (sent, received));
	g_bytes_unref (sent);
	g_bytes_unref (received);
	received = NULL;

	sent = g_bytes_new_take (g_strnfill (100 * 1000, '?'), 100 * 1000);
	soup_websocket_connection_send_text (test->server, g_bytes_get_data (sent, NULL));
	WAIT_UNTIL (received != NULL);
	g_assert (g_bytes_equal (sent, received));
	g_bytes_unref (sent);
	g_bytes_unref (received);
	received = NULL;

	soup_websocket_connection_set_max_incoming_payload_size (test->client, 1000 * 1000 + 1);
	g_assert (soup_websocket_connection_get_max_incoming_payload_size (test->client) == (1000 * 1000 + 1));
	soup_websocket_connection_set_max_incoming_payload_size (test->server, 1000 * 1000 + 1);
	g_assert (soup_websocket_connection_get_max_incoming_payload_size (test->server) == (1000 * 1000 + 1));

	sent = g_bytes_new_take (g_strnfill (1000 * 1000, '?'), 1000 * 1000);
	soup_websocket_connection_send_text (test->server, g_bytes_get_data (sent, NULL));
	WAIT_UNTIL (received != NULL);
	g_assert (g_bytes_equal (sent, received));
	g_bytes_unref (sent);
	g_bytes_unref (received);
}

static void
test_send_empty_packets (Test *test,
			 gconstpointer data)
{
	GBytes *received = NULL;
	gulong id;

	id = g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	soup_websocket_connection_send_text (test->server, "\0");
	WAIT_UNTIL (received != NULL);
	g_assert_nonnull (g_bytes_get_data (received, NULL));
	g_assert_cmpuint (((char *) g_bytes_get_data (received, NULL))[0], ==, '\0');
	g_assert_cmpuint (g_bytes_get_size (received), ==, 0);
	g_bytes_unref (received);
	received = NULL;
	g_signal_handler_disconnect (test->client, id);

	id = g_signal_connect (test->client, "message", G_CALLBACK (on_binary_message), &received);

	soup_websocket_connection_send_binary (test->server, NULL, 0);
	WAIT_UNTIL (received != NULL);
	/* We always include at least a null character */
	g_assert_nonnull (g_bytes_get_data (received, NULL));
	g_assert_cmpuint (((char *) g_bytes_get_data (received, NULL))[0], ==, '\0');
	g_assert_cmpuint (g_bytes_get_size (received), ==, 0);
	g_bytes_unref (received);
	received = NULL;
	g_signal_handler_disconnect (test->client, id);
}

static void
test_send_bad_data (Test *test,
                    gconstpointer unused)
{
	GError *error = NULL;
	GIOStream *io;
	gsize written;
	const char *frame;
	gboolean close_event = FALSE;

	g_signal_handlers_disconnect_by_func (test->server, on_error_not_reached, NULL);
	g_signal_connect (test->server, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event);

	io = soup_websocket_connection_get_io_stream (test->client);

	/* Bad UTF-8 frame */
	frame = "\x81\x84\x00\x00\x00\x00\xEE\xEE\xEE\xEE";
	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					frame, 10, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (written, ==, 10);

	WAIT_UNTIL (error != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_BAD_DATA);
	g_clear_error (&error);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
	g_assert (close_event);

	g_assert_cmpuint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_BAD_DATA);
}

static const char *negotiate_client_protocols[] = { "bbb", "ccc", NULL };
static const char *negotiate_server_protocols[] = { "aaa", "bbb", "ccc", NULL };
static const char *negotiated_protocol = "bbb";

static void
test_protocol_negotiate_direct (Test *test,
				gconstpointer unused)
{
	SoupMessage *msg;
	gboolean ok;
	const char *protocol;
	GError *error = NULL;

	msg = soup_message_new ("GET", "http://127.0.0.1");
	soup_websocket_client_prepare_handshake (msg, NULL,
						 (char **) negotiate_client_protocols);

	ok = soup_websocket_server_check_handshake (msg, NULL,
						    (char **) negotiate_server_protocols,
						    &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	ok = soup_websocket_server_process_handshake (msg, NULL,
						      (char **) negotiate_server_protocols);
	g_assert_true (ok);

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	g_assert_cmpstr (protocol, ==, negotiated_protocol);

	ok = soup_websocket_client_verify_handshake (msg, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	g_object_unref (msg);
}

static void
test_protocol_negotiate_soup (Test *test,
			      gconstpointer unused)
{
	setup_soup_server (test, NULL, negotiate_server_protocols, got_server_connection, test);
	client_connect (test, NULL, negotiate_client_protocols, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, negotiated_protocol);
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, negotiated_protocol);
}

static const char *mismatch_client_protocols[] = { "ddd", NULL };
static const char *mismatch_server_protocols[] = { "aaa", "bbb", "ccc", NULL };

static void
test_protocol_mismatch_direct (Test *test,
			       gconstpointer unused)
{
	SoupMessage *msg;
	gboolean ok;
	const char *protocol;
	GError *error = NULL;

	msg = soup_message_new ("GET", "http://127.0.0.1");
	soup_websocket_client_prepare_handshake (msg, NULL,
						 (char **) mismatch_client_protocols);

	ok = soup_websocket_server_check_handshake (msg, NULL,
						    (char **) mismatch_server_protocols,
						    &error);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE);
	g_clear_error (&error);
	g_assert_false (ok);

	ok = soup_websocket_server_process_handshake (msg, NULL,
						      (char **) mismatch_server_protocols);
	g_assert_false (ok);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	g_assert_cmpstr (protocol, ==, NULL);

	ok = soup_websocket_client_verify_handshake (msg, &error);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE);
	g_clear_error (&error);
	g_assert_false (ok);

	g_object_unref (msg);
}

static void
test_protocol_mismatch_soup (Test *test,
			     gconstpointer unused)
{
	setup_soup_server (test, NULL, mismatch_server_protocols, got_server_connection, test);
	client_connect (test, NULL, mismatch_client_protocols, got_client_connection, test);
	WAIT_UNTIL (test->client_error != NULL);

	g_assert_error (test->client_error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET);
}

static const char *all_protocols[] = { "aaa", "bbb", "ccc", NULL };

static void
test_protocol_server_any_direct (Test *test,
				 gconstpointer unused)
{
	SoupMessage *msg;
	gboolean ok;
	const char *protocol;
	GError *error = NULL;

	msg = soup_message_new ("GET", "http://127.0.0.1");
	soup_websocket_client_prepare_handshake (msg, NULL, (char **) all_protocols);

	ok = soup_websocket_server_check_handshake (msg, NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	ok = soup_websocket_server_process_handshake (msg, NULL, NULL);
	g_assert_true (ok);

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	g_assert_cmpstr (protocol, ==, NULL);

	ok = soup_websocket_client_verify_handshake (msg, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	g_object_unref (msg);
}

static void
test_protocol_server_any_soup (Test *test,
			       gconstpointer unused)
{
	setup_soup_server (test, NULL, NULL, got_server_connection, test);
	client_connect (test, NULL, all_protocols, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, NULL);
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, NULL);
	g_assert_cmpstr (soup_message_headers_get_one (test->msg->response_headers, "Sec-WebSocket-Protocol"), ==, NULL);
}

static void
test_protocol_client_any_direct (Test *test,
				 gconstpointer unused)
{
	SoupMessage *msg;
	gboolean ok;
	const char *protocol;
	GError *error = NULL;

	msg = soup_message_new ("GET", "http://127.0.0.1");
	soup_websocket_client_prepare_handshake (msg, NULL, NULL);

	ok = soup_websocket_server_check_handshake (msg, NULL, (char **) all_protocols, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	ok = soup_websocket_server_process_handshake (msg, NULL, (char **) all_protocols);
	g_assert_true (ok);

	protocol = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol");
	g_assert_cmpstr (protocol, ==, NULL);

	ok = soup_websocket_client_verify_handshake (msg, &error);
	g_assert_no_error (error);
	g_assert_true (ok);

	g_object_unref (msg);
}

static void
test_protocol_client_any_soup (Test *test,
			       gconstpointer unused)
{
	setup_soup_server (test, NULL, all_protocols, got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->client), ==, NULL);
	g_assert_cmpstr (soup_websocket_connection_get_protocol (test->server), ==, NULL);
	g_assert_cmpstr (soup_message_headers_get_one (test->msg->response_headers, "Sec-WebSocket-Protocol"), ==, NULL);
}

static const struct {
	gushort code;
	const char *reason;
	gushort expected_sender_code;
	const char *expected_sender_reason;
	gushort expected_receiver_code;
	const char *expected_receiver_reason;
} close_clean_tests[] = {
	{ SOUP_WEBSOCKET_CLOSE_NORMAL, "NORMAL", SOUP_WEBSOCKET_CLOSE_NORMAL, "NORMAL", SOUP_WEBSOCKET_CLOSE_NORMAL, "NORMAL" },
	{ SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "GOING_AWAY", SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "GOING_AWAY", SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "GOING_AWAY" },
	{ SOUP_WEBSOCKET_CLOSE_NORMAL, NULL, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL },
	{ SOUP_WEBSOCKET_CLOSE_NO_STATUS, NULL, SOUP_WEBSOCKET_CLOSE_NORMAL, NULL, SOUP_WEBSOCKET_CLOSE_NO_STATUS, NULL },
};

static void
do_close_clean_client (Test *test,
		       gushort code,
		       const char *reason,
		       gushort expected_sender_code,
		       const char *expected_sender_reason,
		       gushort expected_receiver_code,
		       const char *expected_receiver_reason)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->client, code, reason);
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, expected_sender_code);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->client), ==, expected_sender_reason);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, expected_receiver_code);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->server), ==, expected_receiver_reason);
}

static void
test_close_clean_client_soup (Test *test,
			      gconstpointer data)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (close_clean_tests); i++) {
		setup_soup_connection (test, data);

		do_close_clean_client (test,
				       close_clean_tests[i].code,
				       close_clean_tests[i].reason,
				       close_clean_tests[i].expected_sender_code,
				       close_clean_tests[i].expected_sender_reason,
				       close_clean_tests[i].expected_receiver_code,
				       close_clean_tests[i].expected_receiver_reason);

		teardown_soup_connection (test, data);
	}
}

static void
test_close_clean_client_direct (Test *test,
				gconstpointer data)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (close_clean_tests); i++) {
		setup_direct_connection (test, data);

		do_close_clean_client (test,
				       close_clean_tests[i].code,
				       close_clean_tests[i].reason,
				       close_clean_tests[i].expected_sender_code,
				       close_clean_tests[i].expected_sender_reason,
				       close_clean_tests[i].expected_receiver_code,
				       close_clean_tests[i].expected_receiver_reason);

		teardown_direct_connection (test, data);
	}
}

static void
do_close_clean_server (Test *test,
		       gushort code,
		       const char *reason,
		       gushort expected_sender_code,
		       const char *expected_sender_reason,
		       gushort expected_receiver_code,
		       const char *expected_receiver_reason)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->server, code, reason);
	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, expected_sender_code);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->server), ==, expected_sender_reason);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, expected_receiver_code);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->client), ==, expected_receiver_reason);
}

static void
test_close_clean_server_soup (Test *test,
			      gconstpointer data)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (close_clean_tests); i++) {
		setup_direct_connection (test, data);

		do_close_clean_server (test,
				       close_clean_tests[i].code,
				       close_clean_tests[i].reason,
				       close_clean_tests[i].expected_sender_code,
				       close_clean_tests[i].expected_sender_reason,
				       close_clean_tests[i].expected_receiver_code,
				       close_clean_tests[i].expected_receiver_reason);

		teardown_direct_connection (test, data);
	}
}

static void
test_close_clean_server_direct (Test *test,
				gconstpointer data)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (close_clean_tests); i++) {
		setup_direct_connection (test, data);

		do_close_clean_server (test,
				       close_clean_tests[i].code,
				       close_clean_tests[i].reason,
				       close_clean_tests[i].expected_sender_code,
				       close_clean_tests[i].expected_sender_reason,
				       close_clean_tests[i].expected_receiver_code,
				       close_clean_tests[i].expected_receiver_reason);

		teardown_direct_connection (test, data);
	}
}

static gboolean
on_closing_send_message (SoupWebsocketConnection *ws,
                         gpointer data)
{
	GBytes *message = data;

	soup_websocket_connection_send_text (ws, g_bytes_get_data (message, NULL));
	g_signal_handlers_disconnect_by_func (ws, on_closing_send_message, data);
	return TRUE;
}

static void
test_message_after_closing (Test *test,
                            gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;
	GBytes *received = NULL;
	GBytes *message;

	message = g_bytes_new_static ("another test because", strlen ("another test because"));
	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_set_flag), &close_event_server);
	g_signal_connect (test->server, "closing", G_CALLBACK (on_closing_send_message), message);

	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "another reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert (received != NULL);
	g_assert (g_bytes_equal (message, received));

	g_bytes_unref (received);
	g_bytes_unref (message);
}

static gpointer
close_after_close_server_thread (gpointer user_data)
{
	Test *test = user_data;
	gsize written;
	const char frames[] =
		"\x88\x09\x03\xe8""reason1"
		"\x88\x09\x03\xe8""reason2";
	GSocket *socket;
	GError *error = NULL;

	g_mutex_lock (&test->mutex);
	g_mutex_unlock (&test->mutex);

	g_output_stream_write_all (g_io_stream_get_output_stream (test->raw_server),
				   frames, sizeof (frames) -1, &written, NULL, &error);
	g_assert_no_error (error);
	g_assert_cmpuint (written, ==, sizeof (frames) - 1);
	socket = g_socket_connection_get_socket (G_SOCKET_CONNECTION (test->raw_server));
	g_socket_shutdown (socket, FALSE, TRUE, &error);
	g_assert_no_error (error);

	return NULL;
}

static void
test_close_after_close (Test *test,
			gconstpointer data)
{
	GThread *thread;

	g_mutex_lock (&test->mutex);

	thread = g_thread_new ("close-after-close-thread", close_after_close_server_thread, test);

	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_NORMAL, "reason1");
	g_mutex_unlock (&test->mutex);

	g_thread_join (thread);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
	g_assert_cmpuint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_NORMAL);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->client), ==, "reason1");
	g_io_stream_close (test->raw_server, NULL, NULL);
}

static gboolean
on_close_unref_connection (SoupWebsocketConnection *ws,
			   gpointer user_data)
{
	Test *test = user_data;

	g_assert_true (test->server == ws);
	g_clear_object (&test->server);
	return TRUE;
}

static void
test_server_unref_connection_on_close (Test *test,
				       gconstpointer data)
{
	gboolean close_event_client = FALSE;

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_unref_connection), test);
	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "client closed");
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (test->server == NULL);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert_true (close_event_client);
}

static gpointer
timeout_server_thread (gpointer user_data)
{
	Test *test = user_data;
	GError *error = NULL;

	/* don't close until the client has timed out */
	g_mutex_lock (&test->mutex);
	g_mutex_unlock (&test->mutex);

	g_io_stream_close (test->raw_server, NULL, &error);
	g_assert_no_error (error);

	return NULL;
}

static void
test_close_after_timeout (Test *test,
			  gconstpointer data)
{
	gboolean close_event = FALSE;
	GThread *thread;

	g_mutex_lock (&test->mutex);

	/* Note that no real server is around in this test, so no close happens */
	thread = g_thread_new ("timeout-thread", timeout_server_thread, test);

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event);
	g_signal_connect (test->client, "error", G_CALLBACK (on_error_not_reached), NULL);

	/* Now try and close things */
	soup_websocket_connection_close (test->client, 0, NULL);
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event == TRUE);

	/* Now actually close the server side stream */
	g_mutex_unlock (&test->mutex);
	g_thread_join (thread);
}

static gpointer
send_fragments_server_thread (gpointer user_data)
{
	Test *test = user_data;
	gsize written;
	const char fragments[] = "\x01\x04""one "   /* !fin | opcode */
		"\x00\x04""two "   /* !fin | no opcode */
		"\x80\x05""three"; /* fin  | no opcode */
	GError *error = NULL;

	g_output_stream_write_all (g_io_stream_get_output_stream (test->raw_server),
				   fragments, sizeof (fragments) -1, &written, NULL, &error);
	g_assert_no_error (error);
	g_assert_cmpuint (written, ==, sizeof (fragments) - 1);
	g_io_stream_close (test->raw_server, NULL, &error);
	g_assert_no_error (error);

	return NULL;
}

static void
do_deflate (z_stream *zstream,
            const char *str,
            guint8 *buffer,
            gsize *length)
{
        zstream->next_in = (void *)str;
        zstream->avail_in = strlen (str);
        zstream->next_out = buffer;
        zstream->avail_out = 512;

        g_assert_cmpint (deflate(zstream, Z_NO_FLUSH), ==, Z_OK);
        g_assert_cmpint (zstream->avail_in, ==, 0);
        g_assert_cmpint (deflate(zstream, Z_SYNC_FLUSH), ==, Z_OK);
        g_assert_cmpint (deflate(zstream, Z_SYNC_FLUSH), ==, Z_BUF_ERROR);

        *length = 512 - zstream->avail_out;
        g_assert_cmpuint (*length, <, 126);
}

static gpointer
send_compressed_fragments_server_thread (gpointer user_data)
{
        Test *test = user_data;
        gsize written;
        z_stream zstream;
        GByteArray *data;
        guint8 byte;
        guint8 buffer[512];
        gsize buffer_length;
        GError *error = NULL;

        memset (&zstream, 0, sizeof(z_stream));
        g_assert (deflateInit2 (&zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) == Z_OK);

        data = g_byte_array_new ();

        do_deflate (&zstream, "one ", buffer, &buffer_length);
        byte = 0x00 | 0x01 | 0x40; /* !fin | opcode | compressed */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

        do_deflate (&zstream, "two ", buffer, &buffer_length);
        byte = 0x00; /* !fin | no opcode */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

        do_deflate (&zstream, "three", buffer, &buffer_length);
        g_assert_cmpuint (buffer_length, >=, 4);
        buffer_length -= 4;
        byte = 0x80; /* fin | no opcode */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

        g_output_stream_write_all (g_io_stream_get_output_stream (test->raw_server),
                                   data->data, data->len, &written, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpuint (written, ==, data->len);
        g_io_stream_close (test->raw_server, NULL, &error);
        g_assert_no_error (error);

        deflateEnd (&zstream);
        g_byte_array_free (data, TRUE);

        return NULL;
}

static void
test_receive_fragmented (Test *test,
			 gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GBytes *expect;

	thread = g_thread_new ("fragment-thread",
			       test->enable_extensions ?
			       send_compressed_fragments_server_thread :
			       send_fragments_server_thread,
			       test);

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_not_reached), NULL);
	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);

	WAIT_UNTIL (received != NULL);
	expect = g_bytes_new ("one two three", 13);
	g_assert (g_bytes_equal (expect, received));
	g_bytes_unref (expect);
	g_bytes_unref (received);

	g_thread_join (thread);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
}

typedef struct {
	Test *test;
	const char *header;
	GString *payload;
} InvalidEncodeLengthTest;

static gpointer
send_invalid_encode_length_server_thread (gpointer user_data)
{
	InvalidEncodeLengthTest *test = user_data;
	gsize header_size;
	gsize written;
	GError *error = NULL;

	header_size = test->payload->len == 125 ? 6 : 10;
	g_output_stream_write_all (g_io_stream_get_output_stream (test->test->raw_server),
				   test->header, header_size, &written, NULL, &error);
	g_assert_no_error (error);
	g_assert_cmpuint (written, ==, header_size);

	g_output_stream_write_all (g_io_stream_get_output_stream (test->test->raw_server),
				   test->payload->str, test->payload->len, &written, NULL, &error);
	g_assert_no_error (error);
	g_assert_cmpuint (written, ==, test->payload->len);

	g_io_stream_close (test->test->raw_server, NULL, &error);
	g_assert_no_error (error);

	return NULL;
}

static void
test_receive_invalid_encode_length_16 (Test *test,
				       gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GError *error = NULL;
	InvalidEncodeLengthTest context = { test, NULL };
	guint i;

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "message", G_CALLBACK (on_binary_message), &received);

	/* We use 126(~) as payload length with 125 extended length */
	context.header = "\x82~\x00}";
	context.payload = g_string_new (NULL);
	for (i = 0; i < 125; i++)
		g_string_append (context.payload, "X");
	thread = g_thread_new ("invalid-encode-length-thread", send_invalid_encode_length_server_thread, &context);

	WAIT_UNTIL (error != NULL || received != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
	g_clear_error (&error);
	g_assert_null (received);

	g_thread_join (thread);
	g_string_free (context.payload, TRUE);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
}

static void
test_receive_invalid_encode_length_64 (Test *test,
				       gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GError *error = NULL;
	InvalidEncodeLengthTest context = { test, NULL };
	guint i;

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "message", G_CALLBACK (on_binary_message), &received);

	/* We use 127(\x7f) as payload length with 65535 extended length */
	context.header = "\x82\x7f\x00\x00\x00\x00\x00\x00\xff\xff";
	context.payload = g_string_new (NULL);
	for (i = 0; i < 65535; i++)
		g_string_append (context.payload, "X");
	thread = g_thread_new ("invalid-encode-length-thread", send_invalid_encode_length_server_thread, &context);

	WAIT_UNTIL (error != NULL || received != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
	g_clear_error (&error);
	g_assert_null (received);

        g_thread_join (thread);
	g_string_free (context.payload, TRUE);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
}

static gpointer
send_masked_frame_server_thread (gpointer user_data)
{
	Test *test = user_data;
	const char frame[] = "\x82\x8e\x9a";
	gsize written;
	GError *error = NULL;

	g_output_stream_write_all (g_io_stream_get_output_stream (test->raw_server),
				   frame, sizeof (frame), &written, NULL, &error);
	g_assert_no_error (error);
	g_assert_cmpuint (written, ==, sizeof (frame));

	g_io_stream_close (test->raw_server, NULL, &error);
	g_assert_no_error (error);

	return NULL;
}

static void
test_client_receive_masked_frame (Test *test,
				  gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GError *error = NULL;

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "message", G_CALLBACK (on_binary_message), &received);

	thread = g_thread_new ("send-masked-frame-thread", send_masked_frame_server_thread, test);

	WAIT_UNTIL (error != NULL || received != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
	g_clear_error (&error);
	g_assert_null (received);

        g_thread_join (thread);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
}

static void
test_server_receive_unmasked_frame (Test *test,
				    gconstpointer data)
{
	GError *error = NULL;
	GIOStream *io;
	gsize written;
	const char *frame;
	gboolean close_event = FALSE;

	g_signal_handlers_disconnect_by_func (test->server, on_error_not_reached, NULL);
	g_signal_connect (test->server, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event);

	io = soup_websocket_connection_get_io_stream (test->client);

	/* Unmasked frame */
	frame = "\x81\x0bHello World";
	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					frame, 13, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (written, ==, 13);

	WAIT_UNTIL (error != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
	g_clear_error (&error);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
	g_assert (close_event);

	g_assert_cmpuint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);

}

static void
test_client_context_got_server_connection (SoupServer              *server,
					   SoupWebsocketConnection *connection,
					   const char              *path,
					   SoupClientContext       *client,
					   gpointer                 user_data)
{
	Test *test = user_data;
	GSocketAddress *addr;
	GInetAddress *iaddr;
	char *str;
	const char *remote_ip;

	addr = soup_client_context_get_local_address (client);
	iaddr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
	str = g_inet_address_to_string (iaddr);
	if (g_inet_address_get_family (iaddr) == G_SOCKET_FAMILY_IPV4)
		g_assert_cmpstr (str, ==, "127.0.0.1");
	else
		g_assert_cmpstr (str, ==, "::1");
	g_free (str);

	addr = soup_client_context_get_remote_address (client);
	iaddr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
	str = g_inet_address_to_string (iaddr);
	if (g_inet_address_get_family (iaddr) == G_SOCKET_FAMILY_IPV4)
		g_assert_cmpstr (str, ==, "127.0.0.1");
	else
		g_assert_cmpstr (str, ==, "::1");

	remote_ip = soup_client_context_get_host (client);
	g_assert_cmpstr (remote_ip, ==, str);
	g_free (str);

	test->server = g_object_ref (connection);
}

static void
test_client_context (Test *test,
		     gconstpointer unused)
{
	setup_soup_server (test, NULL, NULL, test_client_context_got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);
}

static struct {
	const char *client_extension;
	gboolean expected_prepare_result;
	gboolean server_supports_extensions;
	gboolean expected_check_result;
	gboolean expected_accepted_extension;
	gboolean expected_verify_result;
	const char *server_extension;
} deflate_negotiate_tests[] = {
	{ "permessage-deflate",
	  /* prepare supported check accepted verify */
	    TRUE,      TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate"
	},
	{ "permessage-deflate",
	  /* prepare supported check accepted verify */
	      TRUE,    FALSE,  TRUE,  FALSE,  TRUE,
	  "permessage-deflate"
	},
	{ "permessage-deflate; server_no_context_takeover",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; server_no_context_takeover"
	},
	{ "permessage-deflate; client_no_context_takeover",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; client_no_context_takeover"
	},
	{ "permessage-deflate; server_max_window_bits=8",
	  /* prepare supported check accepted verify */
	      TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; server_max_window_bits=8"
	},
	{ "permessage-deflate; client_max_window_bits",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; client_max_window_bits=15"
	},
	{ "permessage-deflate; client_max_window_bits=10",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; client_max_window_bits=10"
	},
	{ "permessage-deflate; client_no_context_takeover; server_max_window_bits=10",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   TRUE,  TRUE,   TRUE,
	  "permessage-deflate; client_no_context_takeover; server_max_window_bits=10"
	},
	{ "permessage-deflate; unknown_parameter",
	  /* prepare supported check accepted verify */
	      TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
	  NULL
	},
	{ "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
	  NULL
        },
	{ "permessage-deflate; server_max_window_bits=10; server_max_window_bits=15",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
	  NULL
        },
	{ "permessage-deflate; client_no_context_takeover=15",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; server_no_context_takeover=15",
	  /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; server_max_window_bits",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; server_max_window_bits=7",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; server_max_window_bits=16",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; client_max_window_bits=7",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
        { "permessage-deflate; client_max_window_bits=16",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; client_max_window_bits=foo",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; server_max_window_bits=bar",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
	{ "permessage-deflate; client_max_window_bits=15foo",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
        { "permessage-deflate; server_max_window_bits=10bar",
          /* prepare supported check accepted verify */
              TRUE,    TRUE,   FALSE,  FALSE,  FALSE,
          NULL
        },
};

static void
test_deflate_negotiate_direct (Test *test,
			       gconstpointer unused)
{
	GPtrArray *supported_extensions;
	guint i;

	supported_extensions = g_ptr_array_new_full (1, g_type_class_unref);
	g_ptr_array_add (supported_extensions, g_type_class_ref (SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE));

	for (i = 0; i < G_N_ELEMENTS (deflate_negotiate_tests); i++) {
		SoupMessage *msg;
		gboolean result;
		GList *accepted_extensions = NULL;
		GError *error = NULL;

		msg = soup_message_new ("GET", "http://127.0.0.1");

		soup_websocket_client_prepare_handshake (msg, NULL, NULL);
		soup_message_headers_append (msg->request_headers, "Sec-WebSocket-Extensions", deflate_negotiate_tests[i].client_extension);
		result = soup_websocket_server_check_handshake_with_extensions (msg, NULL, NULL,
										deflate_negotiate_tests[i].server_supports_extensions ?
										supported_extensions : NULL,
										&error);
		g_assert (result == deflate_negotiate_tests[i].expected_check_result);
		if (result) {
			g_assert_no_error (error);
		} else {
			g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE);
			g_clear_error (&error);
		}

		result = soup_websocket_server_process_handshake_with_extensions (msg, NULL, NULL,
										  deflate_negotiate_tests[i].server_supports_extensions ?
										  supported_extensions : NULL,
										  &accepted_extensions);
		g_assert (result == deflate_negotiate_tests[i].expected_check_result);
		if (deflate_negotiate_tests[i].expected_accepted_extension) {
			const char *extension;

			extension = soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Extensions");
			g_assert_cmpstr (extension, ==, deflate_negotiate_tests[i].server_extension);
			g_assert_nonnull (accepted_extensions);
			g_assert_cmpuint (g_list_length (accepted_extensions), ==, 1);
			g_assert (SOUP_IS_WEBSOCKET_EXTENSION_DEFLATE (accepted_extensions->data));
			g_list_free_full (accepted_extensions, g_object_unref);
			accepted_extensions = NULL;
		} else {
			g_assert_null (accepted_extensions);
		}

		result = soup_websocket_client_verify_handshake_with_extensions (msg, supported_extensions, &accepted_extensions, &error);
		g_assert (result == deflate_negotiate_tests[i].expected_verify_result);
		if (result) {
                        g_assert_no_error (error);
                } else {
                        g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE);
                        g_clear_error (&error);
                }
		if (deflate_negotiate_tests[i].expected_accepted_extension) {
			g_assert_nonnull (accepted_extensions);
                        g_assert_cmpuint (g_list_length (accepted_extensions), ==, 1);
                        g_assert (SOUP_IS_WEBSOCKET_EXTENSION_DEFLATE (accepted_extensions->data));
                        g_list_free_full (accepted_extensions, g_object_unref);
                        accepted_extensions = NULL;
                } else {
                        g_assert_null (accepted_extensions);
                }

		g_object_unref (msg);
        }

	g_ptr_array_unref (supported_extensions);
}

static void
test_deflate_disabled_in_message_direct (Test *test,
					 gconstpointer unused)
{
	SoupMessage *msg;
	GPtrArray *supported_extensions;
	GList *accepted_extensions = NULL;
	GError *error = NULL;

	supported_extensions = g_ptr_array_new_full (1, g_type_class_unref);
        g_ptr_array_add (supported_extensions, g_type_class_ref (SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE));

	msg = soup_message_new ("GET", "http://127.0.0.1");
	soup_message_disable_feature (msg, SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE);
	soup_websocket_client_prepare_handshake_with_extensions (msg, NULL, NULL, supported_extensions);
	g_assert_cmpstr (soup_message_headers_get_one (msg->request_headers, "Sec-WebSocket-Extensions"), ==, NULL);

	g_assert_true (soup_websocket_server_check_handshake_with_extensions (msg, NULL, NULL, supported_extensions, &error));
	g_assert_no_error (error);

	g_assert_true (soup_websocket_server_process_handshake_with_extensions (msg, NULL, NULL, supported_extensions, &accepted_extensions));
	g_assert_null (accepted_extensions);
	g_assert_cmpstr (soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Extensions"), ==, NULL);

	g_assert_true (soup_websocket_client_verify_handshake_with_extensions (msg, supported_extensions, &accepted_extensions, &error));
	g_assert_no_error (error);
	g_assert_null (accepted_extensions);

	g_object_unref (msg);
	g_ptr_array_unref (supported_extensions);
}

static void
test_deflate_disabled_in_message_soup (Test *test,
				       gconstpointer unused)
{
	test->enable_extensions = TRUE;
	test->disable_deflate_in_message = TRUE;
	setup_soup_server (test, NULL, NULL, got_server_connection, test);
	client_connect (test, NULL, NULL, got_client_connection, test);
	WAIT_UNTIL (test->server != NULL);
	WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
	g_assert_no_error (test->client_error);

	g_assert_cmpstr (soup_message_headers_get_one (test->msg->request_headers, "Sec-WebSocket-Extensions"), ==, NULL);
	g_assert_cmpstr (soup_message_headers_get_one (test->msg->response_headers, "Sec-WebSocket-Extensions"), ==, NULL);
}

static gpointer
send_compressed_fragments_error_server_thread (gpointer user_data)
{
        Test *test = user_data;
        gsize written;
        z_stream zstream;
        GByteArray *data;
        guint8 byte;
        guint8 buffer[512];
        gsize buffer_length;
        GError *error = NULL;

        memset (&zstream, 0, sizeof(z_stream));
        g_assert (deflateInit2 (&zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) == Z_OK);

        data = g_byte_array_new ();

        do_deflate (&zstream, "one ", buffer, &buffer_length);
        byte = 0x00 | 0x01 | 0x40; /* !fin | opcode | compressed */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

	/* Only the first fragment should include the compressed bit set. */
        do_deflate (&zstream, "two ", buffer, &buffer_length);
        byte = 0x00 | 0x00 | 0x40; /* !fin | no opcode | compressed */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

        do_deflate (&zstream, "three", buffer, &buffer_length);
        g_assert_cmpuint (buffer_length, >=, 4);
        buffer_length -= 4;
        byte = 0x80; /* fin | no opcode */
        data = g_byte_array_append (data, &byte, 1);
        byte = (0xFF & buffer_length); /* mask | 7-bit-len */
        data = g_byte_array_append (data, &byte, 1);
        data = g_byte_array_append (data, buffer, buffer_length);

        g_output_stream_write_all (g_io_stream_get_output_stream (test->raw_server),
                                   data->data, data->len, &written, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpuint (written, ==, data->len);
        g_io_stream_close (test->raw_server, NULL, &error);
        g_assert_no_error (error);

        deflateEnd (&zstream);
        g_byte_array_free (data, TRUE);

        return NULL;
}

static void
test_deflate_receive_fragmented_error (Test *test,
				       gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	gboolean close_event = FALSE;
	GError *error = NULL;

	thread = g_thread_new ("deflate-fragment-error-thread",
			       send_compressed_fragments_error_server_thread,
			       test);

	g_signal_connect (test->client, "error", G_CALLBACK (on_error_copy), &error);
	g_signal_connect (test->client, "message", G_CALLBACK (on_text_message), &received);
	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event);

	WAIT_UNTIL (error != NULL || received != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR);
	g_clear_error (&error);
	g_assert_null (received);

	g_thread_join (thread);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);
	g_assert (close_event);
}

static void
test_cookies_in_request (Test *test,
                         gconstpointer data)
{
        SoupCookie *cookie;
        const char *cookie_header;
        SoupCookie *requested_cookie;

        cookie = soup_cookie_new ("foo", "bar", "127.0.0.1", "/", -1);
        test->initial_cookies = g_list_prepend (test->initial_cookies, soup_cookie_copy (cookie));

        setup_soup_server (test, NULL, NULL, got_server_connection, test);
        client_connect (test, NULL, NULL, got_client_connection, test);
        WAIT_UNTIL (test->server != NULL);
        WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
        g_assert_no_error (test->client_error);

        cookie_header = soup_message_headers_get_one (test->msg->request_headers, "Cookie");
        requested_cookie = soup_cookie_parse (cookie_header, NULL);
        g_assert_true (soup_cookie_equal (cookie, requested_cookie));
        soup_cookie_free (cookie);
        soup_cookie_free (requested_cookie);
}

static void
cookies_test_websocket_server_request_started (SoupServer *server, SoupMessage *msg,
                                               SoupClientContext *client, gpointer user_data)
{
        soup_message_headers_append (msg->response_headers, "Set-Cookie", "foo=bar; Path=/");
}

static void
test_cookies_in_response (Test *test,
                          gconstpointer data)
{
        SoupCookieJar *jar;
        GSList *cookies;
        SoupCookie *cookie;

        setup_soup_server (test, NULL, NULL, got_server_connection, test);
        g_signal_connect (test->soup_server, "request-started",
                          G_CALLBACK (cookies_test_websocket_server_request_started),
                          NULL);
        client_connect (test, NULL, NULL, got_client_connection, test);
        WAIT_UNTIL (test->server != NULL);
        WAIT_UNTIL (test->client != NULL || test->client_error != NULL);
        g_assert_no_error (test->client_error);

        jar = SOUP_COOKIE_JAR (soup_session_get_feature (test->session, SOUP_TYPE_COOKIE_JAR));
        cookies = soup_cookie_jar_all_cookies (jar);
        g_assert_nonnull (cookies);
        g_assert_cmpuint (g_slist_length (cookies), ==, 1);
        cookie = soup_cookie_new ("foo", "bar", "127.0.0.1", "/", -1);
        g_assert_true (soup_cookie_equal (cookie, (SoupCookie *)cookies->data));
        g_slist_free_full (cookies, (GDestroyNotify)soup_cookie_free);
        soup_cookie_free (cookie);
}

int
main (int argc,
      char *argv[])
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add ("/websocket/soup/handshake", Test, NULL, 
		    setup_soup_connection,
		    test_handshake,
		    teardown_soup_connection);

	g_test_add ("/websocket/soup/handshake-error", Test, NULL, NULL,
		    test_handshake_unsupported_extension,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/send-client-to-server", Test, NULL,
		    setup_direct_connection,
		    test_send_client_to_server,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-client-to-server", Test, NULL, 
		    setup_soup_connection,
		    test_send_client_to_server,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/send-server-to-client", Test, NULL,
		    setup_direct_connection,
		    test_send_server_to_client,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-server-to-client", Test, NULL,
		    setup_soup_connection,
		    test_send_server_to_client,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/send-big-packets", Test, NULL,
		    setup_direct_connection,
		    test_send_big_packets,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-big-packets", Test, NULL,
		    setup_soup_connection,
		    test_send_big_packets,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/send-empty-packets", Test, NULL,
		    setup_direct_connection,
		    test_send_empty_packets,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-empty-packets", Test, NULL,
		    setup_soup_connection,
		    test_send_empty_packets,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/send-bad-data", Test, NULL,
		    setup_direct_connection,
		    test_send_bad_data,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-bad-data", Test, NULL,
		    setup_soup_connection,
		    test_send_bad_data,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/close-clean-client", Test, NULL, NULL,
		    test_close_clean_client_direct,
		    NULL);
	g_test_add ("/websocket/soup/close-clean-client", Test, NULL, NULL,
		    test_close_clean_client_soup,
		    NULL);

	g_test_add ("/websocket/direct/close-clean-server", Test, NULL, NULL,
		    test_close_clean_server_direct,
		    NULL);
	g_test_add ("/websocket/soup/close-clean-server", Test, NULL, NULL,
		    test_close_clean_server_soup,
		    NULL);

	g_test_add ("/websocket/direct/message-after-closing", Test, NULL,
		    setup_direct_connection,
		    test_message_after_closing,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/message-after-closing", Test, NULL,
		    setup_soup_connection,
		    test_message_after_closing,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/close-after-close", Test, NULL,
		    setup_half_direct_connection,
		    test_close_after_close,
		    teardown_direct_connection);

	g_test_add ("/websocket/soup/server-unref-connection-on-close", Test, NULL,
		    setup_soup_connection,
		    test_server_unref_connection_on_close,
		    teardown_soup_connection);


	g_test_add ("/websocket/direct/protocol-negotiate", Test, NULL, NULL,
		    test_protocol_negotiate_direct,
		    NULL);
	g_test_add ("/websocket/soup/protocol-negotiate", Test, NULL, NULL,
		    test_protocol_negotiate_soup,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/protocol-mismatch", Test, NULL, NULL,
		    test_protocol_mismatch_direct,
		    NULL);
	g_test_add ("/websocket/soup/protocol-mismatch", Test, NULL, NULL,
		    test_protocol_mismatch_soup,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/protocol-server-any", Test, NULL, NULL,
		    test_protocol_server_any_direct,
		    NULL);
	g_test_add ("/websocket/soup/protocol-server-any", Test, NULL, NULL,
		    test_protocol_server_any_soup,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/protocol-client-any", Test, NULL, NULL,
		    test_protocol_client_any_direct,
		    NULL);
	g_test_add ("/websocket/soup/protocol-client-any", Test, NULL, NULL,
		    test_protocol_client_any_soup,
		    teardown_soup_connection);


	g_test_add ("/websocket/direct/receive-fragmented", Test, NULL,
		    setup_half_direct_connection,
		    test_receive_fragmented,
		    teardown_direct_connection);

	g_test_add ("/websocket/direct/receive-invalid-encode-length-16", Test, NULL,
		    setup_half_direct_connection,
		    test_receive_invalid_encode_length_16,
		    teardown_direct_connection);

	g_test_add ("/websocket/direct/receive-invalid-encode-length-64", Test, NULL,
		    setup_half_direct_connection,
		    test_receive_invalid_encode_length_64,
		    teardown_direct_connection);

	g_test_add ("/websocket/direct/client-receive-masked-frame", Test, NULL,
		    setup_half_direct_connection,
		    test_client_receive_masked_frame,
		    teardown_direct_connection);

	g_test_add ("/websocket/direct/server-receive-unmasked-frame", Test, NULL,
		    setup_direct_connection,
		    test_server_receive_unmasked_frame,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/server-receive-unmasked-frame", Test, NULL,
		    setup_soup_connection,
		    test_server_receive_unmasked_frame,
		    teardown_soup_connection);

	g_test_add ("/websocket/soup/deflate-handshake", Test, NULL,
		    setup_soup_connection_with_extensions,
		    test_handshake,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-negotiate", Test, NULL, NULL,
		    test_deflate_negotiate_direct,
		    NULL);

	g_test_add ("/websocket/direct/deflate-disabled-in-message", Test, NULL, NULL,
		    test_deflate_disabled_in_message_direct,
		    NULL);
	g_test_add ("/websocket/soup/deflate-disabled-in-message", Test, NULL, NULL,
		    test_deflate_disabled_in_message_soup,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-send-client-to-server", Test, NULL,
		    setup_direct_connection_with_extensions,
		    test_send_client_to_server,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/deflate-send-client-to-server", Test, NULL,
		    setup_soup_connection_with_extensions,
		    test_send_client_to_server,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-send-server-to-client", Test, NULL,
		    setup_direct_connection_with_extensions,
		    test_send_server_to_client,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/deflate-send-server-to-client", Test, NULL,
		    setup_soup_connection_with_extensions,
		    test_send_server_to_client,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-send-big-packets", Test, NULL,
		    setup_direct_connection_with_extensions,
		    test_send_big_packets,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/deflate-send-big-packets", Test, NULL,
		    setup_soup_connection_with_extensions,
		    test_send_big_packets,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-send-empty-packets", Test, NULL,
		    setup_direct_connection_with_extensions,
		    test_send_empty_packets,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/deflate-send-empty-packets", Test, NULL,
		    setup_soup_connection_with_extensions,
		    test_send_empty_packets,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/deflate-receive-fragmented", Test, NULL,
		    setup_half_direct_connection_with_extensions,
		    test_receive_fragmented,
		    teardown_direct_connection);
	g_test_add ("/websocket/direct/deflate-receive-fragmented-error", Test, NULL,
		    setup_half_direct_connection_with_extensions,
		    test_deflate_receive_fragmented_error,
		    teardown_direct_connection);

	if (g_test_slow ()) {
		g_test_add ("/websocket/direct/close-after-timeout", Test, NULL,
			    setup_half_direct_connection,
			    test_close_after_timeout,
			    teardown_direct_connection);
	}

	g_test_add ("/websocket/soup/client-context", Test, NULL, NULL,
		    test_client_context,
		    teardown_soup_connection);

        g_test_add ("/websocket/soup/cookies-in-request", Test, NULL, NULL,
                    test_cookies_in_request,
                    teardown_soup_connection);
        g_test_add ("/websocket/soup/cookies-in-response", Test, NULL, NULL,
                    test_cookies_in_response,
                    teardown_soup_connection);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
