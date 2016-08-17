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

	conn = g_socket_client_connect_to_host_finish (G_SOCKET_CLIENT (object),
						       result, &error);
	g_assert_no_error (error);

	uri = soup_uri_new ("http://127.0.0.1/");
	test->client = soup_websocket_connection_new (G_IO_STREAM (conn), uri,
						      SOUP_WEBSOCKET_CONNECTION_CLIENT,
						      NULL, NULL);
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
		test->server = soup_websocket_connection_new (G_IO_STREAM (conn), uri,
							      SOUP_WEBSOCKET_CONNECTION_SERVER,
							      NULL, NULL);
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
setup_half_direct_connection (Test *test,
			      gconstpointer data)
{
	test->no_server = TRUE;
	setup_direct_connection (test, data);
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

	if (!test->session)
		test->session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);

	url = g_strdup_printf ("ws://127.0.0.1:%u/unix", test->port);
	test->msg = soup_message_new ("GET", url);
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
	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_OPEN);
}

#define TEST_STRING "this is a test"

static void
test_send_client_to_server (Test *test,
                            gconstpointer data)
{
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

	g_bytes_unref (received);
}

static void
test_send_server_to_client (Test *test,
                            gconstpointer data)
{
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

	g_bytes_unref (received);
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
test_send_bad_data (Test *test,
                    gconstpointer unused)
{
	GError *error = NULL;
	GIOStream *io;
	gsize written;
	const char *frame;

	g_signal_handlers_disconnect_by_func (test->server, on_error_not_reached, NULL);
	g_signal_connect (test->server, "error", G_CALLBACK (on_error_copy), &error);

	io = soup_websocket_connection_get_io_stream (test->client);

	/* Bad UTF-8 frame */
	frame = "\x81\x04\xEE\xEE\xEE\xEE";
	if (!g_output_stream_write_all (g_io_stream_get_output_stream (io),
					frame, 6, &written, NULL, NULL))
		g_assert_not_reached ();
	g_assert_cmpuint (written, ==, 6);

	WAIT_UNTIL (error != NULL);
	g_assert_error (error, SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_CLOSE_BAD_DATA);
	g_clear_error (&error);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

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

static void
test_close_clean_client (Test *test,
                         gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->client, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "give me a reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->client), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->server), ==, "give me a reason");
}

static void
test_close_clean_server (Test *test,
                         gconstpointer data)
{
	gboolean close_event_client = FALSE;
	gboolean close_event_server = FALSE;

	g_signal_connect (test->client, "closed", G_CALLBACK (on_close_set_flag), &close_event_client);
	g_signal_connect (test->server, "closed", G_CALLBACK (on_close_set_flag), &close_event_server);

	soup_websocket_connection_close (test->server, SOUP_WEBSOCKET_CLOSE_GOING_AWAY, "another reason");
	g_assert_cmpint (soup_websocket_connection_get_state (test->server), ==, SOUP_WEBSOCKET_STATE_CLOSING);

	WAIT_UNTIL (soup_websocket_connection_get_state (test->server) == SOUP_WEBSOCKET_STATE_CLOSED);
	WAIT_UNTIL (soup_websocket_connection_get_state (test->client) == SOUP_WEBSOCKET_STATE_CLOSED);

	g_assert (close_event_client);
	g_assert (close_event_server);

	g_assert_cmpint (soup_websocket_connection_get_close_code (test->server), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpint (soup_websocket_connection_get_close_code (test->client), ==, SOUP_WEBSOCKET_CLOSE_GOING_AWAY);
	g_assert_cmpstr (soup_websocket_connection_get_close_data (test->client), ==, "another reason");
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
test_receive_fragmented (Test *test,
			 gconstpointer data)
{
	GThread *thread;
	GBytes *received = NULL;
	GBytes *expect;

	thread = g_thread_new ("fragment-thread", send_fragments_server_thread, test);

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

	g_test_add ("/websocket/direct/send-bad-data", Test, NULL,
		    setup_direct_connection,
		    test_send_bad_data,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/send-bad-data", Test, NULL,
		    setup_soup_connection,
		    test_send_bad_data,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/close-clean-client", Test, NULL,
		    setup_direct_connection,
		    test_close_clean_client,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/close-clean-client", Test, NULL,
		    setup_soup_connection,
		    test_close_clean_client,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/close-clean-server", Test, NULL,
		    setup_direct_connection,
		    test_close_clean_server,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/close-clean-server", Test, NULL,
		    setup_soup_connection,
		    test_close_clean_server,
		    teardown_soup_connection);

	g_test_add ("/websocket/direct/message-after-closing", Test, NULL,
		    setup_direct_connection,
		    test_message_after_closing,
		    teardown_direct_connection);
	g_test_add ("/websocket/soup/message-after-closing", Test, NULL,
		    setup_soup_connection,
		    test_message_after_closing,
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

	if (g_test_slow ()) {
		g_test_add ("/websocket/direct/close-after-timeout", Test, NULL,
			    setup_half_direct_connection,
			    test_close_after_timeout,
			    teardown_direct_connection);
	}

	g_test_add ("/websocket/soup/client-context", Test, NULL, NULL,
		    test_client_context,
		    teardown_soup_connection);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
