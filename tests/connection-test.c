/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

#include "soup-connection.h"
#include "soup-server-connection.h"
#include "soup-server-message-private.h"

#include <gio/gnetworking.h>

static SoupServer *server;
static GUri *base_uri;
static GUri *base_https_uri;
static GMutex server_mutex;

static void
forget_close (SoupServerMessage *msg,
	      gpointer           user_data)
{
	soup_message_headers_remove (soup_server_message_get_response_headers (msg),
				     "Connection");
}

static void
close_socket (SoupServerMessage    *msg,
	      SoupServerConnection *conn)
{
        GSocket *socket;
	int sockfd;

	/* Actually calling soup_socket_disconnect() here would cause
	 * us to leak memory, so just shutdown the socket instead.
	 */
        socket = soup_server_connection_get_socket (conn);
	sockfd = g_socket_get_fd (socket);
#ifdef G_OS_WIN32
	shutdown (sockfd, SD_SEND);
#else
	shutdown (sockfd, SHUT_WR);
#endif

	/* Then add the missing data to the message now, so SoupServer
	 * can clean up after itself properly.
	 */
	soup_message_body_append (soup_server_message_get_response_body (msg),
				  SOUP_MEMORY_STATIC,
				  "foo", 3);
}

static gboolean
timeout_socket (GObject              *pollable,
		SoupServerConnection *conn)
{
	soup_server_connection_disconnect (conn);
	return FALSE;
}

static void
timeout_request_finished (SoupServer        *server,
                          SoupServerMessage *msg,
                          gpointer           user_data)
{
	SoupServerConnection *conn;
	GIOStream *iostream;
	GInputStream *istream;
	GSource *source;

	g_signal_handlers_disconnect_by_func (server, timeout_request_finished, NULL);

	conn = soup_server_message_get_connection (msg);
	iostream = soup_server_connection_get_iostream (conn);
	istream = g_io_stream_get_input_stream (iostream);
	source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (istream), NULL);
	g_source_set_callback (source, (GSourceFunc)timeout_socket, conn, NULL);
	g_source_attach (source, g_main_context_get_thread_default ());
	g_source_unref (source);

	g_mutex_unlock (&server_mutex);
}

static void
setup_timeout_persistent (SoupServer           *server,
                          SoupServerConnection *conn)
{
	/* In order for the test to work correctly, we have to
	 * close the connection *after* the client side writes
	 * the request. To ensure that this happens reliably,
	 * regardless of thread scheduling, we:
	 *
	 *   1. Wait for the server to finish this request and
	 *      start reading the next one (and lock server_mutex
	 *      to interlock with the client and ensure that it
	 *      doesn't start writing its next request until
	 *      that point).
	 *   2. Block until input stream is readable, meaning the
	 *      client has written its request.
	 *   3. Close the socket.
	 */
	g_mutex_lock (&server_mutex);
	g_signal_connect (server, "request-finished",
			  G_CALLBACK (timeout_request_finished), NULL);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *method;

	/* The way this gets used in the tests, we don't actually
	 * need to hold it through the whole function, so it's simpler
	 * to just release it right away.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	method = soup_server_message_get_method (msg);
	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_POST) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	if (g_str_has_prefix (path, "/content-length/")) {
		gboolean too_long = strcmp (path, "/content-length/long") == 0;
		gboolean no_close = strcmp (path, "/content-length/noclose") == 0;
		SoupMessageHeaders *response_headers;

		soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
		soup_server_message_set_response (msg, "text/plain",
						  SOUP_MEMORY_STATIC, "foobar", 6);

		response_headers = soup_server_message_get_response_headers (msg);
		if (too_long)
			soup_message_headers_set_content_length (response_headers, 9);
		soup_message_headers_append (response_headers,
					     "Connection", "close");

		if (too_long) {
			SoupServerConnection *conn;

			/* soup-message-io will wait for us to add
			 * another chunk after the first, to fill out
			 * the declared Content-Length. Instead, we
			 * forcibly close the socket at that point.
			 */
			conn = soup_server_message_get_connection (msg);
			g_signal_connect (msg, "wrote-chunk",
					  G_CALLBACK (close_socket), conn);
		} else if (no_close) {
			/* Remove the 'Connection: close' after writing
			 * the headers, so that when we check it after
			 * writing the body, we'll think we aren't
			 * supposed to close it.
			 */
			g_signal_connect (msg, "wrote-headers",
					  G_CALLBACK (forget_close), NULL);
		}
		return;
	}

	if (!strcmp (path, "/timeout-persistent")) {
		SoupServerConnection *conn;

		conn = soup_server_message_get_connection (msg);
		setup_timeout_persistent (server, conn);
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_STATIC, "index", 5);
	return;
}

static void
do_content_length_framing_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *request_uri;
	goffset declared_length;
	GBytes *body;

	g_test_bug ("611481");

	session = soup_test_session_new (NULL);

	debug_printf (1, "  Content-Length larger than message body length\n");
	request_uri = g_uri_parse_relative (base_uri, "/content-length/long", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", request_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	declared_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));
	debug_printf (2, "    Content-Length: %lu, body: %s\n",
		      (gulong)declared_length, (char *)g_bytes_get_data (body, NULL));
	g_assert_cmpint (g_bytes_get_size (body), <, declared_length);

	g_uri_unref (request_uri);
	g_bytes_unref (body);
	g_object_unref (msg);

	debug_printf (1, "  Server claims 'Connection: close' but doesn't\n");
	request_uri = g_uri_parse_relative (base_uri, "/content-length/noclose", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", request_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	declared_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));
	g_assert_cmpint (g_bytes_get_size (body), ==, declared_length);

	g_uri_unref (request_uri);
	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
message_started_socket_collector (SoupMessage *msg,
				  GSocket    **sockets)
{
        SoupConnection *conn = soup_message_get_connection (msg);
        GSocket *socket = soup_connection_get_socket (conn);
	int i;

	debug_printf (2, "      msg %p => socket %p\n", msg, socket);
	for (i = 0; i < 4; i++) {
		if (!sockets[i]) {
			/* We ref the socket to make sure that even if
			 * it gets disconnected, it doesn't get freed,
			 * since our checks would get messed up if the
			 * slice allocator reused the same address for
			 * two consecutive sockets.
			 */
			sockets[i] = g_object_ref (socket);
			break;
		}
	}

	soup_test_assert (i < 4, "socket queue overflowed");
}

static void
request_queued_socket_collector (SoupSession *session,
				 SoupMessage *msg,
				 gpointer     data)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (message_started_socket_collector),
			  data);
}

static void
do_timeout_test_for_base_uri (GUri *base_uri)
{
        SoupSession *session;
	SoupMessage *msg;
	GSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	GUri *timeout_uri;
	int i;
	GBytes *body;

        session = soup_test_session_new (NULL);

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (request_queued_socket_collector),
			  &sockets);

	debug_printf (1, "    First message\n");
	timeout_uri = g_uri_parse_relative (base_uri, "/timeout-persistent", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	g_uri_unref (timeout_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_bytes_unref (body);
	g_object_unref (msg);

	/* The server will grab server_mutex before returning the response,
	 * and release it when it's ready for us to send the second request.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	debug_printf (1, "    Second message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	soup_test_assert (sockets[1] == sockets[0],
			  "Message was not retried on existing connection");
	soup_test_assert (sockets[2] != NULL,
			  "Message was not retried after disconnect");
	soup_test_assert (sockets[2] != sockets[1],
			  "Message was retried on closed connection");
	soup_test_assert (sockets[3] == NULL,
			  "Message was retried again");
	g_bytes_unref (body);
	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);

        soup_test_session_abort_unref (session);
}

static void
do_persistent_connection_timeout_test (void)
{
	g_test_bug ("631525");

        debug_printf (1, "  HTTP/1\n");
        do_timeout_test_for_base_uri (base_uri);

        debug_printf (1, "  HTTP/2\n");
        do_timeout_test_for_base_uri (base_https_uri);
}

static void
do_persistent_connection_timeout_test_with_cancellation_for_base_uri (GUri *base_uri)
{
	SoupSession *session;
	SoupMessage *msg;
	GSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	GUri *timeout_uri;
	GCancellable *cancellable;
	GInputStream *response;
	int i;
	char buf[8192];

	session = soup_test_session_new (NULL);

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (request_queued_socket_collector),
			  &sockets);

	debug_printf (1, "    First message\n");
	timeout_uri = g_uri_parse_relative (base_uri, "/timeout-persistent", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	cancellable = g_cancellable_new ();
	g_uri_unref (timeout_uri);
	response = soup_session_send (session, msg, cancellable, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (msg);

	soup_test_assert (response, "No response received");

	while (g_input_stream_read (response, buf, sizeof (buf), NULL, NULL))
		debug_printf (1, "Reading response\n");

	soup_test_assert (!g_cancellable_is_cancelled (cancellable),
			  "User-supplied cancellable was cancelled");

	g_object_unref (response);

	/* The server will grab server_mutex before returning the response,
	 * and release it when it's ready for us to send the second request.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	debug_printf (1, "    Second message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);

	/* Cancel the cancellable in the signal handler, and then check that it
	 * was not reset below */
	g_signal_connect_swapped (msg, "starting",
				  G_CALLBACK (g_cancellable_cancel),
				  cancellable);

	response = soup_session_send (session, msg, cancellable, NULL);

	soup_test_assert (response == NULL, "Unexpected response");

	soup_test_assert_message_status (msg, SOUP_STATUS_NONE);

	soup_test_assert (sockets[1] == sockets[0],
			  "Message was not retried on existing connection");
	soup_test_assert (sockets[2] != sockets[1],
			  "Message was retried on closed connection");
	soup_test_assert (sockets[3] == NULL,
			  "Message was retried again");
	g_object_unref (msg);

	/* cancellable should not have been reset, it should still be in the
	 * cancelled state */
	soup_test_assert (g_cancellable_is_cancelled (cancellable),
			  "User-supplied cancellable was reset");

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);

	g_object_unref (cancellable);

	soup_test_session_abort_unref (session);
}

static void
do_persistent_connection_timeout_test_with_cancellation (void)
{
        debug_printf (1, "  HTTP/1\n");
        do_persistent_connection_timeout_test_with_cancellation_for_base_uri (base_uri);

        debug_printf (1, "  HTTP/2\n");
        do_persistent_connection_timeout_test_with_cancellation_for_base_uri (base_https_uri);
}

static GMainLoop *max_conns_loop;
static int msgs_done;
static guint quit_loop_timeout;
#define MAX_CONNS 2
#define TEST_CONNS ((MAX_CONNS * 2) + 1)

static gboolean
idle_start_server (gpointer data)
{
	g_mutex_unlock (&server_mutex);
	return FALSE;
}

static gboolean
quit_loop (gpointer data)
{
	quit_loop_timeout = 0;
	g_main_loop_quit (max_conns_loop);
	return FALSE;
}

static void
max_conns_message_started (SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, max_conns_message_started, NULL);

	if (++msgs_done >= MAX_CONNS) {
                if (quit_loop_timeout)
                        g_source_remove (quit_loop_timeout);
	        quit_loop_timeout = g_timeout_add (100, quit_loop, NULL);
        }
}

static void
max_conns_request_queued (SoupSession *session,
			  SoupMessage *msg,
			  gpointer     data)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (max_conns_message_started),
			  data);
}

static void
max_conns_message_complete (SoupMessage *msg, gpointer user_data)
{
	if (++msgs_done == TEST_CONNS)
		g_main_loop_quit (max_conns_loop);
}

static void
do_max_conns_test_for_session (SoupSession *session)
{
	SoupMessage *msgs[TEST_CONNS];
	int i;
	GCancellable *cancellable;

	max_conns_loop = g_main_loop_new (NULL, TRUE);

	g_mutex_lock (&server_mutex);

	cancellable = g_cancellable_new ();
	g_signal_connect (session, "request-queued",
			  G_CALLBACK (max_conns_request_queued), NULL);
	msgs_done = 0;
	for (i = 0; i < TEST_CONNS; i++) {
		msgs[i] = soup_message_new_from_uri ("GET", base_uri);
		g_signal_connect (msgs[i], "finished",
				  G_CALLBACK (max_conns_message_complete), NULL);
		soup_session_send_async (session, msgs[i], G_PRIORITY_DEFAULT, cancellable, NULL, NULL);
	}

	g_main_loop_run (max_conns_loop);
	g_assert_cmpint (msgs_done, ==, MAX_CONNS);

	if (quit_loop_timeout)
		g_source_remove (quit_loop_timeout);
	quit_loop_timeout = g_timeout_add (1000, quit_loop, NULL);

	for (i = 0; i < TEST_CONNS; i++)
		g_signal_handlers_disconnect_by_func (msgs[i], max_conns_message_started, NULL);

	msgs_done = 0;
	g_idle_add (idle_start_server, NULL);
	if (quit_loop_timeout)
		g_source_remove (quit_loop_timeout);
	quit_loop_timeout = g_timeout_add (1000, quit_loop, NULL);
	g_main_loop_run (max_conns_loop);

	for (i = 0; i < TEST_CONNS; i++)
		soup_test_assert_message_status (msgs[i], SOUP_STATUS_OK);

	if (msgs_done != TEST_CONNS) {
		/* Clean up so we don't get a spurious "Leaked
		 * session" error.
		 */
		g_cancellable_cancel (cancellable);
		g_main_loop_run (max_conns_loop);
	}

	g_object_unref (cancellable);
	g_main_loop_unref (max_conns_loop);
	if (quit_loop_timeout) {
		g_source_remove (quit_loop_timeout);
		quit_loop_timeout = 0;
	}

	for (i = 0; i < TEST_CONNS; i++)
		g_object_unref (msgs[i]);
}

static void
do_max_conns_test (void)
{
	SoupSession *session;

	g_test_bug ("634422");

	session = soup_test_session_new ("max-conns", MAX_CONNS,
					 NULL);
	do_max_conns_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
np_message_started (SoupMessage *msg,
		    GSocket    **save_socket)
{
        SoupConnection *conn = soup_message_get_connection (msg);
        GSocket *socket = soup_connection_get_socket (conn);

	*save_socket = g_object_ref (socket);
}

static void
np_request_queued (SoupSession *session,
		   SoupMessage *msg,
		   gpointer     data)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (np_message_started),
			  data);
}

static void
np_request_unqueued (SoupSession *session,
		     SoupMessage *msg,
		     GSocket    **socket)
{
	g_assert_false (g_socket_is_connected (*socket));
}

static void
np_request_finished (SoupMessage *msg,
		     gpointer     user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
}

static void
do_non_persistent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	GSocket *socket = NULL;
	GMainLoop *loop;

	loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (np_request_queued),
			  &socket);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (np_request_unqueued),
			  &socket);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Connection", "close");
	g_signal_connect (msg, "finished",
			  G_CALLBACK (np_request_finished), loop);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	g_object_unref (socket);
}

static void
do_non_persistent_connection_test (void)
{
	SoupSession *session;

	g_test_bug ("578990");

	session = soup_test_session_new (NULL);
	do_non_persistent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_non_idempotent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	GSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	int i;
	GBytes *body;

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (request_queued_socket_collector),
			  &sockets);

	debug_printf (2, "    GET\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_bytes_unref (body);
	g_object_unref (msg);

	debug_printf (2, "    POST\n");
	msg = soup_message_new_from_uri ("POST", base_uri);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	soup_test_assert (sockets[1] != sockets[0],
			  "Message was sent on existing connection");
	soup_test_assert (sockets[2] == NULL,
			  "Too many connections used");
	g_bytes_unref (body);
	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_non_idempotent_connection_test (void)
{
	SoupSession *session;

	session = soup_test_session_new (NULL);
	do_non_idempotent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

#define HTTP_SERVER          "http://127.0.0.1:47524"
#define HTTP_SERVER_BAD_PORT "http://127.0.0.1:1234"
#define HTTPS_SERVER         "https://127.0.0.1:47525"
#define HTTP_PROXY           "http://127.0.0.1:47526"

static const char *state_names[] = {
	"NEW", "CONNECTING", "IDLE", "IN_USE",
	"REMOTE_DISCONNECTED", "DISCONNECTED"
};

static void
connection_state_changed (SoupConnection      *conn,
			  GParamSpec          *param,
			  SoupConnectionState *state)
{
	SoupConnectionState new_state;

	g_object_get (conn, "state", &new_state, NULL);
	debug_printf (2, "      %s -> %s\n",
		      state_names[*state], state_names[new_state]);
	switch (*state) {
	case SOUP_CONNECTION_NEW:
		soup_test_assert (new_state == SOUP_CONNECTION_CONNECTING,
				  "Unexpected transition: %s -> %s\n",
				  state_names[*state], state_names[new_state]);
		break;
	case SOUP_CONNECTION_CONNECTING:
		soup_test_assert (new_state == SOUP_CONNECTION_IN_USE || new_state == SOUP_CONNECTION_DISCONNECTED,
				  "Unexpected transition: %s -> %s\n",
				  state_names[*state], state_names[new_state]);
		break;
	case SOUP_CONNECTION_IDLE:
		soup_test_assert (new_state == SOUP_CONNECTION_IN_USE || new_state == SOUP_CONNECTION_DISCONNECTED,
				  "Unexpected transition: %s -> %s\n",
				  state_names[*state], state_names[new_state]);
		break;
	case SOUP_CONNECTION_IN_USE:
		soup_test_assert (new_state == SOUP_CONNECTION_IDLE,
				  "Unexpected transition: %s -> %s\n",
				  state_names[*state], state_names[new_state]);
		break;
	case SOUP_CONNECTION_DISCONNECTED:
		soup_test_assert (FALSE,
				  "Unexpected transition: %s -> %s\n",
				  state_names[*state], state_names[new_state]);
		break;
	}
	*state = new_state;
}

static void
message_network_event (SoupMessage         *msg,
		       GSocketClientEvent   event,
		       GIOStream           *connection,
		       SoupConnectionState *state)
{
	SoupConnection *conn;

	if (event != G_SOCKET_CLIENT_RESOLVING)
		return;

	/* This is connecting, so we know it comes from a NEW state. */
	*state = SOUP_CONNECTION_NEW;

	conn = soup_message_get_connection (msg);
	g_assert_nonnull (conn);
	connection_state_changed (conn, NULL, state);

	g_signal_connect (conn, "notify::state",
                          G_CALLBACK (connection_state_changed),
                          state);
}

static void
do_one_connection_state_test (SoupSession         *session,
			      const char          *uri,
			      SoupConnectionState *state)
{
	SoupMessage *msg;
	GBytes *body;

	msg = soup_message_new ("GET", uri);
	g_signal_connect (msg, "network-event",
			  G_CALLBACK (message_network_event),
			  state);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);
	soup_session_abort (session);
}

static void
do_connection_state_test_for_session (SoupSession *session)
{
	SoupConnectionState state;
	GProxyResolver *resolver;

	debug_printf (1, "    http\n");
	do_one_connection_state_test (session, HTTP_SERVER, &state);

	if (tls_available) {
		debug_printf (1, "    https\n");
		do_one_connection_state_test (session, HTTPS_SERVER, &state);
	} else
		debug_printf (1, "    https -- SKIPPING\n");

	resolver = g_simple_proxy_resolver_new (HTTP_PROXY, NULL);
	soup_session_set_proxy_resolver (session, resolver);
	g_object_unref (resolver);

	debug_printf (1, "    http with proxy\n");
	do_one_connection_state_test (session, HTTP_SERVER, &state);

	if (tls_available) {
		debug_printf (1, "    https with proxy\n");
		do_one_connection_state_test (session, HTTPS_SERVER, &state);
	} else
		debug_printf (1, "    https with proxy -- SKIPPING\n");
}

static void
do_connection_state_test (void)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new (NULL);
	do_connection_state_test_for_session (session);
	soup_test_session_abort_unref (session);
}


static const char *event_names[] = {
	"RESOLVING", "RESOLVED", "CONNECTING", "CONNECTED",
	"PROXY_NEGOTIATING", "PROXY_NEGOTIATED",
	"TLS_HANDSHAKING", "TLS_HANDSHAKED", "COMPLETE"
};

static const char event_abbrevs[] = {
	'r', 'R', 'c', 'C', 'p', 'P', 't', 'T', 'x', '\0'
};

static const char *
event_name_from_abbrev (char abbrev)
{
	int evt;

	for (evt = 0; event_abbrevs[evt]; evt++) {
		if (event_abbrevs[evt] == abbrev)
			return event_names[evt];
	}
	return "???";
}

static void
network_event (SoupMessage *msg, GSocketClientEvent event,
	       GIOStream *connection, gpointer user_data)
{
	const char **events = user_data;

	debug_printf (2, "      %s\n", event_names[event]);
	soup_test_assert (**events == event_abbrevs[event],
			  "Unexpected event: %s (expected %s)",
			  event_names[event],
			  event_name_from_abbrev (**events));

	if (**events == event_abbrevs[event]) {
		if (event == G_SOCKET_CLIENT_RESOLVING ||
		    event == G_SOCKET_CLIENT_RESOLVED) {
			soup_test_assert (connection == NULL,
					  "Unexpectedly got connection (%s) with '%s' event",
					  G_OBJECT_TYPE_NAME (connection),
					  event_names[event]);
		} else if (event < G_SOCKET_CLIENT_TLS_HANDSHAKING) {
			soup_test_assert (G_IS_SOCKET_CONNECTION (connection),
					  "Unexpectedly got %s with '%s' event",
					  G_OBJECT_TYPE_NAME (connection),
					  event_names[event]);
		} else if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING ||
			   event == G_SOCKET_CLIENT_TLS_HANDSHAKED) {
			soup_test_assert (G_IS_TLS_CLIENT_CONNECTION (connection),
					  "Unexpectedly got %s with '%s' event",
					  G_OBJECT_TYPE_NAME (connection),
					  event_names[event]);
		} else if (event == G_SOCKET_CLIENT_COMPLETE) {
			/* See if the previous expected event was TLS_HANDSHAKED */
			if ((*events)[-1] == 'T') {
				soup_test_assert (G_IS_TLS_CLIENT_CONNECTION (connection),
						  "Unexpectedly got %s with '%s' event",
						  G_OBJECT_TYPE_NAME (connection),
						  event_names[event]);
			} else {
				soup_test_assert (G_IS_SOCKET_CONNECTION (connection),
						  "Unexpectedly got %s with '%s' event",
						  G_OBJECT_TYPE_NAME (connection),
						  event_names[event]);
			}
		}
	}

        if (soup_message_query_flags (msg, SOUP_MESSAGE_COLLECT_METRICS)) {
                SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

                g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);

                switch (event) {
                case G_SOCKET_CLIENT_RESOLVING:
                        g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), >, 0);
                        break;
                case G_SOCKET_CLIENT_RESOLVED:
                        g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >, 0);
                        g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >=, soup_message_metrics_get_dns_start (metrics));
                        break;
                case G_SOCKET_CLIENT_CONNECTING:
                        g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >, 0);
                        g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >=, soup_message_metrics_get_dns_end (metrics));
                        break;
                case G_SOCKET_CLIENT_TLS_HANDSHAKING:
                        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >, 0);
                        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >=, soup_message_metrics_get_connect_start (metrics));
                        break;
                case G_SOCKET_CLIENT_COMPLETE:
                        g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >, 0);
                        g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >=, soup_message_metrics_get_connect_start (metrics));
                        if (soup_message_metrics_get_tls_start (metrics))
                                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >=, soup_message_metrics_get_tls_start (metrics));
                        break;
                default:
                        break;
                }
        }

	*events = *events + 1;
}

static void
metrics_test_message_starting_cb (SoupMessage *msg)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >=, soup_message_metrics_get_fetch_start (metrics));
}

static void
metrics_test_status_changed_cb (SoupMessage *msg)
{
        SoupMessageMetrics *metrics;

        metrics = soup_message_get_metrics (msg);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >=, soup_message_metrics_get_request_start (metrics));
}

static void
metrics_test_got_body_cb (SoupMessage *msg)
{
        SoupMessageMetrics *metrics = soup_message_get_metrics (msg);

        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >=, soup_message_metrics_get_response_start (metrics));
}

static void
do_one_connection_event_test (SoupSession *session,
                              const char  *uri,
                              gboolean     collect_metrics,
			      const char  *events)
{
	SoupMessage *msg;
	GBytes *body;
        SoupMessageMetrics *metrics;
        GSocketAddress *remote_address;
        char *ip_address;

	msg = soup_message_new ("GET", uri);
        if (collect_metrics) {
                soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
                g_signal_connect (msg, "starting",
                                  G_CALLBACK (metrics_test_message_starting_cb),
                                  NULL);
                g_signal_connect (msg, "notify::status-code",
                                  G_CALLBACK (metrics_test_status_changed_cb),
                                  NULL);
                g_signal_connect (msg, "got-body",
                                  G_CALLBACK (metrics_test_got_body_cb),
                                  NULL);
        }
	g_signal_connect (msg, "network-event",
			  G_CALLBACK (network_event),
			  &events);
        g_assert_null (soup_message_get_remote_address (msg));
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	while (*events) {
		soup_test_assert (!*events,
				  "Expected %s",
				  event_name_from_abbrev (*events));
		events++;
	}

        metrics = soup_message_get_metrics (msg);
        if (collect_metrics) {
                g_assert_nonnull (metrics);

                g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), >, 0);
                if (g_str_equal (uri, HTTPS_SERVER))
                        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >, 0);
        } else {
                g_assert_null (metrics);
        }

        remote_address = soup_message_get_remote_address (msg);
        g_assert_true (G_IS_INET_SOCKET_ADDRESS (remote_address));
        ip_address = g_inet_address_to_string (g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (remote_address)));
        g_assert_cmpstr (ip_address, ==, "127.0.0.1");
        g_free (ip_address);
        if (G_IS_PROXY_ADDRESS (remote_address)) {
                g_assert_cmpuint (g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (remote_address)), ==, 47526);
                g_assert_cmpuint (g_proxy_address_get_destination_port (G_PROXY_ADDRESS (remote_address)), ==, g_uri_get_port (soup_message_get_uri (msg)));
                g_assert_cmpstr (g_proxy_address_get_destination_hostname (G_PROXY_ADDRESS (remote_address)), ==, "127.0.0.1");
        } else {
                g_assert_cmpuint (g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (remote_address)), ==, g_uri_get_port (soup_message_get_uri (msg)));
        }

	g_bytes_unref (body);
	g_object_unref (msg);
	soup_session_abort (session);
}

static void
do_one_connection_event_fail_test (SoupSession *session,
                                   const char  *uri,
                                   gboolean     collect_metrics,
                                   GQuark       domain,
                                   gint         code,
                                   const char  *events)
{
        SoupMessage *msg;
        GBytes *body;
        SoupMessageMetrics *metrics;
        GError *error = NULL;
        GTlsDatabase *previous_tlsdb = NULL;

        if (tls_available) {
                GTlsDatabase *tlsdb;

                previous_tlsdb = g_object_ref (soup_session_get_tls_database (session));
                tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
                soup_session_set_tls_database (session, tlsdb);
                g_object_unref (tlsdb);
        }

        msg = soup_message_new ("GET", uri);
        if (collect_metrics) {
                soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
                g_signal_connect (msg, "starting",
                                  G_CALLBACK (metrics_test_message_starting_cb),
                                  NULL);
                g_signal_connect (msg, "notify::status-code",
                                  G_CALLBACK (metrics_test_status_changed_cb),
                                  NULL);
                g_signal_connect (msg, "got-body",
                                  G_CALLBACK (metrics_test_got_body_cb),
                                  NULL);
        }
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (network_event),
                          &events);
        body = soup_session_send_and_read (session, msg, NULL, &error);
        soup_test_assert_message_status (msg, SOUP_STATUS_NONE);
        g_assert_error (error, domain, code);
        g_error_free (error);

        while (*events) {
                soup_test_assert (!*events,
                                  "Expected %s",
                                  event_name_from_abbrev (*events));
                events++;
        }

        metrics = soup_message_get_metrics (msg);
        if (collect_metrics) {
                g_assert_nonnull (metrics);

                g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), >, 0);
                if (g_str_equal (uri, HTTPS_SERVER))
                        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), >, 0);
                g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), ==, 0);
                g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >, 0);
        } else {
                g_assert_null (metrics);
        }

        /* When failing the TLS handshake we got a remote address */
        if (g_str_equal (uri, HTTPS_SERVER))
                g_assert_nonnull (soup_message_get_remote_address (msg));
        else
                g_assert_null (soup_message_get_remote_address (msg));

        g_bytes_unref (body);
        g_object_unref (msg);
        soup_session_abort (session);

        if (tls_available) {
                soup_session_set_tls_database (session, previous_tlsdb);
                g_object_unref (previous_tlsdb);
        }
}

static void
do_connection_event_test_for_session (SoupSession *session,
                                      gboolean     collect_metrics)
{
	GProxyResolver *resolver;

	debug_printf (1, "    http\n");
	do_one_connection_event_test (session, HTTP_SERVER, collect_metrics, "rRcCx");

        debug_printf (1, "    wrong http (invalid port)\n");
        do_one_connection_event_fail_test (session, HTTP_SERVER_BAD_PORT, collect_metrics,
                                           G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED,
                                           "rRc");

	if (tls_available) {
		debug_printf (1, "    https\n");
		do_one_connection_event_test (session, HTTPS_SERVER, collect_metrics, "rRcCtTx");
                debug_printf (1, "    wrong https (invalid certificate)\n");
                do_one_connection_event_fail_test (session, HTTPS_SERVER, collect_metrics,
                                                   G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                                   "rRcCt");
	} else
		debug_printf (1, "    https -- SKIPPING\n");

	resolver = g_simple_proxy_resolver_new (HTTP_PROXY, NULL);
	soup_session_set_proxy_resolver (session, resolver);
	g_object_unref (resolver);

	debug_printf (1, "    http with proxy\n");
	do_one_connection_event_test (session, HTTP_SERVER, collect_metrics, "rRcCx");

	if (tls_available) {
		debug_printf (1, "    https with proxy\n");
		do_one_connection_event_test (session, HTTPS_SERVER, collect_metrics, "rRcCpPtTx");
	} else
		debug_printf (1, "    https with proxy -- SKIPPING\n");
}

static void
do_connection_event_test (void)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new (NULL);
	do_connection_event_test_for_session (session, FALSE);
	soup_test_session_abort_unref (session);
}

typedef struct {
        GMainLoop *loop;
        GError *error;
        const char *events;
        SoupConnectionState state;
        SoupConnection *conn;
        gboolean quit_on_preconnect;
} PreconnectTestData;

static void
preconnection_test_message_network_event (SoupMessage        *msg,
                                          GSocketClientEvent  event,
                                          GIOStream          *connection,
                                          PreconnectTestData *data)
{
        SoupConnection *conn;

        if (event == G_SOCKET_CLIENT_RESOLVING) {
                /* This is connecting, so we know it comes from a NEW state. */
                data->state = SOUP_CONNECTION_NEW;

                conn = soup_message_get_connection (msg);
                g_assert_nonnull (conn);
                g_assert_null (data->conn);
                data->conn = g_object_ref (conn);
                connection_state_changed (conn, NULL, &data->state);

                g_signal_connect (conn, "notify::state",
                                  G_CALLBACK (connection_state_changed),
                                  &data->state);
        }

        if (soup_message_get_method (msg) == SOUP_METHOD_HEAD) {
                soup_test_assert (*data->events == event_abbrevs[event],
                                  "Unexpected event: %s (expected %s)",
                                  event_names[event],
                                  event_name_from_abbrev (*data->events));
                data->events = data->events + 1;
        }
}

static void
preconnection_test_request_queued (SoupSession *session,
                                   SoupMessage *msg,
                                   gpointer     data)
{
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (preconnection_test_message_network_event),
                          data);
}

static void
preconnect_finished (SoupSession        *session,
                     GAsyncResult       *result,
                     PreconnectTestData *data)
{
        soup_session_preconnect_finish (session, result, &data->error);
        if (data->quit_on_preconnect)
                g_main_loop_quit (data->loop);
}

static void
do_idle_connection_preconnect_test (const char *uri,
                                    const char *proxy_uri,
                                    const char *events)
{
        SoupSession *session;
        PreconnectTestData data = { NULL, NULL, events, SOUP_CONNECTION_DISCONNECTED, NULL, TRUE };
        SoupConnection *conn;
        SoupMessage *msg;
        GBytes *bytes;

        session = soup_test_session_new (NULL);

        if (proxy_uri) {
                GProxyResolver *resolver;

                resolver = g_simple_proxy_resolver_new (proxy_uri, NULL);
                soup_session_set_proxy_resolver (session, resolver);
                g_object_unref (resolver);
        }

        data.loop = g_main_loop_new (NULL, FALSE);
        g_signal_connect (session, "request-queued",
                          G_CALLBACK (preconnection_test_request_queued),
                          &data);

        msg = soup_message_new ("HEAD", uri);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished,
                                       &data);
        g_object_unref (msg);
        g_main_loop_run (data.loop);
        g_assert_no_error (data.error);
        g_assert_nonnull (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_IDLE);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }

        conn = data.conn;
        data.conn = NULL;
        msg = soup_message_new ("GET", uri);
        bytes = soup_session_send_and_read (session, msg, NULL, NULL);
        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_object_unref (msg);
        g_bytes_unref (bytes);

        /* connection-created hasn't been called. */
        g_assert_null (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_IDLE);

        /* Preconnect again does nothing because there's already an idle connection ready. */
        msg = soup_message_new ("HEAD", uri);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished,
                                       &data);
        g_object_unref (msg);
        g_main_loop_run (data.loop);
        g_assert_no_error (data.error);
        g_assert_null (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_IDLE);

        soup_session_abort (session);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_DISCONNECTED);
        g_object_unref (conn);

        g_main_loop_unref (data.loop);

        soup_test_session_abort_unref (session);
}

static void
do_idle_connection_preconnect_fail_test (const char *uri,
                                         GQuark      domain,
                                         gint        code,
                                         const char *events)
{
        SoupSession *session;
        SoupMessage *msg;
        PreconnectTestData data = { NULL, NULL, events, SOUP_CONNECTION_DISCONNECTED, NULL, TRUE };

        session = soup_test_session_new (NULL);

        if (tls_available) {
                GTlsDatabase *tlsdb;

                tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
                soup_session_set_tls_database (session, tlsdb);
                g_object_unref (tlsdb);
        }

        data.loop = g_main_loop_new (NULL, FALSE);
        g_signal_connect (session, "request-queued",
                          G_CALLBACK (preconnection_test_request_queued),
                          &data);

        msg = soup_message_new ("HEAD", uri);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished,
                                       &data);
        g_object_unref (msg);
        g_main_loop_run (data.loop);
        g_assert_error (data.error, domain, code);
        g_error_free (data.error);
        g_assert_nonnull (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_DISCONNECTED);
        g_object_unref (data.conn);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }

        g_main_loop_unref (data.loop);

        soup_test_session_abort_unref (session);
}

static void
do_steal_connection_preconnect_test (const char *uri,
                                     const char *proxy_uri,
                                     const char *events)
{
        SoupSession *session;
        PreconnectTestData data = { NULL, NULL, events, SOUP_CONNECTION_DISCONNECTED, NULL, FALSE };
        SoupMessage *msg;
        GBytes *bytes;

        session = soup_test_session_new (NULL);

        if (proxy_uri) {
                GProxyResolver *resolver;

                resolver = g_simple_proxy_resolver_new (proxy_uri, NULL);
                soup_session_set_proxy_resolver (session, resolver);
                g_object_unref (resolver);

        }

        g_signal_connect (session, "request-queued",
                          G_CALLBACK (preconnection_test_request_queued),
                          &data);

        msg = soup_message_new ("HEAD", uri);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished,
                                       &data);
        g_object_unref (msg);

        msg = soup_message_new ("GET", uri);
        bytes = soup_test_session_async_send (session, msg, NULL, &data.error);
        g_object_unref (msg);
        g_bytes_unref (bytes);
        g_assert_no_error (data.error);
        g_assert_nonnull (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_IDLE);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }

        soup_session_abort (session);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_DISCONNECTED);
        g_object_unref (data.conn);

        soup_test_session_abort_unref (session);
}

static void
do_steal_connection_preconnect_fail_test (const char *uri,
                                          GQuark      domain,
                                          gint        code,
                                          const char *events)
{
        SoupSession *session;
        PreconnectTestData data = { NULL, NULL, events, SOUP_CONNECTION_DISCONNECTED, NULL, FALSE };
        SoupMessage *msg;
        GBytes *bytes;

        session = soup_test_session_new (NULL);

        if (tls_available) {
                GTlsDatabase *tlsdb;

                tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
                soup_session_set_tls_database (session, tlsdb);
                g_object_unref (tlsdb);
        }

        g_signal_connect (session, "request-queued",
                          G_CALLBACK (preconnection_test_request_queued),
                          &data);

        msg = soup_message_new ("HEAD", uri);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)preconnect_finished,
                                       &data);
        g_object_unref (msg);

        msg = soup_message_new ("GET", uri);
        bytes = soup_test_session_async_send (session, msg, NULL, &data.error);
        g_object_unref (msg);
        g_bytes_unref (bytes);
        g_assert_error (data.error, domain, code);
        g_error_free (data.error);
        g_assert_nonnull (data.conn);
        g_assert_cmpint (data.state, ==, SOUP_CONNECTION_DISCONNECTED);
        g_object_unref (data.conn);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }

        soup_test_session_abort_unref (session);
}

typedef struct {
        GMainLoop *loop;
        guint count;
} StealPreconnectTestData;

static void
steal_preconnect_finished (SoupSession             *session,
                           GAsyncResult            *result,
                           StealPreconnectTestData *data)
{
        soup_session_preconnect_finish (session, result, NULL);
        if (++data->count == 2)
                g_main_loop_quit (data->loop);
}

static void
steal_preconnect_send_and_read_finished (SoupSession             *session,
                                         GAsyncResult            *result,
                                         StealPreconnectTestData *data)
{
        GBytes *bytes;

        bytes = soup_session_send_and_read_finish (session, result, NULL);
        g_bytes_unref (bytes);
        if (++data->count == 2)
                g_main_loop_quit (data->loop);
}

static void
do_steal_preconnect_connection_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        StealPreconnectTestData data = { NULL, 0 };
        PreconnectTestData data1 = { NULL, NULL, "rRcCx", SOUP_CONNECTION_DISCONNECTED, NULL, FALSE };
        PreconnectTestData data2 = { NULL, NULL, "rRcCx", SOUP_CONNECTION_DISCONNECTED, NULL, FALSE };

        session = soup_test_session_new (NULL);

        /* Preconnect requests should never steal the connection of another preconnect. */

        data.loop = g_main_loop_new (NULL, FALSE);
        msg = soup_message_new ("HEAD", HTTP_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (preconnection_test_message_network_event),
                          &data1);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)steal_preconnect_finished,
                                       &data);
        g_object_unref (msg);

        msg = soup_message_new ("HEAD", HTTP_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (preconnection_test_message_network_event),
                          &data2);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)steal_preconnect_finished,
                                       &data);
        g_object_unref (msg);

        g_main_loop_run (data.loop);
        g_assert_nonnull (data1.conn);
        g_assert_nonnull (data2.conn);
        g_assert_false (data1.conn == data2.conn);
        g_assert_cmpint (data1.state, ==, SOUP_CONNECTION_IDLE);
        g_assert_cmpint (data2.state, ==, SOUP_CONNECTION_IDLE);

        while (*data1.events) {
                soup_test_assert (!*data1.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data1.events));
                soup_test_assert (!*data2.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data2.events));
                data1.events++;
                data2.events++;
        }

        data.count = 0;
        g_clear_object (&data1.conn);
        g_clear_object (&data2.conn);

        msg = soup_message_new ("GET", HTTP_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (preconnection_test_message_network_event),
                          &data1);
        soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)steal_preconnect_send_and_read_finished,
                                          &data);
        g_object_unref (msg);

        msg = soup_message_new ("GET", HTTP_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (preconnection_test_message_network_event),
                          &data2);
        soup_session_send_and_read_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                          (GAsyncReadyCallback)steal_preconnect_send_and_read_finished,
                                          &data);
        g_object_unref (msg);

        g_main_loop_run (data.loop);

        /* connection-created hasn't been called. */
        g_assert_null (data1.conn);
        g_assert_null (data2.conn);
        g_assert_cmpint (data1.state, ==, SOUP_CONNECTION_IDLE);
        g_assert_cmpint (data2.state, ==, SOUP_CONNECTION_IDLE);

        g_main_loop_unref (data.loop);

        soup_test_session_abort_unref (session);
}

static void
do_connection_preconnect_test (void)
{
        SOUP_TEST_SKIP_IF_NO_APACHE;

        debug_printf (1, "    http\n");
        do_idle_connection_preconnect_test (HTTP_SERVER, NULL, "rRcCx");
        do_steal_connection_preconnect_test (HTTP_SERVER, NULL, "r");

        debug_printf (1, "    http with proxy\n");
        do_idle_connection_preconnect_test (HTTP_SERVER, HTTP_PROXY, "rRcCx");
        do_steal_connection_preconnect_test (HTTP_SERVER, HTTP_PROXY, "r");

        debug_printf (1, "    wrong http (invalid port)\n");
        do_idle_connection_preconnect_fail_test (HTTP_SERVER_BAD_PORT,
                                                 G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED,
                                                 "rRc");
        do_steal_connection_preconnect_fail_test (HTTP_SERVER_BAD_PORT,
                                                  G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED,
                                                  "r");

        if (tls_available) {
                debug_printf (1, "    https\n");
                do_idle_connection_preconnect_test (HTTPS_SERVER, NULL, "rRcCtTx");
                do_steal_connection_preconnect_test (HTTPS_SERVER, NULL, "r");

                debug_printf (1, "    https with proxy\n");
                do_idle_connection_preconnect_test (HTTPS_SERVER, HTTP_PROXY, "rRcCpPtTx");
                do_steal_connection_preconnect_test (HTTPS_SERVER, HTTP_PROXY, "r");

                debug_printf (1, "    wrong https (invalid certificate)\n");
                do_idle_connection_preconnect_fail_test (HTTPS_SERVER,
                                                         G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                                         "rRcCt");
                do_steal_connection_preconnect_fail_test (HTTPS_SERVER,
                                                          G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                                          "r");
        } else
                debug_printf (1, "    https -- SKIPPING\n");

        debug_printf (1, "    preconnect should never steal a connection\n");
        do_steal_preconnect_connection_test ();
}

static void
do_connection_metrics_test (void)
{
        SoupSession *session;

        SOUP_TEST_SKIP_IF_NO_APACHE;

        session = soup_test_session_new (NULL);
        do_connection_event_test_for_session (session, TRUE);
        soup_test_session_abort_unref (session);
}

static void
force_http2_test_network_event (SoupMessage        *msg,
                                GSocketClientEvent  event,
                                GIOStream          *connection,
                                SoupConnection    **conn)
{
        if (event != G_SOCKET_CLIENT_RESOLVING)
                return;

        *conn = soup_message_get_connection (msg);
}

static void
do_connection_force_http2_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        SoupConnection *conn1 = NULL;
        SoupConnection *conn2 = NULL;
        GBytes *body;

        SOUP_TEST_SKIP_IF_NO_TLS;
        SOUP_TEST_SKIP_IF_NO_APACHE;

        session = soup_test_session_new (NULL);

        msg = soup_message_new ("GET", HTTPS_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (force_http2_test_network_event),
                          &conn1);
        body = soup_session_send_and_read (session, msg, NULL, NULL);
        g_assert_nonnull (conn1);
        g_assert_cmpint (soup_connection_get_state (conn1), ==, SOUP_CONNECTION_IDLE);
        g_assert_cmpint (soup_connection_get_negotiated_protocol (conn1), ==, SOUP_HTTP_1_1);
        g_object_unref (msg);
        g_bytes_unref (body);

        /* With HTTP/2 forced, a new connection must be created */
        msg = soup_message_new ("GET", HTTPS_SERVER);
        g_signal_connect (msg, "network-event",
                          G_CALLBACK (force_http2_test_network_event),
                          &conn2);
        soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        body = soup_session_send_and_read (session, msg, NULL, NULL);
        g_assert_nonnull (conn2);
        g_assert_cmpint (soup_connection_get_state (conn2), ==, SOUP_CONNECTION_IDLE);
        g_assert_cmpint (soup_connection_get_negotiated_protocol (conn2), ==, SOUP_HTTP_2_0);
        g_assert_false (conn1 == conn2);
        g_object_unref (msg);
        g_bytes_unref (body);

        soup_test_session_abort_unref (session);
}

static void
message_restarted (SoupMessage *msg,
                   gboolean    *was_restarted)
{
        *was_restarted = TRUE;
}

static void
do_connection_http_1_1_required_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *body;
        gboolean was_restarted = FALSE;
        GError *error = NULL;

        SOUP_TEST_SKIP_IF_NO_TLS;
        SOUP_TEST_SKIP_IF_NO_APACHE;

        session = soup_test_session_new (NULL);

        msg = soup_message_new ("GET", "https://127.0.0.1:47525/client-cert");
        soup_message_set_force_http_version (msg, SOUP_HTTP_2_0);
        g_signal_connect (msg, "restarted",
                          G_CALLBACK (message_restarted), &was_restarted);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_no_error (error);
        g_assert_cmpuint (soup_message_get_status (msg), ==, 403);
        g_assert_true (was_restarted);
        g_assert_nonnull (body);
        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);
	apache_init ();

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD | SOUP_TEST_SERVER_HTTP2);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);
        base_https_uri = soup_test_server_get_uri (server, "https", NULL);

	g_test_add_func ("/connection/content-length-framing", do_content_length_framing_test);
	g_test_add_func ("/connection/persistent-connection-timeout", do_persistent_connection_timeout_test);
	g_test_add_func ("/connection/persistent-connection-timeout-with-cancellable",
			 do_persistent_connection_timeout_test_with_cancellation);
	g_test_add_func ("/connection/max-conns", do_max_conns_test);
	g_test_add_func ("/connection/non-persistent", do_non_persistent_connection_test);
	g_test_add_func ("/connection/non-idempotent", do_non_idempotent_connection_test);
	g_test_add_func ("/connection/state", do_connection_state_test);
	g_test_add_func ("/connection/event", do_connection_event_test);
	g_test_add_func ("/connection/preconnect", do_connection_preconnect_test);
        g_test_add_func ("/connection/metrics", do_connection_metrics_test);
        g_test_add_func ("/connection/force-http2", do_connection_force_http2_test);
        g_test_add_func ("/connection/http2/http-1-1-required", do_connection_http_1_1_required_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
