/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

#include <gio/gnetworking.h>

SoupServer *server;
SoupURI *base_uri;
GMutex server_mutex;

static void
forget_close (SoupMessage *msg, gpointer user_data)
{
	soup_message_headers_remove (msg->response_headers, "Connection");
}

static void
close_socket (SoupMessage *msg, gpointer user_data)
{
	SoupSocket *sock = user_data;
	int sockfd;

	/* Actually calling soup_socket_disconnect() here would cause
	 * us to leak memory, so just shutdown the socket instead.
	 */
	sockfd = soup_socket_get_fd (sock);
#ifdef G_OS_WIN32
	shutdown (sockfd, SD_SEND);
#else
	shutdown (sockfd, SHUT_WR);
#endif

	/* Then add the missing data to the message now, so SoupServer
	 * can clean up after itself properly.
	 */
	soup_message_body_append (msg->response_body, SOUP_MEMORY_STATIC,
				  "foo", 3);
}

static void
timeout_socket (SoupSocket *sock, gpointer user_data)
{
	soup_socket_disconnect (sock);
}

static void
timeout_request_started (SoupServer *server, SoupMessage *msg,
			 SoupClientContext *client, gpointer user_data)
{
	SoupSocket *sock;
	GMainContext *context = g_main_context_get_thread_default ();
	guint readable;

	g_signal_handlers_disconnect_by_func (server, timeout_request_started, NULL);

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	sock = soup_client_context_get_socket (client);
	G_GNUC_END_IGNORE_DEPRECATIONS;
	readable = g_signal_connect (sock, "readable",
				    G_CALLBACK (timeout_socket), NULL);

	g_mutex_unlock (&server_mutex);
	while (soup_socket_is_connected (sock))
		g_main_context_iteration (context, TRUE);
	g_signal_handler_disconnect (sock, readable);
}

static void
setup_timeout_persistent (SoupServer *server, SoupSocket *sock)
{
	char buf[1];
	gsize nread;

	/* In order for the test to work correctly, we have to
	 * close the connection *after* the client side writes
	 * the request. To ensure that this happens reliably,
	 * regardless of thread scheduling, we:
	 *
	 *   1. Try to read off the socket now, knowing it will
	 *      fail (since the client is waiting for us to
	 *      return a response). This will cause it to
	 *      emit "readable" later.
	 *   2. Wait for the server to finish this request and
	 *      start reading the next one (and lock server_mutex
	 *      to interlock with the client and ensure that it
	 *      doesn't start writing its next request until
	 *      that point).
	 *   3. Block until "readable" is emitted, meaning the
	 *      client has written its request.
	 *   4. Close the socket.
	 */

	soup_socket_read (sock, buf, 1, &nread, NULL, NULL);
	g_mutex_lock (&server_mutex);
	g_signal_connect (server, "request-started",
			  G_CALLBACK (timeout_request_started), NULL);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	/* The way this gets used in the tests, we don't actually
	 * need to hold it through the whole function, so it's simpler
	 * to just release it right away.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (g_str_has_prefix (path, "/content-length/")) {
		gboolean too_long = strcmp (path, "/content-length/long") == 0;
		gboolean no_close = strcmp (path, "/content-length/noclose") == 0;

		soup_message_set_status (msg, SOUP_STATUS_OK);
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC, "foobar", 6);
		if (too_long)
			soup_message_headers_set_content_length (msg->response_headers, 9);
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");

		if (too_long) {
			SoupSocket *sock;

			/* soup-message-io will wait for us to add
			 * another chunk after the first, to fill out
			 * the declared Content-Length. Instead, we
			 * forcibly close the socket at that point.
			 */
			G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
			sock = soup_client_context_get_socket (context);
			G_GNUC_END_IGNORE_DEPRECATIONS;
			g_signal_connect (msg, "wrote-chunk",
					  G_CALLBACK (close_socket), sock);
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
		SoupSocket *sock;

		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		sock = soup_client_context_get_socket (context);
		G_GNUC_END_IGNORE_DEPRECATIONS;
		setup_timeout_persistent (server, sock);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC, "index", 5);
	return;
}

static void
do_content_length_framing_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *request_uri;
	goffset declared_length;

	g_test_bug ("611481");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	debug_printf (1, "  Content-Length larger than message body length\n");
	request_uri = soup_uri_new_with_base (base_uri, "/content-length/long");
	msg = soup_message_new_from_uri ("GET", request_uri);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	declared_length = soup_message_headers_get_content_length (msg->response_headers);
	debug_printf (2, "    Content-Length: %lu, body: %s\n",
		      (gulong)declared_length, msg->response_body->data);
	g_assert_cmpint (msg->response_body->length, <, declared_length);

	soup_uri_free (request_uri);
	g_object_unref (msg);

	debug_printf (1, "  Server claims 'Connection: close' but doesn't\n");
	request_uri = soup_uri_new_with_base (base_uri, "/content-length/noclose");
	msg = soup_message_new_from_uri ("GET", request_uri);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	declared_length = soup_message_headers_get_content_length (msg->response_headers);
	g_assert_cmpint (msg->response_body->length, ==, declared_length);

	soup_uri_free (request_uri);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
request_started_socket_collector (SoupSession *session, SoupMessage *msg,
				  SoupSocket *socket, gpointer user_data)
{
	SoupSocket **sockets = user_data;
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
do_timeout_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	SoupURI *timeout_uri;
	int i;

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (1, "    First message\n");
	timeout_uri = soup_uri_new_with_base (base_uri, "/timeout-persistent");
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	soup_uri_free (timeout_uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (msg);

	/* The server will grab server_mutex before returning the response,
	 * and release it when it's ready for us to send the second request.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	debug_printf (1, "    Second message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	soup_test_assert (sockets[1] == sockets[0],
			  "Message was not retried on existing connection");
	soup_test_assert (sockets[2] != NULL,
			  "Message was not retried after disconnect");
	soup_test_assert (sockets[2] != sockets[1],
			  "Message was retried on closed connection");
	soup_test_assert (sockets[3] == NULL,
			  "Message was retried again");
	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_timeout_req_test_for_session (SoupSession *session)
{
	SoupRequest *req;
	SoupMessage *msg;
	GInputStream *stream;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	SoupURI *timeout_uri;
	GError *error = NULL;
	int i;

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (1, "    First request\n");
	timeout_uri = soup_uri_new_with_base (base_uri, "/timeout-persistent");
	req = soup_session_request_uri (session, timeout_uri, NULL);
	soup_uri_free (timeout_uri);

	stream = soup_test_request_send (req, NULL, 0, &error);
	if (error) {
		g_assert_no_error (error);
		g_clear_error (&error);
	} else {
		soup_test_request_read_all (req, stream, NULL, &error);
		if (error) {
			g_assert_no_error (error);
			g_clear_error (&error);
		}

		soup_test_request_close_stream (req, stream, NULL, &error);
		if (error) {
			g_assert_no_error (error);
			g_clear_error (&error);
		}
		g_object_unref (stream);
	}

	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (req);

	/* The server will grab server_mutex before returning the response,
	 * and release it when it's ready for us to send the second request.
	 */
	g_mutex_lock (&server_mutex);
	g_mutex_unlock (&server_mutex);

	debug_printf (1, "    Second request\n");
	req = soup_session_request_uri (session, base_uri, NULL);

	stream = soup_test_request_send (req, NULL, 0, &error);
	if (error) {
		g_assert_no_error (error);
		g_clear_error (&error);
	} else {
		soup_test_request_close_stream (req, stream, NULL, &error);
		if (error) {
			g_assert_no_error (error);
			g_clear_error (&error);
		}
		g_object_unref (stream);
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	soup_test_assert (sockets[1] == sockets[0],
			  "Message was not retried on existing connection");
	soup_test_assert (sockets[2] != NULL,
			  "Message was not retried after disconnect");
	soup_test_assert (sockets[2] != sockets[1],
			  "Message was retried on closed connection");
	soup_test_assert (sockets[3] == NULL,
			  "Message was retried again");
	g_object_unref (msg);
	g_object_unref (req);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_persistent_connection_timeout_test (void)
{
	SoupSession *session;

	g_test_bug ("631525");

	debug_printf (1, "  Async session, message API\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_timeout_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Async session, request API\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_timeout_req_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session, message API\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_timeout_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session, request API\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_timeout_req_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
cancel_cancellable_handler (SoupSession *session, SoupMessage *msg,
			    SoupSocket *socket, gpointer user_data)
{
	g_cancellable_cancel (user_data);
}

static void
do_persistent_connection_timeout_test_with_cancellation (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	SoupURI *timeout_uri;
	GCancellable *cancellable;
	GInputStream *response;
	int i;
	char buf[8192];

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (1, "    First message\n");
	timeout_uri = soup_uri_new_with_base (base_uri, "/timeout-persistent");
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	cancellable = g_cancellable_new ();
	soup_uri_free (timeout_uri);
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
	g_signal_connect (session, "request-started",
			  G_CALLBACK (cancel_cancellable_handler),
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

static GMainLoop *max_conns_loop;
static int msgs_done;
static guint quit_loop_timeout;
#define MAX_CONNS 2
#define TEST_CONNS (MAX_CONNS * 2) + 1

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
max_conns_request_started (SoupSession *session, SoupMessage *msg,
			   SoupSocket *socket, gpointer user_data)
{
	if (++msgs_done >= MAX_CONNS) {
		if (quit_loop_timeout)
			g_source_remove (quit_loop_timeout);
		quit_loop_timeout = g_timeout_add (100, quit_loop, NULL);
	}
}

static void
max_conns_message_complete (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	if (++msgs_done == TEST_CONNS)
		g_main_loop_quit (max_conns_loop);
}

static void
do_max_conns_test_for_session (SoupSession *session)
{
	SoupMessage *msgs[TEST_CONNS + 1];
	SoupMessageFlags flags;
	int i;

	max_conns_loop = g_main_loop_new (NULL, TRUE);

	g_mutex_lock (&server_mutex);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (max_conns_request_started), NULL);
	msgs_done = 0;
	for (i = 0; i < TEST_CONNS - 1; i++) {
		msgs[i] = soup_message_new_from_uri ("GET", base_uri);
		g_object_ref (msgs[i]);
		soup_session_queue_message (session, msgs[i],
					    max_conns_message_complete, NULL);
	}

	g_main_loop_run (max_conns_loop);
	g_assert_cmpint (msgs_done, ==, MAX_CONNS);

	if (quit_loop_timeout)
		g_source_remove (quit_loop_timeout);
	quit_loop_timeout = g_timeout_add (1000, quit_loop, NULL);

	/* Message with SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS should start */
	msgs[i] = soup_message_new_from_uri ("GET", base_uri);
	flags = soup_message_get_flags (msgs[i]);
	soup_message_set_flags (msgs[i], flags | SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS);
	g_object_ref (msgs[i]);
	soup_session_queue_message (session, msgs[i],
				    max_conns_message_complete, NULL);

	g_main_loop_run (max_conns_loop);
	g_assert_cmpint (msgs_done, ==, MAX_CONNS + 1);
	g_signal_handlers_disconnect_by_func (session, max_conns_request_started, NULL);

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
		for (i = 0; i < TEST_CONNS; i++)
			soup_session_cancel_message (session, msgs[i], SOUP_STATUS_CANCELLED);
		g_main_loop_run (max_conns_loop);
	}

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

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_MAX_CONNS, MAX_CONNS,
					 NULL);
	do_max_conns_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_MAX_CONNS, MAX_CONNS,
					 NULL);
	do_max_conns_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
np_request_started (SoupSession *session, SoupMessage *msg,
		    SoupSocket *socket, gpointer user_data)
{
	SoupSocket **save_socket = user_data;

	*save_socket = g_object_ref (socket);
}

static void
np_request_unqueued (SoupSession *session, SoupMessage *msg,
		     gpointer user_data)
{
	SoupSocket *socket = *(SoupSocket **)user_data;

	g_assert_false (soup_socket_is_connected (socket));
}

static void
np_request_finished (SoupSession *session, SoupMessage *msg,
		     gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
}

static void
do_non_persistent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *socket = NULL;
	GMainLoop *loop;

	loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (session, "request-started",
			  G_CALLBACK (np_request_started),
			  &socket);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (np_request_unqueued),
			  &socket);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_append (msg->request_headers, "Connection", "close");
	g_object_ref (msg);
	soup_session_queue_message (session, msg,
				    np_request_finished, loop);
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

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_non_persistent_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_non_persistent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_non_idempotent_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	SoupSocket *sockets[4] = { NULL, NULL, NULL, NULL };
	int i;

	g_signal_connect (session, "request-started",
			  G_CALLBACK (request_started_socket_collector),
			  &sockets);

	debug_printf (2, "    GET\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	if (sockets[1]) {
		soup_test_assert (sockets[1] == NULL, "Message was retried");
		sockets[1] = sockets[2] = sockets[3] = NULL;
	}
	g_object_unref (msg);

	debug_printf (2, "    POST\n");
	msg = soup_message_new_from_uri ("POST", base_uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	soup_test_assert (sockets[1] != sockets[0],
			  "Message was sent on existing connection");
	soup_test_assert (sockets[2] == NULL,
			  "Too many connections used");

	g_object_unref (msg);

	for (i = 0; sockets[i]; i++)
		g_object_unref (sockets[i]);
}

static void
do_non_idempotent_connection_test (void)
{
	SoupSession *session;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_non_idempotent_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_non_idempotent_test_for_session (session);
	soup_test_session_abort_unref (session);
}

#define HTTP_SERVER  "http://127.0.0.1:47524"
#define HTTPS_SERVER "https://127.0.0.1:47525"
#define HTTP_PROXY   "http://127.0.0.1:47526"

static SoupConnectionState state_transitions[] = {
	/* NEW -> */        SOUP_CONNECTION_CONNECTING,
	/* CONNECTING -> */ SOUP_CONNECTION_IN_USE,
	/* IDLE -> */       SOUP_CONNECTION_DISCONNECTED,
	/* IN_USE -> */     SOUP_CONNECTION_IDLE,

	/* REMOTE_DISCONNECTED */ -1,
	/* DISCONNECTED */        -1,
};

static const char *state_names[] = {
	"NEW", "CONNECTING", "IDLE", "IN_USE",
	"REMOTE_DISCONNECTED", "DISCONNECTED"
};

static void
connection_state_changed (GObject *object, GParamSpec *param,
			  gpointer user_data)
{
	SoupConnectionState *state = user_data;
	SoupConnectionState new_state;

	g_object_get (object, "state", &new_state, NULL);
	debug_printf (2, "      %s -> %s\n",
		      state_names[*state], state_names[new_state]);
	soup_test_assert (state_transitions[*state] == new_state,
			  "Unexpected transition: %s -> %s\n",
			  state_names[*state], state_names[new_state]);
	*state = new_state;
}

static void
connection_created (SoupSession *session, GObject *conn,
		    gpointer user_data)
{
	SoupConnectionState *state = user_data;

	g_object_get (conn, "state", state, NULL);
	g_assert_cmpint (*state, ==, SOUP_CONNECTION_NEW);

	g_signal_connect (conn, "notify::state",
			  G_CALLBACK (connection_state_changed),
			  state);
}

static void
do_one_connection_state_test (SoupSession *session, const char *uri)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_object_unref (msg);
	soup_session_abort (session);
}

static void
do_connection_state_test_for_session (SoupSession *session)
{
	SoupConnectionState state;
	SoupURI *proxy_uri;

	g_signal_connect (session, "connection-created",
			  G_CALLBACK (connection_created),
			  &state);

	debug_printf (1, "    http\n");
	do_one_connection_state_test (session, HTTP_SERVER);

	if (tls_available) {
		debug_printf (1, "    https\n");
		do_one_connection_state_test (session, HTTPS_SERVER);
	} else
		debug_printf (1, "    https -- SKIPPING\n");

	proxy_uri = soup_uri_new (HTTP_PROXY);
	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_PROXY_URI, proxy_uri,
		      NULL);
	soup_uri_free (proxy_uri);

	debug_printf (1, "    http with proxy\n");
	do_one_connection_state_test (session, HTTP_SERVER);

	if (tls_available) {
		debug_printf (1, "    https with proxy\n");
		do_one_connection_state_test (session, HTTPS_SERVER);
	} else
		debug_printf (1, "    https with proxy -- SKIPPING\n");
}

static void
do_connection_state_test (void)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_connection_state_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
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

	*events = *events + 1;
}

static void
do_one_connection_event_test (SoupSession *session, const char *uri,
			      const char *events)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	g_signal_connect (msg, "network-event",
			  G_CALLBACK (network_event),
			  &events);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	while (*events) {
		soup_test_assert (!*events,
				  "Expected %s",
				  event_name_from_abbrev (*events));
		events++;
	}

	g_object_unref (msg);
	soup_session_abort (session);
}

static void
do_connection_event_test_for_session (SoupSession *session)
{
	SoupURI *proxy_uri;

	debug_printf (1, "    http\n");
	do_one_connection_event_test (session, HTTP_SERVER, "rRcCx");

	if (tls_available) {
		debug_printf (1, "    https\n");
		do_one_connection_event_test (session, HTTPS_SERVER, "rRcCtTx");
	} else
		debug_printf (1, "    https -- SKIPPING\n");

	proxy_uri = soup_uri_new (HTTP_PROXY);
	g_object_set (G_OBJECT (session),
		      SOUP_SESSION_PROXY_URI, proxy_uri,
		      NULL);
	soup_uri_free (proxy_uri);

	debug_printf (1, "    http with proxy\n");
	do_one_connection_event_test (session, HTTP_SERVER, "rRcCx");

	if (tls_available) {
		debug_printf (1, "    https with proxy\n");
		do_one_connection_event_test (session, HTTPS_SERVER, "rRcCpPtTx");
	} else
		debug_printf (1, "    https with proxy -- SKIPPING\n");
}

static void
do_connection_event_test (void)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_connection_event_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_connection_event_test_for_session (session);
	soup_test_session_abort_unref (session);
}

typedef struct {
        GMainLoop *loop;
        GIOStream *stream;
        GError *error;
        const char *events;
} ConnectTestData;

static void
connect_progress (SoupSession *session, GSocketClientEvent event, GIOStream *connection, ConnectTestData *data)
{
        soup_test_assert (*data->events == event_abbrevs[event],
                          "Unexpected event: %s (expected %s)",
                          event_names[event],
                          event_name_from_abbrev (*data->events));
        data->events = data->events + 1;
}

static void
connect_finished (SoupSession *session, GAsyncResult *result, ConnectTestData *data)
{
        data->stream = soup_session_connect_finish (session, result, &data->error);
        g_main_loop_quit (data->loop);
}

static void
do_one_connection_connect_test (SoupSession *session, SoupURI *uri, const char *response, const char *events)
{
        ConnectTestData data = { NULL, NULL, NULL, events };
        static const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        gsize bytes = 0;
        char buffer[128];

        data.loop = g_main_loop_new (NULL, FALSE);
        soup_session_connect_async (session, uri, NULL,
                                    (SoupSessionConnectProgressCallback)connect_progress,
                                    (GAsyncReadyCallback)connect_finished,
                                    &data);
        g_main_loop_run (data.loop);

        g_assert (G_IS_IO_STREAM (data.stream));
        g_assert_no_error (data.error);
        g_assert (g_output_stream_write_all (g_io_stream_get_output_stream (data.stream),
                                             request, strlen (request), &bytes, NULL, NULL));
        g_assert (g_input_stream_read_all (g_io_stream_get_input_stream (data.stream),
                                           buffer, sizeof (buffer), &bytes, NULL, NULL));
        buffer[strlen (response)] = '\0';
        g_assert_cmpstr (buffer, ==, response);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }

        g_object_unref (data.stream);
        g_main_loop_unref (data.loop);
}

static void
do_one_connection_connect_fail_test (SoupSession *session, SoupURI *uri, GQuark domain, gint code, const char *events)
{
        ConnectTestData data = { NULL, NULL, NULL, events };

        data.loop = g_main_loop_new (NULL, FALSE);
        soup_session_connect_async (session, uri, NULL,
                                    (SoupSessionConnectProgressCallback)connect_progress,
                                    (GAsyncReadyCallback)connect_finished,
                                    &data);
        g_main_loop_run (data.loop);
        g_main_loop_unref (data.loop);

        g_assert (!data.stream);
        g_assert_error (data.error, domain, code);
        g_clear_error (&data.error);

        while (*data.events) {
                soup_test_assert (!*data.events,
                                  "Expected %s",
                                  event_name_from_abbrev (*data.events));
                data.events++;
        }
}

static void
do_connection_connect_test (void)
{
        SoupSession *session;
        SoupURI *http_uri;
        SoupURI *https_uri = NULL;
        SoupURI *ws_uri;
        SoupURI *wss_uri = NULL;
        SoupURI *file_uri;
        SoupURI *wrong_http_uri;
        SoupURI *proxy_uri;
        const char *wrong_http_uri_events;

        SOUP_TEST_SKIP_IF_NO_APACHE;

        session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
                                         SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
                                         NULL);

        debug_printf (1, "    http\n");
        http_uri = soup_uri_new (HTTP_SERVER);
        do_one_connection_connect_test (session, http_uri,
                                        "HTTP/1.1 200 OK", "rRcCx");

        if (tls_available) {
                debug_printf (1, "    https\n");
                https_uri = soup_uri_new (HTTPS_SERVER);
                do_one_connection_connect_test (session, https_uri,
                                                "HTTP/1.1 200 OK", "rRcCtTx");
        } else
                debug_printf (1, "    https -- SKIPPING\n");

        debug_printf (1, "    ws\n");
        ws_uri = soup_uri_new (HTTP_SERVER);
        ws_uri->scheme = SOUP_URI_SCHEME_WS;
        do_one_connection_connect_test (session, ws_uri,
                                        "HTTP/1.1 200 OK", "rRcCx");

        if (tls_available) {
                debug_printf (1, "    wss\n");
                wss_uri = soup_uri_new (HTTPS_SERVER);
                do_one_connection_connect_test (session, wss_uri,
                                                "HTTP/1.1 200 OK", "rRcCtTx");
        } else
                debug_printf (1, "    wss -- SKIPPING\n");

        debug_printf (1, "    file\n");
        file_uri = soup_uri_new ("file:///foo/bar");
        do_one_connection_connect_fail_test (session, file_uri,
                                             G_RESOLVER_ERROR, G_RESOLVER_ERROR_NOT_FOUND,
                                             "r");

        debug_printf (1, "    wrong http (invalid port)\n");
        wrong_http_uri = soup_uri_new (HTTP_SERVER);
        wrong_http_uri->port = 1234;
        if (glib_check_version (2, 67, 0) == NULL) {
                wrong_http_uri_events = "rRc";
        } else {
                /* The extra "r" here is for a GLib bug in versions before
                 * 2.67.0. See f0a7b147806e852e2090eeda6e4e38f7d3f52b52 in GLib
                 * for more details. */
                wrong_http_uri_events = "rRcr";
        }
        do_one_connection_connect_fail_test (session, wrong_http_uri,
                                             G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED,
                                             wrong_http_uri_events);

        proxy_uri = soup_uri_new (HTTP_PROXY);
        g_object_set (G_OBJECT (session),
                      SOUP_SESSION_PROXY_URI, proxy_uri,
                      NULL);

        debug_printf (1, "    http with proxy\n");
        do_one_connection_connect_test (session, http_uri,
                                        "HTTP/1.1 403 Forbidden", "rRcCx");

        if (tls_available) {
                debug_printf (1, "    https with proxy\n");
                do_one_connection_connect_test (session, https_uri,
                                                "HTTP/1.1 200 OK", "rRcCpPtTx");
        } else
                debug_printf (1, "    https with proxy -- SKIPPING\n");

        debug_printf (1, "    ws with proxy\n");
        do_one_connection_connect_test (session, ws_uri,
                                        "HTTP/1.1 403 Forbidden", "rRcCx");

        if (tls_available) {
                debug_printf (1, "    wss with proxy\n");
                do_one_connection_connect_test (session, wss_uri,
                                                "HTTP/1.1 200 OK", "rRcCpPtTx");
        } else
                debug_printf (1, "    wss with proxy -- SKIPPING\n");

        soup_uri_free (http_uri);
        if (https_uri)
                soup_uri_free (https_uri);
        soup_uri_free (ws_uri);
        if (wss_uri)
                soup_uri_free (wss_uri);
        soup_uri_free (file_uri);
        soup_uri_free (wrong_http_uri);
        soup_uri_free (proxy_uri);

        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);
	apache_init ();

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, "http", NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add_func ("/connection/content-length-framing", do_content_length_framing_test);
	g_test_add_func ("/connection/persistent-connection-timeout", do_persistent_connection_timeout_test);
	g_test_add_func ("/connection/persistent-connection-timeout-with-cancellable",
			 do_persistent_connection_timeout_test_with_cancellation);
	g_test_add_func ("/connection/max-conns", do_max_conns_test);
	g_test_add_func ("/connection/non-persistent", do_non_persistent_connection_test);
	g_test_add_func ("/connection/non-idempotent", do_non_idempotent_connection_test);
	g_test_add_func ("/connection/state", do_connection_state_test);
	g_test_add_func ("/connection/event", do_connection_event_test);
	g_test_add_func ("/connection/connect", do_connection_connect_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
