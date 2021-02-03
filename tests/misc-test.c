/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"

SoupServer *server, *ssl_server;
SoupURI *base_uri, *ssl_base_uri;

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static gboolean
timeout_finish_message (gpointer msg)
{
	SoupServer *server = g_object_get_data (G_OBJECT (msg), "server");

	soup_server_unpause_message (server, msg);
	return FALSE;
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SoupURI *uri = soup_message_get_uri (msg);
	const char *server_protocol = data;

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (!strcmp (path, "/redirect")) {
		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		return;
	}

	if (!strcmp (path, "/alias-redirect")) {
		SoupURI *redirect_uri;
		char *redirect_string;
		const char *redirect_protocol;

		redirect_protocol = soup_message_headers_get_one (msg->request_headers, "X-Redirect-Protocol");

		redirect_uri = soup_uri_copy (uri);
		soup_uri_set_scheme (redirect_uri, "foo");
		if (!g_strcmp0 (redirect_protocol, "https"))
			soup_uri_set_port (redirect_uri, ssl_base_uri->port);
		else
			soup_uri_set_port (redirect_uri, base_uri->port);
		soup_uri_set_path (redirect_uri, "/alias-redirected");
		redirect_string = soup_uri_to_string (redirect_uri, FALSE);

		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, redirect_string);
		g_free (redirect_string);
		soup_uri_free (redirect_uri);
		return;
	} else if (!strcmp (path, "/alias-redirected")) {
		soup_message_set_status (msg, SOUP_STATUS_OK);
		soup_message_headers_append (msg->response_headers,
					     "X-Redirected-Protocol",
					     server_protocol);
		return;
	}

	if (!strcmp (path, "/slow")) {
		soup_server_pause_message (server, msg);
		g_object_set_data (G_OBJECT (msg), "server", server);
		soup_add_timeout (g_main_context_get_thread_default (),
				  1000, timeout_finish_message, msg);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	if (!strcmp (uri->host, "foo")) {
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC, "foo-index", 9);
		return;
	} else {
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC, "index", 5);
		return;
	}
}

/* Host header handling: client must be able to override the default
 * value, server must be able to recognize different Host values.
 */
static void
do_host_test (void)
{
	SoupSession *session;
	SoupMessage *one, *two;

	g_test_bug ("539803");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	one = soup_message_new_from_uri ("GET", base_uri);
	two = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_replace (two->request_headers, "Host", "foo");

	soup_session_send_message (session, one);
	soup_session_send_message (session, two);

	soup_test_session_abort_unref (session);

	soup_test_assert_message_status (one, SOUP_STATUS_OK);
	g_assert_cmpstr (one->response_body->data, ==, "index");
	g_object_unref (one);

	soup_test_assert_message_status (two, SOUP_STATUS_OK);
	g_assert_cmpstr (two->response_body->data, ==, "foo-index");
	g_object_unref (two);
}

/* request with too big header should be discarded with a IO error to 
 * prevent DOS attacks.
 */
static void
do_host_big_header (void)
{
	SoupMessage *msg;
	SoupSession *session;
	int i;

	g_test_bug ("792173");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	msg = soup_message_new_from_uri ("GET", base_uri);
	for (i = 0; i < 2048; i++) {
		char *key = g_strdup_printf ("test-long-header-key%d", i);
		char *value = g_strdup_printf ("test-long-header-key%d", i);
		soup_message_headers_append (msg->request_headers, key, value);
		g_free (value);
		g_free (key);
	}

	soup_session_send_message (session, msg);

	soup_test_session_abort_unref (session);

	soup_test_assert_message_status (msg, SOUP_STATUS_IO_ERROR);

	g_object_unref (msg);
}

/* Dropping the application's ref on the session from a callback
 * should not cause the session to be freed at an incorrect time.
 * (This test will crash if it fails.)
 */
static void
cu_one_completed (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	debug_printf (2, "  Message 1 completed\n");
	soup_test_assert_message_status (msg, SOUP_STATUS_CANT_CONNECT);
	g_object_unref (session);
}

static gboolean
cu_idle_quit (gpointer loop)
{
	g_main_loop_quit (loop);
	return FALSE;
}

static void
cu_two_completed (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	debug_printf (2, "  Message 2 completed\n");
	soup_test_assert_message_status (msg, SOUP_STATUS_CANT_CONNECT);
	g_idle_add (cu_idle_quit, loop); 
}

static void
do_callback_unref_test (void)
{
	SoupServer *bad_server;
	SoupSession *session;
	SoupMessage *one, *two;
	GMainLoop *loop;
	SoupURI *bad_uri;

	g_test_bug ("533473");

	/* Get a guaranteed-bad URI */
	bad_server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	bad_uri = soup_test_server_get_uri (bad_server, "http", NULL);
	soup_test_server_quit_unref (bad_server);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_object_add_weak_pointer (G_OBJECT (session), (gpointer *)&session);

	loop = g_main_loop_new (NULL, TRUE);

	one = soup_message_new_from_uri ("GET", bad_uri);
	g_object_add_weak_pointer (G_OBJECT (one), (gpointer *)&one);
	two = soup_message_new_from_uri ("GET", bad_uri);
	g_object_add_weak_pointer (G_OBJECT (two), (gpointer *)&two);
	soup_uri_free (bad_uri);

	soup_session_queue_message (session, one, cu_one_completed, loop);
	soup_session_queue_message (session, two, cu_two_completed, loop);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_assert_null (session);
	if (session) {
		g_object_remove_weak_pointer (G_OBJECT (session), (gpointer *)&session);
		g_object_unref (session);
	}
	g_assert_null (one);
	if (one) {
		g_object_remove_weak_pointer (G_OBJECT (one), (gpointer *)&one);
		g_object_unref (one);
	}
	g_assert_null (two);
	if (two) {
		g_object_remove_weak_pointer (G_OBJECT (two), (gpointer *)&two);
		g_object_unref (two);
	}

	/* Otherwise, if we haven't crashed, we're ok. */
}

static void
cur_one_completed (GObject *source, GAsyncResult *result, gpointer session)
{
	SoupRequest *one = SOUP_REQUEST (source);
	GError *error = NULL;

	debug_printf (2, "  Request 1 completed\n");
	soup_request_send_finish (one, result, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED);
	g_clear_error (&error);

	g_object_unref (session);
}

static gboolean
cur_idle_quit (gpointer loop)
{
	g_main_loop_quit (loop);
	return FALSE;
}

static void
cur_two_completed (GObject *source, GAsyncResult *result, gpointer loop)
{
	SoupRequest *two = SOUP_REQUEST (source);
	GError *error = NULL;

	debug_printf (2, "  Request 2 completed\n");
	soup_request_send_finish (two, result, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED);
	g_clear_error (&error);

	g_idle_add (cur_idle_quit, loop); 
}

static void
do_callback_unref_req_test (void)
{
	SoupServer *bad_server;
	SoupSession *session;
	SoupRequest *one, *two;
	GMainLoop *loop;
	SoupURI *bad_uri;

	/* Get a guaranteed-bad URI */
	bad_server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	bad_uri = soup_test_server_get_uri (bad_server, "http", NULL);
	soup_test_server_quit_unref (bad_server);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	g_object_add_weak_pointer (G_OBJECT (session), (gpointer *)&session);

	loop = g_main_loop_new (NULL, TRUE);

	one = soup_session_request_uri (session, bad_uri, NULL);
	g_object_add_weak_pointer (G_OBJECT (one), (gpointer *)&one);
	two = soup_session_request_uri (session, bad_uri, NULL);
	g_object_add_weak_pointer (G_OBJECT (two), (gpointer *)&two);
	soup_uri_free (bad_uri);

	soup_request_send_async (one, NULL, cur_one_completed, session);
	g_object_unref (one);
	soup_request_send_async (two, NULL, cur_two_completed, loop);
	g_object_unref (two);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_assert_null (session);
	if (session) {
		g_object_remove_weak_pointer (G_OBJECT (session), (gpointer *)&session);
		g_object_unref (session);
	}
	g_assert_null (one);
	if (one) {
		g_object_remove_weak_pointer (G_OBJECT (one), (gpointer *)&one);
		g_object_unref (one);
	}
	g_assert_null (two);
	if (two) {
		g_object_remove_weak_pointer (G_OBJECT (two), (gpointer *)&two);
		g_object_unref (two);
	}

	/* Otherwise, if we haven't crashed, we're ok. */
}

/* SoupSession should clean up all signal handlers on a message after
 * it is finished, allowing the message to be reused if desired.
 */
static void
ensure_no_signal_handlers (SoupMessage *msg, guint *signal_ids, guint n_signal_ids)
{
	int i;
	guint id;

	for (i = 0; i < n_signal_ids; i++) {
		id = g_signal_handler_find (msg, G_SIGNAL_MATCH_ID, signal_ids[i],
					    0, NULL, NULL, NULL);
		soup_test_assert (id == 0,
				  "message has handler for '%s'",
				  g_signal_name (signal_ids[i]));
	}
}

static void
reuse_test_authenticate (SoupSession *session, SoupMessage *msg,
			 SoupAuth *auth, gboolean retrying)
{
	/* Get it wrong the first time, then succeed */
	if (!retrying)
		soup_auth_authenticate (auth, "user", "wrong password");
	else
		soup_auth_authenticate (auth, "user", "password");
}

static void
do_msg_reuse_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;
	guint *signal_ids, n_signal_ids;

	g_test_bug ("559054");

	signal_ids = g_signal_list_ids (SOUP_TYPE_MESSAGE, &n_signal_ids);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (reuse_test_authenticate), NULL);

	debug_printf (1, "  First message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	debug_printf (1, "  Redirect message\n");
	uri = soup_uri_new_with_base (base_uri, "/redirect");
	soup_message_set_uri (msg, uri);
	soup_uri_free (uri);
	soup_session_send_message (session, msg);
	g_assert_true (soup_uri_equal (soup_message_get_uri (msg), base_uri));
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	debug_printf (1, "  Auth message\n");
	uri = soup_uri_new_with_base (base_uri, "/auth");
	soup_message_set_uri (msg, uri);
	soup_uri_free (uri);
	soup_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	/* One last try to make sure the auth stuff got cleaned up */
	debug_printf (1, "  Last message\n");
	soup_message_set_uri (msg, base_uri);
	soup_session_send_message (session, msg);
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	soup_test_session_abort_unref (session);
	g_object_unref (msg);
	g_free (signal_ids);
}

/* Handle unexpectedly-early aborts. */
static void
ea_msg_completed_one (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	debug_printf (2, "  Message 1 completed\n");
	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_main_loop_quit (loop);
}

static gboolean
ea_abort_session (gpointer session)
{
	soup_session_abort (session);
	return FALSE;
}

static void
ea_connection_state_changed (GObject *conn, GParamSpec *pspec, gpointer session)
{
	SoupConnectionState state;

	g_object_get (conn, "state", &state, NULL);
	if (state == SOUP_CONNECTION_CONNECTING) {
		g_idle_add_full (G_PRIORITY_HIGH,
				 ea_abort_session,
				 session, NULL);
		g_signal_handlers_disconnect_by_func (conn, ea_connection_state_changed, session);
	}
}		

static void
ea_connection_created (SoupSession *session, GObject *conn, gpointer user_data)
{
	g_signal_connect (conn, "notify::state",
			  G_CALLBACK (ea_connection_state_changed), session);
	g_signal_handlers_disconnect_by_func (session, ea_connection_created, user_data);
}

static void
ea_message_starting (SoupMessage *msg, SoupSession *session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
}

static void
do_early_abort_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GMainContext *context;
	GMainLoop *loop;

	g_test_bug ("596074");
	g_test_bug ("618641");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);

	context = g_main_context_default ();
	loop = g_main_loop_new (context, TRUE);
	soup_session_queue_message (session, msg, ea_msg_completed_one, loop);
	g_main_context_iteration (context, FALSE);

	soup_session_abort (session);
	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);
	g_main_loop_unref (loop);
	soup_test_session_abort_unref (session);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);

	g_signal_connect (session, "connection-created",
			  G_CALLBACK (ea_connection_created), NULL);
	soup_session_send_message (session, msg);
	debug_printf (2, "  Message 2 completed\n");

	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);

	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);

	soup_test_session_abort_unref (session);

	g_test_bug ("668098");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);

	g_signal_connect (msg, "starting",
			  G_CALLBACK (ea_message_starting), session);
	soup_session_send_message (session, msg);
	debug_printf (2, "  Message 3 completed\n");

	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);

	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);

	soup_test_session_abort_unref (session);
}

static void
ear_one_completed (GObject *source, GAsyncResult *result, gpointer user_data)
{
	GError *error = NULL;

	debug_printf (2, "  Request 1 completed\n");
	soup_request_send_finish (SOUP_REQUEST (source), result, &error);
	g_assert_error (error, SOUP_HTTP_ERROR, SOUP_STATUS_CANCELLED);
	g_clear_error (&error);
}

static void
ear_two_completed (GObject *source, GAsyncResult *result, gpointer loop)
{
	GError *error = NULL;

	debug_printf (2, "  Request 2 completed\n");
	soup_request_send_finish (SOUP_REQUEST (source), result, &error);
	g_assert_error (error, SOUP_HTTP_ERROR, SOUP_STATUS_CANCELLED);
	g_clear_error (&error);

	g_main_loop_quit (loop);
}

static void
ear_three_completed (GObject *source, GAsyncResult *result, gpointer loop)
{
	GError *error = NULL;

	debug_printf (2, "  Request 3 completed\n");
	soup_request_send_finish (SOUP_REQUEST (source), result, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);

	g_main_loop_quit (loop);
}

static void
ear_message_starting (SoupMessage *msg, gpointer cancellable)
{
	g_cancellable_cancel (cancellable);
}

static void
ear_request_queued (SoupSession *session, SoupMessage *msg,
		    gpointer cancellable)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (ear_message_starting),
			  cancellable);
}

static void
do_early_abort_req_test (void)
{
	SoupSession *session;
	SoupRequest *req;
	GMainContext *context;
	GMainLoop *loop;
	GCancellable *cancellable;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	req = soup_session_request_uri (session, base_uri, NULL);

	context = g_main_context_default ();
	loop = g_main_loop_new (context, TRUE);
	soup_request_send_async (req, NULL, ear_one_completed, NULL);
	g_object_unref (req);
	g_main_context_iteration (context, FALSE);

	soup_session_abort (session);
	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);
	soup_test_session_abort_unref (session);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	req = soup_session_request_uri (session, base_uri, NULL);

	g_signal_connect (session, "connection-created",
			  G_CALLBACK (ea_connection_created), NULL);
	soup_request_send_async (req, NULL, ear_two_completed, loop);
	g_main_loop_run (loop);
	g_object_unref (req);

	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);

	soup_test_session_abort_unref (session);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	req = soup_session_request_uri (session, base_uri, NULL);

	cancellable = g_cancellable_new ();
	g_signal_connect (session, "request-queued",
			  G_CALLBACK (ear_request_queued), cancellable);
	soup_request_send_async (req, cancellable, ear_three_completed, loop);
	g_main_loop_run (loop);
	g_object_unref (req);
	g_object_unref (cancellable);

	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);

	soup_test_session_abort_unref (session);
	g_main_loop_unref (loop);
}

static void
do_one_accept_language_test (const char *language, const char *expected_header)
{
	SoupSession *session;
	SoupMessage *msg;
	const char *val;

	debug_printf (1, "  LANGUAGE=%s\n", language);
	g_setenv ("LANGUAGE", language, TRUE);
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
					 NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	soup_test_session_abort_unref (session);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	val = soup_message_headers_get_list (msg->request_headers,
					     "Accept-Language");
	g_assert_cmpstr (val, ==, expected_header);

	g_object_unref (msg);
}

static void
do_accept_language_test (void)
{
	const char *orig_language;

	g_test_bug ("602547");

	orig_language = g_getenv ("LANGUAGE");
	do_one_accept_language_test ("C", "en");
	do_one_accept_language_test ("fr_FR", "fr-fr, fr;q=0.9");
	do_one_accept_language_test ("fr_FR:de:en_US", "fr-fr, fr;q=0.9, de;q=0.8, en-us;q=0.7, en;q=0.6");

	if (orig_language)
		g_setenv ("LANGUAGE", orig_language, TRUE);
	else
		g_unsetenv ("LANGUAGE");
}

static gboolean
cancel_message_timeout (gpointer msg)
{
	SoupSession *session = g_object_get_data (G_OBJECT (msg), "session");

	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);
	g_object_unref (session);
	return FALSE;
}

static gpointer
cancel_message_thread (gpointer msg)
{
	SoupSession *session = g_object_get_data (G_OBJECT (msg), "session");

	g_usleep (100000); /* .1s */
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);
	g_object_unref (session);
	return NULL;
}

static void
set_done (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	gboolean *done = user_data;

	*done = TRUE;
}

static void
do_cancel_while_reading_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	GThread *thread = NULL;
	SoupURI *uri;
	gboolean done = FALSE;

	uri = soup_uri_new_with_base (base_uri, "/slow");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	g_object_set_data (G_OBJECT (msg), "session", session);
	g_object_ref (msg);
	g_object_ref (session);
	if (SOUP_IS_SESSION_ASYNC (session))
		g_timeout_add (100, cancel_message_timeout, msg);
	else
		thread = g_thread_new ("cancel_message_thread", cancel_message_thread, msg);

	/* We intentionally don't use soup_session_send_message() here,
	 * because it holds an extra ref on the SoupMessageQueueItem
	 * relative to soup_session_queue_message().
	 */
	g_object_ref (msg);
	soup_session_queue_message (session, msg, set_done, &done);
	while (!done)
		g_main_context_iteration (NULL, TRUE);

	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);

	if (thread)
		g_thread_join (thread);
}

static void
do_cancel_while_reading_test (void)
{
	SoupSession *session;

	g_test_bug ("637741");
	g_test_bug ("676038");

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_cancel_while_reading_test_for_session (session);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	do_cancel_while_reading_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_req_test_for_session (SoupSession *session,
					      guint flags)
{
	SoupRequest *req;
	SoupURI *uri;
	GCancellable *cancellable;
	GError *error = NULL;

	uri = soup_uri_new_with_base (base_uri, "/slow");
	req = soup_session_request_uri (session, uri, NULL);
	soup_uri_free (uri);

	cancellable = g_cancellable_new ();
	soup_test_request_send (req, cancellable, flags, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);

	g_object_unref (req);
	g_object_unref (cancellable);
}

static void
do_cancel_while_reading_immediate_req_test (void)
{
	SoupSession *session;
	guint flags;

	g_test_bug ("692310");

	flags = SOUP_TEST_REQUEST_CANCEL_CANCELLABLE | SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_delayed_req_test (void)
{
	SoupSession *session;
	guint flags;

	flags = SOUP_TEST_REQUEST_CANCEL_CANCELLABLE | SOUP_TEST_REQUEST_CANCEL_SOON;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_preemptive_req_test (void)
{
	SoupSession *session;
	guint flags;

	g_test_bug ("637039");

	flags = SOUP_TEST_REQUEST_CANCEL_CANCELLABLE | SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE;

	debug_printf (1, "  Async session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  Sync session\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_aliases_test_for_session (SoupSession *session,
			     const char *redirect_protocol)
{
	SoupMessage *msg;
	SoupURI *uri;
	const char *redirected_protocol;

	uri = soup_uri_new_with_base (base_uri, "/alias-redirect");
	msg = soup_message_new_from_uri ("GET", uri);
	if (redirect_protocol)
		soup_message_headers_append (msg->request_headers, "X-Redirect-Protocol", redirect_protocol);
	soup_uri_free (uri);
	soup_session_send_message (session, msg);

	redirected_protocol = soup_message_headers_get_one (msg->response_headers, "X-Redirected-Protocol");

	g_assert_cmpstr (redirect_protocol, ==, redirected_protocol);
	if (redirect_protocol)
		soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	else
		soup_test_assert_message_status (msg, SOUP_STATUS_FOUND);

	g_object_unref (msg);
}

static void
do_aliases_test (void)
{
	SoupSession *session;
	char *aliases[] = { "foo", NULL };

	debug_printf (1, "  Default behavior\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	do_aliases_test_for_session (session, "http");
	soup_test_session_abort_unref (session);

	if (tls_available) {
		debug_printf (1, "  foo-means-https\n");
		session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
						 SOUP_SESSION_HTTPS_ALIASES, aliases,
						 NULL);
		do_aliases_test_for_session (session, "https");
		soup_test_session_abort_unref (session);
	} else
		debug_printf (1, "  foo-means-https -- SKIPPING\n");

	debug_printf (1, "  foo-means-nothing\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_HTTP_ALIASES, NULL,
					 NULL);
	do_aliases_test_for_session (session, NULL);
	soup_test_session_abort_unref (session);
}

static void
do_idle_on_dispose_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GMainContext *async_context;

	g_test_bug ("667364");

	async_context = g_main_context_new ();
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_ASYNC_CONTEXT, async_context,
					 NULL);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);

	while (g_main_context_iteration (async_context, FALSE))
		;

	g_object_run_dispose (G_OBJECT (session));

	if (g_main_context_iteration (async_context, FALSE))
		soup_test_assert (FALSE, "idle was queued");

	g_object_unref (session);
	g_main_context_unref (async_context);
}

static void
do_pause_abort_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	gpointer ptr;

	g_test_bug ("673905");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_session_queue_message (session, msg, NULL, NULL);
	soup_session_pause_message (session, msg);

	g_object_add_weak_pointer (G_OBJECT (msg), &ptr);
	soup_test_session_abort_unref (session);

	g_assert_null (ptr);
}

static GMainLoop *pause_cancel_loop;

static void
pause_cancel_got_headers (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;

	soup_session_pause_message (session, msg);
	g_main_loop_quit (pause_cancel_loop);
}

static void
pause_cancel_finished (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
	g_main_loop_quit (pause_cancel_loop);
}

static gboolean
pause_cancel_timeout (gpointer user_data)
{
	gboolean *timed_out = user_data;

	*timed_out = TRUE;
	g_main_loop_quit (pause_cancel_loop);
	return FALSE;
}

static void
do_pause_cancel_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	gboolean finished = FALSE, timed_out = FALSE;
	guint timeout_id;

	g_test_bug ("745094");

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	pause_cancel_loop = g_main_loop_new (NULL, FALSE);

	timeout_id = g_timeout_add_seconds (5, pause_cancel_timeout, &timed_out);

	msg = soup_message_new_from_uri ("GET", base_uri);
	g_object_ref (msg);
	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (pause_cancel_got_headers), session);

	soup_session_queue_message (session, msg, pause_cancel_finished, &finished);
	g_main_loop_run (pause_cancel_loop);
	g_assert_false (finished);

	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_main_loop_run (pause_cancel_loop);
	g_assert_true (finished);
	g_assert_false (timed_out);

	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	g_main_loop_unref (pause_cancel_loop);
	if (!timed_out)
		g_source_remove (timeout_id);
}

static gboolean
run_echo_server (gpointer user_data)
{
	GIOStream *stream = user_data;
	GInputStream *istream;
	GDataInputStream *distream;
	GOutputStream *ostream;
	char *str, *caps;
	gssize n;
	GError *error = NULL;

	istream = g_io_stream_get_input_stream (stream);
	distream = G_DATA_INPUT_STREAM (g_data_input_stream_new (istream));
	ostream = g_io_stream_get_output_stream (stream);

	/* Echo until the client disconnects */
	while (TRUE) {
		str = g_data_input_stream_read_line (distream, NULL, NULL, &error);
		g_assert_no_error (error);
		if (!str)
			break;

		caps = g_ascii_strup (str, -1);
		n = g_output_stream_write (ostream, caps, strlen (caps), NULL, &error);
		g_assert_no_error (error);
		g_assert_cmpint (n, ==, strlen (caps)); 
		n = g_output_stream_write (ostream, "\n", 1, NULL, &error);
		g_assert_no_error (error);
		g_assert_cmpint (n, ==, 1);
		g_free (caps);
		g_free (str);
	}

	g_object_unref (distream);

	g_io_stream_close (stream, NULL, &error);
	g_assert_no_error (error);
	g_object_unref (stream);

	return FALSE;
}

static void
steal_after_upgrade (SoupMessage *msg, gpointer user_data)
{
	SoupClientContext *context = user_data;
	GIOStream *stream;
	GSource *source;

	/* This should not ever be seen. */
	soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);

	stream = soup_client_context_steal_connection (context);

	source = g_idle_source_new ();
	g_source_set_callback (source, run_echo_server, stream, NULL);
	g_source_attach (source, g_main_context_get_thread_default ());
	g_source_unref (source);
}

static void
upgrade_server_callback (SoupServer *server, SoupMessage *msg,
			 const char *path, GHashTable *query,
			 SoupClientContext *context, gpointer data)
{
	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS);
	soup_message_headers_append (msg->request_headers, "Upgrade", "ECHO");
	soup_message_headers_append (msg->request_headers, "Connection", "upgrade");

	g_signal_connect (msg, "wrote-informational",
			  G_CALLBACK (steal_after_upgrade), context);
}

static void
callback_not_reached (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	g_assert_not_reached ();
}

static void
switching_protocols (SoupMessage *msg, gpointer user_data)
{
	GIOStream **out_iostream = user_data;
	SoupSession *session = g_object_get_data (G_OBJECT (msg), "SoupSession");

	*out_iostream = soup_session_steal_connection (session, msg);
}

static void
do_stealing_test (gconstpointer data)
{
	gboolean sync = GPOINTER_TO_INT (data);
	SoupServer *server;
	SoupURI *uri;
	SoupSession *session;
	SoupMessage *msg;
	GIOStream *iostream;
	GInputStream *istream;
	GDataInputStream *distream;
	GOutputStream *ostream;
	int i;
	gssize n;
	char *str, *caps;
	GError *error = NULL;
	static const char *strings[] = { "one", "two", "three", "four", "five" };

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	uri = soup_test_server_get_uri (server, SOUP_URI_SCHEME_HTTP, "127.0.0.1");
	soup_server_add_handler (server, NULL, upgrade_server_callback, NULL, NULL);

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msg->request_headers, "Upgrade", "echo");
	soup_message_headers_append (msg->request_headers, "Connection", "upgrade");
	g_object_set_data (G_OBJECT (msg), "SoupSession", session);

	soup_message_add_status_code_handler (msg, "got-informational",
					      SOUP_STATUS_SWITCHING_PROTOCOLS,
					      G_CALLBACK (switching_protocols), &iostream);

	iostream = NULL;

	if (sync) {
		soup_session_send_message (session, msg);
		soup_test_assert_message_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS);
	} else {
		g_object_ref (msg);
		soup_session_queue_message (session, msg, callback_not_reached, NULL);
		while (iostream == NULL)
			g_main_context_iteration (NULL, TRUE);
	}

	g_assert (iostream != NULL);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
	soup_uri_free (uri);

	/* Now iostream connects to a (capitalizing) echo server */

	istream = g_io_stream_get_input_stream (iostream);
	distream = G_DATA_INPUT_STREAM (g_data_input_stream_new (istream));
	ostream = g_io_stream_get_output_stream (iostream);

	for (i = 0; i < G_N_ELEMENTS (strings); i++) {
		n = g_output_stream_write (ostream, strings[i], strlen (strings[i]),
					   NULL, &error);
		g_assert_no_error (error);
		g_assert_cmpint (n, ==, strlen (strings[i]));
		n = g_output_stream_write (ostream, "\n", 1, NULL, &error);
		g_assert_no_error (error);
		g_assert_cmpint (n, ==, 1);
	}

	for (i = 0; i < G_N_ELEMENTS (strings); i++) {
		str = g_data_input_stream_read_line (distream, NULL, NULL, &error);
		g_assert_no_error (error);
		caps = g_ascii_strup (strings[i], -1);
		g_assert_cmpstr (caps, ==, str);
		g_free (caps);
		g_free (str);
	}

	g_object_unref (distream);

	g_io_stream_close (iostream, NULL, &error);
	g_assert_no_error (error);
	g_object_unref (iostream);

	/* We can't do this until the end because it's in another thread, and
	 * soup_test_server_quit_unref() will wait for that thread to exit.
	 */ 
	soup_test_server_quit_unref (server);
}

static void
wrote_informational_check_content_length (SoupMessage *msg, gpointer user_data)
{
	g_assert_null (soup_message_headers_get_one (msg->response_headers, "Content-Length"));
}

static void
upgrade_server_check_content_length_callback (SoupServer *server, SoupMessage *msg,
                                              const char *path, GHashTable *query,
                                              SoupClientContext *context, gpointer data)
{
	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS);
	soup_message_headers_append (msg->request_headers, "Upgrade", "ECHO");
	soup_message_headers_append (msg->request_headers, "Connection", "upgrade");

	g_signal_connect (msg, "wrote-informational",
			  G_CALLBACK (wrote_informational_check_content_length), context);
}

static void
switching_protocols_check_length (SoupMessage *msg, gpointer user_data)
{
	g_assert_null (soup_message_headers_get_one (msg->response_headers, "Content-Length"));
}

static void
do_response_informational_content_length_test (void)
{
	SoupServer *server;
	SoupURI *uri;
	SoupSession *session;
	SoupMessage *msg;

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	uri = soup_test_server_get_uri (server, SOUP_URI_SCHEME_HTTP, NULL);
	soup_server_add_handler (server, NULL, upgrade_server_check_content_length_callback, NULL, NULL);

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msg->request_headers, "Upgrade", "echo");
	soup_message_headers_append (msg->request_headers, "Connection", "upgrade");

	soup_message_add_status_code_handler (msg, "got-informational",
					      SOUP_STATUS_SWITCHING_PROTOCOLS,
					      G_CALLBACK (switching_protocols_check_length), NULL);

	soup_session_send_message (session, msg);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
	soup_uri_free (uri);

	soup_test_server_quit_unref (server);
}

int
main (int argc, char **argv)
{
	SoupAuthDomain *auth_domain;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, "http", NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	auth_domain = soup_auth_domain_basic_new (
		SOUP_AUTH_DOMAIN_REALM, "misc-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/auth",
		SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, auth_callback,
		NULL);
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	if (tls_available) {
		ssl_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
		soup_server_add_handler (ssl_server, NULL, server_callback, "https", NULL);
		ssl_base_uri = soup_test_server_get_uri (ssl_server, "https", "127.0.0.1");
	}

	g_test_add_func ("/misc/bigheader", do_host_big_header);
	g_test_add_func ("/misc/host", do_host_test);
	g_test_add_func ("/misc/callback-unref/msg", do_callback_unref_test);
	g_test_add_func ("/misc/callback-unref/req", do_callback_unref_req_test);
	g_test_add_func ("/misc/msg-reuse", do_msg_reuse_test);
	g_test_add_func ("/misc/early-abort/msg", do_early_abort_test);
	g_test_add_func ("/misc/early-abort/req", do_early_abort_req_test);
	g_test_add_func ("/misc/accept-language", do_accept_language_test);
	g_test_add_func ("/misc/cancel-while-reading/msg", do_cancel_while_reading_test);
	g_test_add_func ("/misc/cancel-while-reading/req/immediate", do_cancel_while_reading_immediate_req_test);
	g_test_add_func ("/misc/cancel-while-reading/req/delayed", do_cancel_while_reading_delayed_req_test);
	g_test_add_func ("/misc/cancel-while-reading/req/preemptive", do_cancel_while_reading_preemptive_req_test);
	g_test_add_func ("/misc/aliases", do_aliases_test);
	g_test_add_func ("/misc/idle-on-dispose", do_idle_on_dispose_test);
	g_test_add_func ("/misc/pause-abort", do_pause_abort_test);
	g_test_add_func ("/misc/pause-cancel", do_pause_cancel_test);
	g_test_add_data_func ("/misc/stealing/async", GINT_TO_POINTER (FALSE), do_stealing_test);
	g_test_add_data_func ("/misc/stealing/sync", GINT_TO_POINTER (TRUE), do_stealing_test);
	g_test_add_func ("/misc/response/informational/content-length", do_response_informational_content_length_test);


	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	if (tls_available) {
		soup_uri_free (ssl_base_uri);
		soup_test_server_quit_unref (ssl_server);
	}

	test_cleanup ();
	return ret;
}
