/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"
#include "soup-connection.h"
#include "soup-session-private.h"
#include "soup-message-headers-private.h"

#include <stdint.h>

SoupServer *server;
GUri *base_uri;

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static gboolean
timeout_finish_message (gpointer msg)
{
	soup_server_message_unpause (msg);
        g_object_unref (msg);
	return FALSE;
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *method = soup_server_message_get_method (msg);
	GUri *uri = soup_server_message_get_uri (msg);

	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_POST && method != SOUP_METHOD_PUT) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	if (!strcmp (path, "/redirect")) {
		soup_server_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		return;
	}

        if (!strcmp (path, "/session")) {
                SoupMessageHeaders *request_headers;
                const char *session_id;

                request_headers = soup_server_message_get_request_headers (msg);
                session_id = soup_message_headers_get_one (request_headers, "X-SoupTest-Session-Id");
                if (!session_id) {
                        SoupMessageHeaders *response_headers;

                        response_headers = soup_server_message_get_response_headers (msg);
                        soup_message_headers_replace (response_headers, "X-SoupTest-Session-Id", "session-1");
                        soup_server_message_set_status (msg, SOUP_STATUS_CONFLICT, NULL);
                } else {
                        soup_server_message_set_status (msg, SOUP_STATUS_CREATED, NULL);
                }

                return;
        }

	if (!strcmp (path, "/slow")) {
                GSource *timeout;
		soup_server_message_pause (msg);
		timeout = soup_add_timeout (g_main_context_get_thread_default (),
                                            1000, timeout_finish_message, g_object_ref (msg));
                g_source_unref (timeout);
	}

        if (!strcmp (path, "/invalid_utf8_headers")) {
                SoupMessageHeaders *headers = soup_server_message_get_response_headers (msg);
                const char *invalid_utf8_value = "\xe2\x82\xa0gh\xe2\xffjl";

                /* Purposefully insert invalid utf8 data */
                g_assert_false (g_utf8_validate (invalid_utf8_value, -1, NULL));
                soup_message_headers_append (headers, "InvalidValue", invalid_utf8_value);
        }

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	if (!strcmp (g_uri_get_host (uri), "foo")) {
		soup_server_message_set_response (msg, "text/plain",
                                                  SOUP_MEMORY_STATIC, "foo-index", 9);
		return;
	} else if (!strcmp (path, "/large-body")) {
	        gsize size = 64 * 1024 + 32;
	        const char *body = g_malloc (size);
	        for (gsize i = 0; i < size; i+= 16) {
	                memcpy ((void *)(body + i), (void*) "0123456789ABCDEF", 16); // NOLINT(*-not-null-terminated-result)
	        }
	        soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_TAKE, body, size);
	} else {
		soup_server_message_set_response (msg, "text/plain",
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
	GBytes *body_one, *body_two;

	g_test_bug ("539803");

	session = soup_test_session_new (NULL);

	one = soup_message_new_from_uri ("GET", base_uri);
	two = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_replace (soup_message_get_request_headers (two), "Host", "foo");

	body_one = soup_session_send_and_read (session, one, NULL, NULL);
	body_two = soup_session_send_and_read (session, two, NULL, NULL);

	soup_test_session_abort_unref (session);

	soup_test_assert_message_status (one, SOUP_STATUS_OK);
	g_assert_cmpstr (g_bytes_get_data (body_one, NULL), ==, "index");
	g_bytes_unref (body_one);
	g_object_unref (one);

	soup_test_assert_message_status (two, SOUP_STATUS_OK);
	g_assert_cmpstr (g_bytes_get_data (body_two, NULL), ==, "foo-index");
	g_bytes_unref (body_two);
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
	GInputStream *stream;
	GError *error = NULL;

	g_test_bug ("792173");

	session = soup_test_session_new (NULL);

	msg = soup_message_new_from_uri ("GET", base_uri);
	for (i = 0; i < 3072; i++) {
		char *key = g_strdup_printf ("test-long-header-key%d", i);
		char *value = g_strdup_printf ("test-long-header-key%d", i);
		soup_message_headers_append (soup_message_get_request_headers (msg), key, value);
		g_free (value);
		g_free (key);
	}

	stream = soup_session_send (session, msg, NULL, &error);
	g_assert_null (stream);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);
	g_clear_error (&error);

	soup_test_session_abort_unref (session);

	g_object_unref (msg);
}

/* Dropping the application's ref on the session from a callback
 * should not cause the session to be freed at an incorrect time.
 * (This test will crash if it fails.)
 */
static void
cu_one_completed (SoupMessage *msg,
		  SoupSession *session)
{
	debug_printf (2, "  Message 1 completed\n");
	g_object_unref (session);
}

static gboolean
cu_idle_quit (gpointer loop)
{
	g_main_loop_quit (loop);
	return FALSE;
}

static void
cu_two_completed (SoupMessage *msg,
		  GMainLoop   *loop)
{
	debug_printf (2, "  Message 2 completed\n");
	g_idle_add (cu_idle_quit, loop); 
}

static void
do_callback_unref_test (void)
{
	SoupServer *bad_server;
	SoupSession *session;
	SoupMessage *one, *two;
	GMainLoop *loop;
	GUri *bad_uri;

	g_test_bug ("533473");

	/* Get a guaranteed-bad URI */
	bad_server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	bad_uri = soup_test_server_get_uri (bad_server, "http", NULL);
	soup_test_server_quit_unref (bad_server);

	session = soup_test_session_new (NULL);
	g_object_add_weak_pointer (G_OBJECT (session), (gpointer *)&session);

	loop = g_main_loop_new (NULL, TRUE);

	one = soup_message_new_from_uri ("GET", bad_uri);
	g_signal_connect (one, "finished",
			  G_CALLBACK (cu_one_completed), session);
	g_object_add_weak_pointer (G_OBJECT (one), (gpointer *)&one);
	two = soup_message_new_from_uri ("GET", bad_uri);
	g_signal_connect (two, "finished",
			  G_CALLBACK (cu_two_completed), loop);
	g_object_add_weak_pointer (G_OBJECT (two), (gpointer *)&two);
	g_uri_unref (bad_uri);

	soup_session_send_async (session, one, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
	soup_session_send_async (session, two, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
	g_object_unref (one);
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

/* SoupSession should clean up all internal signal handlers on a message after
 * it is finished, allowing the message to be reused if desired.
 */
static void
ensure_no_signal_handlers (SoupMessage *msg, guint *signal_ids, guint n_signal_ids)
{
	int i;
	guint id;

	for (i = 0; i < n_signal_ids; i++) {
		if (strcmp (g_signal_name (signal_ids[i]), "authenticate") == 0)
			continue;

		id = g_signal_handler_find (msg, G_SIGNAL_MATCH_ID, signal_ids[i],
					    0, NULL, NULL, NULL);
		soup_test_assert (id == 0,
				  "message has handler for '%s'",
				  g_signal_name (signal_ids[i]));
	}
}

static gboolean
reuse_test_authenticate (SoupMessage *msg,
			 SoupAuth    *auth,
			 gboolean     retrying)
{
	/* Get it wrong the first time, then succeed */
	if (!retrying)
		soup_auth_authenticate (auth, "user", "wrong password");
	else
		soup_auth_authenticate (auth, "user", "password");

	return TRUE;
}

static void
reuse_preconnect_finished (SoupSession   *session,
                           GAsyncResult  *result,
                           GError       **error)
{
        g_assert_false (soup_session_preconnect_finish (session, result, error));
}

static void
reuse_websocket_connect_finished (SoupSession   *session,
                                  GAsyncResult  *result,
                                  GError       **error)
{
        g_assert_false (soup_session_websocket_connect_finish (session, result, error));
}

static void
do_msg_reuse_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
        GBytes *body;
	GUri *uri;
	guint *signal_ids, n_signal_ids;
        GInputStream *stream;
        GError *error = NULL;

	g_test_bug ("559054");

	signal_ids = g_signal_list_ids (SOUP_TYPE_MESSAGE, &n_signal_ids);

	session = soup_test_session_new (NULL);

	debug_printf (1, "  First message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	g_signal_connect (msg, "authenticate",
                          G_CALLBACK (reuse_test_authenticate), NULL);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);
        g_bytes_unref (body);

	debug_printf (1, "  Redirect message\n");
	uri = g_uri_parse_relative (base_uri, "/redirect", SOUP_HTTP_URI_FLAGS, NULL);
	soup_message_set_uri (msg, uri);
	g_uri_unref (uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);
	g_assert_true (soup_uri_equal (soup_message_get_uri (msg), base_uri));
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);
        g_bytes_unref (body);

	debug_printf (1, "  Auth message\n");
	uri = g_uri_parse_relative (base_uri, "/auth", SOUP_HTTP_URI_FLAGS, NULL);
	soup_message_set_uri (msg, uri);
	g_uri_unref (uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_bytes_unref (body);
	soup_message_set_uri (msg, base_uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);
        g_bytes_unref (body);

        debug_printf (1, "  Reuse before finishing\n");
        msg = soup_message_new_from_uri ("GET", base_uri);
        stream = soup_test_request_send (session, msg, NULL, 0, &error);
        g_assert_no_error (error);
        g_assert_null (soup_test_request_send (session, msg, NULL, 0, &error));
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        g_assert_null (soup_test_session_async_send (session, msg, NULL, &error));
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        g_assert_null (soup_session_send (session, msg, NULL, &error));
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        g_assert_null (soup_session_send_and_read (session, msg, NULL, &error));
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                       (GAsyncReadyCallback)reuse_preconnect_finished, &error);
        while (error == NULL)
                g_main_context_iteration (NULL, TRUE);
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        soup_session_websocket_connect_async (session, msg, NULL, NULL, G_PRIORITY_DEFAULT, NULL,
                                              (GAsyncReadyCallback)reuse_websocket_connect_finished, &error);
        while (error == NULL)
                g_main_context_iteration (NULL, TRUE);
        g_assert_error (error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE);
        g_clear_error (&error);
        g_object_unref (stream);

        ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	soup_test_session_abort_unref (session);
	g_object_unref (msg);
	g_free (signal_ids);
}

/* Handle unexpectedly-early aborts. */
static void
ea_msg_completed_one (SoupSession  *session,
		      GAsyncResult *result,
		      GMainLoop    *loop)
{
	GError *error = NULL;

	debug_printf (2, "  Message 1 completed\n");
	g_assert_null (soup_session_send_finish (session, result, &error));
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_main_loop_quit (loop);
}

static gboolean
ea_abort_session (gpointer session)
{
	soup_session_abort (session);
	return FALSE;
}

static void
ea_message_network_event (SoupMessage       *msg,
			  GSocketClientEvent event,
			  GIOStream         *connection,
			  SoupSession       *session)
{
	if (event != G_SOCKET_CLIENT_RESOLVING)
		return;

	g_idle_add_full (G_PRIORITY_HIGH,
			 ea_abort_session,
			 session, NULL);
	g_signal_handlers_disconnect_by_func (msg, ea_message_network_event, session);
}

static void
ea_message_starting (SoupMessage  *msg,
		     GCancellable *cancellable)
{
	g_cancellable_cancel (cancellable);
}

static void
do_early_abort_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	GCancellable *cancellable;
	GMainContext *context;
	GMainLoop *loop;
	GError *error = NULL;

	g_test_bug ("596074");
	g_test_bug ("618641");

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);

	context = g_main_context_default ();
	loop = g_main_loop_new (context, TRUE);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL,
				 (GAsyncReadyCallback)ea_msg_completed_one,
				 loop);
	g_object_unref (msg);

	soup_session_abort (session);
	while (g_main_context_pending (context))
		g_main_context_iteration (context, FALSE);
	g_main_loop_unref (loop);
	soup_test_session_abort_unref (session);

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);

	g_signal_connect (msg, "network-event",
			  G_CALLBACK (ea_message_network_event),
			  session);
	g_assert_null (soup_test_session_async_send (session, msg, NULL, &error));
	debug_printf (2, "  Message 2 completed\n");

	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);

	g_test_bug ("668098");

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);
	cancellable = g_cancellable_new ();

	g_signal_connect (msg, "starting",
			  G_CALLBACK (ea_message_starting), cancellable);
	g_assert_null (soup_test_session_async_send (session, msg, cancellable, &error));
	debug_printf (2, "  Message 3 completed\n");

	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_object_unref (cancellable);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_one_accept_language_test (const char *language, const char *expected_header)
{
	SoupSession *session;
	SoupMessage *msg;
	const char *val;

	debug_printf (1, "  LANGUAGE=%s\n", language);
	g_setenv ("LANGUAGE", language, TRUE);
	session = soup_test_session_new ("accept-language-auto", TRUE,
					 NULL);
	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_test_session_send_message (session, msg);
	soup_test_session_abort_unref (session);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	val = soup_message_headers_get_list (soup_message_get_request_headers (msg),
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
cancel_message_timeout (GCancellable *cancellable)
{
	g_cancellable_cancel (cancellable);
	return FALSE;
}

static void
do_cancel_while_reading_test_for_session (SoupSession *session)
{
	SoupMessage *msg;
	GUri *uri;
	GCancellable *cancellable;
	GError *error = NULL;

	uri = g_uri_parse_relative (base_uri, "/slow", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	cancellable = g_cancellable_new ();
	g_timeout_add_full (G_PRIORITY_DEFAULT, 100,
			    (GSourceFunc)cancel_message_timeout,
			    g_object_ref (cancellable),
			    g_object_unref);

	g_assert_null (soup_test_session_async_send (session, msg, cancellable, &error));
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_object_unref (cancellable);
	g_object_unref (msg);
}

static void
do_cancel_while_reading_test (void)
{
	SoupSession *session;

	g_test_bug ("637741");
	g_test_bug ("676038");

	session = soup_test_session_new (NULL);
	do_cancel_while_reading_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_req_test_for_session (SoupSession *session,
					      guint flags)
{
	SoupMessage *msg;
	GUri *uri;
	GCancellable *cancellable;
	GError *error = NULL;

	uri = g_uri_parse_relative (base_uri, "/slow", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	cancellable = g_cancellable_new ();
	soup_test_request_send (session, msg, cancellable, flags, &error);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);

	g_object_unref (msg);
	g_object_unref (cancellable);
}

static void
do_cancel_while_reading_immediate_req_test (void)
{
	SoupSession *session;
	guint flags;

	g_test_bug ("692310");

	flags = SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;

	session = soup_test_session_new (NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_delayed_req_test (void)
{
	SoupSession *session;
	guint flags;

	flags = SOUP_TEST_REQUEST_CANCEL_SOON;

	session = soup_test_session_new (NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_cancel_while_reading_preemptive_req_test (void)
{
	SoupSession *session;
	guint flags;

	g_test_bug ("637039");

	flags = SOUP_TEST_REQUEST_CANCEL_PREEMPTIVE;

	session = soup_test_session_new (NULL);
	do_cancel_while_reading_req_test_for_session (session, flags);
	soup_test_session_abort_unref (session);
}

static void
do_one_cancel_after_send_request_test (SoupSession *session,
                                       gboolean     reuse_cancellable,
                                       gboolean     cancelled_by_session)
{
        SoupMessage *msg;
        GCancellable *cancellable;
        GInputStream *istream;
        GOutputStream *ostream;
        guint flags = SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH;
        GBytes *body;
        GError *error = NULL;

        if (cancelled_by_session)
                flags |= SOUP_TEST_REQUEST_CANCEL_BY_SESSION;

        msg = soup_message_new_from_uri ("GET", base_uri);
        cancellable = g_cancellable_new ();
        istream = soup_test_request_send (session, msg, cancellable, flags, &error);
        g_assert_no_error (error);
        g_assert_nonnull (istream);

        /* If we use a new cancellable to read the stream
         * it shouldn't fail with cancelled error.
         */
        if (!reuse_cancellable) {
                g_object_unref (cancellable);
                cancellable = g_cancellable_new ();
        }
        ostream = g_memory_output_stream_new_resizable ();
        g_output_stream_splice (ostream, istream,
                                G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                cancellable, &error);

        if (reuse_cancellable || cancelled_by_session) {
                g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
                g_clear_error (&error);
        } else {
                g_assert_no_error (error);
                body = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream));
                g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "index");
                g_bytes_unref (body);
        }

        g_object_unref (cancellable);
        g_object_unref (ostream);
        g_object_unref (istream);
        g_object_unref (msg);
}

static void
do_cancel_after_send_request_tests (void)
{
        SoupSession *session;

        session = soup_test_session_new (NULL);
        do_one_cancel_after_send_request_test (session, TRUE, FALSE);
        do_one_cancel_after_send_request_test (session, FALSE, FALSE);
        do_one_cancel_after_send_request_test (session, FALSE, TRUE);
        soup_test_session_abort_unref (session);
}

static void
do_msg_flags_test (void)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", "http://foo.org");

	/* Flags are initially empty */
	g_assert_cmpuint (soup_message_get_flags (msg), ==, 0);
	g_assert_false (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT));

	/* Set a single flag */
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, SOUP_MESSAGE_NO_REDIRECT);
	g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT));
	g_assert_false (soup_message_query_flags (msg, SOUP_MESSAGE_NEW_CONNECTION));

	/* Add another flag */
	soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, (SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION));
	g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION));

	/* Add an existing flag */
	soup_message_add_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, (SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION));
        g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION));

	/* Remove a single flag */
	soup_message_remove_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, SOUP_MESSAGE_NO_REDIRECT);
        g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT));
        g_assert_false (soup_message_query_flags (msg, SOUP_MESSAGE_NEW_CONNECTION));

	/* Remove a non-existing flag */
	soup_message_remove_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, SOUP_MESSAGE_NO_REDIRECT);
        g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT));
        g_assert_false (soup_message_query_flags (msg, SOUP_MESSAGE_NEW_CONNECTION));

	/* Add a set of flags */
	soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_IDEMPOTENT | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, (SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_IDEMPOTENT | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE));
	g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_IDEMPOTENT | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE));

	/* Remove a set of flags */
	soup_message_remove_flags (msg, (SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_IDEMPOTENT));
	g_assert_cmpuint (soup_message_get_flags (msg), ==, (SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE));
	g_assert_true (soup_message_query_flags (msg, SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE));

	/* Remove all flags */
	soup_message_set_flags (msg, 0);
	g_assert_cmpuint (soup_message_get_flags (msg), ==, 0);
        g_assert_false (soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT | SOUP_MESSAGE_NEW_CONNECTION | SOUP_MESSAGE_IDEMPOTENT | SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE));

	g_object_unref (msg);
}

static void
do_connection_id_test (void)
{
        SoupSession *session = soup_test_session_new (NULL);
        SoupMessage *msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);

        /* Test that the ID is set for each new connection and that it is
         * cached after the message is completed */

        g_assert_cmpuint (soup_message_get_connection_id (msg), ==, 0);

        guint status = soup_test_session_send_message (session, msg);

        g_assert_cmpuint (status, ==, SOUP_STATUS_OK);
        g_assert_cmpuint (soup_message_get_connection_id (msg), ==, 1);

        status = soup_test_session_send_message (session, msg);

        g_assert_cmpuint (status, ==, SOUP_STATUS_OK);
        g_assert_cmpuint (soup_message_get_connection_id (msg), ==, 2);

	GUri *uri = g_uri_parse_relative (base_uri, "/redirect", SOUP_HTTP_URI_FLAGS, NULL);
	soup_message_set_uri (msg, uri);
        g_uri_unref (uri);

        status = soup_test_session_send_message (session, msg);

        g_assert_cmpuint (status, ==, SOUP_STATUS_OK);
        g_assert_cmpuint (soup_message_get_connection_id (msg), ==, 3);

        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

static void
do_remote_address_test (void)
{
        SoupSession *session;
        SoupMessage *msg1, *msg2;
        GBytes *body;

        session = soup_test_session_new (NULL);

        msg1 = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        g_assert_null (soup_message_get_remote_address (msg1));
        body = soup_test_session_async_send (session, msg1, NULL, NULL);
        g_assert_nonnull (soup_message_get_remote_address (msg1));
        g_bytes_unref (body);

        /* In case of reusing an idle conection, we still get a remote address */
        msg2 = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        g_assert_null (soup_message_get_remote_address (msg2));
        body = soup_test_session_async_send (session, msg2, NULL, NULL);
        g_assert_cmpuint (soup_message_get_connection_id (msg1), ==, soup_message_get_connection_id (msg2));
        g_assert_true (soup_message_get_remote_address (msg1) == soup_message_get_remote_address (msg2));
        g_bytes_unref (body);
        g_object_unref (msg2);

        /* We get the same one if we force a new connection */
        msg2 = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        soup_message_add_flags (msg2, SOUP_MESSAGE_NEW_CONNECTION);
        g_assert_null (soup_message_get_remote_address (msg2));
        body = soup_test_session_async_send (session, msg2, NULL, NULL);
        g_assert_nonnull (soup_message_get_remote_address (msg2));
        g_assert_cmpuint (soup_message_get_connection_id (msg1), !=, soup_message_get_connection_id (msg2));
        g_assert_true (soup_message_get_remote_address (msg1) == soup_message_get_remote_address (msg2));
        g_bytes_unref (body);
        g_object_unref (msg2);

        g_object_unref (msg1);
        soup_test_session_abort_unref (session);
}

static void
redirect_handler (SoupMessage *msg,
                  SoupSession *session)
{
        SoupMessage *new_msg;
        GBytes *body;

        new_msg = soup_message_new_from_uri ("GET", base_uri);
        body = soup_test_session_async_send (session, new_msg, NULL, NULL);
        g_assert_nonnull (body);
        g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "index");
        g_object_unref (new_msg);
        g_bytes_unref (body);
}

static void
do_new_request_on_redirect_test (void)
{
        SoupSession *session;
        GUri *uri;
        SoupMessage *msg;
        GBytes *body;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/redirect", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_signal_connect_after (msg, "got-body",
                                G_CALLBACK (redirect_handler),
                                session);
        body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);
        g_assert_cmpstr (g_bytes_get_data (body, NULL), ==, "index");

        g_bytes_unref (body);
        g_object_unref (msg);
        g_uri_unref (uri);
        soup_test_session_abort_unref (session);
}

typedef struct {
        SoupSession *session;
        GCancellable *cancellable;
        GBytes *body;
        guint64 connections[2];
        gboolean done;
} ConflictTestData;

static void
conflict_test_send_ready_cb (SoupSession      *session,
                             GAsyncResult     *result,
                             ConflictTestData *data)
{
        GInputStream *stream;
        SoupMessage *msg = soup_session_get_async_result_message (session, result);
        GError *error = NULL;

        stream = soup_session_send_finish (session, result, &error);
        if (stream) {
                guint status = soup_message_get_status (msg);

                soup_test_request_read_all (stream, NULL, NULL);
                g_object_unref (stream);

                if (status != SOUP_STATUS_CONFLICT) {
                        g_assert_cmpuint (status, ==, SOUP_STATUS_CREATED);
                        data->connections[1] = soup_message_get_connection_id (msg);
                        data->done = TRUE;
                }
        } else {
                g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
                g_error_free (error);
        }
}

static void
conflict_test_on_conflict_cb (SoupMessage      *msg,
                              ConflictTestData *data)
{
        SoupMessageHeaders *response_headers;
        SoupMessageHeaders *request_headers;
        const gchar *session_id;
        SoupMessage *new_msg;

        g_cancellable_cancel (data->cancellable);
        g_clear_object (&data->cancellable);

        data->connections[0] = soup_message_get_connection_id (msg);
        response_headers = soup_message_get_response_headers (msg);
        session_id = soup_message_headers_get_one (response_headers, "X-SoupTest-Session-Id");
        new_msg = soup_message_new_from_uri (SOUP_METHOD_PUT, soup_message_get_uri (msg));
        request_headers = soup_message_get_request_headers (new_msg);
        soup_message_headers_replace (request_headers, "X-SoupTest-Session-Id", session_id);

        data->cancellable = g_cancellable_new ();
        soup_message_set_request_body_from_bytes (new_msg, "text/plain", data->body);
        soup_session_send_async (data->session, new_msg, G_PRIORITY_DEFAULT, data->cancellable,
                                 (GAsyncReadyCallback)conflict_test_send_ready_cb, data);
        g_object_unref (new_msg);
}

static void
conflict_test_on_got_body_cb (SoupMessage      *msg,
                              ConflictTestData *data)
{
        if (soup_message_get_status (msg) == SOUP_STATUS_CONFLICT)
                conflict_test_on_conflict_cb (msg, data);
}

static void
do_new_request_on_conflict_test (void)
{
        GUri *uri;
        SoupMessage *msg;
        ConflictTestData data;
        static const char *body = "conflict test body";

        data.session = soup_test_session_new (NULL);
        data.cancellable = g_cancellable_new ();
        data.body = g_bytes_new_static (body, strlen (body));
        data.connections[0] = data.connections[1] = 0;
        data.done = FALSE;

        /* First try with restarting on got-headers */
        uri = g_uri_parse_relative (base_uri, "/session", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri (SOUP_METHOD_PUT, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", data.body);
        soup_message_add_status_code_handler (msg, "got-headers", SOUP_STATUS_CONFLICT,
                                              G_CALLBACK (conflict_test_on_conflict_cb),
                                              &data);
        soup_session_send_async (data.session, msg, G_PRIORITY_DEFAULT, data.cancellable,
                                 (GAsyncReadyCallback)conflict_test_send_ready_cb, &data);

        while (!data.done)
                g_main_context_iteration (NULL, TRUE);

        g_assert_cmpuint (data.connections[0], >, 0);
        g_assert_cmpuint (data.connections[1], >, 0);
        g_assert_cmpuint (data.connections[0], !=, data.connections[1]);

        g_object_unref (msg);
        g_object_unref (data.cancellable);

        data.cancellable = g_cancellable_new ();
        data.connections[0] = data.connections[1] = 0;
        data.done = FALSE;

        /* Now try with the restarting on got-body */
        msg = soup_message_new_from_uri (SOUP_METHOD_PUT, uri);
        soup_message_set_request_body_from_bytes (msg, "text/plain", data.body);
        g_signal_connect (msg, "got-body", G_CALLBACK (conflict_test_on_got_body_cb), &data);
        soup_session_send_async (data.session, msg, G_PRIORITY_DEFAULT, data.cancellable,
                                 (GAsyncReadyCallback)conflict_test_send_ready_cb, &data);

        while (!data.done)
                g_main_context_iteration (NULL, TRUE);

        g_assert_cmpuint (data.connections[0], >, 0);
        g_assert_cmpuint (data.connections[1], >, 0);
        g_assert_cmpuint (data.connections[0], ==, data.connections[1]);

        g_object_unref (msg);
        g_object_unref (data.cancellable);
        g_uri_unref (uri);
        g_bytes_unref (data.body);
        soup_test_session_abort_unref (data.session);
}

static void
wrote_informational_check_content_length (SoupServerMessage *msg,
                                          gpointer           user_data)
{
        SoupMessageHeaders *response_headers;

        response_headers = soup_server_message_get_response_headers (msg);
        g_assert_null (soup_message_headers_get_one (response_headers, "Content-Length"));
}

static void
upgrade_server_check_content_length_callback (SoupServer        *server,
                                              SoupServerMessage *msg,
                                              const char        *path,
                                              GHashTable        *query,
                                              gpointer           data)
{
        SoupMessageHeaders *request_headers;

        if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
                soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
                return;
        }

        soup_server_message_set_status (msg, SOUP_STATUS_SWITCHING_PROTOCOLS, NULL);

        request_headers = soup_server_message_get_request_headers (msg);
        soup_message_headers_append (request_headers, "Upgrade", "ECHO");
        soup_message_headers_append (request_headers, "Connection", "upgrade");

        g_signal_connect (msg, "wrote-informational",
                          G_CALLBACK (wrote_informational_check_content_length), NULL);
}

static void
switching_protocols_check_length (SoupMessage *msg,
                                  gpointer     user_data)
{
        SoupMessageHeaders *response_headers;

        response_headers = soup_message_get_response_headers (msg);
        g_assert_null (soup_message_headers_get_one (response_headers, "Content-Length"));
}

static void
do_response_informational_content_length_test (void)
{
        SoupServer *server;
        SoupSession *session;
        SoupMessage *msg;
        SoupMessageHeaders *request_headers;

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
        soup_server_add_handler (server, NULL, upgrade_server_check_content_length_callback, NULL, NULL);

        session = soup_test_session_new (NULL);
        msg = soup_message_new_from_uri ("GET", base_uri);
        request_headers = soup_message_get_request_headers (msg);
        soup_message_headers_append (request_headers, "Upgrade", "echo");
        soup_message_headers_append (request_headers, "Connection", "upgrade");

        soup_message_add_status_code_handler (msg, "got-informational",
                                              SOUP_STATUS_SWITCHING_PROTOCOLS,
                                              G_CALLBACK (switching_protocols_check_length), NULL);

        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        soup_test_session_abort_unref (session);
        soup_test_server_quit_unref (server);
}

static void
do_invalid_utf8_headers_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        GUri *uri;
        SoupMessageHeaders *headers;
        guint status;
        const char *header_value;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/invalid_utf8_headers", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);

        status = soup_test_session_send_message (session, msg);
        g_assert_cmpuint (status, ==, SOUP_STATUS_OK);

        headers = soup_message_get_response_headers (msg);
        header_value = soup_message_headers_get_one (headers, "InvalidValue");
        g_assert_nonnull (header_value);
        g_assert_true (g_utf8_validate (header_value, -1, NULL));

        g_object_unref (msg);
        g_uri_unref (uri);
        soup_test_session_abort_unref (session);
}

static void
do_io_pollable_test (void)
{
        SoupSession *session;
        SoupMessage *msg;
        GPollableInputStream *stream;
        GUri *uri;
        guint8 buffer[4096];
        goffset length;
        gssize read_total = 0;
        gssize nread;
        GError *error = NULL;

        session = soup_test_session_new (NULL);
        uri = g_uri_parse_relative (base_uri, "/large-body", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        stream = G_POLLABLE_INPUT_STREAM (soup_session_send (session, msg, NULL, NULL));
        length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));

        g_assert_cmpuint (length, ==, 64 * 1024 + 32);
        g_assert_true (g_pollable_input_stream_can_poll (stream));

        while (read_total < length) {
                if (g_pollable_input_stream_is_readable (stream)) {
                        nread = g_pollable_input_stream_read_nonblocking (stream, buffer, 4096, NULL, &error);
                        if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
                                g_clear_error (&error);
                                g_usleep (10000);
                                continue;
                        }
                        g_assert_no_error (error);
                        g_assert_cmpint (nread, >, 0);
                        read_total += nread;
                } else {
                        g_usleep (10000);
                }
        }

        g_assert_true (g_pollable_input_stream_is_readable (stream));
        g_assert_cmpuint (g_pollable_input_stream_read_nonblocking (stream, buffer, 4096, NULL, NULL), ==, 0);

        g_object_unref (stream);
        g_object_unref (msg);
        g_uri_unref (uri);
        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	SoupAuthDomain *auth_domain;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	auth_domain = soup_auth_domain_basic_new (
		"realm", "misc-test",
		"auth-callback", auth_callback,
		NULL);
        soup_auth_domain_add_path (auth_domain, "/auth");
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	g_test_add_func ("/misc/bigheader", do_host_big_header);
	g_test_add_func ("/misc/host", do_host_test);
	g_test_add_func ("/misc/callback-unref/msg", do_callback_unref_test);
	g_test_add_func ("/misc/msg-reuse", do_msg_reuse_test);
	g_test_add_func ("/misc/early-abort/msg", do_early_abort_test);
	g_test_add_func ("/misc/accept-language", do_accept_language_test);
	g_test_add_func ("/misc/cancel-while-reading/msg", do_cancel_while_reading_test);
	g_test_add_func ("/misc/cancel-while-reading/req/immediate", do_cancel_while_reading_immediate_req_test);
	g_test_add_func ("/misc/cancel-while-reading/req/delayed", do_cancel_while_reading_delayed_req_test);
	g_test_add_func ("/misc/cancel-while-reading/req/preemptive", do_cancel_while_reading_preemptive_req_test);
        g_test_add_func ("/misc/cancel-after-send-request", do_cancel_after_send_request_tests);
	g_test_add_func ("/misc/msg-flags", do_msg_flags_test);
        g_test_add_func ("/misc/connection-id", do_connection_id_test);
        g_test_add_func ("/misc/remote-address", do_remote_address_test);
        g_test_add_func ("/misc/new-request-on-redirect", do_new_request_on_redirect_test);
        g_test_add_func ("/misc/new-request-on-conflict", do_new_request_on_conflict_test);
        g_test_add_func ("/misc/response/informational/content-length", do_response_informational_content_length_test);
        g_test_add_func ("/misc/invalid-utf8-headers", do_invalid_utf8_headers_test);
        g_test_add_func ("/misc/io-pollable", do_io_pollable_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
