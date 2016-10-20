/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

/* Kill SoupRequester-related deprecation warnings */
#define SOUP_VERSION_MIN_REQUIRED SOUP_VERSION_2_40

#include "test-utils.h"

SoupServer *server;
GMainLoop *loop;
char buf[1024];

SoupBuffer *response, *auth_response;

#define REDIRECT_HTML_BODY "<html><body>Try again</body></html>\r\n"
#define AUTH_HTML_BODY "<html><body>Unauthorized</body></html>\r\n"

typedef enum {
	NO_CANCEL,
	SYNC_CANCEL,
	PAUSE_AND_CANCEL_ON_IDLE
} CancelPolicy;

static gboolean
slow_finish_message (gpointer msg)
{
	SoupServer *server = g_object_get_data (G_OBJECT (msg), "server");

	soup_server_unpause_message (server, msg);
	return FALSE;
}

static void
slow_pause_message (SoupMessage *msg, gpointer server)
{
	soup_server_pause_message (server, msg);
	soup_add_timeout (soup_server_get_async_context (server),
			  1000, slow_finish_message, msg);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	gboolean chunked = FALSE;
	int i;

	if (strcmp (path, "/auth") == 0) {
		soup_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED);
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   AUTH_HTML_BODY,
					   strlen (AUTH_HTML_BODY));
		soup_message_headers_append (msg->response_headers,
					     "WWW-Authenticate",
					     "Basic: realm=\"requester-test\"");
		return;
	} else if (strcmp (path, "/foo") == 0) {
		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		/* Make the response HTML so if we sniff that instead of the
		 * real body, we'll notice.
		 */
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_STATIC,
					   REDIRECT_HTML_BODY,
					   strlen (REDIRECT_HTML_BODY));
		return;
	} else if (strcmp (path, "/chunked") == 0) {
		chunked = TRUE;
	} else if (strcmp (path, "/non-persistent") == 0) {
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");
	} else if (!strcmp (path, "/slow")) {
		g_object_set_data (G_OBJECT (msg), "server", server);
		g_signal_connect (msg, "wrote-headers",
				  G_CALLBACK (slow_pause_message), server);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);

	if (chunked) {
		soup_message_headers_set_encoding (msg->response_headers,
						   SOUP_ENCODING_CHUNKED);

		for (i = 0; i < response->length; i += 8192) {
			SoupBuffer *tmp;

			tmp = soup_buffer_new_subbuffer (response, i,
							 MIN (8192, response->length - i));
			soup_message_body_append_buffer (msg->response_body, tmp);
			soup_buffer_free (tmp);
		}
		soup_message_body_complete (msg->response_body);
	} else
		soup_message_body_append_buffer (msg->response_body, response);
}

typedef struct {
	GString *body;
	gboolean cancel;
} RequestData;

static void
stream_closed (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	GError *error = NULL;

	g_input_stream_close_finish (stream, res, &error);
	g_assert_no_error (error);
	g_main_loop_quit (loop);
	g_object_unref (stream);
}

static void
test_read_ready (GObject *source, GAsyncResult *res, gpointer user_data)
{
	GInputStream *stream = G_INPUT_STREAM (source);
	RequestData *data = user_data;
	GString *body = data->body;
	GError *error = NULL;
	gsize nread;

	nread = g_input_stream_read_finish (stream, res, &error);
	if (nread == -1) {
		g_assert_no_error (error);
		g_error_free (error);
		g_input_stream_close (stream, NULL, NULL);
		g_object_unref (stream);
		g_main_loop_quit (loop);
		return;
	} else if (nread == 0) {
		g_input_stream_close_async (stream,
					    G_PRIORITY_DEFAULT, NULL,
					    stream_closed, NULL);
		return;
	}

	g_string_append_len (body, buf, nread);
	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
auth_test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	RequestData *data = user_data;
	GInputStream *stream;
	GError *error = NULL;
	SoupMessage *msg;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (!stream) {
		g_assert_no_error (error);
		g_clear_error (&error);
		g_main_loop_quit (loop);
		return;
	}

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (source));
	soup_test_assert_message_status (msg, SOUP_STATUS_UNAUTHORIZED);
	g_object_unref (msg);

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	g_assert_cmpstr (content_type, ==, "text/html");

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
test_sent (GObject *source, GAsyncResult *res, gpointer user_data)
{
	RequestData *data = user_data;
	GInputStream *stream;
	GError *error = NULL;
	const char *content_type;

	stream = soup_request_send_finish (SOUP_REQUEST (source), res, &error);
	if (data->cancel) {
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
		g_clear_error (&error);
		g_main_loop_quit (loop);
		return;
	} else {
		g_assert_no_error (error);
		if (!stream) {
			g_main_loop_quit (loop);
			g_clear_error (&error);
			return;
		}
	}

	content_type = soup_request_get_content_type (SOUP_REQUEST (source));
	g_assert_cmpstr (content_type, ==, "text/plain");

	g_input_stream_read_async (stream, buf, sizeof (buf),
				   G_PRIORITY_DEFAULT, NULL,
				   test_read_ready, data);
}

static void
cancel_message (SoupMessage *msg, gpointer session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_FORBIDDEN);
}

typedef struct {
	SoupMessage *msg;
	SoupSession *session;
} CancelData;

static gboolean
cancel_message_idle (CancelData *data)
{
	cancel_message (data->msg, data->session);
	return FALSE;
}

static void
pause_and_cancel_message (SoupMessage *msg, gpointer session)
{
	CancelData *data = g_new (CancelData, 1);
	GSource *source = g_idle_source_new ();

	soup_session_pause_message (session, msg);
	data->msg = msg;
	data->session = session;
	g_source_set_callback (source, (GSourceFunc)cancel_message_idle, data, g_free);
	g_source_attach (source, soup_session_get_async_context (session));
	g_source_unref (source);
}

static void
request_started (SoupSession *session, SoupMessage *msg,
		 SoupSocket *socket, gpointer user_data)
{
	SoupSocket **save_socket = user_data;

	g_clear_object (save_socket);
	*save_socket = g_object_ref (socket);
}

static void
do_async_test (SoupSession *session, SoupURI *uri,
	       GAsyncReadyCallback callback, guint expected_status,
	       SoupBuffer *expected_response,
	       gboolean persistent, CancelPolicy cancel_policy)
{
	SoupRequester *requester;
	SoupRequest *request;
	guint started_id;
	SoupSocket *socket = NULL;
	SoupMessage *msg;
	RequestData data;

	if (SOUP_IS_SESSION_ASYNC (session))
		requester = SOUP_REQUESTER (soup_session_get_feature (session, SOUP_TYPE_REQUESTER));
	else
		requester = NULL;

	data.body = g_string_new (NULL);
	data.cancel = cancel_policy != NO_CANCEL;
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	switch (cancel_policy) {
	case SYNC_CANCEL:
		g_signal_connect (msg, "got-headers",
				  G_CALLBACK (cancel_message), session);
		break;
	case PAUSE_AND_CANCEL_ON_IDLE:
		g_signal_connect (msg, "got-headers",
				  G_CALLBACK (pause_and_cancel_message), session);
		break;
	case NO_CANCEL:
		break;
	}

	started_id = g_signal_connect (session, "request-started",
				       G_CALLBACK (request_started),
				       &socket);

	soup_request_send_async (request, NULL, callback, &data);
	g_object_unref (request);

	loop = g_main_loop_new (soup_session_get_async_context (session), TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	g_signal_handler_disconnect (session, started_id);

	soup_test_assert_message_status (msg, expected_status);
	g_object_unref (msg);

	if (expected_response) {
		soup_assert_cmpmem (data.body->str, data.body->len,
				    expected_response->data, expected_response->length);
	} else
		g_assert_cmpint (data.body->len, ==, 0);

	if (persistent)
		g_assert_true (soup_socket_is_connected (socket));
	else
		g_assert_false (soup_socket_is_connected (socket));

	g_object_unref (socket);

	g_string_free (data.body, TRUE);
}

static void
do_test_for_thread_and_context (SoupSession *session, SoupURI *base_uri)
{
	SoupRequester *requester;
	SoupURI *uri;

	if (SOUP_IS_SESSION_ASYNC (session)) {
		requester = soup_requester_new ();
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
		g_object_unref (requester);
	}
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

	debug_printf (1, "    basic test\n");
	do_async_test (session, base_uri, test_sent,
		       SOUP_STATUS_OK, response,
		       TRUE, NO_CANCEL);

	debug_printf (1, "    chunked test\n");
	uri = soup_uri_new_with_base (base_uri, "/chunked");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_OK, response,
		       TRUE, NO_CANCEL);
	soup_uri_free (uri);

	debug_printf (1, "    auth test\n");
	uri = soup_uri_new_with_base (base_uri, "/auth");
	do_async_test (session, uri, auth_test_sent,
		       SOUP_STATUS_UNAUTHORIZED, auth_response,
		       TRUE, NO_CANCEL);
	soup_uri_free (uri);

	debug_printf (1, "    non-persistent test\n");
	uri = soup_uri_new_with_base (base_uri, "/non-persistent");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_OK, response,
		       FALSE, NO_CANCEL);
	soup_uri_free (uri);

	debug_printf (1, "    cancellation test\n");
	uri = soup_uri_new_with_base (base_uri, "/");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_FORBIDDEN, NULL,
		       FALSE, SYNC_CANCEL);
	soup_uri_free (uri);

	debug_printf (1, "    cancellation after paused test\n");
	uri = soup_uri_new_with_base (base_uri, "/");
	do_async_test (session, uri, test_sent,
		       SOUP_STATUS_FORBIDDEN, NULL,
		       FALSE, PAUSE_AND_CANCEL_ON_IDLE);
	soup_uri_free (uri);
}

static void
do_simple_plain_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;

	g_test_bug ("653707");

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_simple_async_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;

	g_test_bug ("653707");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_test_with_context_and_type (SoupURI *uri, gboolean plain_session)
{
	GMainContext *async_context;
	SoupSession *session;

	g_test_bug ("653707");

	async_context = g_main_context_new ();
	g_main_context_push_thread_default (async_context);

	session = soup_test_session_new (plain_session ? SOUP_TYPE_SESSION : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_ASYNC_CONTEXT, async_context,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);

	do_test_for_thread_and_context (session, uri);
	soup_test_session_abort_unref (session);

	g_main_context_pop_thread_default (async_context);
	g_main_context_unref (async_context);
}

static void
do_async_test_with_context (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;

	do_test_with_context_and_type (uri, FALSE);
}

static void
do_plain_test_with_context (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;

	do_test_with_context_and_type (uri, TRUE);
}

static gpointer
async_test_thread (gpointer uri)
{
	do_test_with_context_and_type (uri, TRUE);
	return NULL;
}

static gpointer
plain_test_thread (gpointer uri)
{
	do_test_with_context_and_type (uri, FALSE);
	return NULL;
}

static void
do_async_test_in_thread (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	GThread *thread;

	thread = g_thread_new ("do_async_test_in_thread",
			       async_test_thread,
			       (gpointer)uri);
	g_thread_join (thread);
}

static void
do_plain_test_in_thread (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	GThread *thread;

	thread = g_thread_new ("do_plain_test_in_thread",
			       plain_test_thread,
			       (gpointer)uri);
	g_thread_join (thread);
}

static void
do_sync_request (SoupSession *session, SoupRequest *request,
		 guint expected_status, SoupBuffer *expected_response,
		 gboolean persistent, CancelPolicy cancel_policy)
{
	GInputStream *in;
	SoupMessage *msg;
	GError *error = NULL;
	GString *body;
	char buf[1024];
	gssize nread;
	guint started_id;
	SoupSocket *socket = NULL;

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	if (cancel_policy == SYNC_CANCEL) {
		g_signal_connect (msg, "got-headers",
				  G_CALLBACK (cancel_message), session);
	}

	started_id = g_signal_connect (session, "request-started",
				       G_CALLBACK (request_started),
				       &socket);

	in = soup_request_send (request, NULL, &error);
	g_signal_handler_disconnect (session, started_id);
	if (cancel_policy == SYNC_CANCEL) {
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
		g_clear_error (&error);
		g_object_unref (msg);
		g_object_unref (socket);
		return;
	} else if (!in) {
		g_assert_no_error (error);
		g_clear_error (&error);
		g_object_unref (msg);
		g_object_unref (socket);
		return;
	}

	soup_test_assert_message_status (msg, expected_status);
	g_object_unref (msg);

	body = g_string_new (NULL);
	do {
		nread = g_input_stream_read (in, buf, sizeof (buf),
					     NULL, &error);
		g_assert_no_error (error);
		if (nread == -1) {
			g_clear_error (&error);
			break;
		}
		g_string_append_len (body, buf, nread);
	} while (nread > 0);

	g_input_stream_close (in, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (in);

	if (expected_response) {
		soup_assert_cmpmem (body->str, body->len,
				    expected_response->data, expected_response->length);
	} else
		g_assert_cmpint (body->len, ==, 0);

	if (persistent)
		g_assert_true (soup_socket_is_connected (socket));
	else
		g_assert_false (soup_socket_is_connected (socket));
	g_object_unref (socket);

	g_string_free (body, TRUE);
}

static void
do_sync_tests_for_session (SoupSession *session, SoupURI *base_uri)
{
	SoupRequester *requester;
	SoupRequest *request;
	SoupURI *uri;

	requester = SOUP_REQUESTER (soup_session_get_feature (session, SOUP_TYPE_REQUESTER));

	uri = soup_uri_copy (base_uri);

	debug_printf (1, "    basic test\n");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 TRUE, NO_CANCEL);
	g_object_unref (request);

	debug_printf (1, "    chunked test\n");
	soup_uri_set_path (uri, "/chunked");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 TRUE, NO_CANCEL);
	g_object_unref (request);

	debug_printf (1, "    auth test\n");
	soup_uri_set_path (uri, "/auth");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_UNAUTHORIZED, auth_response,
			 TRUE, NO_CANCEL);
	g_object_unref (request);

	debug_printf (1, "    non-persistent test\n");
	soup_uri_set_path (uri, "/non-persistent");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_OK, response,
			 FALSE, NO_CANCEL);
	g_object_unref (request);

	debug_printf (1, "    cancel test\n");
	soup_uri_set_path (uri, "/");
	if (requester)
		request = soup_requester_request_uri (requester, uri, NULL);
	else
		request = soup_session_request_uri (session, uri, NULL);
	do_sync_request (session, request,
			 SOUP_STATUS_FORBIDDEN, NULL,
			 TRUE, SYNC_CANCEL);
	g_object_unref (request);

	soup_uri_free (uri);
}

static void
do_plain_sync_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_sync_tests_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_sync_sync_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;
	SoupRequester *requester;

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
	requester = soup_requester_new ();
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (requester));
	g_object_unref (requester);
	do_sync_tests_for_session (session, uri);
	soup_test_session_abort_unref (session);
}

static void
do_null_char_request (SoupSession *session, const char *encoded_data,
		      const char *expected_data, int expected_len)
{
	GError *error = NULL;
	GInputStream *stream;
	SoupRequest *request;
	SoupURI *uri;
	char *uri_string, buf[256];
	gsize nread;

	uri_string = g_strdup_printf ("data:text/html,%s", encoded_data);
	uri = soup_uri_new (uri_string);
	g_free (uri_string);

	request = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (request, NULL, 0, &error);
	g_assert_no_error (error);
	if (error) {
		g_error_free (error);
		g_object_unref (request);
		soup_uri_free (uri);
		return;
	}

	g_input_stream_read_all (stream, buf, sizeof (buf), &nread, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	soup_test_request_close_stream (request, stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	soup_assert_cmpmem (buf, nread, expected_data, expected_len);

	g_object_unref (stream);
	g_object_unref (request);
	soup_uri_free (uri);
}

static void
do_null_char_test_for_session (SoupSession *session)
{
	static struct {
		const char *encoded_data;
		const char *expected_data;
		int expected_len;
	} test_cases[] = {
		{ "%3Cscript%3Ea%3D'%00'%3C%2Fscript%3E", "<script>a='\0'</script>", 22 },
		{ "%00%3Cscript%3Ea%3D42%3C%2Fscript%3E", "\0<script>a=42</script>", 22 },
		{ "%3Cscript%3E%00%3Cbr%2F%3E%3C%2Fscript%3E%00", "<script>\0<br/></script>\0", 24 },
	};
	static int num_test_cases = G_N_ELEMENTS(test_cases);
	int i;

	for (i = 0; i < num_test_cases; i++) {
		do_null_char_request (session, test_cases[i].encoded_data,
				      test_cases[i].expected_data, test_cases[i].expected_len);
	}
}

static void
do_plain_null_char_test (void)
{
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_null_char_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
do_async_null_char_test (void)
{
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_null_char_test_for_session (session);
	soup_test_session_abort_unref (session);
}

static void
close_test_msg_finished (SoupMessage *msg,
			 gpointer     user_data)
{
	gboolean *finished = user_data;

	*finished = TRUE;
}

static void
do_close_test_for_session (SoupSession *session,
			   SoupURI     *uri)
{
	GError *error = NULL;
	GInputStream *stream;
	SoupRequest *request;
	guint64 start, end;
	GCancellable *cancellable;
	SoupMessage *msg;
	gboolean finished = FALSE;

	debug_printf (1, "    normal close\n");

	request = soup_session_request_uri (session, uri, NULL);
	stream = soup_test_request_send (request, NULL, 0, &error);
	g_assert_no_error (error);
	if (error) {
		g_error_free (error);
		g_object_unref (request);
		return;
	}

	start = g_get_monotonic_time ();
	soup_test_request_close_stream (request, stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	end = g_get_monotonic_time ();

	g_assert_cmpint (end - start, <=, 500000);

	g_object_unref (stream);
	g_object_unref (request);


	debug_printf (1, "    error close\n");

	request = soup_session_request_uri (session, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));
	g_signal_connect (msg, "finished", G_CALLBACK (close_test_msg_finished), &finished);
	g_object_unref (msg);

	stream = soup_test_request_send (request, NULL, 0, &error);
	g_assert_no_error (error);
	if (error) {
		g_error_free (error);
		g_object_unref (request);
		return;
	}

	cancellable = g_cancellable_new ();
	g_cancellable_cancel (cancellable);
	soup_test_request_close_stream (request, stream, cancellable, &error);
	if (error)
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
	g_clear_error (&error);
	g_object_unref (cancellable);

	g_assert_true (finished);

	g_object_unref (stream);
	g_object_unref (request);
}

static void
do_async_close_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;
	SoupURI *slow_uri;

	g_test_bug ("695652");
	g_test_bug ("711260");

	slow_uri = soup_uri_new_with_base ((SoupURI *)uri, "/slow");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_close_test_for_session (session, slow_uri);
	soup_test_session_abort_unref (session);

	soup_uri_free (slow_uri);
}

static void
do_sync_close_test (gconstpointer data)
{
	SoupURI *uri = (SoupURI *)data;
	SoupSession *session;
	SoupURI *slow_uri;

	g_test_bug ("695652");
	g_test_bug ("711260");

	slow_uri = soup_uri_new_with_base ((SoupURI *)uri, "/slow");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	do_close_test_for_session (session, slow_uri);
	soup_test_session_abort_unref (session);

	soup_uri_free (slow_uri);
}

int
main (int argc, char **argv)
{
	SoupURI *uri;
	int ret;

	test_init (argc, argv, NULL);

	response = soup_test_get_index ();
	auth_response = soup_buffer_new (SOUP_MEMORY_STATIC,
					 AUTH_HTML_BODY,
					 strlen (AUTH_HTML_BODY));

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	uri = soup_test_server_get_uri (server, "http", NULL);
	soup_uri_set_path (uri, "/foo");

	g_test_add_data_func ("/requester/simple/SoupSession", uri, do_simple_plain_test);
	g_test_add_data_func ("/requester/simple/SoupSessionAsync", uri, do_simple_async_test);
	g_test_add_data_func ("/requester/threaded/SoupSession", uri, do_plain_test_in_thread);
	g_test_add_data_func ("/requester/threaded/SoupSessionAsync", uri, do_async_test_in_thread);
	g_test_add_data_func ("/requester/context/SoupSession", uri, do_plain_test_with_context);
	g_test_add_data_func ("/requester/context/SoupSessionAsync", uri, do_async_test_with_context);
	g_test_add_data_func ("/requester/sync/SoupSession", uri, do_plain_sync_test);
	g_test_add_data_func ("/requester/sync/SoupSessionSync", uri, do_sync_sync_test);
	g_test_add_func ("/requester/null-char/SoupSession", do_plain_null_char_test);
	g_test_add_func ("/requester/null-char/SoupSessionAsync", do_async_null_char_test);
	g_test_add_data_func ("/requester/close/SoupSessionAsync", uri, do_async_close_test);
	g_test_add_data_func ("/requester/close/SoupSessionSync", uri, do_sync_close_test);

	ret = g_test_run ();

	soup_uri_free (uri);
	soup_buffer_free (auth_response);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
