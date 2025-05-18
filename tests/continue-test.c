/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#include "test-utils.h"

#define SHORT_BODY "This is a test.\r\n"
#define LONG_BODY (SHORT_BODY SHORT_BODY)

#define MAX_POST_LENGTH (sizeof (SHORT_BODY))

static GUri *base_uri;
static GSList *events;

static void
client_event (SoupMessage *msg,
	      const char  *message)
{
	char *data = g_strdup_printf ("client-%s", message);

	debug_printf (2, "  %s", data);
	debug_printf (2, "\n");

	events = g_slist_append (events, data);
}

static void
server_event (SoupServerMessage *msg,
	      const char        *message)
{
	char *data = g_strdup_printf ("server-%s", message);
	gboolean record_status =
		(!strcmp (data, "server-wrote_headers") ||
		 !strcmp (data, "server-wrote_informational"));
	const char *reason_phrase = soup_server_message_get_reason_phrase (msg);
	guint status_code = soup_server_message_get_status (msg);

	debug_printf (2, "  %s", data);
	if (record_status)
		debug_printf (2, " (%s)", reason_phrase);
	debug_printf (2, "\n");

	events = g_slist_append (events, data);
	if (record_status)
		events = g_slist_append (events, GUINT_TO_POINTER (status_code));
}

#define CLIENT_EVENT_HANDLER(name)		\
static void					\
client_##name (SoupMessage *msg, gpointer side)	\
{						\
	client_event (msg, #name);		\
}

#define SERVER_EVENT_HANDLER(name)		\
static void					\
server_##name (SoupServerMessage *msg, gpointer side)	\
{						\
	server_event (msg, #name);		\
}

CLIENT_EVENT_HANDLER (got_informational)
CLIENT_EVENT_HANDLER (got_headers)
CLIENT_EVENT_HANDLER (got_body)
CLIENT_EVENT_HANDLER (wrote_headers)
CLIENT_EVENT_HANDLER (wrote_body)
CLIENT_EVENT_HANDLER (finished)

SERVER_EVENT_HANDLER (got_headers)
SERVER_EVENT_HANDLER (got_body)
SERVER_EVENT_HANDLER (wrote_informational)
SERVER_EVENT_HANDLER (wrote_headers)
SERVER_EVENT_HANDLER (wrote_body)
SERVER_EVENT_HANDLER (finished)

static void
restarted (SoupMessage *msg,
           GBytes      *body)
{
        soup_message_set_request_body_from_bytes (msg, "text/plain", body);
}

static void
do_message (const char *path, gboolean long_body,
	    gboolean expect_continue, gboolean auth,
	    ...)
{
	SoupSession *session;
	SoupMessage *msg;
	const char *body;
	GUri *uri, *msg_uri;
	va_list ap;
	const char *expected_event;
	char *actual_event;
	int expected_status, actual_status;
	GBytes *request_body;
	GBytes *response_body;

	if (auth)
                uri = soup_uri_copy (base_uri, SOUP_URI_USER, "user", SOUP_URI_PASSWORD, "pass", SOUP_URI_NONE);
        else
                uri = g_uri_ref (base_uri);

        msg_uri = g_uri_parse_relative (uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("POST", msg_uri);
	g_uri_unref (uri);
	g_uri_unref (msg_uri);

	body = long_body ? LONG_BODY : SHORT_BODY;
	request_body = g_bytes_new_static (body, strlen (body));
	soup_message_set_request_body_from_bytes (msg, "text/plain", request_body);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Connection", "close");
	if (expect_continue) {
		soup_message_headers_set_expectations (soup_message_get_request_headers (msg),
						       SOUP_EXPECTATION_CONTINUE);
	}

	g_signal_connect (msg, "got-informational",
			  G_CALLBACK (client_got_informational), NULL);
	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (client_got_headers), NULL);
	g_signal_connect (msg, "got-body",
			  G_CALLBACK (client_got_body), NULL);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (client_wrote_headers), NULL);
	g_signal_connect (msg, "wrote-body",
			  G_CALLBACK (client_wrote_body), NULL);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (client_finished), NULL);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (restarted), request_body);

	events = NULL;
	session = soup_test_session_new (NULL);
        g_assert_true (SOUP_IS_MESSAGE (msg));
	response_body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_true (SOUP_IS_MESSAGE (msg));
	soup_test_session_abort_unref (session);
        g_assert_true (SOUP_IS_MESSAGE (msg));

	va_start (ap, auth);
	while ((expected_event = va_arg (ap, const char *))) {

		if (!events) {
			soup_test_assert (events != NULL,
					  "Expected '%s', got end of list",
					  expected_event);
			continue;
		} else {
			actual_event = events->data;
			g_assert_cmpstr (expected_event, ==, actual_event);
			events = g_slist_delete_link (events, events);
		}

		if (!strcmp (expected_event, "server-wrote_headers") ||
		    !strcmp (expected_event, "server-wrote_informational"))
			expected_status = va_arg (ap, int);
		else
			expected_status = -1;
		if (!strcmp (actual_event, "server-wrote_headers") ||
		    !strcmp (actual_event, "server-wrote_informational")) {
			actual_status = GPOINTER_TO_INT (events->data);
			events = g_slist_delete_link (events, events);
		} else
			expected_status = -1;

		if (expected_status != -1 && actual_status != -1 &&
		    expected_status != actual_status) {
			soup_test_assert (expected_status == actual_status,
					  "Expected status '%s', got '%s'",
					  soup_status_get_phrase (expected_status),
					  soup_status_get_phrase (actual_status));
		}

		g_free (actual_event);
	}
	va_end (ap);
	while (events) {
		actual_event = events->data;
		soup_test_assert (events == NULL,
				  "Expected to be done, got '%s'", actual_event);
		events = g_slist_delete_link (events, events);

		if (!strcmp (actual_event, "server-wrote_headers") ||
		    !strcmp (actual_event, "server-wrote_informational"))
			events = g_slist_delete_link (events, events);
	}
	g_bytes_unref (request_body);
	g_bytes_unref (response_body);
	g_object_unref (msg);
}

static void
do_test_unauth_short_noexpect_nopass (void)
{
	do_message ("/unauth", FALSE, FALSE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_unauth_long_noexpect_nopass (void)
{
	do_message ("/unauth", TRUE, FALSE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_unauth_short_expect_nopass (void)
{
	do_message ("/unauth", FALSE, TRUE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_informational", SOUP_STATUS_CONTINUE,
		    "client-got_informational",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_unauth_long_expect_nopass (void)
{
	do_message ("/unauth", TRUE, TRUE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_short_noexpect_nopass (void)
{
	do_message ("/auth", FALSE, FALSE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_long_noexpect_nopass (void)
{
	do_message ("/auth", TRUE, FALSE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_short_expect_nopass (void)
{
	do_message ("/auth", FALSE, TRUE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_long_expect_nopass (void)
{
	do_message ("/auth", TRUE, TRUE, FALSE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_short_noexpect_pass (void)
{
	do_message ("/auth", FALSE, FALSE, TRUE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_long_noexpect_pass (void)
{
	do_message ("/auth", TRUE, FALSE, TRUE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_short_expect_pass (void)
{
	do_message ("/auth", FALSE, TRUE, TRUE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_informational", SOUP_STATUS_CONTINUE,
		    "client-got_informational",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
		    "client-wrote_body",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}

static void
do_test_auth_long_expect_pass (void)
{
	do_message ("/auth", TRUE, TRUE, TRUE,
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "server-got_headers",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-finished",
		    NULL);
}


/* SERVER */

static void
_server_got_headers (SoupServerMessage *msg,
		     gpointer           server)
{
	guint status_code;
	SoupMessageHeaders *request_headers;

	status_code = soup_server_message_get_status (msg);
	/* FIXME */
	if (status_code != SOUP_STATUS_CONTINUE && status_code != 0)
		return;

	request_headers = soup_server_message_get_request_headers (msg);
	if (soup_message_headers_get_expectations (request_headers) &
	    SOUP_EXPECTATION_CONTINUE) {
		const char *length;

		length = soup_message_headers_get_one (request_headers,
						       "Content-Length");
		if (length && atoi (length) > MAX_POST_LENGTH) {
			SoupMessageHeaders *response_headers;

			response_headers = soup_server_message_get_response_headers (msg);
			soup_server_message_set_status (msg, SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE, NULL);
			soup_message_headers_append (response_headers, "Connection", "close");
		}
	}
}

static void
request_started (SoupServer        *server,
		 SoupServerMessage *msg,
		 gpointer           user_data)
{
	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (_server_got_headers), server);

	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (server_got_headers), NULL);
	g_signal_connect (msg, "got-body",
			  G_CALLBACK (server_got_body), NULL);
	g_signal_connect (msg, "wrote-informational",
			  G_CALLBACK (server_wrote_informational), NULL);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (server_wrote_headers), NULL);
	g_signal_connect (msg, "wrote-body",
			  G_CALLBACK (server_wrote_body), NULL);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (server_finished), NULL);
}

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer user_data)
{
	return !strcmp (username, "user") && !strcmp (password, "pass");
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	SoupMessageHeaders *response_headers;
	SoupMessageBody *request_body;

	response_headers = soup_server_message_get_response_headers (msg);
	request_body = soup_server_message_get_request_body (msg);
	if (soup_server_message_get_method (msg) != SOUP_METHOD_POST) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		soup_message_headers_append (response_headers, "Connection", "close");
	} else if (request_body->length > MAX_POST_LENGTH) {
		soup_server_message_set_status (msg, SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE, NULL);
		soup_message_headers_append (response_headers, "Connection", "close");
	} else
		soup_server_message_set_status (msg, SOUP_STATUS_CREATED, NULL);
}

static SoupServer *
setup_server (void)
{
	SoupServer *server;
	SoupAuthDomain *auth_domain;

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);

	g_signal_connect (server, "request-started",
			  G_CALLBACK (request_started), NULL);

	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	auth_domain = soup_auth_domain_basic_new (
		"realm", "continue-test",
		"auth-callback", auth_callback,
		NULL);
        soup_auth_domain_add_path (auth_domain, "/auth");
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	return server;
}

/* MAIN */

int
main (int argc, char **argv)
{
	SoupServer *server;
	int ret;

	test_init (argc, argv, NULL);

	server = setup_server ();
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add_func ("/continue/unauth_short_noexpect_nopass", do_test_unauth_short_noexpect_nopass);
	g_test_add_func ("/continue/unauth_long_noexpect_nopass", do_test_unauth_long_noexpect_nopass);
	g_test_add_func ("/continue/unauth_short_expect_nopass", do_test_unauth_short_expect_nopass);
	g_test_add_func ("/continue/unauth_long_expect_nopass", do_test_unauth_long_expect_nopass);
	g_test_add_func ("/continue/auth_short_noexpect_nopass", do_test_auth_short_noexpect_nopass);
	g_test_add_func ("/continue/auth_long_noexpect_nopass", do_test_auth_long_noexpect_nopass);
	g_test_add_func ("/continue/auth_short_expect_nopass", do_test_auth_short_expect_nopass);
	g_test_add_func ("/continue/auth_long_expect_nopass", do_test_auth_long_expect_nopass);
	g_test_add_func ("/continue/auth_short_noexpect_pass", do_test_auth_short_noexpect_pass);
	g_test_add_func ("/continue/auth_long_noexpect_pass", do_test_auth_long_noexpect_pass);
	g_test_add_func ("/continue/auth_short_expect_pass", do_test_auth_short_expect_pass);
	g_test_add_func ("/continue/auth_long_expect_pass", do_test_auth_long_expect_pass);

	ret = g_test_run ();

	soup_test_server_quit_unref (server);
	g_uri_unref (base_uri);

	test_cleanup ();

	return ret;
}
