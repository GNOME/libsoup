/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#include "test-utils.h"

#define SHORT_BODY "This is a test.\r\n"
#define LONG_BODY (SHORT_BODY SHORT_BODY)

#define MAX_POST_LENGTH (sizeof (SHORT_BODY))

static SoupURI *base_uri;
static GSList *events;

static void
event (SoupMessage *msg, const char *side, const char *message)
{
	char *data = g_strdup_printf ("%s-%s", side, message);
	gboolean record_status =
		(!strcmp (data, "server-wrote_headers") ||
		 !strcmp (data, "server-wrote_informational"));

	debug_printf (2, "  %s", data);
	if (record_status)
		debug_printf (2, " (%s)", msg->reason_phrase);
	debug_printf (2, "\n");

	events = g_slist_append (events, data);
	if (record_status)
		events = g_slist_append (events, GUINT_TO_POINTER (msg->status_code));
}

#define EVENT_HANDLER(name)			\
static void					\
name (SoupMessage *msg, gpointer side)		\
{						\
	event (msg, side, #name);		\
}

EVENT_HANDLER (got_informational)
EVENT_HANDLER (got_headers)
EVENT_HANDLER (got_body)
EVENT_HANDLER (wrote_informational)
EVENT_HANDLER (wrote_headers)
EVENT_HANDLER (wrote_body)
EVENT_HANDLER (finished)

static void
do_message (const char *path, gboolean long_body,
	    gboolean expect_continue, gboolean auth,
	    ...)
{
	SoupSession *session;
	SoupMessage *msg;
	const char *body;
	SoupURI *uri;
	va_list ap;
	const char *expected_event;
	char *actual_event;
	int expected_status, actual_status;

	uri = soup_uri_copy (base_uri);
	if (auth) {
		soup_uri_set_user (uri, "user");
		soup_uri_set_password (uri, "pass");
	}
	soup_uri_set_path (uri, path);
	msg = soup_message_new_from_uri ("POST", uri);
	soup_uri_free (uri);

	body = long_body ? LONG_BODY : SHORT_BODY;
	soup_message_set_request (msg, "text/plain", SOUP_MEMORY_STATIC,
				  body, strlen (body));
	soup_message_headers_append (msg->request_headers, "Connection", "close");
	if (expect_continue) {
		soup_message_headers_set_expectations (msg->request_headers,
						       SOUP_EXPECTATION_CONTINUE);
	}

	g_signal_connect (msg, "got_informational",
			  G_CALLBACK (got_informational), "client");
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), "client");
	g_signal_connect (msg, "got_body",
			  G_CALLBACK (got_body), "client");
	g_signal_connect (msg, "wrote_informational",
			  G_CALLBACK (wrote_informational), "client");
	g_signal_connect (msg, "wrote_headers",
			  G_CALLBACK (wrote_headers), "client");
	g_signal_connect (msg, "wrote_body",
			  G_CALLBACK (wrote_body), "client");
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished), "client");

	events = NULL;
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	soup_session_send_message (session, msg);
	soup_test_session_abort_unref (session);

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
	g_object_unref (msg);
}

static void
do_test_unauth_short_noexpect_nopass (void)
{
	do_message ("/unauth", FALSE, FALSE, FALSE,
		    "client-wrote_headers",
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
		    "server-wrote_body",
		    "server-finished",
		    "client-got_headers",
		    "client-got_body",
		    "client-wrote_headers",
		    "client-wrote_body",
		    "server-got_headers",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
		    "server-wrote_body",
		    "server-finished",
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
		    "client-wrote_body",
		    "server-got_body",
		    "server-wrote_headers", SOUP_STATUS_CREATED,
		    "server-wrote_body",
		    "server-finished",
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
server_got_headers (SoupMessage *msg, gpointer server)
{
	/* FIXME */
	if (msg->status_code != SOUP_STATUS_CONTINUE &&
	    msg->status_code != 0)
		return;

	if (soup_message_headers_get_expectations (msg->request_headers) &
	    SOUP_EXPECTATION_CONTINUE) {
		const char *length;

		length = soup_message_headers_get_one (msg->request_headers,
						       "Content-Length");
		if (length && atoi (length) > MAX_POST_LENGTH) {
			soup_message_set_status (msg, SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE);
			soup_message_headers_append (msg->response_headers, "Connection", "close");
		}
	}
}	

static void
request_started (SoupServer *server, SoupMessage *msg,
		 SoupClientContext *client, gpointer user_data)
{
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (server_got_headers), server);

	g_signal_connect (msg, "got_informational",
			  G_CALLBACK (got_informational), "server");
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers), "server");
	g_signal_connect (msg, "got_body",
			  G_CALLBACK (got_body), "server");
	g_signal_connect (msg, "wrote_informational",
			  G_CALLBACK (wrote_informational), "server");
	g_signal_connect (msg, "wrote_headers",
			  G_CALLBACK (wrote_headers), "server");
	g_signal_connect (msg, "wrote_body",
			  G_CALLBACK (wrote_body), "server");
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished), "server");
}

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer user_data)
{
	return !strcmp (username, "user") && !strcmp (password, "pass");
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	if (msg->method != SOUP_METHOD_POST) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		soup_message_headers_append (msg->response_headers, "Connection", "close");
	} else if (msg->request_body->length > MAX_POST_LENGTH) {
		soup_message_set_status (msg, SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE);
		soup_message_headers_append (msg->response_headers, "Connection", "close");
	} else
		soup_message_set_status (msg, SOUP_STATUS_CREATED);
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
		SOUP_AUTH_DOMAIN_REALM, "continue-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/auth",
		SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, auth_callback,
		NULL);
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
	soup_uri_free (base_uri);

	test_cleanup ();

	return ret;
}
