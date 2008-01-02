/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Novell, Inc.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libsoup/soup.h>
#include <libsoup/soup-auth-domain-basic.h>
#include <libsoup/soup-server.h>

#define SHORT_BODY "This is a test.\r\n"
#define LONG_BODY (SHORT_BODY SHORT_BODY)

#define MAX_POST_LENGTH (sizeof (SHORT_BODY))

int debug, port;
GSList *events;

static void
dprintf (int level, const char *format, ...)
{
	va_list args;

	if (debug < level)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

static void
event (SoupMessage *msg, char *side, char *message)
{
	char *data = g_strdup_printf ("%s-%s", side, message);
	gboolean record_status =
		(!strcmp (data, "server-wrote_headers") ||
		 !strcmp (data, "server-wrote_informational"));

	dprintf (2, "  %s", data);
	if (record_status)
		dprintf (2, " (%s)", msg->reason_phrase);
	dprintf (2, "\n");

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

EVENT_HANDLER (got_informational);
EVENT_HANDLER (got_headers);
EVENT_HANDLER (got_body);
EVENT_HANDLER (wrote_informational);
EVENT_HANDLER (wrote_headers);
EVENT_HANDLER (wrote_body);
EVENT_HANDLER (finished);

static int
do_message (const char *path, gboolean long_body,
	    gboolean expect_continue, gboolean auth,
	    ...)
{
	SoupSession *session;
	SoupMessage *msg;
	char *uri, *body;
	va_list ap;
	const char *expected_event;
	char *actual_event;
	int expected_status, actual_status;
	int errors = 0;
	static int count = 1;

	dprintf (1, "%d. /%s, %s body, %sExpect, %s password\n",
		 count++, path,
		 long_body ? "long" : "short",
		 expect_continue ? "" : "no ",
		 auth ? "with" : "without");

	uri = g_strdup_printf ("http://%slocalhost:%d/%s",
			       auth ? "user:pass@" : "",
			       port, path);
	msg = soup_message_new ("POST", uri);
	g_free (uri);

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
	session = soup_session_async_new ();
	soup_session_send_message (session, msg);
	soup_session_abort (session);
	g_object_unref (session);

	va_start (ap, auth);
	while ((expected_event = va_arg (ap, const char *))) {

		if (!events) {
			actual_event = "";
			dprintf (1, "  Expected '%s', got end of list\n",
				 expected_event);
			errors++;
		} else {
			actual_event = events->data;
			if (strcmp (expected_event, actual_event) != 0) {
				dprintf (1, "  Expected '%s', got '%s'\n",
					 expected_event, actual_event);
				errors++;
			}
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
			dprintf (1, "  Expected status '%s', got '%s'\n",
				 soup_status_get_phrase (expected_status),
				 soup_status_get_phrase (actual_status));
			errors++;
		}

		g_free (actual_event);
	}
	va_end (ap);
	while (events) {
		actual_event = events->data;
		dprintf (1, "  Expected to be done, got '%s'\n", actual_event);
		errors++;
		events = g_slist_delete_link (events, events);

		if (!strcmp (actual_event, "server-wrote_headers") ||
		    !strcmp (actual_event, "server-wrote_informational"))
			events = g_slist_delete_link (events, events);
	}
	g_object_unref (msg);

	return errors;
}

static int
run_tests (void)
{
	int errors = 0;

	errors += do_message ("unauth", FALSE, FALSE, FALSE,
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
	errors += do_message ("unauth", TRUE, FALSE, FALSE,
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
	errors += do_message ("unauth", FALSE, TRUE, FALSE,
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
	errors += do_message ("unauth", TRUE, TRUE, FALSE,
			      "client-wrote_headers",
			      "server-got_headers",
			      "server-wrote_headers", SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE,
			      "server-wrote_body",
			      "server-finished",
			      "client-got_headers",
			      "client-got_body",
			      "client-finished",
			      NULL);

	errors += do_message ("auth", FALSE, FALSE, FALSE,
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
	errors += do_message ("auth", TRUE, FALSE, FALSE,
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
	errors += do_message ("auth", FALSE, TRUE, FALSE,
			      "client-wrote_headers",
			      "server-got_headers",
			      "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
			      "server-wrote_body",
			      "server-finished",
			      "client-got_headers",
			      "client-got_body",
			      "client-finished",
			      NULL);
	errors += do_message ("auth", TRUE, TRUE, FALSE,
			      "client-wrote_headers",
			      "server-got_headers",
			      "server-wrote_headers", SOUP_STATUS_UNAUTHORIZED,
			      "server-wrote_body",
			      "server-finished",
			      "client-got_headers",
			      "client-got_body",
			      "client-finished",
			      NULL);

	errors += do_message ("auth", FALSE, FALSE, TRUE,
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
	errors += do_message ("auth", TRUE, FALSE, TRUE,
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
	errors += do_message ("auth", FALSE, TRUE, TRUE,
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
	errors += do_message ("auth", TRUE, TRUE, TRUE,
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

	return errors;
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

		length = soup_message_headers_get (msg->request_headers,
						    "Content-Length");
		if (length && atoi (length) > MAX_POST_LENGTH) {
			soup_message_set_status (msg, SOUP_STATUS_REQUEST_ENTITY_TOO_LARGE);
			soup_message_headers_append (msg->response_headers, "Connection", "close");
		}
	}
}	

static void
request_started (SoupServer *server, SoupSocket *sock,
		 SoupMessage *msg, gpointer user_data)
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
	       const char *username, gpointer password, gpointer user_data)
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
	} else if (soup_message_body_get_length (msg->request_body) > MAX_POST_LENGTH) {
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

	server = soup_server_new (SOUP_SERVER_PORT, 0,
				  NULL);

	g_signal_connect (server, "request-started",
			  G_CALLBACK (request_started), NULL);

	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	auth_domain = soup_auth_domain_basic_new (
		SOUP_AUTH_DOMAIN_REALM, "continue-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/auth",
		NULL);
	g_signal_connect (auth_domain, "authenticate",
			  G_CALLBACK (auth_callback), NULL);
	soup_server_add_auth_domain (server, auth_domain);

	return server;
}

/* MAIN */

static void
usage (void)
{
	fprintf (stderr, "Usage: continue-test [-d] [-d]\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	int opt, errors;
	SoupServer *server;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug++;
			break;

		case '?':
			usage ();
			break;
		}
	}

	server = setup_server ();
	port = soup_server_get_port (server);
	soup_server_run_async (server);

	errors = run_tests ();
	soup_server_quit (server);

	dprintf (1, "\n");
	if (errors) {
		printf ("continue-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("continue-test: OK\n");

	return errors > 0;
}
