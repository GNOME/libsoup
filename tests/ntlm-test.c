/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

/* This doesn't implement full server-side NTLM, and it mostly doesn't
 * even test that the client is doing the crypto/encoding/etc parts of
 * NTLM correctly. It only tests that the right message headers get
 * set in the right messages.
 */

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <libsoup/soup-address.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-server-message.h>
#include <libsoup/soup-session-async.h>

gboolean debug = FALSE;

static void
dprintf (const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

typedef enum {
	NTLM_UNAUTHENTICATED,
	NTLM_RECEIVED_REQUEST,
	NTLM_SENT_CHALLENGE,
	NTLM_AUTHENTICATED_ALICE,
	NTLM_AUTHENTICATED_BOB,
} NTLMServerState;

#define NTLM_REQUEST_START "TlRMTVNTUAABAAAA"
#define NTLM_RESPONSE_START "TlRMTVNTUAADAAAA"

#define NTLM_CHALLENGE "TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA="

#define NTLM_RESPONSE_USER(response) ((response)[87] == 'h' ? NTLM_AUTHENTICATED_ALICE : NTLM_AUTHENTICATED_BOB)

static void
server_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
	GHashTable *connections = data;
	const char *auth;
	char *path;
	NTLMServerState state, required_user;
	gboolean not_found = FALSE;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	path = soup_uri_to_string (soup_message_get_uri (msg), TRUE);
	if (!strcmp (path, "/noauth"))
		required_user = 0;
	else if (!strncmp (path, "/alice", 6))
		required_user = NTLM_AUTHENTICATED_ALICE;
	else if (!strncmp (path, "/bob", 4))
		required_user = NTLM_AUTHENTICATED_BOB;
	if (strstr (path, "/404"))
		not_found = TRUE;
	g_free (path);

	state = GPOINTER_TO_INT (g_hash_table_lookup (connections, context->sock));
	auth = soup_message_headers_find (msg->request_headers, "Authorization");

	if (auth && !strncmp (auth, "NTLM ", 5)) {
		if (!strncmp (auth + 5, NTLM_REQUEST_START,
			      strlen (NTLM_REQUEST_START)))
			state = NTLM_RECEIVED_REQUEST;
		else if (state == NTLM_SENT_CHALLENGE &&
			 !strncmp (auth + 5, NTLM_RESPONSE_START,
				   strlen (NTLM_RESPONSE_START)))
			state = NTLM_RESPONSE_USER (auth + 5);
		else
			state = NTLM_UNAUTHENTICATED;
	}

	if (state == NTLM_RECEIVED_REQUEST) {
		soup_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED);
		soup_message_headers_append (msg->response_headers,
					     "WWW-Authenticate",
					     "NTLM " NTLM_CHALLENGE);
		state = NTLM_SENT_CHALLENGE;
	} else if (!required_user || required_user == state) {
		if (not_found)
			soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		else {
			soup_message_set_response (msg, "text/plain",
						   SOUP_BUFFER_STATIC,
						   "OK\r\n", 4);
			soup_message_set_status (msg, SOUP_STATUS_OK);
		}
	} else {
		soup_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED);
		soup_message_headers_append (msg->response_headers,
					     "WWW-Authenticate", "NTLM");
		soup_message_headers_append (msg->response_headers,
					     "Connection", "close");
	}

	g_hash_table_insert (connections, context->sock,
			     GINT_TO_POINTER (state));
}

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      const char *auth_type, const char *auth_realm,
	      char **username, char **password, gpointer data)
{
	const char *user = data;

	*username = g_strdup (user);
	*password = g_strdup ("password");
}

typedef struct {
	gboolean got_prompt;
	gboolean sent_request;
	gboolean got_challenge;
	gboolean sent_response;
} NTLMState;

static void
ntlm_prompt_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	if (state->sent_request)
		return;
	header = soup_message_headers_find (msg->response_headers,
					    "WWW-Authenticate");
	if (header && !strcmp (header, "NTLM"))
		state->got_prompt = TRUE;
}

static void
ntlm_challenge_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_find (msg->response_headers,
					    "WWW-Authenticate");
	if (header && !strncmp (header, "NTLM ", 5))
		state->got_challenge = TRUE;
}

static void
ntlm_request_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_find (msg->request_headers,
					    "Authorization");
	if (header && !strncmp (header, "NTLM " NTLM_REQUEST_START,
				strlen ("NTLM " NTLM_REQUEST_START)))
		state->sent_request = TRUE;
}

static void
ntlm_response_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_find (msg->request_headers,
					    "Authorization");
	if (header && !strncmp (header, "NTLM " NTLM_RESPONSE_START,
				strlen ("NTLM " NTLM_RESPONSE_START)))
		state->sent_response = TRUE;
}

static int
do_message (SoupSession *session, SoupURI *base_uri, const char *path,
	    gboolean get_prompt, gboolean do_ntlm, guint status_code)
{
	SoupURI *uri;
	SoupMessage *msg;
	NTLMState state = { FALSE, FALSE, FALSE, FALSE };
	int errors = 0;

	uri = soup_uri_copy (base_uri);
	g_free (uri->path);
	uri->path = g_strdup (path);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	soup_message_add_header_handler (msg, "WWW-Authenticate",
					 SOUP_HANDLER_PRE_BODY,
					 ntlm_prompt_check, &state);
	soup_message_add_header_handler (msg, "WWW-Authenticate",
					 SOUP_HANDLER_PRE_BODY,
					 ntlm_challenge_check, &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (ntlm_request_check), &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (ntlm_response_check), &state);

	soup_session_send_message (session, msg);
	dprintf ("  %-10s -> ", path);

	if (state.got_prompt) {
		dprintf (" PROMPT");
		if (!get_prompt) {
			dprintf ("???");
			errors++;
		}
	} else if (get_prompt) {
		dprintf (" no-prompt???");
		errors++;
	}

	if (state.sent_request) {
		dprintf (" REQUEST");
		if (!do_ntlm) {
			dprintf ("???");
			errors++;
		}
	} else if (do_ntlm) {
		dprintf (" no-request???");
		errors++;
	}

	if (state.got_challenge) {
		dprintf (" CHALLENGE");
		if (!do_ntlm) {
			dprintf ("???");
			errors++;
		}
	} else if (do_ntlm) {
		dprintf (" no-challenge???");
		errors++;
	}

	if (state.sent_response) {
		dprintf (" RESPONSE");
		if (!do_ntlm) {
			dprintf ("???");
			errors++;
		}
	} else if (do_ntlm) {
		dprintf (" no-response???");
		errors++;
	}

	dprintf (" -> %s", msg->reason_phrase);
	if (msg->status_code != status_code) {
		dprintf ("???");
		errors++;
	}
	dprintf ("\n");

	g_object_unref (msg);
	return errors;
}

static int
do_ntlm_round (SoupURI *base_uri, const char *user)
{
	SoupSession *session;
	int errors = 0;
	gboolean use_ntlm = user != NULL;
	gboolean alice = use_ntlm && !strcmp (user, "alice");
	gboolean bob = use_ntlm && !strcmp (user, "bob");

	g_return_val_if_fail (use_ntlm || !alice, 0);

	session = soup_session_async_new_with_options (
		SOUP_SESSION_USE_NTLM, use_ntlm,
		NULL);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), (char *)user);

	errors += do_message (session, base_uri, "/noauth",
			      FALSE, use_ntlm, SOUP_STATUS_OK);
	errors += do_message (session, base_uri, "/alice",
			      !use_ntlm || bob, FALSE,
			      alice ? SOUP_STATUS_OK :
			      SOUP_STATUS_UNAUTHORIZED);
	errors += do_message (session, base_uri, "/alice/404",
			      !use_ntlm, bob,
			      alice ? SOUP_STATUS_NOT_FOUND :
			      SOUP_STATUS_UNAUTHORIZED);
	errors += do_message (session, base_uri, "/alice",
			      !use_ntlm, bob,
			      alice ? SOUP_STATUS_OK :
			      SOUP_STATUS_UNAUTHORIZED);
	errors += do_message (session, base_uri, "/bob",
			      !use_ntlm || alice, bob,
			      bob ? SOUP_STATUS_OK :
			      SOUP_STATUS_UNAUTHORIZED);
	errors += do_message (session, base_uri, "/alice",
			      !use_ntlm || bob, alice,
			      alice ? SOUP_STATUS_OK :
			      SOUP_STATUS_UNAUTHORIZED);

	soup_session_abort (session);
	g_object_unref (session);

	return errors;
}

static int
do_ntlm_tests (SoupURI *base_uri)
{
	int errors = 0;

	dprintf ("Round 1: Non-NTLM Connection\n");
	errors += do_ntlm_round (base_uri, NULL);
	dprintf ("Round 2: NTLM Connection, user=alice\n");
	errors += do_ntlm_round (base_uri, "alice");
	dprintf ("Round 3: NTLM Connection, user=bob\n");
	errors += do_ntlm_round (base_uri, "bob");

	return errors;
}

static void
quit (int sig)
{
	/* Exit cleanly on ^C in case we're valgrinding. */
	exit (0);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	int opt;
	GHashTable *connections;
	SoupURI *uri;
	int errors;

	g_type_init ();
	g_thread_init (NULL);
	signal (SIGINT, quit);

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n",
				 argv[0]);
			exit (1);
		}
	}

	connections = g_hash_table_new (NULL, NULL);

	server = soup_server_new (SOUP_SERVER_PORT, 0,
				  NULL);
	if (!server) {
		fprintf (stderr, "Unable to bind server\n");
		exit (1);
	}
	soup_server_add_handler (server, NULL, NULL,
				 server_callback, NULL, connections);
	soup_server_run_async (server);

	loop = g_main_loop_new (NULL, TRUE);

	uri = soup_uri_new ("http://localhost/");
	uri->port = soup_server_get_port (server);
	errors = do_ntlm_tests (uri);
	soup_uri_free (uri);

	soup_server_quit (server);
	g_object_unref (server);
	g_main_loop_unref (loop);
	g_hash_table_destroy (connections);
	g_main_context_unref (g_main_context_default ());

	dprintf ("\n");
	if (errors) {
		printf ("ntlm-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("ntlm-test: OK\n");
	return errors != 0;
}
