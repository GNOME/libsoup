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
#include <libsoup/soup-auth.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-session-async.h>

#include "test-utils.h"

GHashTable *connections;

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
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *client, gpointer data)
{
	GHashTable *connections = data;
	const char *auth;
	NTLMServerState state, required_user;
	gboolean not_found = FALSE;

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (!strcmp (path, "/noauth"))
		required_user = 0;
	else if (!strncmp (path, "/alice", 6))
		required_user = NTLM_AUTHENTICATED_ALICE;
	else if (!strncmp (path, "/bob", 4))
		required_user = NTLM_AUTHENTICATED_BOB;
	if (strstr (path, "/404"))
		not_found = TRUE;

	state = GPOINTER_TO_INT (g_hash_table_lookup (connections, soup_client_context_get_socket (client)));
	auth = soup_message_headers_get (msg->request_headers, "Authorization");

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
						   SOUP_MEMORY_STATIC,
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

	g_hash_table_insert (connections, soup_client_context_get_socket (client),
			     GINT_TO_POINTER (state));
}

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      SoupAuth *auth, gboolean retrying, gpointer user)
{
	soup_auth_authenticate (auth, user, "password");
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
	header = soup_message_headers_get (msg->response_headers,
					    "WWW-Authenticate");
	if (header && !strcmp (header, "NTLM"))
		state->got_prompt = TRUE;
}

static void
ntlm_challenge_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_get (msg->response_headers,
					    "WWW-Authenticate");
	if (header && !strncmp (header, "NTLM ", 5))
		state->got_challenge = TRUE;
}

static void
ntlm_request_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_get (msg->request_headers,
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

	header = soup_message_headers_get (msg->request_headers,
					    "Authorization");
	if (header && !strncmp (header, "NTLM " NTLM_RESPONSE_START,
				strlen ("NTLM " NTLM_RESPONSE_START)))
		state->sent_response = TRUE;
}

static void
do_message (SoupSession *session, SoupURI *base_uri, const char *path,
	    gboolean get_prompt, gboolean do_ntlm, guint status_code)
{
	SoupURI *uri;
	SoupMessage *msg;
	NTLMState state = { FALSE, FALSE, FALSE, FALSE };

	uri = soup_uri_copy (base_uri);
	g_free (uri->path);
	uri->path = g_strdup (path);
	msg = soup_message_new_from_uri ("GET", uri);
	soup_uri_free (uri);

	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (ntlm_prompt_check), &state);
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (ntlm_challenge_check), &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (ntlm_request_check), &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (ntlm_response_check), &state);

	soup_session_send_message (session, msg);
	debug_printf (1, "  %-10s -> ", path);

	if (state.got_prompt) {
		debug_printf (1, " PROMPT");
		if (!get_prompt) {
			debug_printf (1, "???");
			errors++;
		}
	} else if (get_prompt) {
		debug_printf (1, " no-prompt???");
		errors++;
	}

	if (state.sent_request) {
		debug_printf (1, " REQUEST");
		if (!do_ntlm) {
			debug_printf (1, "???");
			errors++;
		}
	} else if (do_ntlm) {
		debug_printf (1, " no-request???");
		errors++;
	}

	if (state.got_challenge) {
		debug_printf (1, " CHALLENGE");
		if (!do_ntlm) {
			debug_printf (1, "???");
			errors++;
		}
	} else if (do_ntlm) {
		debug_printf (1, " no-challenge???");
		errors++;
	}

	if (state.sent_response) {
		debug_printf (1, " RESPONSE");
		if (!do_ntlm) {
			debug_printf (1, "???");
			errors++;
		}
	} else if (do_ntlm) {
		debug_printf (1, " no-response???");
		errors++;
	}

	debug_printf (1, " -> %s", msg->reason_phrase);
	if (msg->status_code != status_code) {
		debug_printf (1, "???");
		errors++;
	}
	debug_printf (1, "\n");

	g_object_unref (msg);
}

static void
do_ntlm_round (SoupURI *base_uri, const char *user)
{
	SoupSession *session;
	gboolean use_ntlm = user != NULL;
	gboolean alice = use_ntlm && !strcmp (user, "alice");
	gboolean bob = use_ntlm && !strcmp (user, "bob");

	g_return_if_fail (use_ntlm || !alice);

	session = soup_test_session_new (
		SOUP_TYPE_SESSION_ASYNC,
		SOUP_SESSION_USE_NTLM, use_ntlm,
		NULL);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), (char *)user);

	do_message (session, base_uri, "/noauth",
		    FALSE, use_ntlm, SOUP_STATUS_OK);
	do_message (session, base_uri, "/alice",
		    !use_ntlm || bob, FALSE,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);
	do_message (session, base_uri, "/alice/404",
		    !use_ntlm, bob,
		    alice ? SOUP_STATUS_NOT_FOUND :
		    SOUP_STATUS_UNAUTHORIZED);
	do_message (session, base_uri, "/alice",
		    !use_ntlm, bob,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);
	do_message (session, base_uri, "/bob",
		    !use_ntlm || alice, bob,
		    bob ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);
	do_message (session, base_uri, "/alice",
		    !use_ntlm || bob, alice,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	soup_session_abort (session);
	g_object_unref (session);
}

static void
do_ntlm_tests (SoupURI *base_uri)
{
	debug_printf (1, "Round 1: Non-NTLM Connection\n");
	do_ntlm_round (base_uri, NULL);
	debug_printf (1, "Round 2: NTLM Connection, user=alice\n");
	do_ntlm_round (base_uri, "alice");
	debug_printf (1, "Round 3: NTLM Connection, user=bob\n");
	do_ntlm_round (base_uri, "bob");
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	GHashTable *connections;
	SoupURI *uri;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (FALSE);
	connections = g_hash_table_new (NULL, NULL);
	soup_server_add_handler (server, NULL,
				 server_callback, connections, NULL);

	loop = g_main_loop_new (NULL, TRUE);

	uri = soup_uri_new ("http://localhost/");
	uri->port = soup_server_get_port (server);
	do_ntlm_tests (uri);
	soup_uri_free (uri);

	g_main_loop_unref (loop);
	g_hash_table_destroy (connections);

	test_cleanup ();
	return errors != 0;
}
