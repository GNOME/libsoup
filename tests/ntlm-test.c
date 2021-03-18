/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

/* This doesn't implement full server-side NTLM, and it mostly doesn't
 * even test that the client is doing the crypto/encoding/etc parts of
 * NTLM correctly. It only tests that the right message headers get
 * set in the right messages.
 */

#include "test-utils.h"

typedef enum {
	NTLM_UNAUTHENTICATED,
	NTLM_RECEIVED_REQUEST,
	NTLM_SENT_CHALLENGE,
	NTLM_AUTHENTICATED_ALICE,
	NTLM_AUTHENTICATED_BOB
} NTLMServerState;

static const char *state_name[] = {
	"unauth", "recv", "sent", "alice", "bob"
};

#define NTLM_REQUEST_START "TlRMTVNTUAABAAAA"
#define NTLM_RESPONSE_START "TlRMTVNTUAADAAAA"

/*
 * NTLMV1_CHALLENGE - does not have "Negotiate Target Info" nor "Negotiate NTLM2 Key flags"
 * NTLMV2_CHALLENGE - "Negotiate Target Info" flag is set
 * NTLMSSP_CHALLENGE - "Negotiate NTLM2 Key" flag is set
 */
#define NTLMV1_CHALLENGE "TlRMTVNTUAACAAAADAAMADAAAAABAgEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA="
#define NTLMV2_CHALLENGE "TlRMTVNTUAACAAAADAAMADAAAAABAoEAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA="
#define NTLMSSP_CHALLENGE "TlRMTVNTUAACAAAADAAMADAAAAABAgkAASNFZ4mrze8AAAAAAAAAAGIAYgA8AAAARABPAE0AQQBJAE4AAgAMAEQATwBNAEEASQBOAAEADABTAEUAUgBWAEUAUgAEABQAZABvAG0AYQBpAG4ALgBjAG8AbQADACIAcwBlAHIAdgBlAHIALgBkAG8AbQBhAGkAbgAuAGMAbwBtAAAAAAA="

#define NTLM_RESPONSE_FLAGS_OFFSET 60
#define NTLM_FLAGS_REQUEST_TARGET 0x00000004

#define NTLM_RESPONSE_USER(response) ((response)[86] == 'E' ? NTLM_AUTHENTICATED_ALICE : ((response)[86] == 'I' ? NTLM_AUTHENTICATED_BOB : NTLM_UNAUTHENTICATED))

typedef struct {
	SoupServer *server;
	GHashTable *connections;
	GUri *uri;
	gboolean ntlmssp;
	gboolean ntlmv2;
} TestServer;

static void
clear_state (gpointer connections, GObject *ex_connection)
{
	g_hash_table_remove (connections, ex_connection);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	TestServer *ts = data;
	GSocket *socket;
	const char *auth;
	SoupMessageHeaders *request_headers;
	NTLMServerState state, required_user = 0;
	gboolean auth_required, not_found = FALSE;
	gboolean basic_allowed = TRUE, ntlm_allowed = TRUE;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_GET) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	if (!strncmp (path, "/alice", 6))
		required_user = NTLM_AUTHENTICATED_ALICE;
	else if (!strncmp (path, "/bob", 4))
		required_user = NTLM_AUTHENTICATED_BOB;
	else if (!strncmp (path, "/either", 7))
		;
	else if (!strncmp (path, "/basic", 6))
		ntlm_allowed = FALSE;
	else if (!strncmp (path, "/noauth", 7))
		basic_allowed = ntlm_allowed = FALSE;
	auth_required = ntlm_allowed || basic_allowed;

	if (strstr (path, "/404"))
		not_found = TRUE;

	socket = soup_server_message_get_socket (msg);
	state = GPOINTER_TO_INT (g_hash_table_lookup (ts->connections, socket));
	request_headers = soup_server_message_get_request_headers (msg);
	auth = soup_message_headers_get_one (request_headers, "Authorization");

	if (auth) {
		if (!strncmp (auth, "NTLM ", 5)) {
			if (!strncmp (auth + 5, NTLM_REQUEST_START,
				      strlen (NTLM_REQUEST_START))) {
				state = NTLM_RECEIVED_REQUEST;
				/* If they start, they must finish, even if
				 * it was unnecessary.
				 */
				auth_required = ntlm_allowed = TRUE;
				basic_allowed = FALSE;
			} else if (state == NTLM_SENT_CHALLENGE &&
				   !strncmp (auth + 5, NTLM_RESPONSE_START,
					     strlen (NTLM_RESPONSE_START))) {
				state = NTLM_RESPONSE_USER (auth + 5);
			} else
				state = NTLM_UNAUTHENTICATED;
		} else if (basic_allowed && !strncmp (auth, "Basic ", 6)) {
			gsize len;
			char *decoded = (char *)g_base64_decode (auth + 6, &len);

			if (!strncmp (decoded, "alice:password", len) &&
			    required_user != NTLM_AUTHENTICATED_BOB)
				auth_required = FALSE;
			else if (!strncmp (decoded, "bob:password", len) &&
				 required_user != NTLM_AUTHENTICATED_ALICE)
				auth_required = FALSE;
			g_free (decoded);
		}
	}

	if (ntlm_allowed && state > NTLM_SENT_CHALLENGE &&
	    (!required_user || required_user == state))
		auth_required = FALSE;

	if (auth_required) {
		SoupMessageHeaders *response_headers;

		soup_server_message_set_status (msg, SOUP_STATUS_UNAUTHORIZED, NULL);

		response_headers = soup_server_message_get_response_headers (msg);
		if (basic_allowed && state != NTLM_RECEIVED_REQUEST) {
			soup_message_headers_append (response_headers,
						     "WWW-Authenticate",
						     "Basic realm=\"ntlm-test\"");
		}

		if (ntlm_allowed && state == NTLM_RECEIVED_REQUEST) {
			soup_message_headers_append (response_headers,
						     "WWW-Authenticate",
						     ts->ntlmssp ? ("NTLM " NTLMSSP_CHALLENGE) : ts->ntlmv2 ? ("NTLM " NTLMV2_CHALLENGE) : ("NTLM " NTLMV1_CHALLENGE));
			state = NTLM_SENT_CHALLENGE;
		} else if (ntlm_allowed) {
			soup_message_headers_append (response_headers,
						     "WWW-Authenticate", "NTLM");
			soup_message_headers_append (response_headers,
						     "Connection", "close");
		}
	} else {
		if (not_found)
			soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		else {
			soup_server_message_set_response (msg, "text/plain",
							  SOUP_MEMORY_STATIC,
							  "OK\r\n", 4);
			soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
		}
	}

	debug_printf (2, " (S:%s)", state_name[state]);
	g_hash_table_insert (ts->connections, socket, GINT_TO_POINTER (state));
	g_object_weak_ref (G_OBJECT (socket), clear_state, ts->connections);
}

static void
setup_server (TestServer *ts,
	      gconstpointer test_data)
{
	ts->server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	ts->connections = g_hash_table_new (NULL, NULL);
	ts->ntlmssp = FALSE;
	ts->ntlmv2 = FALSE;
	soup_server_add_handler (ts->server, NULL, server_callback, ts, NULL);

	ts->uri = soup_test_server_get_uri (ts->server, "http", NULL);
}

static void
setup_ntlmssp_server (TestServer *ts,
		      gconstpointer test_data)
{
	setup_server (ts, test_data);
	ts->ntlmssp = TRUE;
}

static void
setup_ntlmv2_server (TestServer *ts,
		      gconstpointer test_data)
{
	setup_server (ts, test_data);
	ts->ntlmv2 = TRUE;
}

static void
teardown_server (TestServer *ts,
		 gconstpointer test_data)
{
	g_uri_unref (ts->uri);
	soup_test_server_quit_unref (ts->server);
	g_hash_table_destroy (ts->connections);
}

static gboolean authenticated_ntlm = FALSE;

static gboolean
authenticate (SoupMessage *msg,
	      SoupAuth    *auth,
	      gboolean    retrying,
	      gpointer    user)
{
	if (!retrying) {
		soup_auth_authenticate (auth, user, "password");
		if (g_str_equal (soup_auth_get_scheme_name (auth), "NTLM"))
			authenticated_ntlm = TRUE;

		return TRUE;
	}

	return FALSE;
}

typedef struct {
	gboolean got_ntlm_prompt;
	gboolean got_basic_prompt;
	gboolean sent_ntlm_request;
	gboolean got_ntlm_challenge;
	gboolean sent_ntlm_response;
	gboolean sent_basic_response;
} NTLMState;

static void
prompt_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_get_list (soup_message_get_response_headers (msg),
						"WWW-Authenticate");
	if (header && strstr (header, "Basic "))
		state->got_basic_prompt = TRUE;
	if (header && strstr (header, "NTLM") &&
	    (!strstr (header, NTLMV1_CHALLENGE) &&
	     !strstr (header, NTLMSSP_CHALLENGE) &&
	     !strstr (header, NTLMV2_CHALLENGE))) {
		state->got_ntlm_prompt = TRUE;
	}
}

static void
challenge_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_get_list (soup_message_get_response_headers (msg),
						"WWW-Authenticate");
	if (header && !strncmp (header, "NTLM ", 5))
		state->got_ntlm_challenge = TRUE;
}

static void
request_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;

	header = soup_message_headers_get_one (soup_message_get_request_headers (msg),
					       "Authorization");
	if (header && !strncmp (header, "NTLM " NTLM_REQUEST_START,
				strlen ("NTLM " NTLM_REQUEST_START)))
		state->sent_ntlm_request = TRUE;
}

static void
response_check (SoupMessage *msg, gpointer user_data)
{
	NTLMState *state = user_data;
	const char *header;
	guchar *ntlm_data;
	gsize ntlm_data_sz;
	gboolean request_target;
	guint32 flags;
	int nt_resp_sz;

	header = soup_message_headers_get_one (soup_message_get_request_headers (msg),
					       "Authorization");
	if (header && !strncmp (header, "NTLM " NTLM_RESPONSE_START,
				strlen ("NTLM " NTLM_RESPONSE_START)))
	{
		ntlm_data = g_base64_decode (header + 5, &ntlm_data_sz);

		memcpy (&flags, ntlm_data + NTLM_RESPONSE_FLAGS_OFFSET, sizeof(flags));
		flags = GUINT_FROM_LE (flags);
		request_target = (flags & NTLM_FLAGS_REQUEST_TARGET) ? TRUE : FALSE;
		nt_resp_sz = ntlm_data[22] | ntlm_data[23] << 8;

		/*
		 * If the "Request Target" flag is not set in response, it should return NTLMv1 or NTLM2 Session Response,
		 * they both should return exactly 24-byte NT response.
		 * If the "Request Target" flag is set, it should return NTLMv2 reponse,
		 * which has NT response always over 24 bytes.
		 */
		if ((!request_target && nt_resp_sz == 24) || (request_target && nt_resp_sz > 24))
		{
			state->sent_ntlm_response = TRUE;
		}

		g_free (ntlm_data);
	}
	if (header && !strncmp (header, "Basic ", 6))
		state->sent_basic_response = TRUE;
}

static void
do_message (SoupSession *session,
	    GUri        *base_uri,
	    const char  *path,
	    const char  *user,
	    gboolean     get_ntlm_prompt,
	    gboolean     do_ntlm,
	    gboolean     get_basic_prompt,
	    gboolean     do_basic,
	    guint        status_code)
{
	GUri *uri;
	SoupMessage *msg;
	GBytes *body;
	NTLMState state = { FALSE, FALSE, FALSE, FALSE };

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	if (user) {
		g_signal_connect (msg, "authenticate",
				  G_CALLBACK (authenticate),
				  (gpointer)user);
	}
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (prompt_check), &state);
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (challenge_check), &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (request_check), &state);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (response_check), &state);

	body = soup_session_send_and_read (session, msg, NULL, NULL);
	debug_printf (1, "  %-10s -> ", path);

	if (state.got_ntlm_prompt) {
		debug_printf (1, " NTLM_PROMPT");
		if (!get_ntlm_prompt)
			debug_printf (1, "???");
	} else if (get_ntlm_prompt)
		debug_printf (1, " no-ntlm-prompt???");

	if (state.got_basic_prompt) {
		debug_printf (1, " BASIC_PROMPT");
		if (!get_basic_prompt)
			debug_printf (1, "???");
	} else if (get_basic_prompt)
		debug_printf (1, " no-basic-prompt???");

	if (state.sent_ntlm_request) {
		debug_printf (1, " REQUEST");
		if (!do_ntlm)
			debug_printf (1, "???");
	} else if (do_ntlm)
		debug_printf (1, " no-request???");

	if (state.got_ntlm_challenge) {
		debug_printf (1, " CHALLENGE");
		if (!do_ntlm)
			debug_printf (1, "???");
	} else if (do_ntlm)
		debug_printf (1, " no-challenge???");

	if (state.sent_ntlm_response) {
		debug_printf (1, " NTLM_RESPONSE");
		if (!do_ntlm)
			debug_printf (1, "???");
	} else if (do_ntlm)
		debug_printf (1, " no-ntlm-response???");

	if (state.sent_basic_response) {
		debug_printf (1, " BASIC_RESPONSE");
		if (!do_basic)
			debug_printf (1, "???");
	} else if (do_basic)
		debug_printf (1, " no-basic-response???");

	debug_printf (1, " -> %s", soup_message_get_reason_phrase (msg));
	if (soup_message_get_status (msg) != status_code)
		debug_printf (1, "???");
	debug_printf (1, "\n");

	g_assert_true (state.got_ntlm_prompt == get_ntlm_prompt);
	g_assert_true (state.got_basic_prompt == get_basic_prompt);
	g_assert_true (state.sent_ntlm_request == do_ntlm);
	g_assert_true (state.got_ntlm_challenge == do_ntlm);
	g_assert_true (state.sent_ntlm_response == do_ntlm);
	g_assert_true (state.sent_basic_response == do_basic);
	soup_test_assert_message_status (msg, status_code);

	g_bytes_unref (body);
	g_object_unref (msg);
}

static void
do_ntlm_round (GUri *base_uri, gboolean use_ntlm,
	       const char *user, gboolean use_builtin_ntlm)
{
	SoupSession *session;
	gboolean alice = !g_strcmp0 (user, "alice");
	gboolean bob = !g_strcmp0 (user, "bob");
	gboolean alice_via_ntlm = use_ntlm && alice;
	gboolean bob_via_ntlm = use_ntlm && bob;
	gboolean alice_via_basic = !use_ntlm && alice;

	session = soup_test_session_new (NULL);

	if (user && use_ntlm && !use_builtin_ntlm)
		g_setenv ("NTLMUSER", user, TRUE);

	if (use_ntlm) {
		SoupAuthManager *auth_manager;
		SoupAuth *ntlm;

		soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);
		auth_manager = SOUP_AUTH_MANAGER (soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER));
		ntlm = g_object_new (SOUP_TYPE_AUTH_NTLM, NULL);
		soup_auth_manager_use_auth (auth_manager, base_uri, ntlm);
		g_object_unref (ntlm);
	}

	/* 1. Server doesn't request auth, so both get_ntlm_prompt and
	 * get_basic_prompt are both FALSE, and likewise do_basic. But
	 * if we're using NTLM we'll try that even without the server
	 * asking.
	 */
	authenticated_ntlm = FALSE;
	do_message (session, base_uri, "/noauth/", user,
		    FALSE, use_ntlm,
		    FALSE, FALSE,
		    SOUP_STATUS_OK);

	soup_test_assert (authenticated_ntlm == (use_ntlm && use_builtin_ntlm),
			  "%s built-in NTLM support, but authenticate signal %s emitted\n",
			  use_builtin_ntlm ? "Using" : "Not using",
			  authenticated_ntlm ? "was" : "wasn't");

	/* 2. Server requires auth as Alice, so it will request that
	 * if we didn't already authenticate the connection to her in
	 * the previous step. If we authenticated as Bob in the
	 * previous step, then we'll just immediately get a 401 here.
	 * So in no case will we see the client try to do_ntlm.
	 */
	do_message (session, base_uri, "/alice/", user,
		    !alice_via_ntlm, FALSE,
		    !alice_via_ntlm, alice_via_basic,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 3. Server still requires auth as Alice, but this URI
	 * doesn't exist, so Alice should get a 404, but others still
	 * get 401. Alice-via-NTLM is still authenticated, and so
	 * won't get prompts, and Alice-via-Basic knows at this point
	 * to send auth without it being requested, so also won't get
	 * prompts. But Bob/nobody will.
	 */
	do_message (session, base_uri, "/alice/404", user,
		    !alice, bob_via_ntlm,
		    !alice, alice_via_basic,
		    alice ? SOUP_STATUS_NOT_FOUND :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 4. Should be exactly the same as #3, except the status code */
	do_message (session, base_uri, "/alice/", user,
		    !alice, bob_via_ntlm,
		    !alice, alice_via_basic,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 5. This path requires auth as Bob; Alice-via-NTLM will get
	 * an immediate 401 and not try to reauthenticate.
	 * Alice-via-Basic will get a 401 and then try to do Basic
	 * (and fail). Bob-via-NTLM will try to do NTLM right away and
	 * succeed.
	 */
	do_message (session, base_uri, "/bob/", user,
		    !bob_via_ntlm, bob_via_ntlm,
		    !bob_via_ntlm, alice_via_basic,
		    bob ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 6. Back to /alice. Somewhat the inverse of #5; Bob-via-NTLM
	 * will get an immediate 401 and not try again, Alice-via-NTLM
	 * will try to do NTLM right away and succeed. Alice-via-Basic
	 * still knows about this path, so will try Basic right away
	 * and succeed.
	 */
	do_message (session, base_uri, "/alice/", user,
		    !alice_via_ntlm, alice_via_ntlm,
		    !alice_via_ntlm, alice_via_basic,
		    alice ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 7. Server accepts Basic auth from either user, but not NTLM.
	 * Since Bob-via-NTLM is unauthenticated at this point, he'll try
	 * NTLM before realizing that the server doesn't support it.
	 */
	do_message (session, base_uri, "/basic/", user,
		    FALSE, bob_via_ntlm,
		    TRUE, user != NULL,
		    user != NULL ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	/* 8. Server accepts Basic or NTLM from either user.
	 * NTLM users will try NTLM without getting a prompt (their
	 * previous NTLM connections will have been closed by the 401
	 * from /basic). Non-NTLM users will be prompted for either.
	 */
	do_message (session, base_uri, "/either/", user,
		    !use_ntlm, use_ntlm,
		    !use_ntlm, !use_ntlm && user != NULL,
		    user != NULL ? SOUP_STATUS_OK :
		    SOUP_STATUS_UNAUTHORIZED);

	soup_test_session_abort_unref (session);
}

typedef enum {
	BUILTIN,
	WINBIND,
	FALLBACK
} NtlmType;

typedef struct {
	const char *name, *user;
	gboolean conn_uses_ntlm;
	NtlmType ntlm_type;
} NtlmTest;

static const NtlmTest ntlm_tests[] = {
	{ "/ntlm/builtin/none",   NULL,    FALSE, BUILTIN },
	{ "/ntlm/builtin/alice",  "alice", TRUE,  BUILTIN },
	{ "/ntlm/builtin/bob",    "bob",   TRUE,  BUILTIN },
	{ "/ntlm/builtin/basic",  "alice", FALSE, BUILTIN },

	{ "/ntlm/winbind/none",   NULL,    FALSE, WINBIND },
	{ "/ntlm/winbind/alice",  "alice", TRUE,  WINBIND },
	{ "/ntlm/winbind/bob",    "bob",   TRUE,  WINBIND },
	{ "/ntlm/winbind/basic",  "alice", FALSE, WINBIND },

	{ "/ntlm/fallback/none",  NULL,    FALSE, FALLBACK },
	{ "/ntlm/fallback/alice", "alice", TRUE,  FALLBACK },
	{ "/ntlm/fallback/bob",   "bob",   TRUE,  FALLBACK },
	{ "/ntlm/fallback/basic", "alice", FALSE, FALLBACK }
};

static const NtlmTest ntlmssp_tests[] = {
	{ "/ntlm/ssp/none",  NULL,    FALSE, BUILTIN },
	{ "/ntlm/ssp/alice", "alice", TRUE,  BUILTIN },
	{ "/ntlm/ssp/bob",   "bob",   TRUE,  BUILTIN },
	{ "/ntlm/ssp/basic", "alice", FALSE, BUILTIN }
};

static const NtlmTest ntlmv2_tests[] = {
	{ "/ntlm/v2/none",  NULL,    FALSE, BUILTIN },
	{ "/ntlm/v2/alice", "alice", TRUE,  BUILTIN },
	{ "/ntlm/v2/bob",   "bob",   TRUE,  BUILTIN },
	{ "/ntlm/v2/basic", "alice", FALSE, BUILTIN }
};

static void
do_ntlm_test (TestServer *ts,
	      gconstpointer data)
{
	const NtlmTest *test = data;
	gboolean use_builtin_ntlm = TRUE;

	switch (test->ntlm_type) {
	case BUILTIN:
		/* Built-in NTLM auth support. (We set SOUP_NTLM_AUTH_DEBUG to
		 * an empty string to ensure that the built-in support is
		 * being used, even if /usr/bin/ntlm_auth is available.)
		 */
		g_setenv ("SOUP_NTLM_AUTH_DEBUG", "", TRUE);
		break;

	case WINBIND:
#ifndef USE_NTLM_AUTH
		g_test_skip ("/usr/bin/ntlm_auth is not available");
		return;
#endif

		/* Samba winbind /usr/bin/ntlm_auth helper support (via a
		 * helper program that emulates its interface).
		 */
		g_setenv ("SOUP_NTLM_AUTH_DEBUG",
			  g_test_get_filename (G_TEST_BUILT, "ntlm-test-helper", NULL),
			  TRUE);
		g_unsetenv ("SOUP_NTLM_AUTH_DEBUG_NOCREDS");
		use_builtin_ntlm = FALSE;
		break;

	case FALLBACK:
#ifndef USE_NTLM_AUTH
		g_test_skip ("/usr/bin/ntlm_auth is not available");
		return;
#endif

		/* Support for when ntlm_auth is installed, but the user has
		 * no cached credentials (and thus we have to fall back to
		 * libsoup's built-in NTLM support).
		 */
		g_setenv ("SOUP_NTLM_AUTH_DEBUG",
			  g_test_get_filename (G_TEST_BUILT, "ntlm-test-helper", NULL),
			  TRUE);
		g_setenv ("SOUP_NTLM_AUTH_DEBUG_NOCREDS", "1", TRUE);
		break;
	}

	do_ntlm_round (ts->uri, test->conn_uses_ntlm, test->user, use_builtin_ntlm);
}

static gboolean
retry_test_authenticate (SoupMessage *msg,
			 SoupAuth    *auth,
			 gboolean     retrying,
			 gboolean    *retried)
{
	if (!retrying) {
		/* server_callback doesn't actually verify the password,
		 * only the username. So we pass an incorrect username
		 * rather than an incorrect password.
		 */
		soup_auth_authenticate (auth, "wrong", "password");

		return TRUE;
	}

	if (!*retried) {
		soup_auth_authenticate (auth, "alice", "password");
		*retried = TRUE;

		return TRUE;
	}

	return FALSE;
}

static void
do_retrying_test (TestServer *ts,
		  gconstpointer data)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;
	GBytes *body;
	gboolean retried = FALSE;

	g_test_bug ("693222");

	g_setenv ("SOUP_NTLM_AUTH_DEBUG", "", TRUE);

	debug_printf (1, "  /alice\n");

	session = soup_test_session_new (NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);

	uri = g_uri_parse_relative (ts->uri, "/alice", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_signal_connect (msg, "authenticate",
			  G_CALLBACK (retry_test_authenticate), &retried);
	g_uri_unref (uri);

	body = soup_session_send_and_read (session, msg, NULL, NULL);

	g_assert_true (retried);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);

	debug_printf (1, "  /bob\n");

	session = soup_test_session_new (NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);
	retried = FALSE;

	uri = g_uri_parse_relative (ts->uri, "/bob", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_signal_connect (msg, "authenticate",
			  G_CALLBACK (retry_test_authenticate), &retried);
	g_uri_unref (uri);

	body = soup_session_send_and_read (session, msg, NULL, NULL);

	g_assert_true (retried);
	soup_test_assert_message_status (msg, SOUP_STATUS_UNAUTHORIZED);

	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	int i, ret;

	test_init (argc, argv, NULL);

	for (i = 0; i < G_N_ELEMENTS (ntlm_tests); i++) {
		g_test_add (ntlm_tests[i].name, TestServer, &ntlm_tests[i],
			    setup_server, do_ntlm_test, teardown_server);
	}
	for (i = 0; i < G_N_ELEMENTS (ntlmssp_tests); i++) {
		g_test_add (ntlmssp_tests[i].name, TestServer, &ntlmssp_tests[i],
			    setup_ntlmssp_server, do_ntlm_test, teardown_server);
	}
	for (i = 0; i < G_N_ELEMENTS (ntlmv2_tests); i++) {
		g_test_add (ntlmv2_tests[i].name, TestServer, &ntlmv2_tests[i],
			    setup_ntlmv2_server, do_ntlm_test, teardown_server);
	}

	g_test_add ("/ntlm/retry", TestServer, NULL,
		    setup_server, do_retrying_test, teardown_server);

	ret = g_test_run ();

	test_cleanup ();

	return ret;
}
