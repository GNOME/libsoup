/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
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
#include <libsoup/soup-auth-domain-basic.h>
#include <libsoup/soup-auth-domain-digest.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>

GMainLoop *loop;
gboolean debug = FALSE;

struct {
	gboolean client_sent_basic, client_sent_digest;
	gboolean server_requested_basic, server_requested_digest;
	gboolean succeeded;
} test_data;

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

static void
curl_exited (GPid pid, int status, gpointer data)
{
	gboolean *done = data;

	*done = TRUE;
	test_data.succeeded = (status == 0);
}

static int
do_test (int n, SoupURI *base_uri, const char *path, gboolean good_password,
	 gboolean offer_basic, gboolean offer_digest,
	 gboolean client_sends_basic, gboolean client_sends_digest,
	 gboolean server_requests_basic, gboolean server_requests_digest,
	 gboolean success)
{
	SoupURI *uri;
	char *uri_str;
	GPtrArray *args;
	GPid pid;
	gboolean done;
	int errors = 0;

	dprintf ("%2d. %s, %soffer Basic, %soffer Digest, %s password\n",
		 n, path, offer_basic ? "" : "don't ",
		 offer_digest ? "" : "don't ",
		 good_password ? "good" : "bad");

	uri = soup_uri_new_with_base (base_uri, path);
	uri_str = soup_uri_to_string (uri, FALSE);
	soup_uri_free (uri);

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "curl");
	g_ptr_array_add (args, "-f");
	g_ptr_array_add (args, "-s");
	if (offer_basic || offer_digest) {
		g_ptr_array_add (args, "-u");
		if (good_password)
			g_ptr_array_add (args, "user:password");
		else
			g_ptr_array_add (args, "user:badpassword");

		if (offer_basic && offer_digest)
			g_ptr_array_add (args, "--anyauth");
		else if (offer_basic)
			g_ptr_array_add (args, "--basic");
		else
			g_ptr_array_add (args, "--digest");
	}
	g_ptr_array_add (args, uri_str);
	g_ptr_array_add (args, NULL);

	memset (&test_data, 0, sizeof (test_data));
	if (g_spawn_async (NULL, (char **)args->pdata, NULL,
			   G_SPAWN_SEARCH_PATH | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL | G_SPAWN_DO_NOT_REAP_CHILD,
			   NULL, NULL, &pid, NULL)) {
		done = FALSE;
		g_child_watch_add (pid, curl_exited, &done);

		while (!done)
			g_main_iteration (TRUE);
	} else
		test_data.succeeded = FALSE;
	g_ptr_array_free (args, TRUE);
	g_free (uri_str);

	if (server_requests_basic != test_data.server_requested_basic) {
		errors++;
		if (test_data.server_requested_basic)
			dprintf ("  Server sent WWW-Authenticate: Basic, but shouldn't have!\n");
		else
			dprintf ("  Server didn't send WWW-Authenticate: Basic, but should have!\n");
	}
	if (server_requests_digest != test_data.server_requested_digest) {
		errors++;
		if (test_data.server_requested_digest)
			dprintf ("  Server sent WWW-Authenticate: Digest, but shouldn't have!\n");
		else
			dprintf ("  Server didn't send WWW-Authenticate: Digest, but should have!\n");
	}
	if (client_sends_basic != test_data.client_sent_basic) {
		errors++;
		if (test_data.client_sent_basic)
			dprintf ("  Client sent Authorization: Basic, but shouldn't have!\n");
		else
			dprintf ("  Client didn't send Authorization: Basic, but should have!\n");
	}
	if (client_sends_digest != test_data.client_sent_digest) {
		errors++;
		if (test_data.client_sent_digest)
			dprintf ("  Client sent Authorization: Digest, but shouldn't have!\n");
		else
			dprintf ("  Client didn't send Authorization: Digest, but should have!\n");
	}
	if (success && !test_data.succeeded) {
		errors++;
		dprintf ("  Should have succeeded, but didn't!\n");
	} else if (!success && test_data.succeeded) {
		errors++;
		dprintf ("  Should not have succeeded, but did!\n");
	}

	return errors;
}

static int
do_auth_tests (SoupURI *base_uri)
{
	int i, n = 1, errors = 0;
	gboolean use_basic, use_digest, good_password;
	gboolean preemptive_basic;

	for (i = 0; i < 8; i++) {
		use_basic     = (i & 1) == 1;
		use_digest    = (i & 2) == 2;
		good_password = (i & 4) == 4;

		/* Curl will preemptively send Basic if it's told to
		 * use Basic but not Digest.
		 */
		preemptive_basic = use_basic && !use_digest;

		/* 1. No auth required. The server will ignore the
		 * Authorization headers completely, and the request
		 * will always succeed.
		 */
		errors += do_test (n++, base_uri, "/foo", good_password,
				   /* request */
				   use_basic, use_digest,
				   /* expected from client */
				   preemptive_basic, FALSE,
				   /* expected from server */
				   FALSE, FALSE,
				   /* success? */
				   TRUE);

		/* 2. Basic auth required. The server will send
		 * "WWW-Authenticate: Basic" if the client fails to
		 * send an Authorization: Basic on the first request,
		 * or if it sends a bad password.
		 */
		errors += do_test (n++, base_uri, "/Basic/foo", good_password,
				   /* request */
				   use_basic, use_digest,
				   /* expected from client */
				   use_basic, FALSE,
				   /* expected from server */
				   !preemptive_basic || !good_password, FALSE,
				   /* success? */
				   use_basic && good_password);

		/* 3. Digest auth required. Simpler than the basic
		 * case because the client can't send Digest auth
		 * premptively.
		 */
		errors += do_test (n++, base_uri, "/Digest/foo", good_password,
				   /* request */
				   use_basic, use_digest,
				   /* expected from client */
				   preemptive_basic, use_digest,
				   /* expected from server */
				   FALSE, TRUE,
				   /* success? */
				   use_digest && good_password);

		/* 4. Any auth required. */
		errors += do_test (n++, base_uri, "/Any/foo", good_password,
				   /* request */
				   use_basic, use_digest,
				   /* expected from client */
				   preemptive_basic, use_digest,
				   /* expected from server */
				   !preemptive_basic || !good_password, !preemptive_basic || !good_password,
				   /* success? */
				   (use_basic || use_digest) && good_password);
	}

	return errors;
}

static gboolean
basic_authenticate (SoupAuthDomain *auth_domain, SoupMessage *msg,
		    const char *username, gpointer password, gpointer data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static gboolean
digest_get_auth_info (SoupAuthDomain *auth_domain, SoupMessage *msg,
		      const char *username, char hex_urp[33], gpointer data)
{
	if (strcmp (username, "user") != 0)
		return FALSE;

	soup_auth_domain_digest_compute_hex_urp ("user", "server-auth-test",
						 "password", hex_urp);
	return TRUE;
}

static void
server_callback (SoupServer *server, SoupMessage *msg, SoupURI *uri,
		 SoupClientContext *context, gpointer data)
{
	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_HEAD) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "OK\r\n", 4);
	soup_message_set_status (msg, SOUP_STATUS_OK);
}

static void
got_headers_callback (SoupMessage *msg, gpointer data)
{
	int i;
	const char *header;

	i = 0;
	while ((header = soup_message_headers_find_nth (msg->request_headers, "Authorization", i++))) {
		if (!strncmp (header, "Basic ", 6))
			test_data.client_sent_basic = TRUE;
		else if (!strncmp (header, "Digest ", 7))
			test_data.client_sent_digest = TRUE;
	}
}

static void
wrote_headers_callback (SoupMessage *msg, gpointer data)
{
	int i;
	const char *header;

	i = 0;
	while ((header = soup_message_headers_find_nth (msg->response_headers, "WWW-Authenticate", i++))) {
		if (!strncmp (header, "Basic ", 6))
			test_data.server_requested_basic = TRUE;
		else if (!strncmp (header, "Digest ", 7))
			test_data.server_requested_digest = TRUE;
	}
}

static void
request_started_callback (SoupServer *server, SoupSocket *sock,
			  SoupMessage *msg, gpointer data)
{
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (got_headers_callback), NULL);
	g_signal_connect (msg, "wrote_headers",
			  G_CALLBACK (wrote_headers_callback), NULL);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	int opt;
	SoupURI *uri;
	int errors;
	SoupAuthDomain *auth_domain;
	gboolean run_tests = TRUE;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "dn")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		case 'n':
			run_tests = FALSE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n",
				 argv[0]);
			exit (1);
		}
	}

	server = soup_server_new (SOUP_SERVER_PORT, 0,
				  NULL);
	if (!server) {
		fprintf (stderr, "Unable to bind server\n");
		exit (1);
	}
	g_signal_connect (server, "request_started",
			  G_CALLBACK (request_started_callback), NULL);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);

	auth_domain = soup_auth_domain_basic_new (
		SOUP_AUTH_DOMAIN_REALM, "server-auth-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/Basic",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/Any",
		NULL);
	g_signal_connect (auth_domain, "authenticate",
			  G_CALLBACK (basic_authenticate), NULL);
	soup_server_add_auth_domain (server, auth_domain);

	auth_domain = soup_auth_domain_digest_new (
		SOUP_AUTH_DOMAIN_REALM, "server-auth-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/Digest",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/Any",
		NULL);
	g_signal_connect (auth_domain, "get_auth_info",
			  G_CALLBACK (digest_get_auth_info), NULL);
	soup_server_add_auth_domain (server, auth_domain);

	soup_server_run_async (server);

	loop = g_main_loop_new (NULL, TRUE);

	if (run_tests) {
		uri = soup_uri_new ("http://localhost");
		uri->port = soup_server_get_port (server);
		errors = do_auth_tests (uri);
		soup_uri_free (uri);
	} else {
		printf ("Listening on port %d\n", soup_server_get_port (server));
		g_main_loop_run (loop);
	}

	g_main_loop_unref (loop);

	dprintf ("\n");
	if (errors) {
		printf ("server-auth-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("server-auth-test: OK\n");
	return errors != 0;
}
