/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
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
#include <libsoup/soup.h>

#include "test-utils.h"

SoupURI *base_uri;

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SoupURI *uri = soup_message_get_uri (msg);

	if (msg->method != SOUP_METHOD_GET) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (!strcmp (path, "/redirect")) {
		soup_message_set_status (msg, SOUP_STATUS_FOUND);
		soup_message_headers_append (msg->response_headers,
					     /* Kids: don't try this at home!
					      * RFC2616 says to use an
					      * absolute URI!
					      */
					     "Location", "/");
		return;
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
 * #539803.
 */
static void
do_host_test (void)
{
	SoupSession *session;
	SoupMessage *one, *two;

	debug_printf (1, "Host handling\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	one = soup_message_new_from_uri ("GET", base_uri);
	two = soup_message_new_from_uri ("GET", base_uri);
	soup_message_headers_replace (two->request_headers, "Host", "foo");

	soup_session_send_message (session, one);
	soup_session_send_message (session, two);

	soup_test_session_abort_unref (session);

	if (!SOUP_STATUS_IS_SUCCESSFUL (one->status_code)) {
		debug_printf (1, "  Message 1 failed: %d %s\n",
			      one->status_code, one->reason_phrase);
		errors++;
	} else if (strcmp (one->response_body->data, "index") != 0) {
		debug_printf (1, "  Unexpected response to message 1: '%s'\n",
			      one->response_body->data);
		errors++;
	}
	g_object_unref (one);

	if (!SOUP_STATUS_IS_SUCCESSFUL (two->status_code)) {
		debug_printf (1, "  Message 2 failed: %d %s\n",
			      two->status_code, two->reason_phrase);
		errors++;
	} else if (strcmp (two->response_body->data, "foo-index") != 0) {
		debug_printf (1, "  Unexpected response to message 2: '%s'\n",
			      two->response_body->data);
		errors++;
	}
	g_object_unref (two);
}

/* Dropping the application's ref on the session from a callback
 * should not cause the session to be freed at an incorrect time.
 * (This test will crash if it fails.) #533473
 */
static void
cu_one_completed (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	debug_printf (2, "  Message 1 completed\n");
	if (msg->status_code != SOUP_STATUS_CANT_CONNECT) {
		debug_printf (1, "  Unexpected status on Message 1: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
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
	if (msg->status_code != SOUP_STATUS_CANT_CONNECT) {
		debug_printf (1, "  Unexpected status on Message 2: %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_idle_add (cu_idle_quit, loop); 
}

static void
do_callback_unref_test (void)
{
	SoupServer *bad_server;
	SoupSession *session;
	SoupMessage *one, *two;
	GMainLoop *loop;
	char *bad_uri;

	debug_printf (1, "\nCallback unref handling\n");

	/* Get a guaranteed-bad URI */
	bad_server = soup_server_new (NULL, NULL);
	bad_uri = g_strdup_printf ("http://localhost:%u/",
				   soup_server_get_port (bad_server));
	g_object_unref (bad_server);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	g_object_add_weak_pointer (G_OBJECT (session), (gpointer *)&session);

	loop = g_main_loop_new (NULL, TRUE);

	one = soup_message_new ("GET", bad_uri);
	g_object_add_weak_pointer (G_OBJECT (one), (gpointer *)&one);
	two = soup_message_new ("GET", bad_uri);
	g_object_add_weak_pointer (G_OBJECT (two), (gpointer *)&two);
	g_free (bad_uri);

	soup_session_queue_message (session, one, cu_one_completed, loop);
	soup_session_queue_message (session, two, cu_two_completed, loop);

	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	if (session) {
		g_object_remove_weak_pointer (G_OBJECT (session), (gpointer *)&session);
		debug_printf (1, "  Session not destroyed?\n");
		errors++;
		g_object_unref (session);
	}
	if (one) {
		g_object_remove_weak_pointer (G_OBJECT (one), (gpointer *)&one);
		debug_printf (1, "  Message 1 not destroyed?\n");
		errors++;
		g_object_unref (one);
	}
	if (two) {
		g_object_remove_weak_pointer (G_OBJECT (two), (gpointer *)&two);
		debug_printf (1, "  Message 2 not destroyed?\n");
		errors++;
		g_object_unref (two);
	}

	/* Otherwise, if we haven't crashed, we're ok. */
}

/* SoupSession should clean up all signal handlers on a message after
 * it is finished, allowing the message to be reused if desired.
 * #559054
 */
static void
ensure_no_signal_handlers (SoupMessage *msg, guint *signal_ids, guint n_signal_ids)
{
	int i;

	for (i = 0; i < n_signal_ids; i++) {
		if (g_signal_handler_find (msg, G_SIGNAL_MATCH_ID, signal_ids[i],
					   0, NULL, NULL, NULL)) {
			debug_printf (1, "    Message has handler for '%s'\n",
				      g_signal_name (signal_ids[i]));
			errors++;
		}
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

	debug_printf (1, "\nSoupMessage reuse\n");

	signal_ids = g_signal_list_ids (SOUP_TYPE_MESSAGE, &n_signal_ids);

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);
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
	if (!soup_uri_equal (soup_message_get_uri (msg), base_uri)) {
		debug_printf (1, "    Message did not get redirected!\n");
		errors++;
	}
	ensure_no_signal_handlers (msg, signal_ids, n_signal_ids);

	debug_printf (1, "  Auth message\n");
	uri = soup_uri_new_with_base (base_uri, "/auth");
	soup_message_set_uri (msg, uri);
	soup_uri_free (uri);
	soup_session_send_message (session, msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    Message did not get authenticated!\n");
		errors++;
	}
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

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupAuthDomain *auth_domain;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://localhost/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	auth_domain = soup_auth_domain_basic_new (
		SOUP_AUTH_DOMAIN_REALM, "misc-test",
		SOUP_AUTH_DOMAIN_ADD_PATH, "/auth",
		SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, auth_callback,
		NULL);
	soup_server_add_auth_domain (server, auth_domain);
	g_object_unref (auth_domain);

	do_host_test ();
	do_callback_unref_test ();
	do_msg_reuse_test ();

	soup_uri_free (base_uri);

	test_cleanup ();
	return errors != 0;
}
