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

static char *base_uri;

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
 */

static void
do_host_test (void)
{
	SoupSession *session;
	SoupMessage *one, *two;

	debug_printf (1, "Host handling\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC, NULL);

	one = soup_message_new ("GET", base_uri);
	two = soup_message_new ("GET", base_uri);
	soup_message_headers_replace (two->request_headers, "Host", "foo");

	soup_session_send_message (session, one);
	soup_session_send_message (session, two);

	soup_session_abort (session);
	g_object_unref (session);

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

int
main (int argc, char **argv)
{
	SoupServer *server;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = g_strdup_printf ("http://localhost:%u/",
				    soup_server_get_port (server));

	do_host_test ();

	g_free (base_uri);

	test_cleanup ();
	return errors != 0;
}
