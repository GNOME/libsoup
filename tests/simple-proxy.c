/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>

/* WARNING: this is really really really not especially compliant with
 * RFC 2616. But it does work for basic stuff.
 */

static void
server_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
	char *uristr;

	uristr = soup_uri_to_string (soup_context_get_uri (msg->context), FALSE);
	printf ("%s %s HTTP/1.%d\n", msg->method, uristr,
		soup_message_get_http_version (msg));

	if (soup_method_get_id (msg->method) == SOUP_METHOD_ID_CONNECT) {
		/* FIXME */
		return;
	}

	soup_message_send (msg);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	int opt;
	int port = SOUP_SERVER_ANY_PORT;
	SoupServer *server;

	while ((opt = getopt (argc, argv, "p:s:")) != -1) {
		switch (opt) {
		case 'p':
			port = atoi (optarg);
			break;
		default:
			fprintf (stderr, "Usage: %s [-p port] [-n]\n",
				 argv[0]);
			exit (1);
		}
	}

	server = soup_server_new (SOUP_PROTOCOL_HTTP, port);
	if (!server) {
		fprintf (stderr, "Unable to bind to server port %d\n", port);
		exit (1);
	}
	soup_server_register (server, NULL, NULL, server_callback, NULL, NULL);

	printf ("\nStarting proxy on port %d\n",
		soup_server_get_port (server));
	soup_server_run_async (server);

	printf ("\nWaiting for requests...\n");

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);

	return 0;
}
