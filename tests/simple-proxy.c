/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
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
#include <libsoup/soup-session.h>

/* WARNING: this is really really really not especially compliant with
 * RFC 2616. But it does work for basic stuff.
 */

SoupSession *session;

static void
copy_header (gpointer name, gpointer value, gpointer dest_headers)
{
	soup_message_add_header (dest_headers, name, value);
}

static void
send_headers (SoupMessage *from, SoupMessage *to)
{
	printf ("[%p] HTTP/1.%d %d %s\n", to,
		soup_message_get_http_version (from),
		from->errorcode, from->errorphrase);

	soup_message_set_error_full (to, from->errorcode, from->errorphrase);
	soup_message_foreach_header (from->response_headers, copy_header,
				     to->response_headers);
	soup_message_remove_header (to->response_headers, "Content-Length");
	soup_message_io_unpause (to);
}

static void
send_chunk (SoupMessage *from, SoupMessage *to)
{
	printf ("[%p]   writing chunk of %d bytes\n", to, from->response.length);

	soup_message_add_chunk (to, SOUP_BUFFER_USER_OWNED,
				from->response.body, from->response.length);
	soup_message_io_unpause (to);
}

static void
client_msg_failed (SoupMessage *msg, gpointer msg2)
{
	soup_message_cancel (msg2);
}

static void
finish_msg (SoupMessage *msg2, gpointer msg)
{
	printf ("[%p]   done\n\n", msg);
	g_signal_handlers_disconnect_by_func (msg, client_msg_failed, msg2);

	soup_message_add_final_chunk (msg);
	soup_message_io_unpause (msg);
	g_object_unref (msg);
}

static void
server_callback (SoupServerContext *context, SoupMessage *msg, gpointer data)
{
	SoupMessage *msg2;
	char *uristr;

	uristr = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
	printf ("[%p] %s %s HTTP/1.%d\n", msg, msg->method, uristr,
		soup_message_get_http_version (msg));

	if (soup_method_get_id (msg->method) == SOUP_METHOD_ID_CONNECT) {
		soup_message_set_error (msg, SOUP_ERROR_NOT_IMPLEMENTED);
		return;
	}

	msg2 = soup_message_new (msg->method, uristr);
	soup_message_foreach_header (msg->request_headers, copy_header,
				     msg2->request_headers);
	soup_message_remove_header (msg2->request_headers, "Host");
	soup_message_remove_header (msg2->request_headers, "Connection");

	if (msg->request.length) {
		msg2->request.owner = SOUP_BUFFER_USER_OWNED;
		msg2->request.body = msg->request.body;
		msg2->request.length = msg->request.length;
	}
	soup_server_message_set_encoding (SOUP_SERVER_MESSAGE (msg),
					  SOUP_TRANSFER_CHUNKED);

	g_signal_connect (msg2, "got_headers",
			  G_CALLBACK (send_headers), msg);
	g_signal_connect (msg2, "got_chunk",
			  G_CALLBACK (send_chunk), msg);
	soup_message_set_flags (msg2, SOUP_MESSAGE_OVERWRITE_CHUNKS);

	g_signal_connect (msg, "finished", G_CALLBACK (client_msg_failed), msg2);

	soup_session_queue_message (session, msg2, finish_msg, msg);

	g_object_ref (msg);
	soup_message_io_pause (msg);
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
	int opt;
	int port = SOUP_ADDRESS_ANY_PORT;
	SoupServer *server;

	g_type_init ();
	signal (SIGINT, quit);

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
	soup_server_add_handler (server, NULL, NULL,
				 server_callback, NULL, NULL);

	printf ("\nStarting proxy on port %d\n",
		soup_server_get_port (server));
	soup_server_run_async (server);

	session = soup_session_new ();

	printf ("\nWaiting for requests...\n");

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
