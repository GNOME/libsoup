/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libsoup/soup.h>
#include <libsoup/soup-xmlrpc-message.h>
#include <libsoup/soup-xmlrpc-response.h>

SoupSession *session;
GMainLoop *loop;

static void
print_struct_field (gpointer key, gpointer value, gpointer data)
{
	char *str;
	if (soup_xmlrpc_value_get_string (value, &str))
		printf ("%s: %s\n", (char *)key, str);
}

static void
got_response (SoupMessage *msg, gpointer user_data)
{
	SoupXmlrpcResponse *response;
	SoupXmlrpcValue *value;
	GHashTable *hash;

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		fprintf (stderr, "%d %s\n", msg->status_code, msg->reason_phrase);
		exit (1);
	}

	response = soup_xmlrpc_message_parse_response (SOUP_XMLRPC_MESSAGE (msg));
	if (!response) {
		fprintf (stderr, "Could not parse XMLRPC response\n");
		exit (1);
	}

	value = soup_xmlrpc_response_get_value (response);
	if (!value) {
		fprintf (stderr, "No response value in XMLRPC response\n");
		exit (1);
	}

	if (!soup_xmlrpc_value_get_struct (value, &hash)) {
		fprintf (stderr, "Could not extract result from XMLRPC response\n");
		exit (1);
	}

	g_hash_table_foreach (hash, print_struct_field, NULL);
	g_hash_table_destroy (hash);

	g_object_unref (response);
	g_main_quit (loop);
}

static void
usage (void)
{
	fprintf (stderr, "Usage: getbug [-p proxy_uri] [bugzilla-uri] bug-number\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	SoupUri *proxy = NULL;
	SoupXmlrpcMessage *msg;
	char *uri = "http://bugzilla.redhat.com/bugzilla/xmlrpc.cgi";
	int opt, bug;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "p:")) != -1) {
		switch (opt) {
		case 'p':
			proxy = soup_uri_new (optarg);
			if (!proxy) {
				fprintf (stderr, "Could not parse %s as URI\n",
					 optarg);
				exit (1);
			}
			break;

		case '?':
			usage ();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 1) {
		uri = argv[0];
		argc--;
		argv++;
	}

	if (argc != 1 || (bug = atoi (argv[0])) == 0)
		usage ();

	session = soup_session_async_new_with_options (
		SOUP_SESSION_PROXY_URI, proxy,
		NULL);

	msg = soup_xmlrpc_message_new (uri);
	if (!msg) {
		fprintf (stderr, "Could not create web service request to '%s'\n", uri);
		exit (1);
	}

	soup_xmlrpc_message_start_call (msg, "bugzilla.getBug");
	soup_xmlrpc_message_start_param (msg);
	soup_xmlrpc_message_write_int (msg, bug);
	soup_xmlrpc_message_end_param (msg);
	soup_xmlrpc_message_end_call (msg);

	soup_xmlrpc_message_persist (msg);
	soup_session_queue_message (session, SOUP_MESSAGE (msg),
				    got_response, NULL);

	loop = g_main_loop_new (NULL, TRUE);
	g_main_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
