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
#include <libsoup/soup-soap-message.h>
#include <libsoup/soup-soap-response.h>

SoupSession *session;
GMainLoop *loop;

static void
got_response (SoupMessage *msg, gpointer user_data)
{
	SoupSoapResponse *response;
	SoupSoapParameter *param, *subparam;
	char *word, *dict, *def;
	int count = 0;

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		fprintf (stderr, "%d %s\n", msg->status_code, msg->reason_phrase);
		exit (1);
	}

	response = soup_soap_message_parse_response (SOUP_SOAP_MESSAGE (msg));
	if (!response) {
		fprintf (stderr, "Could not parse SOAP response\n");
		exit (1);
	}

	param = soup_soap_response_get_first_parameter_by_name (response, "DefineResult");
	if (!param) {
		fprintf (stderr, "Could not find result in SOAP response\n");
		exit (1);
	}

	param = soup_soap_parameter_get_first_child_by_name (param, "Definitions");
	if (!param)
		goto done;

	for (param = soup_soap_parameter_get_first_child_by_name (param, "Definition");
	     param;
	     param = soup_soap_parameter_get_next_child_by_name (param, "Definition")) {
		subparam = soup_soap_parameter_get_first_child_by_name (param, "Word");
		if (!subparam)
			continue;
		word = soup_soap_parameter_get_string_value (subparam);

		subparam = soup_soap_parameter_get_first_child_by_name (param, "Dictionary");
		if (subparam)
			subparam = soup_soap_parameter_get_first_child_by_name (subparam, "Name");
		if (subparam)
			dict = soup_soap_parameter_get_string_value (subparam);
		else
			dict = NULL;

		printf ("% 2d. %s (%s):\n", ++count, word, dict);
		g_free (word);
		g_free (dict);

		subparam = soup_soap_parameter_get_first_child_by_name (param, "WordDefinition");
		if (subparam) {
			def = soup_soap_parameter_get_string_value (subparam);
			printf ("%s\n", def);
			g_free (def);
		}
	}

 done:
	if (count == 0)
		printf ("No definition\n");

	g_object_unref (response);
	g_main_quit (loop);
}

static void
usage (void)
{
	fprintf (stderr, "Usage: dict [-p proxy_uri] WORD\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	SoupUri *proxy = NULL;
	SoupSoapMessage *msg;
	int opt;

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

	if (argc != 1)
		usage ();

	session = soup_session_async_new_with_options (
		SOUP_SESSION_PROXY_URI, proxy,
		NULL);

	msg = soup_soap_message_new ("POST",
				     "http://services.aonaware.com/DictService/DictService.asmx",
				     FALSE, NULL, NULL, NULL);
	if (!msg) {
		fprintf (stderr, "Could not create web service request\n");
		exit (1);
	}

	soup_message_add_header (SOUP_MESSAGE (msg)->request_headers,
				 "SOAPAction", "http://services.aonaware.com/webservices/Define");

	soup_soap_message_start_envelope (msg);
	soup_soap_message_start_body (msg);

	soup_soap_message_start_element (msg, "Define", NULL,
					 "http://services.aonaware.com/webservices/");
	soup_soap_message_add_namespace (msg, NULL, "http://services.aonaware.com/webservices/");
	soup_soap_message_start_element (msg, "word", NULL, NULL);
	soup_soap_message_write_string (msg, argv[0]);
	soup_soap_message_end_element (msg);
	soup_soap_message_end_element (msg);

	soup_soap_message_end_body (msg);
	soup_soap_message_end_envelope (msg);
	soup_soap_message_persist (msg);

	soup_session_queue_message (session, SOUP_MESSAGE (msg),
				    got_response, NULL);

	loop = g_main_loop_new (NULL, TRUE);
	g_main_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
