/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include "test-utils.h"
#include <stdio.h>

#ifdef G_OS_WIN32
#include <getopt.h>
#endif

static SoupSession *session;
static GMainLoop *loop;
static gboolean debug = FALSE, quiet = FALSE;
static const char *method;

static void
get_url (const char *url)
{
	const char *name;
	SoupMessage *msg;
	const char *header;

	msg = soup_message_new (method, url);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	soup_session_send_message (session, msg);

	name = soup_message_get_uri (msg)->path;

	if (debug) {
		SoupMessageHeadersIter iter;
		const char *hname, *value;
		char *path = soup_uri_to_string (soup_message_get_uri (msg), TRUE);

		g_print ("%s %s HTTP/1.%d\n", method, path,
			 soup_message_get_http_version (msg));
		soup_message_headers_iter_init (&iter, msg->request_headers);
		while (soup_message_headers_iter_next (&iter, &hname, &value))
			g_print ("%s: %s\r\n", hname, value);
		g_print ("\n");

		g_print ("HTTP/1.%d %d %s\n",
			 soup_message_get_http_version (msg),
			 msg->status_code, msg->reason_phrase);

		soup_message_headers_iter_init (&iter, msg->response_headers);
		while (soup_message_headers_iter_next (&iter, &hname, &value))
			g_print ("%s: %s\r\n", hname, value);
		g_print ("\n");
	} else if (msg->status_code == SOUP_STATUS_SSL_FAILED) {
		GTlsCertificateFlags flags;

		if (soup_message_get_https_status (msg, NULL, &flags))
			g_print ("%s: %d %s (0x%x)\n", name, msg->status_code, msg->reason_phrase, flags);
		else
			g_print ("%s: %d %s (no handshake status)\n", name, msg->status_code, msg->reason_phrase);
	} else if (!quiet || SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
		g_print ("%s: %d %s\n", name, msg->status_code, msg->reason_phrase);

	if (SOUP_STATUS_IS_REDIRECTION (msg->status_code)) {
		header = soup_message_headers_get_one (msg->response_headers,
						       "Location");
		if (header) {
			SoupURI *uri;
			char *uri_string;

			if (!debug && !quiet)
				g_print ("  -> %s\n", header);

			uri = soup_uri_new_with_base (soup_message_get_uri (msg), header);
			uri_string = soup_uri_to_string (uri, FALSE);
			get_url (uri_string);
			g_free (uri_string);
			soup_uri_free (uri);
		}
	} else if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		fwrite (msg->response_body->data, 1,
			msg->response_body->length, stdout);
	}
}

static void
usage (void)
{
	g_printerr ("Usage: get [-c CAfile] [-p proxy URL] [-h] [-d] URL\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	const char *cafile = NULL, *url;
	SoupURI *proxy = NULL, *parsed;
	gboolean synchronous = FALSE, ntlm = FALSE;
	int opt;

	method = SOUP_METHOD_GET;

	while ((opt = getopt (argc, argv, "c:dhnp:qs")) != -1) {
		switch (opt) {
		case 'c':
			cafile = optarg;
			break;

		case 'd':
			debug = TRUE;
			break;

		case 'h':
			method = SOUP_METHOD_HEAD;
			debug = TRUE;
			break;

		case 'n':
			ntlm = TRUE;
			break;

		case 'p':
			proxy = soup_uri_new (optarg);
			if (!proxy) {
				g_printerr ("Could not parse %s as URI\n",
					    optarg);
				exit (1);
			}
			break;

		case 'q':
			quiet = TRUE;
			break;

		case 's':
			synchronous = TRUE;
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
	url = argv[0];
	parsed = soup_uri_new (url);
	if (!parsed) {
		g_printerr ("Could not parse '%s' as a URL\n", url);
		exit (1);
	}
	soup_uri_free (parsed);

	if (synchronous) {
		session = soup_session_sync_new_with_options (
			SOUP_SESSION_SSL_CA_FILE, cafile,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_COOKIE_JAR,
			SOUP_SESSION_USER_AGENT, "get ",
			SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
			SOUP_SESSION_USE_NTLM, ntlm,
			NULL);
	} else {
		session = soup_session_async_new_with_options (
			SOUP_SESSION_SSL_CA_FILE, cafile,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_COOKIE_JAR,
			SOUP_SESSION_USER_AGENT, "get ",
			SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
			SOUP_SESSION_USE_NTLM, ntlm,
			NULL);
	}

	if (proxy) {
		g_object_set (G_OBJECT (session), 
			      SOUP_SESSION_PROXY_URI, proxy,
			      NULL);
	} else
		soup_session_add_feature_by_type (session, SOUP_TYPE_PROXY_RESOLVER_DEFAULT);

	if (!synchronous)
		loop = g_main_loop_new (NULL, TRUE);

	get_url (url);

	if (!synchronous)
		g_main_loop_unref (loop);

	return 0;
}
