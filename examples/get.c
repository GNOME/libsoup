/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 * Copyright (C) 2013 Igalia, S.L.
 */

#include <stdio.h>
#include <stdlib.h>

#include <libsoup/soup.h>

static SoupSession *session;
static GMainLoop *loop;
static gboolean debug, head, quiet;
static const gchar *output_file_path = NULL;

static void
finished (SoupSession *session, SoupMessage *msg, gpointer loop)
{
	g_main_loop_quit (loop);
}

static void
get_url (const char *url)
{
	const char *name;
	SoupMessage *msg;
	const char *header;
	FILE *output_file = NULL;

	msg = soup_message_new (head ? "HEAD" : "GET", url);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	if (loop) {
		g_object_ref (msg);
		soup_session_queue_message (session, msg, finished, loop);
		g_main_loop_run (loop);
	} else
		soup_session_send_message (session, msg);

	name = soup_message_get_uri (msg)->path;

	if (!debug) {
		if (msg->status_code == SOUP_STATUS_SSL_FAILED) {
			GTlsCertificateFlags flags;

			if (soup_message_get_https_status (msg, NULL, &flags))
				g_print ("%s: %d %s (0x%x)\n", name, msg->status_code, msg->reason_phrase, flags);
			else
				g_print ("%s: %d %s (no handshake status)\n", name, msg->status_code, msg->reason_phrase);
		} else if (!quiet || SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code))
			g_print ("%s: %d %s\n", name, msg->status_code, msg->reason_phrase);
	}

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
	} else if (!head && SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		if (output_file_path) {
			output_file = fopen (output_file_path, "w");
			if (!output_file)
				g_printerr ("Error trying to create file %s.\n", output_file_path);
		} else if (!quiet)
			output_file = stdout;

		if (output_file) {
			fwrite (msg->response_body->data,
				1,
				msg->response_body->length,
				output_file);

			if (output_file_path)
				fclose (output_file);
		}
	}
}

static const char *ca_file, *proxy;
static gboolean synchronous, ntlm;

static GOptionEntry entries[] = {
	{ "ca-file", 'c', 0,
	  G_OPTION_ARG_STRING, &ca_file,
	  "Use FILE as the TLS CA file", "FILE" },
	{ "debug", 'd', 0,
	  G_OPTION_ARG_NONE, &debug,
	  "Show HTTP headers", NULL },
	{ "head", 'h', 0,
	  G_OPTION_ARG_NONE, &head,
	  "Do HEAD rather than GET", NULL },
	{ "ntlm", 'n', 0,
	  G_OPTION_ARG_NONE, &ntlm,
	  "Use NTLM authentication", NULL },
	{ "output", 'o', 0,
	  G_OPTION_ARG_STRING, &output_file_path,
	  "Write the received data to FILE instead of stdout", "FILE" },
	{ "proxy", 'p', 0,
	  G_OPTION_ARG_STRING, &proxy,
	  "Use URL as an HTTP proxy", "URL" },
	{ "quiet", 'q', 0,
	  G_OPTION_ARG_NONE, &quiet,
	  "Don't show HTTP status code", NULL },
	{ "sync", 's', 0,
	  G_OPTION_ARG_NONE, &synchronous,
	  "Use SoupSessionSync rather than SoupSessionAsync", NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	const char *url;
	SoupURI *proxy_uri, *parsed;
	GError *error = NULL;
	SoupLogger *logger = NULL;

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);
	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}

	if (argc != 2) {
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	g_option_context_free (opts);

	url = argv[1];
	parsed = soup_uri_new (url);
	if (!parsed) {
		g_printerr ("Could not parse '%s' as a URL\n", url);
		exit (1);
	}
	soup_uri_free (parsed);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_SSL_CA_FILE, ca_file,
				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_COOKIE_JAR,
				SOUP_SESSION_USER_AGENT, "get ",
				SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
				NULL);
	if (ntlm)
		soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);

	if (debug) {
		logger = soup_logger_new (SOUP_LOGGER_LOG_BODY, -1);
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
		g_object_unref (logger);
	}

	if (proxy) {
		proxy_uri = soup_uri_new (proxy);
		if (!proxy_uri) {
			g_printerr ("Could not parse '%s' as URI\n",
				    proxy);
			exit (1);
		}

		g_object_set (G_OBJECT (session),
			      SOUP_SESSION_PROXY_URI, proxy_uri,
			      NULL);
		soup_uri_free (proxy_uri);
	}

	if (!synchronous)
		loop = g_main_loop_new (NULL, TRUE);

	get_url (url);

	if (!synchronous)
		g_main_loop_unref (loop);

	return 0;
}
