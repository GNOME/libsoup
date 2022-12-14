/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 * Copyright (C) 2013 Igalia, S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <gio/gio.h>
#ifdef G_OS_UNIX
#include <gio/gunixinputstream.h>
#endif

#include <libsoup/soup.h>

static SoupSession *session;
static GMainLoop *loop;
static gboolean debug, head, expect_continue, quiet, ignore_tls;
static const gchar *method;
static const gchar *output_file_path;
static const gchar *input_file_path;

#define OUTPUT_BUFFER_SIZE 8192

static void
on_request_spliced (GObject *source, GAsyncResult *result, gpointer user_data)
{
        GError *error = NULL;

        if (soup_session_send_and_splice_finish (SOUP_SESSION (source), result, &error) == -1) {
                g_printerr ("Failed to send request: %s\n", error->message);
                g_error_free (error);
        }

        g_main_loop_quit (loop);
}

static void
on_read_ready (GObject *source, GAsyncResult *result, gpointer user_data)
{
        GInputStream *in = G_INPUT_STREAM (source);
        GError *error = NULL;
        gsize bytes_read = 0;
        char *output_buffer = user_data;

        g_input_stream_read_all_finish (in, result, &bytes_read, &error);

        if (bytes_read) {
                g_print ("%.*s", (int)bytes_read, output_buffer);
        }

        if (error) {
                g_printerr ("\nFailed to read stream: %s\n", error->message);
                g_error_free (error);
                g_free (output_buffer);
                g_main_loop_quit (loop);
        } else if (!bytes_read) {
                g_print ("\n");
                g_free (output_buffer);
                g_main_loop_quit (loop);
        } else {
                g_input_stream_read_all_async (in, output_buffer, OUTPUT_BUFFER_SIZE,
                                               G_PRIORITY_DEFAULT, NULL, on_read_ready, output_buffer);
        }
}

static void
on_request_sent (GObject *source, GAsyncResult *result, gpointer user_data)
{
        char *output_buffer;
        GError *error = NULL;
        GInputStream *in = soup_session_send_finish (SOUP_SESSION (source), result, &error);

        if (error) {
                g_printerr ("Failed to send request: %s\n", error->message);
                g_error_free (error);
                g_main_loop_quit (loop);
                return;
        }

        output_buffer = g_new (char, OUTPUT_BUFFER_SIZE);
        g_input_stream_read_all_async (in, output_buffer, OUTPUT_BUFFER_SIZE,
                                       G_PRIORITY_DEFAULT, NULL, on_read_ready, output_buffer);
        g_object_unref (in);
}

static gboolean
accept_certificate (SoupMessage         *msg,
                    GTlsCertificate     *certificate,
                    GTlsCertificateFlags errors)
{
        return TRUE;
}

static const char *ca_file, *proxy;
static char *client_cert_file, *client_key_file;
static char *user_agent;
static gboolean ntlm;
static gboolean negotiate;

static GOptionEntry entries[] = {
	{ "ca-file", 'c', 0,
	  G_OPTION_ARG_STRING, &ca_file,
	  "Use FILE as the TLS CA file", "FILE" },
	{ "cert", 0, 0,
	  G_OPTION_ARG_STRING, &client_cert_file,
	  "Use FILE as the TLS client certificate file", "FILE" },
	{ "key", 0, 0,
	  G_OPTION_ARG_STRING, &client_key_file,
	  "Use FILE as the TLS client key file", "FILE" },
        { "ignore-tls", 0, 0,
          G_OPTION_ARG_NONE, &ignore_tls,
          "Ignore TLS certificate errors", NULL },
	{ "debug", 'd', 0,
	  G_OPTION_ARG_NONE, &debug,
	  "Show HTTP headers", NULL },
        { "user-agent", 'u', 0,
          G_OPTION_ARG_STRING, &user_agent,
          "User agent string", "STRING" },
        { "method", 'm', 0,
          G_OPTION_ARG_STRING, &method,
          "HTTP method to use", "STRING" },
	{ "head", 'h', 0,
          G_OPTION_ARG_NONE, &head,
          "Do HEAD rather than GET (equivalent to --method=HEAD)", NULL },
        { "expect-continue", 0, 0,
          G_OPTION_ARG_NONE, &expect_continue,
          "Include Expects: 100-continue header in the request", NULL },
	{ "ntlm", 'n', 0,
	  G_OPTION_ARG_NONE, &ntlm,
	  "Use NTLM authentication", NULL },
	{ "output", 'o', 0,
	  G_OPTION_ARG_STRING, &output_file_path,
	  "Write the received data to FILE instead of stdout", "FILE" },
        { "input", 'i', 0,
          G_OPTION_ARG_STRING, &input_file_path,
          "Read data from FILE when method is PUT or POST", "FILE" },
	{ "proxy", 'p', 0,
	  G_OPTION_ARG_STRING, &proxy,
	  "Use URL as an HTTP proxy", "URL" },
	{ "quiet", 'q', 0,
	  G_OPTION_ARG_NONE, &quiet,
	  "Don't show HTTP status code", NULL },
	{ NULL }
};

static GOptionEntry negotiate_entries[] = {
	{ "negotiate", 'N', 0,
	  G_OPTION_ARG_NONE, &negotiate,
	  "Use Negotiate authentication", NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	const char *url;
	SoupMessage *msg;
	GUri *parsed;
        GTlsCertificate *client_cert = NULL;
	GError *error = NULL;

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);
	if (soup_auth_negotiate_supported())
		g_option_context_add_main_entries (opts, negotiate_entries, NULL);
	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}

	if (argc != 2) {
		char *help = g_option_context_get_help (opts, TRUE, NULL);
		g_printerr ("%s", help);
		g_free (help);
		exit (1);
	}
	g_option_context_free (opts);

        /* Validate the URL */
	url = argv[1];
	parsed = g_uri_parse (url, SOUP_HTTP_URI_FLAGS, &error);
	if (!parsed) {
		g_printerr ("Could not parse '%s' as a URL: %s\n", url, error->message);
		exit (1);
	}
	g_uri_unref (parsed);

        /* Build the session with all of the features we need */
	session = soup_session_new_with_options ("user-agent", "get ",
                                                 "accept-language-auto", TRUE,
                                                 "timeout", 15,
                                                 NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);
	if (ntlm)
		soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);
#ifdef LIBSOUP_HAVE_GSSAPI
	if (negotiate)
		soup_session_add_feature_by_type (session,
						  SOUP_TYPE_AUTH_NEGOTIATE);
#endif

        if (ca_file) {
                GTlsDatabase *tls_db = g_tls_file_database_new (ca_file, &error);
                if (error) {
                        g_printerr ("Failed to load TLS database \"%s\": %s", ca_file, error->message);
                        g_error_free (error);
                        g_object_unref (session);
                        exit (1);
                }

		soup_session_set_tls_database (session, tls_db);
                g_object_unref (tls_db);
        }

	if (client_cert_file) {
		if (!client_key_file) {
			g_printerr ("--key is required with --cert\n");
                        g_object_unref (session);
			exit (1);
		}
		client_cert = g_tls_certificate_new_from_files (client_cert_file, client_key_file, &error);
		if (!client_cert) {
			g_printerr ("%s\n", error->message);
                        g_error_free (error);
                        g_object_unref (session);
			exit (1);
		}
	}

        if (user_agent)
                soup_session_set_user_agent (session, user_agent);

	if (debug) {
		SoupLogger *logger = soup_logger_new (SOUP_LOGGER_LOG_HEADERS);
		soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
		g_object_unref (logger);
	}

	if (proxy) {
		GProxyResolver *resolver;
		GUri *proxy_uri = g_uri_parse (proxy, SOUP_HTTP_URI_FLAGS, &error);
		if (!proxy_uri) {
			g_printerr ("Could not parse '%s' as URI: %s\n",
				    proxy, error->message);
                        g_error_free (error);
                        g_object_unref (session);
			exit (1);
		}

		resolver = g_simple_proxy_resolver_new (proxy, NULL);
		soup_session_set_proxy_resolver (session, resolver);
		g_uri_unref (proxy_uri);
		g_object_unref (resolver);
	}

        if (!method)
                method = head ? "HEAD" : "GET";
        msg = soup_message_new (method, url);

        if (g_strcmp0 (method, "PUT") == 0 || g_strcmp0 (method, "POST") == 0) {
                GInputStream *stream;

                if (input_file_path) {
                        GFile *input_file = g_file_new_for_commandline_arg (input_file_path);
                        stream = G_INPUT_STREAM (g_file_read (input_file, NULL, &error));
                        if (!stream) {
                                g_printerr ("Failed to open input file \"%s\": %s\n", input_file_path, error->message);
                                g_error_free (error);
                                g_object_unref (session);
                                exit (1);
                        }
                } else {
#ifdef G_OS_UNIX
                        stream = g_unix_input_stream_new (0, FALSE);
#else
                        g_printerr ("Input file is required for method %s\n", method);
                        g_object_unref (session);
                        exit (1);
#endif
                }

                soup_message_set_request_body (msg, NULL, stream, -1);
                g_object_unref (stream);

                if (expect_continue) {
                        soup_message_headers_set_expectations (soup_message_get_request_headers (msg),
                                                               SOUP_EXPECTATION_CONTINUE);
                }
        }

        if (ignore_tls) {
                g_signal_connect (msg, "accept-certificate",
                                  G_CALLBACK (accept_certificate),
                                  NULL);
        }

        /* Send the request */
        soup_message_set_tls_client_certificate (msg, client_cert);
        if (output_file_path) {
                GFile *output_file = g_file_new_for_commandline_arg (output_file_path);
                GOutputStream *out = G_OUTPUT_STREAM (g_file_create (output_file, G_FILE_CREATE_NONE,
                                                                     NULL, &error));

                if (error) {
                        g_print ("Failed to create \"%s\": %s\n", output_file_path, error->message);
                        g_error_free (error);
                        g_object_unref (output_file);
                        g_object_unref (msg);
                        g_object_unref (session);
                        exit (1);
                }
                soup_session_send_and_splice_async (session, msg, out,
                                                    G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                                    G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                                    G_PRIORITY_DEFAULT,
                                                    NULL, on_request_spliced, NULL);
                g_object_unref (output_file);
                g_object_unref (out);
        } else {
                soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL,
                                         on_request_sent, NULL);
        }
	g_object_unref (msg);

        /* Run the loop */
        loop = g_main_loop_new (NULL, FALSE);
        g_main_loop_run (loop);
	g_main_loop_unref (loop);
	g_object_unref (session);

	return 0;
}
