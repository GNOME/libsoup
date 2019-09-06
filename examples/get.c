/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 * Copyright (C) 2013 Igalia, S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
	g_object_unref (msg);
}

/* Inline class for providing a pre-configured client certificate */
typedef struct _GetTlsCertInteraction        GetTlsCertInteraction;
typedef struct _GetTlsCertInteractionClass   GetTlsCertInteractionClass;

static GType                    _get_tls_cert_interaction_get_type    (void) G_GNUC_CONST;
static GetTlsCertInteraction *  _get_tls_cert_interaction_new         (GTlsCertificate *cert);

struct _GetTlsCertInteraction
{
	GTlsInteraction parent_instance;
	GTlsCertificate *cert;
};

struct _GetTlsCertInteractionClass
{
	GTlsInteractionClass parent_class;
};

G_DEFINE_TYPE (GetTlsCertInteraction, _get_tls_cert_interaction, G_TYPE_TLS_INTERACTION);

static GTlsInteractionResult
request_certificate (GTlsInteraction              *interaction,
                     GTlsConnection               *connection,
                     GTlsCertificateRequestFlags   flags,
                     GCancellable                 *cancellable,
                     GError                      **error)
{
	GetTlsCertInteraction *self = (GetTlsCertInteraction*)interaction;
	g_tls_connection_set_certificate (connection, self->cert);
	return G_TLS_INTERACTION_HANDLED;
}

static void
_get_tls_cert_interaction_init (GetTlsCertInteraction *interaction)
{
}

static void
_get_tls_cert_interaction_class_init (GetTlsCertInteractionClass *klass)
{
	GTlsInteractionClass *interaction_class = G_TLS_INTERACTION_CLASS (klass);
	interaction_class->request_certificate = request_certificate;
}

GetTlsCertInteraction *
_get_tls_cert_interaction_new (GTlsCertificate *cert)
{
	GetTlsCertInteraction *self = g_object_new (_get_tls_cert_interaction_get_type (), NULL);
	self->cert = g_object_ref (cert);
	return self;
}

static const char *ca_file, *proxy;
static char *client_cert_file, *client_key_file;
static gboolean synchronous, ntlm;
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
	SoupURI *proxy_uri, *parsed;
	GError *error = NULL;
	SoupLogger *logger = NULL;
	char *help;

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
		help = g_option_context_get_help (opts, TRUE, NULL);
		g_printerr ("%s", help);
		g_free (help);
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
				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
				SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_COOKIE_JAR,
				SOUP_SESSION_USER_AGENT, "get ",
				SOUP_SESSION_ACCEPT_LANGUAGE_AUTO, TRUE,
				NULL);
	if (ntlm)
		soup_session_add_feature_by_type (session, SOUP_TYPE_AUTH_NTLM);
	if (ca_file)
		g_object_set (session, "ssl-ca-file", ca_file, NULL);

	if (client_cert_file) {
		GTlsCertificate *client_cert;
		GetTlsCertInteraction *interaction;
		if (!client_key_file) {
			g_printerr ("--key is required with --cert\n");
			exit (1);
		}
		client_cert = g_tls_certificate_new_from_files (client_cert_file, client_key_file, &error);
		if (!client_cert) {
			g_printerr ("%s\n", error->message);
			exit (1);
		}
		interaction = _get_tls_cert_interaction_new (client_cert);
		g_object_set (session, SOUP_SESSION_TLS_INTERACTION, interaction, NULL);
	}

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

#ifdef LIBSOUP_HAVE_GSSAPI
	if (negotiate) {
		soup_session_add_feature_by_type (session,
						  SOUP_TYPE_AUTH_NEGOTIATE);
	}
#endif /* LIBSOUP_HAVE_GSSAPI */

	if (!synchronous)
		loop = g_main_loop_new (NULL, TRUE);

	get_url (url);

	if (!synchronous)
		g_main_loop_unref (loop);

	g_object_unref (session);

	return 0;
}
