/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifdef HAVE_GNOME
#include <libsoup/soup-gnome.h>
#else
#include <libsoup/soup.h>
#endif

static SoupSession *session;
static GMainLoop *loop;
static gboolean debug = FALSE;
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

		printf ("%s %s HTTP/1.%d\n\n", method, path,
			soup_message_get_http_version (msg));
		printf ("HTTP/1.%d %d %s\n",
			soup_message_get_http_version (msg),
			msg->status_code, msg->reason_phrase);

		soup_message_headers_iter_init (&iter, msg->response_headers);
		while (soup_message_headers_iter_next (&iter, &hname, &value))
			printf ("%s: %s\r\n", hname, value);
		printf ("\n");
	} else
		printf ("%s: %d %s\n", name, msg->status_code, msg->reason_phrase);

	if (SOUP_STATUS_IS_REDIRECTION (msg->status_code)) {
		header = soup_message_headers_get_one (msg->response_headers,
						       "Location");
		if (header) {
			if (!debug)
				printf ("  -> %s\n", header);
			get_url (header);
		}
	} else if (SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		fwrite (msg->response_body->data, 1,
			msg->response_body->length, stdout);
	}
}

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      SoupAuth *auth, gpointer user_data)
{
	char *uri;
	GSList *saved_users;
	struct termios t;
	int old_lflag;
	char user[80], pwbuf[80];
	const char *password;

	if (tcgetattr (STDIN_FILENO, &t) != 0)
		return;

	uri = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
	fprintf (stderr, "Authentication required for %s:\n", uri);
	g_free (uri);
	fprintf (stderr, "  Realm: %s, Auth type: %s\n",
		soup_auth_get_realm (auth), soup_auth_get_scheme_name (auth));

	saved_users = soup_auth_get_saved_users (auth);
	if (saved_users) {
		GSList *u;

		fprintf (stderr, "  Passwords saved for: ");
		for (u = saved_users; u; u = u->next) {
			if (u != saved_users)
				fprintf (stderr, ", ");
			fprintf (stderr, "%s", (char *)u->data);
		}
		fprintf (stderr, "\n");
	}
	g_slist_free (saved_users);

	fprintf (stderr, "  username: ");
	fflush (stderr);

	if (!fgets (user, sizeof (user), stdin) || user[0] == '\n')
		return;
	*strchr (user, '\n') = '\0';

	password = soup_auth_get_saved_password (auth, user);
	if (!password) {
		fprintf (stderr, "  password: ");
		fflush (stderr);

		old_lflag = t.c_lflag;
		t.c_lflag = (t.c_lflag | ICANON | ECHONL) & ~ECHO;
		tcsetattr (STDIN_FILENO, TCSANOW, &t);

		/* For some reason, fgets can return EINTR on
		 * Linux if ECHO is false...
		 */
		do
			password = fgets (pwbuf, sizeof (pwbuf), stdin);
		while (password == NULL && errno == EINTR);

		t.c_lflag = old_lflag;
		tcsetattr (STDIN_FILENO, TCSANOW, &t);

		if (!password || pwbuf[0] == '\n')
			return;
		*strchr (pwbuf, '\n') = '\0';
	}

	soup_auth_authenticate (auth, user, password);
	soup_auth_save_password (auth, user, password);
}

static void
usage (void)
{
	fprintf (stderr, "Usage: get [-c CAfile] [-p proxy URL] [-h] [-d] URL\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	const char *cafile = NULL, *url;
	SoupURI *proxy = NULL, *parsed;
	gboolean synchronous = FALSE;
	int opt;

	g_thread_init (NULL);
	g_type_init ();
	g_set_application_name ("get");

	method = SOUP_METHOD_GET;

	while ((opt = getopt (argc, argv, "c:dhp:s")) != -1) {
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

		case 'p':
			proxy = soup_uri_new (optarg);
			if (!proxy) {
				fprintf (stderr, "Could not parse %s as URI\n",
					 optarg);
				exit (1);
			}
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
		fprintf (stderr, "Could not parse '%s' as a URL\n", url);
		exit (1);
	}
	soup_uri_free (parsed);

	if (synchronous) {
		session = soup_session_sync_new_with_options (
			SOUP_SESSION_SSL_CA_FILE, cafile,
#ifdef HAVE_GNOME
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_GNOME_FEATURES_2_26,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_PASSWORD_MANAGER_GNOME,
#endif
			SOUP_SESSION_USER_AGENT, "get ",
			NULL);
	} else {
		session = soup_session_async_new_with_options (
			SOUP_SESSION_SSL_CA_FILE, cafile,
#ifdef HAVE_GNOME
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_GNOME_FEATURES_2_26,
			SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_PASSWORD_MANAGER_GNOME,
#endif
			SOUP_SESSION_USER_AGENT, "get ",
			NULL);
	}
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);

	/* Need to do this after creating the session, since adding
	 * SOUP_TYPE_GNOME_FEATURE_2_26 will add a proxy resolver, thereby
	 * bashing over the manually-set proxy.
	 */
	if (proxy) {
		g_object_set (G_OBJECT (session), 
			      SOUP_SESSION_PROXY_URI, proxy,
			      NULL);
	}

	if (!synchronous)
		loop = g_main_loop_new (NULL, TRUE);

	get_url (url);

	if (!synchronous)
		g_main_loop_unref (loop);

	return 0;
}
