/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "libsoup/soup.h"

const char *helper_protocol, *username, *domain;
gboolean use_cached_creds;

static GOptionEntry entries[] = {
	{ "helper-protocol", 0, 0,
	  G_OPTION_ARG_STRING, &helper_protocol,
	  NULL, NULL },
	{ "use-cached-creds", 0, 0,
	  G_OPTION_ARG_NONE, &use_cached_creds,
	  NULL, NULL },
	{ "username", 0, 0,
	  G_OPTION_ARG_STRING, &username,
	  NULL, NULL },
	{ "domain", 0, 0,
	  G_OPTION_ARG_STRING, &domain,
	  NULL, NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	char buf[256], *header;
	SoupMessage *msg;
	SoupAuth *auth;

	/* Don't recurse */
	g_setenv ("SOUP_NTLM_AUTH_DEBUG", "", TRUE);

	setlocale (LC_ALL, "");

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);
	if (!g_option_context_parse (opts, &argc, &argv, NULL)) {
		g_printerr ("Bad arguments\n");
		exit (1);
	}
	g_option_context_free (opts);

	if (!username || !use_cached_creds || !helper_protocol ||
	    !g_str_equal (helper_protocol, "ntlmssp-client-1")) {
		g_printerr ("Wrong arguments; this program is only intended for use by ntlm-test\n");
		exit (1);
	}

	msg = soup_message_new ("GET", "http://localhost/");
	auth = NULL;

	while (fgets (buf, sizeof (buf), stdin)) {
		if (strchr (buf, '\n'))
			*strchr (buf, '\n') = '\0';
		if (!strcmp (buf, "YR")) {
			if (g_getenv ("SOUP_NTLM_AUTH_DEBUG_NOCREDS")) {
				g_print ("PW\n");
				continue;
			}

			g_clear_object (&auth);
			auth = g_object_new (SOUP_TYPE_AUTH_NTLM, NULL);
			header = soup_auth_get_authorization (auth, msg);
			g_print ("YR %s\n", header + 5);
			g_free (header);
		} else if (g_str_has_prefix (buf, "TT ")) {
			header = g_strdup_printf ("NTLM %s\n", buf + 3);
			if (!soup_auth_update (auth, msg, header)) {
				g_printerr ("Bad challenge\n");
				exit (1);
			}
			g_free (header);

			soup_auth_authenticate (auth, username, "password");
			header = soup_auth_get_authorization (auth, msg);
			if (!header) {
				g_printerr ("Internal authentication failure\n");
				exit (1);
			}
			g_print ("KK %s\n", header + 5);
			g_free (header);
		} else {
			g_printerr ("Unexpected command\n");
			exit (1);
		}
	}

	g_object_unref (msg);
	g_clear_object (&auth);

	return 0;
}
