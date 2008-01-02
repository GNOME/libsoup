/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <glib.h>
#include <libsoup/soup-form.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-server.h>
#include <libsoup/soup-session-sync.h>

GMainLoop *loop;
gboolean debug = FALSE;

static void
dprintf (const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start (args, format);
	vprintf (format, args);
	va_end (args);
}

struct {
	char *title, *name;
	char *result;
} tests[] = {
	/* Both fields must be filled in */
	{ NULL, "Name", "" },
	{ "Mr.", NULL, "" },

	/* Filled-in but empty is OK */
	{ "", "", "Hello,  " },
	{ "", "Name", "Hello,  Name" },
	{ "Mr.", "", "Hello, MR. " },

	/* Simple */
	{ "Mr.", "Name", "Hello, MR. Name" },

	/* Encoding of spaces */
	{ "Mr.", "Full Name", "Hello, MR. Full Name" },
	{ "Mr. and Mrs.", "Full Name", "Hello, MR. AND MRS. Full Name" },

	/* Encoding of "+" */
	{ "Mr.+Mrs.", "Full Name", "Hello, MR.+MRS. Full Name" },

	/* Encoding of non-ASCII. */
	{ "Se\xC3\xB1or", "Nombre", "Hello, SE\xC3\xB1OR Nombre" },

	/* Encoding of '%' */
	{ "Mr.", "Foo %2f Bar", "Hello, MR. Foo %2f Bar" },
};

static int
do_test (int n, gboolean extra, const char *uri)
{
	GPtrArray *args;
	int errors = 0;
	GHashTable *form_data_set;
	char *title_arg = NULL, *name_arg = NULL;
	char *stdout = NULL;

	dprintf ("%2d. '%s' '%s'%s: ", n * 2 + (extra ? 2 : 1),
		 tests[n].title ? tests[n].title : "(null)",
		 tests[n].name  ? tests[n].name  : "(null)",
		 extra ? " + extra" : "");

	form_data_set = g_hash_table_new (g_str_hash, g_str_equal);

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "curl");
	g_ptr_array_add (args, "-G");
	if (tests[n].title) {
		g_hash_table_insert (form_data_set, "title", tests[n].title);
		title_arg = soup_form_encode_urlencoded (form_data_set);
		g_hash_table_remove_all (form_data_set);

		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, title_arg);
	}
	if (tests[n].name) {
		g_hash_table_insert (form_data_set, "name", tests[n].name);
		name_arg = soup_form_encode_urlencoded (form_data_set);
		g_hash_table_remove_all (form_data_set);

		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, name_arg);
	}
	if (extra) {
		g_ptr_array_add (args, "-d");
		g_ptr_array_add (args, "extra=something");
	}
	g_ptr_array_add (args, (char *)uri);
	g_ptr_array_add (args, NULL);

	if (g_spawn_sync (NULL, (char **)args->pdata, NULL,
			  G_SPAWN_SEARCH_PATH | G_SPAWN_STDERR_TO_DEV_NULL,
			  NULL, NULL,
			  &stdout, NULL, NULL, NULL)) {
		if (stdout && !strcmp (stdout, tests[n].result))
			dprintf ("OK!\n");
		else {
			dprintf ("WRONG!\n");
			dprintf ("  expected '%s', got '%s'\n",
				 tests[n].result, stdout ? stdout : "(error)");
			errors++;
		}
		g_free (stdout);
	} else {
		dprintf ("ERROR!\n");
		errors++;
	}
	g_ptr_array_free (args, TRUE);
	g_hash_table_destroy (form_data_set);
	g_free (title_arg);
	g_free (name_arg);

	return errors;
}

static int
do_query_tests (const char *uri)
{
	int n, errors = 0;

	for (n = 0; n < G_N_ELEMENTS (tests); n++) {
		errors += do_test (n, FALSE, uri);
		errors += do_test (n, TRUE, uri);
	}

	return errors;
}

GThread *server_thread;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	char *title, *name, *fmt;
	const char *content_type;
	GString *buf;

	if (msg->method != SOUP_METHOD_GET && msg->method != SOUP_METHOD_HEAD) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);
		return;
	}

	if (!strcmp (path, "/shutdown")) {
		soup_server_quit (server);
		return;
	}

	if (query) {
		title = g_hash_table_lookup (query, "title");
		name = g_hash_table_lookup (query, "name");
		fmt = g_hash_table_lookup (query, "fmt");
	} else
		title = name = fmt = NULL;

	buf = g_string_new (NULL);
	if (!query || (fmt && !strcmp (fmt, "html"))) {
		content_type = "text/html";
		g_string_append (buf, "<html><head><title>query-test</title></head><body>\r\n");
		if (title && name) {
			/* mumble mumble html-escape... */
			g_string_append_printf (buf, "<p>Hello, <b><em>%s</em> %s</b></p>\r\n",
						title, name);
		}
		g_string_append (buf, "<form action='/' method='get'>"
				 "<p>Title: <input name='title'></p>"
				 "<p>Name: <input name='name'></p>"
				 "<p><input type=hidden name='fmt' value='html'></p>"
				 "<p><input type=submit></p>"
				 "</form>\r\n");
		g_string_append (buf, "</body></html>\r\n");
	} else {
		content_type = "text/plain";
		if (title && name) {
			char *uptitle = g_ascii_strup (title, -1);
			g_string_append_printf (buf, "Hello, %s %s",
						uptitle, name);
			g_free (uptitle);
		}
	}

	soup_message_set_response (msg, content_type,
				   SOUP_MEMORY_TAKE,
				   buf->str, buf->len);
	g_string_free (buf, FALSE);
	soup_message_set_status (msg, SOUP_STATUS_OK);
}

static gpointer
run_server_thread (gpointer user_data)
{
	SoupServer *server = user_data;

	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);
	soup_server_run (server);
	g_object_unref (server);

	return NULL;
}

static guint
create_server (void)
{
	SoupServer *server;
	GMainContext *async_context;
	guint port;

	async_context = g_main_context_new ();
	server = soup_server_new (SOUP_SERVER_PORT, 0,
				  SOUP_SERVER_ASYNC_CONTEXT, async_context,
				  NULL);
	g_main_context_unref (async_context);

	if (!server) {
		fprintf (stderr, "Unable to bind server\n");
		exit (1);
	}

	port = soup_server_get_port (server);
	server_thread = g_thread_create (run_server_thread, server, TRUE, NULL);

	return port;
}

static void
shutdown_server (const char *base_uri)
{
	SoupSession *session;
	char *uri;
	SoupMessage *msg;

	session = soup_session_sync_new ();
	uri = g_build_filename (base_uri, "shutdown", NULL);
	msg = soup_message_new ("GET", uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);
	g_free (uri);

	soup_session_abort (session);
	g_object_unref (session);

	g_thread_join (server_thread);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	guint port;
	int opt;
	int errors;
	gboolean run_tests = TRUE;
	SoupURI *uri;
	char *uri_str;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "dn")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		case 'n':
			run_tests = FALSE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n",
				 argv[0]);
			exit (1);
		}
	}

	port = create_server ();
	loop = g_main_loop_new (NULL, TRUE);

	if (run_tests) {
		uri = soup_uri_new ("http://localhost");
		uri->port = port;
		uri_str = soup_uri_to_string (uri, FALSE);
		soup_uri_free (uri);

		errors = do_query_tests (uri_str);
		shutdown_server (uri_str);
		g_free (uri_str);
	} else {
		printf ("Listening on port %d\n", port);
		g_main_loop_run (loop);
	}

	g_main_loop_unref (loop);

	dprintf ("\n");
	if (errors) {
		printf ("query-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("query-test: OK\n");
	return errors != 0;
}
