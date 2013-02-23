/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <libsoup/soup.h>

static int
compare_strings (gconstpointer a, gconstpointer b)
{
	const char **sa = (const char **)a;
	const char **sb = (const char **)b;

	return strcmp (*sa, *sb);
}

static GString *
get_directory_listing (const char *path)
{
	GPtrArray *entries;
	GString *listing;
	char *escaped;
	DIR *dir;
	struct dirent *dent;
	int i;

	entries = g_ptr_array_new ();
	dir = opendir (path);
	if (dir) {
		while ((dent = readdir (dir))) {
			if (!strcmp (dent->d_name, ".") ||
			    (!strcmp (dent->d_name, "..") &&
			     !strcmp (path, "./")))
				continue;
			escaped = g_markup_escape_text (dent->d_name, -1);
			g_ptr_array_add (entries, escaped);
		}
		closedir (dir);
	}

	g_ptr_array_sort (entries, (GCompareFunc)compare_strings);

	listing = g_string_new ("<html>\r\n");
	escaped = g_markup_escape_text (strchr (path, '/'), -1);
	g_string_append_printf (listing, "<head><title>Index of %s</title></head>\r\n", escaped);
	g_string_append_printf (listing, "<body><h1>Index of %s</h1>\r\n<p>\r\n", escaped);
	g_free (escaped);
	for (i = 0; i < entries->len; i++) {
		g_string_append_printf (listing, "<a href=\"%s\">%s</a><br>\r\n",
					(char *)entries->pdata[i], 
					(char *)entries->pdata[i]);
		g_free (entries->pdata[i]);
	}
	g_string_append (listing, "</body>\r\n</html>\r\n");

	g_ptr_array_free (entries, TRUE);
	return listing;
}

static void
do_get (SoupServer *server, SoupMessage *msg, const char *path)
{
	char *slash;
	struct stat st;

	if (stat (path, &st) == -1) {
		if (errno == EPERM)
			soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
		else if (errno == ENOENT)
			soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		else
			soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (S_ISDIR (st.st_mode)) {
		GString *listing;
		char *index_path;

		slash = strrchr (path, '/');
		if (!slash || slash[1]) {
			char *redir_uri;

			redir_uri = g_strdup_printf ("%s/", soup_message_get_uri (msg)->path);
			soup_message_set_redirect (msg, SOUP_STATUS_MOVED_PERMANENTLY,
						   redir_uri);
			g_free (redir_uri);
			return;
		}

		index_path = g_strdup_printf ("%s/index.html", path);
		if (stat (index_path, &st) != -1) {
			do_get (server, msg, index_path);
			g_free (index_path);
			return;
		}
		g_free (index_path);

		listing = get_directory_listing (path);
		soup_message_set_response (msg, "text/html",
					   SOUP_MEMORY_TAKE,
					   listing->str, listing->len);
		g_string_free (listing, FALSE);
		return;
	}

	if (msg->method == SOUP_METHOD_GET) {
		GMappedFile *mapping;
		SoupBuffer *buffer;

		mapping = g_mapped_file_new (path, FALSE, NULL);
		if (!mapping) {
			soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
			return;
		}

		buffer = soup_buffer_new_with_owner (g_mapped_file_get_contents (mapping),
						     g_mapped_file_get_length (mapping),
						     mapping, (GDestroyNotify)g_mapped_file_unref);
		soup_message_body_append_buffer (msg->response_body, buffer);
		soup_buffer_free (buffer);
	} else /* msg->method == SOUP_METHOD_HEAD */ {
		char *length;

		/* We could just use the same code for both GET and
		 * HEAD (soup-message-server-io.c will fix things up).
		 * But we'll optimize and avoid the extra I/O.
		 */
		length = g_strdup_printf ("%lu", (gulong)st.st_size);
		soup_message_headers_append (msg->response_headers,
					     "Content-Length", length);
		g_free (length);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
}

static void
do_put (SoupServer *server, SoupMessage *msg, const char *path)
{
	struct stat st;
	FILE *f;
	gboolean created = TRUE;

	if (stat (path, &st) != -1) {
		const char *match = soup_message_headers_get_one (msg->request_headers, "If-None-Match");
		if (match && !strcmp (match, "*")) {
			soup_message_set_status (msg, SOUP_STATUS_CONFLICT);
			return;
		}

		if (!S_ISREG (st.st_mode)) {
			soup_message_set_status (msg, SOUP_STATUS_FORBIDDEN);
			return;
		}

		created = FALSE;
	}

	f = fopen (path, "w");
	if (!f) {
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	fwrite (msg->request_body->data, 1, msg->request_body->length, f);
	fclose (f);

	soup_message_set_status (msg, created ? SOUP_STATUS_CREATED : SOUP_STATUS_OK);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	char *file_path;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	g_print ("%s %s HTTP/1.%d\n", msg->method, path,
		 soup_message_get_http_version (msg));
	soup_message_headers_iter_init (&iter, msg->request_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_print ("%s: %s\n", name, value);
	if (msg->request_body->length)
		g_print ("%s\n", msg->request_body->data);

	file_path = g_strdup_printf (".%s", path);

	if (msg->method == SOUP_METHOD_GET || msg->method == SOUP_METHOD_HEAD)
		do_get (server, msg, file_path);
	else if (msg->method == SOUP_METHOD_PUT)
		do_put (server, msg, file_path);
	else
		soup_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED);

	g_free (file_path);
	g_print ("  -> %d %s\n\n", msg->status_code, msg->reason_phrase);
}

static void
quit (int sig)
{
	/* Exit cleanly on ^C in case we're valgrinding. */
	exit (0);
}

static int port, ssl_port;
static const char *ssl_cert_file, *ssl_key_file;

static GOptionEntry entries[] = {
	{ "cert-file", 'c', 0,
	  G_OPTION_ARG_STRING, &ssl_cert_file,
	  "Use FILE as the TLS certificate file", "FILE" },
	{ "key-file", 'k', 0,
	  G_OPTION_ARG_STRING, &ssl_key_file,
	  "Use FILE as the TLS private key file", "FILE" },
	{ "port", 'p', 0,
	  G_OPTION_ARG_INT, &port,
	  "Port to listen on", NULL },
	{ "ssl-port", 's', 0,
	  G_OPTION_ARG_INT, &port,
	  "Port to listen on for TLS traffic", NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	GMainLoop *loop;
	SoupServer *server, *ssl_server;
	GError *error = NULL;

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);
	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	if (argc != 1) {
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	g_option_context_free (opts);

	signal (SIGINT, quit);

	server = soup_server_new (SOUP_SERVER_PORT, port,
				  SOUP_SERVER_SERVER_HEADER, "simple-httpd ",
				  NULL);
	if (!server) {
		g_printerr ("Unable to bind to server port %d\n", port);
		exit (1);
	}
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);
	g_print ("\nStarting Server on port %d\n",
		 soup_server_get_port (server));
	soup_server_run_async (server);

	if (ssl_cert_file && ssl_key_file) {
		ssl_server = soup_server_new (
			SOUP_SERVER_PORT, ssl_port,
			SOUP_SERVER_SSL_CERT_FILE, ssl_cert_file,
			SOUP_SERVER_SSL_KEY_FILE, ssl_key_file,
			NULL);

		if (!ssl_server) {
			g_printerr ("Unable to bind to SSL server port %d\n", ssl_port);
			exit (1);
		}
		soup_server_add_handler (ssl_server, NULL,
					 server_callback, NULL, NULL);
		g_print ("Starting SSL Server on port %d\n", 
			 soup_server_get_port (ssl_server));
		soup_server_run_async (ssl_server);
	}

	g_print ("\nWaiting for requests...\n");

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);

	return 0;
}
