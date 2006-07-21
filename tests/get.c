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

#ifdef G_OS_WIN32
#include <io.h>
#define mkdir(path, mode) _mkdir (path)
#endif

SoupSession *session;
GMainLoop *loop;
gboolean recurse = FALSE, debug = FALSE;
const char *method = SOUP_METHOD_GET;
char *base;
SoupUri *base_uri;
int pending;

static GPtrArray *
find_hrefs (const SoupUri *base, const char *body, int length)
{
	GPtrArray *hrefs = g_ptr_array_new ();
	char *buf = g_strndup (body, length);
	char *start = buf, *end;
	char *href, *frag;
	SoupUri *uri;

	while ((start = strstr (start, "href"))) {
		start += 4;
		while (isspace ((unsigned char) *start))
			start++;
		if (*start++ != '=') 
			continue;
		while (isspace ((unsigned char) *start))
			start++;
		if (*start++ != '"')
			continue;

		end = strchr (start, '"');
		if (!end)
			break;

		href = g_strndup (start, end - start);
		start = end;
		frag = strchr (href, '#');
		if (frag)
			*frag = '\0';

		uri = soup_uri_new_with_base (base, href);
		g_free (href);

		if (!uri)
			continue;
		if (base->protocol != uri->protocol ||
		    base->port != uri->port ||
		    g_ascii_strcasecmp (base->host, uri->host) != 0) {
			soup_uri_free (uri);
			continue;
		}

		if (strncmp (base->path, uri->path, strlen (base->path)) != 0) {
			soup_uri_free (uri);
			continue;
		}

		g_ptr_array_add (hrefs, soup_uri_to_string (uri, FALSE));
		soup_uri_free (uri);
	}
	g_free (buf);

	return hrefs;
}

static void
mkdirs (const char *path)
{
	char *slash;

	for (slash = strchr (path, '/'); slash; slash = strchr (slash + 1, '/')) {
		*slash = '\0';
		if (*path && mkdir (path, 0755) == -1 && errno != EEXIST) {
			fprintf (stderr, "Could not create '%s'\n", path);
			g_main_loop_quit (loop);
			return;
		}
		*slash = '/';
	}
}

static void get_url (const char *url);

static void
print_header (gpointer name, gpointer value, gpointer data)
{
	printf ("%s: %s\n", (const char *)name, (const char *)value);
}

static void
got_url (SoupMessage *msg, gpointer uri)
{
	char *name;
	int fd, i;
	GPtrArray *hrefs;
	const char *header;

	name = soup_message_get_uri (msg)->path;
	if (strncmp (base_uri->path, name, strlen (base_uri->path)) != 0) {
		fprintf (stderr, "  Error: not under %s\n", base_uri->path);
		goto DONE;
	}
	if (debug) {
		char *path = soup_uri_to_string (soup_message_get_uri (msg), TRUE);
		printf ("%s %s HTTP/1.%d\n\n", method, path,
			soup_message_get_http_version (msg));
		printf ("HTTP/1.%d %d %s\n",
			soup_message_get_http_version (msg),
			msg->status_code, msg->reason_phrase);
		soup_message_foreach_header (msg->response_headers, print_header, NULL);
		printf ("\n");
	} else
		printf ("%s: %d %s\n", name, msg->status_code, msg->reason_phrase);

	name += strlen (base_uri->path);
	if (*name == '/')
		name++;

	if (SOUP_STATUS_IS_REDIRECTION (msg->status_code)) {
		unlink (name);
		header = soup_message_get_header (msg->response_headers, "Location");
		if (header) {
			if (!debug)
				printf ("  -> %s\n", header);
			get_url (header);
		}
		goto DONE;
	}

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code))
		goto DONE;

	if (recurse)
		fd = open (name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	else
		fd = STDOUT_FILENO;
	write (fd, msg->response.body, msg->response.length);
	if (!recurse)
		goto DONE;
	close (fd);

	header = soup_message_get_header (msg->response_headers, "Content-Type");
	if (header && g_ascii_strncasecmp (header, "text/html", 9) != 0)
		goto DONE;

	hrefs = find_hrefs (uri, msg->response.body, msg->response.length);
	for (i = 0; i < hrefs->len; i++) {
		get_url (hrefs->pdata[i]);
		g_free (hrefs->pdata[i]);
	}
	g_ptr_array_free (hrefs, TRUE);

 DONE:
	soup_uri_free (uri);
	if (!--pending)
		g_main_quit (loop);
}

static void
get_url (const char *url)
{
	char *url_to_get, *slash, *name;
	SoupMessage *msg;
	int fd;

	if (strncmp (url, base, strlen (base)) != 0)
		return;

	slash = strrchr (url, '/');
	if (slash && !slash[1])
		url_to_get = g_strdup_printf ("%sindex.html", url);
	else
		url_to_get = g_strdup (url);

	if (recurse) {
		/* See if we're already downloading it, and create the
		 * file if not.
		 */

		name = url_to_get + strlen (base);
		if (*name == '/')
			name++;
		if (access (name, F_OK) == 0) {
			g_free (url_to_get);
			return;
		}

		mkdirs (name);
		fd = open (name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		close (fd);
	}

	msg = soup_message_new (method, url_to_get);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	pending++;
	soup_session_queue_message (session, msg, got_url, soup_uri_new (url));
	g_free (url_to_get);
}

static void
usage (void)
{
	fprintf (stderr, "Usage: get [-c CAfile] [-p proxy URL] [-r] [-h] [-d] URL\n");
	exit (1);
}

int
main (int argc, char **argv)
{
	const char *cafile = NULL;
	SoupUri *proxy = NULL;
	int opt;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "c:dhp:r")) != -1) {
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

		case 'r':
			recurse = TRUE;
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
	base = argv[0];
	base_uri = soup_uri_new (base);
	if (!base_uri) {
		fprintf (stderr, "Could not parse '%s' as a URL\n", base);
		exit (1);
	}

	session = soup_session_async_new_with_options (
		SOUP_SESSION_SSL_CA_FILE, cafile,
		SOUP_SESSION_PROXY_URI, proxy,
		NULL);

	if (recurse) {
		char *outdir;

		outdir = g_strdup_printf ("%lu", (unsigned long)getpid ());
		if (mkdir (outdir, 0755) != 0) {
			fprintf (stderr, "Could not make output directory\n");
			exit (1);
		}
		printf ("Output directory is '%s'\n", outdir);
		chdir (outdir);
		g_free (outdir);
	}

	get_url (base);

	loop = g_main_loop_new (NULL, TRUE);
	g_main_run (loop);
	g_main_loop_unref (loop);

	soup_uri_free (base_uri);

	return 0;
}
