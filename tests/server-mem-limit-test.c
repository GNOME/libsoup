/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2025 Red Hat <www.redhat.com>
 */

#include "test-utils.h"

#include <sys/resource.h>

/*
 This test limits memory usage to trigger too large buffer allocation crash.
 As restoring the limits back to what it was does not always work, it's split
 out of the server-test.c test with copied minimal server code.
 */

typedef struct {
	SoupServer *server;
	GUri *base_uri, *ssl_base_uri;
	GSList *handlers;
} ServerData;

static void
server_setup_nohandler (ServerData *sd, gconstpointer test_data)
{
	sd->server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	sd->base_uri = soup_test_server_get_uri (sd->server, "http", NULL);
	if (tls_available)
		sd->ssl_base_uri = soup_test_server_get_uri (sd->server, "https", NULL);
}

static void
server_add_handler (ServerData         *sd,
		    const char         *path,
		    SoupServerCallback  callback,
		    gpointer            user_data,
		    GDestroyNotify      destroy)
{
	soup_server_add_handler (sd->server, path, callback, user_data, destroy);
	sd->handlers = g_slist_prepend (sd->handlers, g_strdup (path));
}

static void
server_setup (ServerData *sd, gconstpointer test_data)
{
	server_setup_nohandler (sd, test_data);
}

static void
server_teardown (ServerData *sd, gconstpointer test_data)
{
	GSList *iter;

	for (iter = sd->handlers; iter; iter = iter->next)
		soup_server_remove_handler (sd->server, iter->data);
	g_slist_free_full (sd->handlers, g_free);

	g_clear_pointer (&sd->server, soup_test_server_quit_unref);
	g_clear_pointer (&sd->base_uri, g_uri_unref);
	g_clear_pointer (&sd->ssl_base_uri, g_uri_unref);
}

static void
server_file_callback (SoupServer        *server,
		      SoupServerMessage *msg,
		      const char        *path,
		      GHashTable        *query,
		      gpointer           data)
{
	void *mem;

	g_assert_cmpstr (path, ==, "/file");
	g_assert_cmpstr (soup_server_message_get_method (msg), ==, SOUP_METHOD_GET);

	mem = g_malloc0 (sizeof (char) * 1024 * 1024);
	/* fedora-scan CI claims a warning about possibly leaked `mem` variable, thus use
	   the copy and free it explicitly, to workaround the false positive; the g_steal_pointer()
	   did not help for the malloc-ed memory */
	soup_server_message_set_response (msg, "application/octet-stream", SOUP_MEMORY_COPY, mem, sizeof (char) * 1024 *1024);
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	g_free (mem);
}

static void
do_ranges_overlaps_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GString *range;
	GUri *uri;
	const char *chunk = ",0,0,0,0,0,0,0,0,0,0,0";

	g_test_bug ("428");

	#ifdef G_OS_WIN32
	g_test_skip ("Cannot run under windows");
	return;
	#endif

	range = g_string_sized_new (99 * 1024);
	g_string_append (range, "bytes=1024");
	while (range->len < 99 * 1024)
		g_string_append (range, chunk);

	session = soup_test_session_new (NULL);
	server_add_handler (sd, "/file", server_file_callback, NULL, NULL);

	uri = g_uri_parse_relative (sd->base_uri, "/file", SOUP_HTTP_URI_FLAGS, NULL);

	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (soup_message_get_request_headers (msg), "Range", range->str);

	soup_test_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_PARTIAL_CONTENT);

	g_object_unref (msg);

	g_string_free (range, TRUE);
	g_uri_unref (uri);

	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	int ret;

	/* a build with an address sanitizer may crash on mmap() with the limit,
	   thus skip the limit set in such case, even it may not necessarily
	   trigger the bug if it regresses */
	#if !defined(G_OS_WIN32) && !defined(B_SANITIZE_OPTION)
	struct rlimit new_rlimit = { 1024UL * 1024UL * 1024UL * 2UL, 1024UL * 1024UL * 1024UL * 2UL };
	/* limit memory usage, to trigger too large memory allocation abort */
	g_assert_cmpint (setrlimit (RLIMIT_DATA, &new_rlimit), ==, 0);
	#else
	g_message ("server-mem-limit-test: Running without memory limit");
	#endif

	test_init (argc, argv, NULL);

	g_test_add ("/server-mem/range-overlaps", ServerData, NULL,
		    server_setup, do_ranges_overlaps_test, server_teardown);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
