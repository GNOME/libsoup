#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libsoup/soup.h"

#include "test-utils.h"

static void
do_tests_for_session (SoupSession *session,
		      char *fast_uri, char *slow_uri)
{
	SoupMessage *msg;

	debug_printf (1, "    fast\n");
	msg = soup_message_new ("GET", fast_uri);
	soup_session_send_message (session, msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "      FAILED: %d %s (expected 200 OK)\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}
	g_object_unref (msg);

	debug_printf (1, "    slow\n");
	msg = soup_message_new ("GET", slow_uri);
	soup_session_send_message (session, msg);
	if (msg->status_code != SOUP_STATUS_IO_ERROR) {
		debug_printf (1, "      FAILED: %d %s (expected %d %s)\n",
			      msg->status_code, msg->reason_phrase,
			      SOUP_STATUS_IO_ERROR,
			      soup_status_get_phrase (SOUP_STATUS_IO_ERROR));
		errors++;
	}
	g_object_unref (msg);
}

static void
do_timeout_tests (char *fast_uri, char *slow_uri)
{
	SoupSession *session;

	debug_printf (1, "  async\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_TIMEOUT, 1,
					 NULL);
	do_tests_for_session (session, fast_uri, slow_uri);
	soup_test_session_abort_unref (session);

	debug_printf (1, "  sync\n");
	session = soup_test_session_new (SOUP_TYPE_SESSION_SYNC,
					 SOUP_SESSION_TIMEOUT, 1,
					 NULL);
	do_tests_for_session (session, fast_uri, slow_uri);
	soup_test_session_abort_unref (session);
}

static void
server_handler (SoupServer        *server,
		SoupMessage       *msg, 
		const char        *path,
		GHashTable        *query,
		SoupClientContext *client,
		gpointer           user_data)
{
	if (!strcmp (path, "/slow")) {
		/* Sleep 1.1 seconds. */
		g_usleep (1100000);
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_set_response (msg, "text/plain",
				   SOUP_MEMORY_STATIC,
				   "ok\r\n", 4);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	char *fast_uri, *slow_uri;

	test_init (argc, argv, NULL);

	debug_printf (1, "http\n");
	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	fast_uri = g_strdup_printf ("http://127.0.0.1:%u/",
				    soup_server_get_port (server));
	slow_uri = g_strdup_printf ("http://127.0.0.1:%u/slow",
				    soup_server_get_port (server));
	do_timeout_tests (fast_uri, slow_uri);
	g_free (fast_uri);
	g_free (slow_uri);

#ifdef HAVE_SSL
	debug_printf (1, "https\n");
	server = soup_test_server_new_ssl (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	fast_uri = g_strdup_printf ("https://127.0.0.1:%u/",
				    soup_server_get_port (server));
	slow_uri = g_strdup_printf ("https://127.0.0.1:%u/slow",
				    soup_server_get_port (server));
	do_timeout_tests (fast_uri, slow_uri);
	g_free (fast_uri);
	g_free (slow_uri);
#endif

	test_cleanup ();
	return errors != 0;
}
