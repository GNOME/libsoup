/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

#ifdef HAVE_APACHE

typedef struct {
	const char *explanation;
	const char *url;
	const guint final_status;
} SoupProxyTest;

static SoupProxyTest tests[] = {
	{ "GET -> 200", "", SOUP_STATUS_OK },
	{ "GET -> 404", "/not-found", SOUP_STATUS_NOT_FOUND },
	{ "GET -> 401 -> 200", "/Basic/realm1/", SOUP_STATUS_OK },
	{ "GET -> 401 -> 401", "/Basic/realm2/", SOUP_STATUS_UNAUTHORIZED },
	{ "GET -> 403", "http://no-such-hostname.xx/", SOUP_STATUS_FORBIDDEN },
};
static const int ntests = sizeof (tests) / sizeof (tests[0]);

#define HTTP_SERVER    "http://127.0.0.1:47524"
#define HTTPS_SERVER   "https://127.0.0.1:47525"

enum {
	SIMPLE_PROXY,
	AUTH_PROXY,
	UNAUTH_PROXY
};
static const char *proxies[] = {
	"http://127.0.0.1:47526",
	"http://127.0.0.1:47527",
	"http://127.0.0.1:47528"
};
static const char *proxy_names[] = {
	"simple proxy",
	"authenticated proxy",
	"unauthenticatable-to proxy"
};

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      SoupAuth *auth, gboolean retrying, gpointer data)
{
	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED) {
		if (soup_auth_is_for_proxy (auth)) {
			debug_printf (1, "  got proxy auth object for 401!\n");
			errors++;
		}
	} else if (msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		if (!soup_auth_is_for_proxy (auth)) {
			debug_printf (1, "  got regular auth object for 407!\n");
			errors++;
		}
	} else {
		debug_printf (1, "  got authenticate signal with status %d\n",
			      msg->status_code);
		errors++;
	}

	if (!retrying)
		soup_auth_authenticate (auth, "user1", "realm1");
}

static void
set_close_on_connect (SoupSession *session, SoupMessage *msg,
		      SoupSocket *sock, gpointer user_data)
{
	/* This is used to test that we can handle the server closing
	 * the connection when returning a 407 in response to a
	 * CONNECT. (Rude!)
	 */
	if (msg->method == SOUP_METHOD_CONNECT) {
		soup_message_headers_append (msg->request_headers,
					     "Connection", "close");
	}
}


static void
test_url (const char *url, int proxy, guint expected,
	  gboolean sync, gboolean close)
{
	SoupSession *session;
	SoupURI *proxy_uri;
	SoupMessage *msg;

	if (!tls_available && g_str_has_prefix (url, "https:"))
		return;

	debug_printf (1, "  GET %s via %s%s\n", url, proxy_names[proxy],
		      close ? " (with Connection: close)" : "");
	if (proxy == UNAUTH_PROXY && expected != SOUP_STATUS_FORBIDDEN)
		expected = SOUP_STATUS_PROXY_UNAUTHORIZED;

	/* We create a new session for each request to ensure that
	 * connections/auth aren't cached between tests.
	 */
	proxy_uri = soup_uri_new (proxies[proxy]);
	session = soup_test_session_new (sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_URI, proxy_uri,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	soup_uri_free (proxy_uri);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);
	if (close) {
		g_signal_connect (session, "request-started",
				  G_CALLBACK (set_close_on_connect), NULL);
	}

	msg = soup_message_new (SOUP_METHOD_GET, url);
	if (!msg) {
		g_printerr ("proxy-test: Could not parse URI\n");
		exit (1);
	}

	soup_session_send_message (session, msg);

	debug_printf (1, "  %d %s\n", msg->status_code, msg->reason_phrase);
	if (msg->status_code != expected) {
		debug_printf (1, "  EXPECTED %d!\n", expected);
		errors++;
	}

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
test_url_new_api (const char *url, int proxy, guint expected,
		  gboolean sync, gboolean close)
{
	SoupSession *session;
	SoupURI *proxy_uri;
	SoupMessage *msg;
	SoupRequest *request;
	GInputStream *stream;
	GError *error = NULL;

	if (!tls_available && g_str_has_prefix (url, "https:"))
		return;

	debug_printf (1, "  GET (request API) %s via %s%s\n", url, proxy_names[proxy],
		      close ? " (with Connection: close)" : "");
	if (proxy == UNAUTH_PROXY && expected != SOUP_STATUS_FORBIDDEN)
		expected = SOUP_STATUS_PROXY_UNAUTHORIZED;

	/* We create a new session for each request to ensure that
	 * connections/auth aren't cached between tests.
	 */
	proxy_uri = soup_uri_new (proxies[proxy]);
	session = soup_test_session_new (sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_PROXY_URI, proxy_uri,
					 NULL);
	soup_uri_free (proxy_uri);

	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);
	if (close) {
		g_signal_connect (session, "request-started",
				  G_CALLBACK (set_close_on_connect), NULL);
	}

	request = soup_session_request (session, url, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	stream = soup_test_request_send (request, NULL, 0, &error);
	if (!stream) {
		debug_printf (1, "  Unexpected error on Request: %s\n",
			      error->message);
		errors++;
		g_clear_error (&error);
	}

	if (stream) {
		soup_test_request_close_stream (request, stream, NULL, NULL);
		if (error) {
			debug_printf (1, "  Unexpected error on close: %s\n",
				      error->message);
			errors++;
			g_clear_error (&error);
		}
		g_object_unref (stream);
	}

	debug_printf (1, "  %d %s\n", msg->status_code, msg->reason_phrase);
	if (msg->status_code != expected) {
		debug_printf (1, "  EXPECTED %d!\n", expected);
		errors++;
	}

	g_object_unref (msg);
	g_object_unref (request);

	soup_test_session_abort_unref (session);
}

static void
run_test (int i, gboolean sync)
{
	char *http_url, *https_url;

	debug_printf (1, "Test %d: %s (%s)\n", i + 1, tests[i].explanation,
		      sync ? "sync" : "async");

	if (!strncmp (tests[i].url, "http", 4)) {
		http_url = g_strdup (tests[i].url);
		https_url = g_strdup_printf ("https%s", tests[i].url + 4);
	} else {
		http_url = g_strconcat (HTTP_SERVER, tests[i].url, NULL);
		https_url = g_strconcat (HTTPS_SERVER, tests[i].url, NULL);
	}

	test_url (http_url, SIMPLE_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (http_url, SIMPLE_PROXY, tests[i].final_status, sync, FALSE);
	test_url (https_url, SIMPLE_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (https_url, SIMPLE_PROXY, tests[i].final_status, sync, FALSE);

	test_url (http_url, AUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (http_url, AUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url (https_url, AUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (https_url, AUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url (https_url, AUTH_PROXY, tests[i].final_status, sync, TRUE);
	test_url_new_api (https_url, AUTH_PROXY, tests[i].final_status, sync, TRUE);

	test_url (http_url, UNAUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (http_url, UNAUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url (https_url, UNAUTH_PROXY, tests[i].final_status, sync, FALSE);
	test_url_new_api (https_url, UNAUTH_PROXY, tests[i].final_status, sync, FALSE);

	g_free (http_url);
	g_free (https_url);

	debug_printf (1, "\n");
}

static gpointer
async_proxy_test_thread (gpointer num)
{
	GMainContext *context = g_main_context_new ();

	g_main_context_push_thread_default (context);
	run_test (GPOINTER_TO_INT (num), FALSE);
	g_main_context_pop_thread_default (context);
	g_main_context_unref (context);

	return NULL;
}

static gpointer
sync_proxy_test_thread (gpointer num)
{
	run_test (GPOINTER_TO_INT (num), TRUE);
	return NULL;
}

static void
do_proxy_tests (void)
{
	int i;

	debug_printf (1, "Basic proxy tests\n");

	if (parallelize) {
		GThread *threads[ntests];

		/* Doing the sync and async tests separately is faster
		 * than doing them both at the same time (hitting
		 * apache's connection limit maybe?)
		 */
		for (i = 0; i < ntests; i++) {
			threads[i] = g_thread_new ("async_proxy_test",
						   async_proxy_test_thread,
						   GINT_TO_POINTER (i));
		}
		for (i = 0; i < ntests; i++)
			g_thread_join (threads[i]);

		for (i = 0; i < ntests; i++) {
			threads[i] = g_thread_new ("sync_proxy_test",
						   sync_proxy_test_thread,
						   GINT_TO_POINTER (i));
		}
		for (i = 0; i < ntests; i++)
			g_thread_join (threads[i]);
	} else {
		for (i = 0; i < ntests; i++) {
			run_test (i, FALSE);
			run_test (i, TRUE);
		}
	}
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SoupURI *uri = soup_message_get_uri (msg);

	soup_message_set_status (msg, uri->fragment ? SOUP_STATUS_BAD_REQUEST : SOUP_STATUS_OK);
}

static void
do_proxy_fragment_test (SoupURI *base_uri)
{
	SoupSession *session;
	SoupURI *proxy_uri, *req_uri;
	SoupMessage *msg;

	debug_printf (1, "\nTesting request with fragment via proxy\n");

	proxy_uri = soup_uri_new (proxies[SIMPLE_PROXY]);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_URI, proxy_uri,
					 NULL);
	soup_uri_free (proxy_uri);

	req_uri = soup_uri_new_with_base (base_uri, "/#foo");
	msg = soup_message_new_from_uri (SOUP_METHOD_GET, req_uri);
	soup_uri_free (req_uri);
	soup_session_send_message (session, msg);

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "  unexpected status %d %s!\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_redirect_test (void)
{
	SoupSession *session;
	SoupURI *proxy_uri, *req_uri, *new_uri;
	SoupMessage *msg;

	debug_printf (1, "\nTesting redirection through proxy\n");

	proxy_uri = soup_uri_new (proxies[SIMPLE_PROXY]);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_URI, proxy_uri,
					 NULL);
	soup_uri_free (proxy_uri);

	req_uri = soup_uri_new (HTTPS_SERVER);
	soup_uri_set_path (req_uri, "/redirected");
	msg = soup_message_new_from_uri (SOUP_METHOD_GET, req_uri);
	soup_message_headers_append (msg->request_headers,
				     "Connection", "close");
	soup_session_send_message (session, msg);

	new_uri = soup_message_get_uri (msg);
	if (!strcmp (req_uri->path, new_uri->path)) {
		debug_printf (1, "  message was not redirected!\n");
		errors++;
	}
	soup_uri_free (req_uri);

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "  unexpected status %d %s!\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupURI *base_uri;

	test_init (argc, argv, NULL);
	apache_init ();

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	do_proxy_tests ();
	do_proxy_fragment_test (base_uri);
	do_proxy_redirect_test ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}

#else /* HAVE_APACHE */

int
main (int argc, char **argv)
{
	return 77; /* SKIP */
}

#endif
