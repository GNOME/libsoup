/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

typedef struct {
	const char *explanation;
	const char *url;
	const guint final_status;
	const char *bugref;
} SoupProxyTest;

static SoupProxyTest tests[] = {
	{ "GET -> 200", "", SOUP_STATUS_OK, NULL },
	{ "GET -> 404", "/not-found", SOUP_STATUS_NOT_FOUND, NULL },
	{ "GET -> 401 -> 200", "/Basic/realm1/", SOUP_STATUS_OK, NULL },
	{ "GET -> 401 -> 401", "/Basic/realm2/", SOUP_STATUS_UNAUTHORIZED, NULL },
	{ "GET -> 403", "http://no-such-hostname.xx/", SOUP_STATUS_FORBIDDEN, "577532" },
	{ "GET -> 200 (unproxied)", "http://localhost:47524/", SOUP_STATUS_OK, "700472" },
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
static GProxyResolver *proxy_resolvers[3];
static const char *ignore_hosts[] = { "localhost", NULL };

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      SoupAuth *auth, gboolean retrying, gpointer data)
{
	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED) {
		soup_test_assert (!soup_auth_is_for_proxy (auth),
				  "got proxy auth object for 401");
	} else if (msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		soup_test_assert (soup_auth_is_for_proxy (auth),
				  "got regular auth object for 407");
	} else {
		soup_test_assert (FALSE,
				  "got authenticate signal with status %d\n",
				  msg->status_code);
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
	SoupMessage *msg;
	gboolean noproxy = !!strstr (url, "localhost");

	if (!tls_available && g_str_has_prefix (url, "https:"))
		return;

	debug_printf (1, "  GET %s via %s%s\n", url, proxy_names[proxy],
		      close ? " (with Connection: close)" : "");
	if (proxy == UNAUTH_PROXY && expected != SOUP_STATUS_FORBIDDEN && !noproxy)
		expected = SOUP_STATUS_PROXY_UNAUTHORIZED;

	/* We create a new session for each request to ensure that
	 * connections/auth aren't cached between tests.
	 */
	session = soup_test_session_new (sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_RESOLVER, proxy_resolvers[proxy],
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_SSL_STRICT, FALSE,
					 NULL);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);
	if (close) {
		/* FIXME g_test_bug ("611663") */
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
	soup_test_assert_message_status (msg, expected);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
test_url_new_api (const char *url, int proxy, guint expected,
		  gboolean sync, gboolean close)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupRequest *request;
	GInputStream *stream;
	GError *error = NULL;
	gboolean noproxy = !!strstr (url, "localhost");

	/* FIXME g_test_skip() FIXME g_test_bug ("675865") */
	if (!tls_available && g_str_has_prefix (url, "https:"))
		return;

	debug_printf (1, "  GET (request API) %s via %s%s\n", url, proxy_names[proxy],
		      close ? " (with Connection: close)" : "");
	if (proxy == UNAUTH_PROXY && expected != SOUP_STATUS_FORBIDDEN && !noproxy)
		expected = SOUP_STATUS_PROXY_UNAUTHORIZED;

	/* We create a new session for each request to ensure that
	 * connections/auth aren't cached between tests.
	 */
	session = soup_test_session_new (sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_PROXY_RESOLVER, proxy_resolvers[proxy],
					 SOUP_SESSION_SSL_STRICT, FALSE,
					 NULL);

	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);
	if (close) {
		/* FIXME g_test_bug ("611663") */
		g_signal_connect (session, "request-started",
				  G_CALLBACK (set_close_on_connect), NULL);
	}

	request = soup_session_request (session, url, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	stream = soup_test_request_send (request, NULL, 0, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	if (stream) {
		soup_test_request_close_stream (request, stream, NULL, &error);
		g_assert_no_error (error);
		g_clear_error (&error);
		g_object_unref (stream);
	}

	debug_printf (1, "  %d %s\n", msg->status_code, msg->reason_phrase);
	soup_test_assert_message_status (msg, expected);

	g_object_unref (msg);
	g_object_unref (request);

	soup_test_session_abort_unref (session);
}

static void
do_proxy_test (SoupProxyTest *test, gboolean sync)
{
	char *http_url, *https_url;

	if (test->bugref)
		g_test_bug (test->bugref);

	if (!strncmp (test->url, "http", 4)) {
		SoupURI *uri;
		guint port;

		http_url = g_strdup (test->url);

		uri = soup_uri_new (test->url);
		port = uri->port;
		soup_uri_set_scheme (uri, "https");
		if (port)
			soup_uri_set_port (uri, port + 1);
		https_url = soup_uri_to_string (uri, FALSE);
		soup_uri_free (uri);
	} else {
		http_url = g_strconcat (HTTP_SERVER, test->url, NULL);
		https_url = g_strconcat (HTTPS_SERVER, test->url, NULL);
	}

	test_url (http_url, SIMPLE_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (http_url, SIMPLE_PROXY, test->final_status, sync, FALSE);
	test_url (https_url, SIMPLE_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (https_url, SIMPLE_PROXY, test->final_status, sync, FALSE);

	test_url (http_url, AUTH_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (http_url, AUTH_PROXY, test->final_status, sync, FALSE);
	test_url (https_url, AUTH_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (https_url, AUTH_PROXY, test->final_status, sync, FALSE);
	test_url (https_url, AUTH_PROXY, test->final_status, sync, TRUE);
	test_url_new_api (https_url, AUTH_PROXY, test->final_status, sync, TRUE);

	test_url (http_url, UNAUTH_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (http_url, UNAUTH_PROXY, test->final_status, sync, FALSE);
	test_url (https_url, UNAUTH_PROXY, test->final_status, sync, FALSE);
	test_url_new_api (https_url, UNAUTH_PROXY, test->final_status, sync, FALSE);

	g_free (http_url);
	g_free (https_url);
}

static void
do_async_proxy_test (gconstpointer data)
{
	SoupProxyTest *test = (SoupProxyTest *)data;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	do_proxy_test (test, FALSE);
}

static void
do_sync_proxy_test (gconstpointer data)
{
	SoupProxyTest *test = (SoupProxyTest *)data;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	do_proxy_test (test, TRUE);
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
do_proxy_fragment_test (gconstpointer data)
{
	SoupURI *base_uri = (SoupURI *)data;
	SoupSession *session;
	SoupURI *proxy_uri, *req_uri;
	SoupMessage *msg;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	proxy_uri = soup_uri_new (proxies[SIMPLE_PROXY]);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_URI, proxy_uri,
					 NULL);
	soup_uri_free (proxy_uri);

	req_uri = soup_uri_new_with_base (base_uri, "/#foo");
	msg = soup_message_new_from_uri (SOUP_METHOD_GET, req_uri);
	soup_uri_free (req_uri);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_redirect_test (void)
{
	SoupSession *session;
	SoupURI *proxy_uri, *req_uri, *new_uri;
	SoupMessage *msg;

	g_test_bug ("631368");

	SOUP_TEST_SKIP_IF_NO_APACHE;
	SOUP_TEST_SKIP_IF_NO_TLS;

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
	soup_test_assert (strcmp (req_uri->path, new_uri->path) != 0,
			  "message was not redirected");
	soup_uri_free (req_uri);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_auth_request (const char *url, SoupSession *session, gboolean do_read)
{
	SoupRequest *request;
	SoupMessage *msg;
	GInputStream *stream;
	GError *error = NULL;

	request = soup_session_request (session, url, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (request));

	stream = soup_test_request_send (request, NULL, 0, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	if (do_read) {
		char buffer[256];
		gsize nread;

		do {
			g_input_stream_read_all (stream, buffer, sizeof (buffer), &nread,
						 NULL, &error);
			g_assert_no_error (error);
			g_clear_error (&error);
		} while (nread > 0);
	}

	soup_test_request_close_stream (request, stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (stream);

	debug_printf (1, "  %d %s\n", msg->status_code, msg->reason_phrase);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	g_object_unref (request);
}

static void
do_proxy_auth_cache_test (void)
{
	SoupSession *session;
	char *cache_dir;
	SoupCache *cache;
	char *url;

	g_test_bug ("756076");

	SOUP_TEST_SKIP_IF_NO_APACHE;

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	g_free (cache_dir);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_PROXY_RESOLVER, proxy_resolvers[AUTH_PROXY],
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE, cache,
					 NULL);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);

	url = g_strconcat (HTTP_SERVER, "/Basic/realm1/", NULL);

	debug_printf (1, "  GET %s via %s (from network)\n", url, proxy_names[AUTH_PROXY]);
	do_proxy_auth_request (url, session, TRUE);
	soup_cache_flush (cache);

	debug_printf (1, "  GET %s via %s (from cache)\n", url, proxy_names[AUTH_PROXY]);
	do_proxy_auth_request (url, session, FALSE);

	g_free (url);
	soup_test_session_abort_unref (session);
	g_object_unref (cache);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	SoupURI *base_uri;
	char *path;
	int i, ret;

	test_init (argc, argv, NULL);
	apache_init ();

	for (i = 0; i < 3; i++) {
		proxy_resolvers[i] =
			g_simple_proxy_resolver_new (proxies[i], (char **) ignore_hosts);
	}

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	for (i = 0; i < ntests; i++) {
		path = g_strdup_printf ("/proxy/async/%s", tests[i].explanation);
		g_test_add_data_func (path, &tests[i], do_async_proxy_test);
		g_free (path);
	}
	for (i = 0; i < ntests; i++) {
		path = g_strdup_printf ("/proxy/sync/%s", tests[i].explanation);
		g_test_add_data_func (path, &tests[i], do_sync_proxy_test);
		g_free (path);
	}

	g_test_add_data_func ("/proxy/fragment", base_uri, do_proxy_fragment_test);
	g_test_add_func ("/proxy/redirect", do_proxy_redirect_test);
	g_test_add_func ("/proxy/auth-cache", do_proxy_auth_cache_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);
	for (i = 0; i < 3; i++)
		g_object_unref (proxy_resolvers[i]);

	test_cleanup ();
	return ret;
}
