/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "test-utils.h"

#include <gio/gio.h>

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

static gboolean
authenticate (SoupMessage *msg,
	      SoupAuth    *auth,
	      gboolean     retrying)
{
	if (soup_auth_is_for_proxy (auth)) {
		char *uri;
		int i;
		gboolean found = FALSE;

		uri = g_strdup_printf ("http://%s", soup_auth_get_authority (auth));
		for (i = 1; i < G_N_ELEMENTS (proxies) && !found; i++) {
			if (strcmp (uri, proxies[i]) == 0)
				found = TRUE;
		}
		g_free (uri);
		g_assert_true (found);
	} else {
		GUri *uri = soup_message_get_uri (msg);
		char *authority;

		authority = g_strdup_printf ("%s:%d", g_uri_get_host (uri), g_uri_get_port (uri));
		g_assert_cmpstr (authority, ==, soup_auth_get_authority (auth));
		g_free (authority);
	}

	if (!retrying) {
		soup_auth_authenticate (auth, "user1", "realm1");

		return TRUE;
	}

	return FALSE;
}

static void
set_close_on_connect (SoupMessage *msg,
                      gpointer user_data)
{
	/* This is used to test that we can handle the server closing
	 * the connection when returning a 407 in response to a
	 * CONNECT. (Rude!)
	 */
	if (soup_message_get_method (msg) == SOUP_METHOD_CONNECT) {
		soup_message_headers_append (soup_message_get_request_headers (msg),
					     "Connection", "close");
	}
}

static gboolean
accept_certificate (SoupMessage         *msg,
		    GTlsCertificate     *certificate,
		    GTlsCertificateFlags errors)
{
	return TRUE;
}

static void
test_url (const char *url, int proxy, guint expected, gboolean close)
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
	session = soup_test_session_new ("proxy-resolver", proxy_resolvers[proxy],
					 NULL);

	msg = soup_message_new (SOUP_METHOD_GET, url);
	if (!msg) {
		g_printerr ("proxy-test: Could not parse URI\n");
		exit (1);
	}

	g_signal_connect (msg, "authenticate",
                          G_CALLBACK (authenticate), NULL);
	g_signal_connect (msg, "accept-certificate",
			  G_CALLBACK (accept_certificate), NULL);

	if (close) {
		/* FIXME g_test_bug ("611663") */
		g_signal_connect (msg, "starting",
				  G_CALLBACK (set_close_on_connect), NULL);
	}

	soup_test_session_send_message (session, msg);

	debug_printf (1, "  %d %s\n", soup_message_get_status (msg), soup_message_get_reason_phrase (msg));
	soup_test_assert_message_status (msg, expected);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_test (SoupProxyTest *test)
{
	char *http_url, *https_url;

	if (test->bugref)
		g_test_bug (test->bugref);

	if (!strncmp (test->url, "http", 4)) {
		GUri *http_uri, *https_uri;
		int port;

		http_url = g_strdup (test->url);

                http_uri = g_uri_parse (test->url, SOUP_HTTP_URI_FLAGS, NULL);
                port = g_uri_get_port (http_uri);
                if (port != -1)
                        port += 1;
                https_uri = g_uri_build (SOUP_HTTP_URI_FLAGS, "https", NULL, g_uri_get_host (http_uri),
                                         port, g_uri_get_path (http_uri),
                                         g_uri_get_query (http_uri), g_uri_get_fragment (http_uri));
		https_url = g_uri_to_string (https_uri);
		g_uri_unref (http_uri);
                g_uri_unref (https_uri);
	} else {
		http_url = g_strconcat (HTTP_SERVER, test->url, NULL);
		https_url = g_strconcat (HTTPS_SERVER, test->url, NULL);
	}

	test_url (http_url, SIMPLE_PROXY, test->final_status, FALSE);
	test_url (https_url, SIMPLE_PROXY, test->final_status, FALSE);

	test_url (http_url, AUTH_PROXY, test->final_status, FALSE);
	test_url (https_url, AUTH_PROXY, test->final_status, FALSE);
	test_url (https_url, AUTH_PROXY, test->final_status, TRUE);

	test_url (http_url, UNAUTH_PROXY, test->final_status, FALSE);
	test_url (https_url, UNAUTH_PROXY, test->final_status, FALSE);

	g_free (http_url);
	g_free (https_url);
}

static void
do_async_proxy_test (gconstpointer data)
{
	SoupProxyTest *test = (SoupProxyTest *)data;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	do_proxy_test (test);
}

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	GUri *uri = soup_server_message_get_uri (msg);

	soup_server_message_set_status (msg, g_uri_get_fragment (uri) ? SOUP_STATUS_BAD_REQUEST : SOUP_STATUS_OK, NULL);
}

static void
do_proxy_fragment_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	GUri *req_uri;
	SoupMessage *msg;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new ("proxy-resolver", proxy_resolvers[SIMPLE_PROXY],
					 NULL);

	req_uri = g_uri_parse_relative (base_uri, "/#foo", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri (SOUP_METHOD_GET, req_uri);
	g_uri_unref (req_uri);
	soup_test_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_redirect_test (void)
{
	SoupSession *session;
	GUri *base_uri, *req_uri, *new_uri;
	SoupMessage *msg;

	g_test_bug ("631368");

	SOUP_TEST_SKIP_IF_NO_APACHE;
	SOUP_TEST_SKIP_IF_NO_TLS;

	session = soup_test_session_new ("proxy-resolver", proxy_resolvers[SIMPLE_PROXY],
					 NULL);

	base_uri = g_uri_parse (HTTPS_SERVER, SOUP_HTTP_URI_FLAGS, NULL);
        req_uri = g_uri_parse_relative (base_uri, "/redirected", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri (SOUP_METHOD_GET, req_uri);
	soup_message_headers_append (soup_message_get_request_headers (msg),
				     "Connection", "close");
	soup_test_session_send_message (session, msg);

	new_uri = soup_message_get_uri (msg);
	soup_test_assert (strcmp (g_uri_get_path (req_uri), g_uri_get_path (new_uri)) != 0,
			  "message was not redirected");
	g_uri_unref (req_uri);
        g_uri_unref (base_uri);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
do_proxy_auth_request (const char *url, SoupSession *session, gboolean do_read)
{
	SoupMessage *msg;
	GInputStream *stream;
	GError *error = NULL;

	msg = soup_message_new ("GET", url);
	g_signal_connect (msg, "authenticate",
			  G_CALLBACK (authenticate), NULL);

	stream = soup_test_request_send (session, msg, NULL, 0, &error);
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

	soup_test_request_close_stream (stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (stream);

	debug_printf (1, "  %d %s\n", soup_message_get_status (msg), soup_message_get_reason_phrase (msg));
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	g_object_unref (msg);
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

	session = soup_test_session_new ("proxy-resolver", proxy_resolvers[AUTH_PROXY],
					 NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));
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

static void
do_proxy_connect_error_test (gconstpointer data)
{
        GUri *base_uri = (GUri *)data;
        GUri *proxy_uri;
        char *proxy_uri_str;
        SoupSession *session;
        SoupMessage *msg;
        GProxyResolver *resolver;
        GBytes *body;
        GError *error = NULL;

        /* Proxy connection will success, but CONNECT message to https will fail due to TLS errors */
        proxy_uri = soup_uri_copy (base_uri, SOUP_URI_SCHEME, "http", NULL);
        proxy_uri_str = g_uri_to_string (proxy_uri);
        g_uri_unref (proxy_uri);

        resolver = g_simple_proxy_resolver_new (proxy_uri_str, (char **)ignore_hosts);
        g_free (proxy_uri_str);
        session = soup_test_session_new ("proxy-resolver", resolver, NULL);
        g_object_unref (resolver);

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, base_uri);
        body = soup_test_session_async_send (session, msg, NULL, &error);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED);

        g_error_free (error);
        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	GUri *base_uri, *base_https_uri;
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
        base_https_uri = soup_test_server_get_uri (server, "https", NULL);

	for (i = 0; i < ntests; i++) {
		path = g_strdup_printf ("/proxy/%s", tests[i].explanation);
		g_test_add_data_func (path, &tests[i], do_async_proxy_test);
		g_free (path);
	}

	g_test_add_data_func ("/proxy/fragment", base_uri, do_proxy_fragment_test);
	g_test_add_func ("/proxy/redirect", do_proxy_redirect_test);
	g_test_add_func ("/proxy/auth-cache", do_proxy_auth_cache_test);
        g_test_add_data_func ("/proxy/connect-error", base_https_uri, do_proxy_connect_error_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
        g_uri_unref (base_https_uri);
	soup_test_server_quit_unref (server);
	for (i = 0; i < 3; i++)
		g_object_unref (proxy_resolvers[i]);

	test_cleanup ();
	return ret;
}
