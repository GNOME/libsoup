#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libsoup/soup.h"
#include "apache-wrapper.h"

int errors = 0;
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

typedef struct {
	const char *explanation;
	const char *url;
	const guint final_status;
} SoupProxyTest;

SoupProxyTest tests[] = {
	{ "GET -> 200", "", SOUP_STATUS_OK },
	{ "GET -> 404", "/not-found", SOUP_STATUS_NOT_FOUND },
	{ "GET -> 401 -> 200", "/Basic/realm1/", SOUP_STATUS_OK },
	{ "GET -> 401 -> 401", "/Basic/realm2/", SOUP_STATUS_UNAUTHORIZED },
	{ "GET -> 403", "http://no-proxy.example.com/", SOUP_STATUS_FORBIDDEN },
};
int ntests = sizeof (tests) / sizeof (tests[0]);

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
	if (!retrying)
		soup_auth_authenticate (auth, "user1", "realm1");
}

static void
test_url (const char *url, int proxy, guint expected, gboolean sync)
{
	SoupSession *session;
	SoupURI *proxy_uri;
	SoupMessage *msg;

	dprintf ("  GET %s via %s\n", url, proxy_names[proxy]);
	if (proxy == UNAUTH_PROXY && expected != SOUP_STATUS_FORBIDDEN)
		expected = SOUP_STATUS_PROXY_UNAUTHORIZED;

	/* We create a new session for each request to ensure that
	 * connections/auth aren't cached between tests.
	 */
	proxy_uri = soup_uri_new (proxies[proxy]);
	session = g_object_new (sync ? SOUP_TYPE_SESSION_SYNC : SOUP_TYPE_SESSION_ASYNC,
				SOUP_SESSION_PROXY_URI, proxy_uri,
				NULL);
	soup_uri_free (proxy_uri);
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), NULL);

	msg = soup_message_new (SOUP_METHOD_GET, url);
	if (!msg) {
		fprintf (stderr, "proxy-test: Could not parse URI\n");
		exit (1);
	}

	soup_session_send_message (session, msg);

	dprintf ("  %d %s\n", msg->status_code, msg->reason_phrase);
	if (msg->status_code != expected) {
		dprintf ("  EXPECTED %d!\n", expected);
		errors++;
	}

	g_object_unref (msg);
	soup_session_abort (session);
	g_object_unref (session);
}

static void
run_test (int i, gboolean sync)
{
	char *http_url, *https_url;

	dprintf ("Test %d: %s (%s)\n", i + 1, tests[i].explanation,
		 sync ? "sync" : "async");

	if (!strncmp (tests[i].url, "http", 4)) {
		http_url = g_strdup (tests[i].url);
		https_url = g_strdup_printf ("https%s", tests[i].url + 4);
	} else {
		http_url = g_strconcat (HTTP_SERVER, tests[i].url, NULL);
		https_url = g_strconcat (HTTPS_SERVER, tests[i].url, NULL);
	}
	test_url (http_url, SIMPLE_PROXY, tests[i].final_status, sync);
#if HAVE_SSL
	test_url (https_url, SIMPLE_PROXY, tests[i].final_status, sync);
#endif
	test_url (http_url, AUTH_PROXY, tests[i].final_status, sync);
#if HAVE_SSL
	test_url (https_url, AUTH_PROXY, tests[i].final_status, sync);
#endif
	test_url (http_url, UNAUTH_PROXY, tests[i].final_status, sync);
#if HAVE_SSL
	test_url (https_url, UNAUTH_PROXY, tests[i].final_status, sync);
#endif

	g_free (http_url);
	g_free (https_url);

	dprintf ("\n");
}

int
main (int argc, char **argv)
{
	int i, opt;

	g_type_init ();
	g_thread_init (NULL);

	while ((opt = getopt (argc, argv, "d")) != -1) {
		switch (opt) {
		case 'd':
			debug = TRUE;
			break;
		default:
			fprintf (stderr, "Usage: %s [-d]\n", argv[0]);
			return 1;
		}
	}

	if (!apache_init ()) {
		fprintf (stderr, "Could not start apache\n");
		return 1;
	}

	for (i = 0; i < ntests; i++) {
		run_test (i, FALSE);
		run_test (i, TRUE);
	}

	apache_cleanup ();
	g_main_context_unref (g_main_context_default ());

	dprintf ("\n");
	if (errors) {
		printf ("proxy-test: %d error(s). Run with '-d' for details\n",
			errors);
	} else
		printf ("proxy-test: OK\n");
	return errors;
}
