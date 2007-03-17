#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libsoup/soup.h"
#include "libsoup/soup-auth.h"
#include "libsoup/soup-session.h"

#ifdef HAVE_APACHE
#include "apache-wrapper.h"
#endif

GMainLoop *loop;
int errors = 0;

typedef struct {
	/* Explanation of what you should see */
	const char *explanation;

	/* URL to test against */
	const char *url;

	/* Provided passwords, 1 character each. ('1', '2', and '3'
	 * mean the correct passwords for "realm1", "realm2", and
	 * "realm3" respectively. '4' means "use the wrong password".)
	 * The first password (if present) will be used by
	 * authenticate(), and the second (if present) will be used by
	 * reauthenticate().
	 */
	const char *provided;

	/* Expected passwords, 1 character each. (As with the provided
	 * passwords, with the addition that '0' means "no
	 * Authorization header expected".) Used to verify that soup
	 * used the password it was supposed to at each step.
	 */
	const char *expected;

	/* What the final status code should be. */
	guint final_status;
} SoupAuthTest;

SoupAuthTest tests[] = {
	{ "No auth available, should fail",
	  "Basic/realm1/", "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Should fail with no auth, fail again with bad password, and give up",
	  "Basic/realm2/", "4", "04", SOUP_STATUS_UNAUTHORIZED },

	{ "Known realm, auth provided, so should succeed immediately",
	  "Basic/realm1/", "1", "1", SOUP_STATUS_OK },

	{ "Now should automatically reuse previous auth",
	  "Basic/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Subdir should also automatically reuse auth",
	  "Basic/realm1/subdir/", "", "1", SOUP_STATUS_OK },

	{ "Subdir should retry last auth, but will fail this time",
	  "Basic/realm1/realm2/", "", "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Now should use provided auth on first try",
	  "Basic/realm1/realm2/", "2", "2", SOUP_STATUS_OK },

	{ "Reusing last auth. Should succeed on first try",
	  "Basic/realm1/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Reuse will fail, but 2nd try will succeed because it's a known realm",
	  "Basic/realm1/realm2/realm1/", "", "21", SOUP_STATUS_OK },

	{ "Should succeed on first try. (Known realm with cached password)",
	  "Basic/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Fail once, then use typoed password, then use right password",
	  "Basic/realm3/", "43", "043", SOUP_STATUS_OK },


	{ "No auth available, should fail",
	  "Digest/realm1/", "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Should fail with no auth, fail again with bad password, and give up",
	  "Digest/realm2/", "4", "04", SOUP_STATUS_UNAUTHORIZED },

	{ "Known realm, auth provided, so should succeed immediately",
	  "Digest/realm1/", "1", "1", SOUP_STATUS_OK },

	{ "Now should automatically reuse previous auth",
	  "Digest/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Subdir should also automatically reuse auth",
	  "Digest/realm1/subdir/", "", "1", SOUP_STATUS_OK },

	{ "Should already know correct domain and use provided auth on first try",
	  "Digest/realm1/realm2/", "2", "2", SOUP_STATUS_OK },

	{ "Reusing last auth. Should succeed on first try",
	  "Digest/realm1/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Should succeed on first try because of earlier domain directive",
	  "Digest/realm1/realm2/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Should succeed on first try. (Known realm with cached password)",
	  "Digest/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Fail once, then use typoed password, then use right password",
	  "Digest/realm3/", "43", "043", SOUP_STATUS_OK },


	{ "Make sure we haven't forgotten anything",
	  "Basic/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Basic/realm1/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Basic/realm1/realm2/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Basic/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Basic/realm3/", "", "3", SOUP_STATUS_OK },


	{ "Make sure we haven't forgotten anything",
	  "Digest/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Digest/realm1/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Digest/realm1/realm2/realm1/", "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Digest/realm2/", "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "Digest/realm3/", "", "3", SOUP_STATUS_OK },

	{ "Now the server will reject the formerly-good password",
	  "Basic/realm1/not/", "1" /* should not be used */, "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Make sure we've forgotten it",
	  "Basic/realm1/", "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Likewise, reject the formerly-good Digest password",
	  "Digest/realm1/not/", "1" /* should not be used */, "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Make sure we've forgotten it",
	  "Digest/realm1/", "", "0", SOUP_STATUS_UNAUTHORIZED }
};
int ntests = sizeof (tests) / sizeof (tests[0]);

static const char *auths[] = {
	"no password", "password 1",
	"password 2", "password 3",
	"intentionally wrong password",
};

static int
identify_auth (SoupMessage *msg)
{
	const char *header;
	int num;

	header = soup_message_get_header (msg->request_headers,
					  "Authorization");
	if (!header)
		return 0;

	if (!g_ascii_strncasecmp (header, "Basic ", 6)) {
		char *token;
		int len;

		token = soup_base64_decode (header + 6, &len);
		num = token[len - 1] - '0';
		g_free (token);
	} else {
		const char *user;

		user = strstr (header, "username=\"user");
		if (user)
			num = user[14] - '0';
		else
			num = 0;
	}

	g_assert (num >= 0 && num <= 4);

	return num;
}

static void
handler (SoupMessage *msg, gpointer data)
{
	char *expected = data;
	int auth, exp;

	auth = identify_auth (msg);

	printf ("  %d %s (using %s)\n", msg->status_code, msg->reason_phrase,
		auths[auth]);

	if (*expected) {
		exp = *expected - '0';
		if (auth != exp) {
			printf ("    expected %s!\n", auths[exp]);
			errors++;
		}
		memmove (expected, expected + 1, strlen (expected));
	} else {
		printf ("    expected to be finished\n");
		errors++;
	}
}

static void
authenticate (SoupSession *session, SoupMessage *msg,
	      const char *auth_type, const char *auth_realm,
	      char **username, char **password, gpointer data)
{
	int *i = data;

	if (tests[*i].provided[0]) {
		*username = g_strdup_printf ("user%c", tests[*i].provided[0]);
		*password = g_strdup_printf ("realm%c", tests[*i].provided[0]);
	}
}

static void
reauthenticate (SoupSession *session, SoupMessage *msg, 
		const char *auth_type, const char *auth_realm,
		char **username, char **password, gpointer data)
{
	int *i = data;

	if (tests[*i].provided[0] && tests[*i].provided[1]) {
		*username = g_strdup_printf ("user%c", tests[*i].provided[1]);
		*password = g_strdup_printf ("realm%c", tests[*i].provided[1]);
	}
}

static void
bug271540_sent (SoupMessage *msg, gpointer data)
{
	int n = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (msg), "#"));
	gboolean *authenticated = data;
	int auth = identify_auth (msg);

	if (!*authenticated && auth) {
		printf ("    using auth on message %d before authenticating!!??\n", n);
		errors++;
	} else if (*authenticated && !auth) {
		printf ("    sent unauthenticated message %d after authenticating!\n", n);
		errors++;
	}
}

static void
bug271540_authenticate (SoupSession *session, SoupMessage *msg,
			const char *auth_type, const char *auth_realm,
			char **username, char **password, gpointer data)
{
	int n = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (msg), "#"));
	gboolean *authenticated = data;

	if (strcmp (auth_type, "Basic") != 0 ||
	    strcmp (auth_realm, "realm1") != 0)
		return;

	if (!*authenticated) {
		printf ("    authenticating message %d\n", n);
		*username = g_strdup ("user1");
		*password = g_strdup ("realm1");
		*authenticated = TRUE;
	} else {
		printf ("    asked to authenticate message %d after authenticating!\n", n);
		errors++;
	}
}

static void
bug271540_finished (SoupMessage *msg, gpointer data)
{
	int *left = data;
	int n = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (msg), "#"));

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		printf ("      got status '%d %s' on message %d!\n",
			msg->status_code, msg->reason_phrase, n);
		errors++;
	}

	(*left)--;
	if (!*left)
		g_main_loop_quit (loop);
}

int
main (int argc, char **argv)
{
	SoupSession *session;
	SoupMessage *msg;
	char *base_uri, *uri, *expected;
	gboolean authenticated;
#ifdef HAVE_APACHE
	gboolean using_apache = FALSE;
#endif
	int i;

	g_type_init ();
	g_thread_init (NULL);

	if (argc != 1) {
		char *p;

		base_uri = argv[0];
		p = strrchr (base_uri, '/');
		if (!p || p[1])
			base_uri = g_strdup_printf ("%s/", base_uri);
	} else {
#ifdef HAVE_APACHE
		if (!apache_init ()) {
			fprintf (stderr, "Could not start apache\n");
			return 1;
		}
		base_uri = "http://localhost:47524/";
		using_apache = TRUE;
#else
		fprintf (stderr, "Must specify base_uri for tests if configured --without-apache\n");
		return 1;
#endif
	}

	session = soup_session_async_new ();
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), &i);
	g_signal_connect (session, "reauthenticate",
			  G_CALLBACK (reauthenticate), &i);

	for (i = 0; i < ntests; i++) {
		printf ("Test %d: %s\n", i + 1, tests[i].explanation);

		uri = g_strconcat (base_uri, tests[i].url, NULL);
		printf ("  GET %s\n", uri);

		msg = soup_message_new (SOUP_METHOD_GET, uri);
		g_free (uri);
		if (!msg) {
			fprintf (stderr, "auth-test: Could not parse URI\n");
			exit (1);
		}

		expected = g_strdup (tests[i].expected);
		soup_message_add_status_code_handler (
			msg, SOUP_STATUS_UNAUTHORIZED,
			SOUP_HANDLER_PRE_BODY, handler, expected);
		soup_message_add_status_code_handler (
			msg, SOUP_STATUS_OK, SOUP_HANDLER_PRE_BODY,
			handler, expected);
		soup_session_send_message (session, msg);
		if (msg->status_code != SOUP_STATUS_UNAUTHORIZED &&
		    msg->status_code != SOUP_STATUS_OK) {
			printf ("  %d %s !\n", msg->status_code,
				msg->reason_phrase);
			errors++;
		}
		if (*expected) {
			printf ("  expected %d more round(s)\n",
				(int)strlen (expected));
			errors++;
		}
		g_free (expected);

		if (msg->status_code != tests[i].final_status)
			printf ("  expected %d\n", tests[i].final_status);

		printf ("\n");

		g_object_unref (msg);
	}
	g_object_unref (session);

	/* And now for a regression test */

	printf ("Regression test for bug 271540:\n");
	session = soup_session_async_new ();

	authenticated = FALSE;
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (bug271540_authenticate), &authenticated);

	uri = g_strconcat (base_uri, "Basic/realm1/", NULL);
	for (i = 0; i < 10; i++) {
		msg = soup_message_new (SOUP_METHOD_GET, uri);
		g_object_set_data (G_OBJECT (msg), "#", GINT_TO_POINTER (i + 1));
		g_signal_connect (msg, "wrote_headers",
				  G_CALLBACK (bug271540_sent), &authenticated);

		soup_session_queue_message (session, msg,
					    bug271540_finished, &i);
	}

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);

	g_object_unref (session);

#ifdef HAVE_APACHE
	if (using_apache)
		apache_cleanup ();
#endif

	printf ("\nauth-test: %d errors\n", errors);
	return errors;
}
