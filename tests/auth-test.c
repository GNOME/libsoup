#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libsoup/soup.h"
#include "libsoup/soup-auth.h"
#include "libsoup/soup-private.h"
#include "libsoup/soup-session.h"

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
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/index.txt",
	  "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Should fail with no auth, fail again with bad password, and give up",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm2/index.txt",
	  "4", "04", SOUP_STATUS_UNAUTHORIZED },

	{ "Known realm, auth provided, so should succeed immediately",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/index.txt",
	  "1", "1", SOUP_STATUS_OK },

	{ "Now should automatically reuse previous auth",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Subdir should also automatically reuse auth",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/subdir/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Subdir should retry last auth, but will fail this time",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/index.txt",
	  "", "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Now should use provided auth on first try",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/index.txt",
	  "2", "2", SOUP_STATUS_OK },

	{ "Reusing last auth. Should succeed on first try",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Reuse will fail, but 2nd try will succeed because it's a known realm",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/realm1/index.txt",
	  "", "21", SOUP_STATUS_OK },

	{ "Should succeed on first try. (Known realm with cached password)",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Fail once, then use typoed password, then use right password",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm3/index.txt",
	  "43", "043", SOUP_STATUS_OK },


	{ "No auth available, should fail",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/index.txt",
	  "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Should fail with no auth, fail again with bad password, and give up",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm2/index.txt",
	  "4", "04", SOUP_STATUS_UNAUTHORIZED },

	{ "Known realm, auth provided, so should succeed immediately",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/index.txt",
	  "1", "1", SOUP_STATUS_OK },

	{ "Now should automatically reuse previous auth",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Subdir should also automatically reuse auth",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/subdir/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Subdir should retry last auth, but will fail this time",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/index.txt",
	  "", "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Now should use provided auth on first try",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/index.txt",
	  "2", "2", SOUP_STATUS_OK },

	{ "Reusing last auth. Should succeed on first try",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Should succeed on first try because of earlier domain directive",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Should succeed on first try. (Known realm with cached password)",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Fail once, then use typoed password, then use right password",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm3/index.txt",
	  "43", "043", SOUP_STATUS_OK },


	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/realm2/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm3/index.txt",
	  "", "3", SOUP_STATUS_OK },


	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/realm2/realm1/index.txt",
	  "", "1", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm2/index.txt",
	  "", "2", SOUP_STATUS_OK },

	{ "Make sure we haven't forgotten anything",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm3/index.txt",
	  "", "3", SOUP_STATUS_OK },

	{ "Now the server will reject the formerly-good password",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/not/index.txt",
	  "1" /* should not be used */, "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Make sure we've forgotten it",
	  "http://primates.ximian.com/~danw/soup-test/Basic/realm1/index.txt",
	  "", "0", SOUP_STATUS_UNAUTHORIZED },

	{ "Likewise, reject the formerly-good Digest password",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/not/index.txt",
	  "1" /* should not be used */, "1", SOUP_STATUS_UNAUTHORIZED },

	{ "Make sure we've forgotten it",
	  "http://primates.ximian.com/~danw/soup-test/Digest/realm1/index.txt",
	  "", "0", SOUP_STATUS_UNAUTHORIZED }
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

int
main (int argc, char **argv)
{
	SoupSession *session;
	SoupMessage *msg;
	char *expected;
	int i;

	g_type_init ();

	session = soup_session_new ();
	g_signal_connect (session, "authenticate",
			  G_CALLBACK (authenticate), &i);
	g_signal_connect (session, "reauthenticate",
			  G_CALLBACK (reauthenticate), &i);

	for (i = 0; i < ntests; i++) {
		printf ("Test %d: %s\n", i + 1, tests[i].explanation);

		printf ("  GET %s\n", tests[i].url);

		msg = soup_message_new (SOUP_METHOD_GET, tests[i].url);
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
				strlen (expected));
			errors++;
		}
		g_free (expected);

		if (msg->status_code != tests[i].final_status)
			printf ("  expected %d\n", tests[i].final_status);

		printf ("\n");

		g_object_unref (msg);
	}

	g_object_unref (session);

	printf ("\nauth-test: %d errors\n", errors);
	return errors;
}
