/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static GBytes *correct_response;

static gboolean
authenticate (SoupMessage *msg,
	      SoupAuth    *auth,
	      gboolean     retrying)
{
	if (!retrying) {
		soup_auth_authenticate (auth, "user2", "realm2");

		return TRUE;
	}

	return FALSE;
}

#ifdef HAVE_APACHE
static void
get_correct_response (const char *uri)
{
	SoupSession *session;
	SoupMessage *msg;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	msg = soup_message_new (SOUP_METHOD_GET, uri);
	correct_response = soup_test_session_send (session, msg, NULL, NULL);
	if (msg->status_code != SOUP_STATUS_OK) {
		g_printerr ("Could not fetch %s: %d %s\n", uri,
			    msg->status_code, msg->reason_phrase);
		exit (1);
	}

	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}
#endif

/* Pull API version 1: fully-async. More like a "poke" API. Rather
 * than having SoupMessage emit "got_chunk" signals whenever it wants,
 * we stop it after it finishes reading the message headers, and then
 * tell it when we want to hear about new chunks.
 */

typedef struct {
	GMainLoop *loop;
	SoupSession *session;
	SoupMessage *msg;
	guint timeout;
	gboolean chunks_ready;
	gboolean chunk_wanted;
	gboolean did_first_timeout;
	gsize read_so_far;
	guint expected_status;
} FullyAsyncData;

static void fully_async_got_headers (SoupMessage *msg, gpointer user_data);
static gboolean fully_async_request_chunk (gpointer user_data);

static void
fully_async_finished (SoupMessage    *msg,
		      FullyAsyncData *ad)
{
	soup_test_assert_message_status (msg, ad->expected_status);

	if (ad->timeout != 0)
		g_source_remove (ad->timeout);

	/* Since our test program is only running the loop for the
	 * purpose of this one test, we quit the loop once the
	 * test is done.
	 */
	g_main_loop_quit (ad->loop);
}

static void
do_fully_async_test (SoupSession *session,
		     const char *base_uri, const char *sub_uri,
		     gboolean fast_request, guint expected_status)
{
	GMainLoop *loop;
	FullyAsyncData ad;
	SoupMessage *msg;
	char *uri;

	loop = g_main_loop_new (NULL, FALSE);

	uri = g_build_filename (base_uri, sub_uri, NULL);
	debug_printf (1, "GET %s\n", uri);

	msg = soup_message_new (SOUP_METHOD_GET, uri);
	g_free (uri);

	ad.loop = loop;
	ad.session = session;
	ad.msg = msg;
	ad.chunks_ready = FALSE;
	ad.chunk_wanted = FALSE;
	ad.did_first_timeout = FALSE;
	ad.read_so_far = 0;
	ad.expected_status = expected_status;

	g_signal_connect (msg, "authenticate",
			  G_CALLBACK (authenticate), NULL);

	/* Connect to "got_headers", from which we'll decide where to
	 * go next.
	 */
	g_signal_connect (msg, "got_headers",
			  G_CALLBACK (fully_async_got_headers), &ad);

	/* Send the request */
	g_signal_connect (msg, "finished",
			  G_CALLBACK (fully_async_finished), &ad);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);

	/* In a real program, we'd probably just return at this point.
	 * Eventually the caller would return all the way to the main
	 * loop, and then eventually, some event would cause the
	 * application to request a chunk of data from the message
	 * response.
	 *
	 * In our test program, there is no "real" main loop, so we
	 * had to create our own. We use a timeout to represent the
	 * event that causes the app to decide to request another body
	 * chunk. We use short timeouts in one set of tests, and long
	 * ones in another, to test both the
	 * chunk-requested-before-its-been-read and
	 * chunk-read-before-its-been-requested cases.
	 */
	ad.timeout = g_timeout_add (fast_request ? 0 : 100,
				    fully_async_request_chunk, &ad);
	g_main_loop_run (ad.loop);
	g_main_loop_unref (ad.loop);
}

static gboolean
fully_async_request_chunk (gpointer user_data)
{
	FullyAsyncData *ad = user_data;

	if (!ad->did_first_timeout) {
		debug_printf (1, "  first timeout\n");
		ad->did_first_timeout = TRUE;
	} else
		debug_printf (2, "  timeout\n");
	ad->timeout = 0;

	/* ad->chunks_ready and ad->chunk_wanted are used because
	 * there's a race condition between the application requesting
	 * the first chunk, and the message reaching a point where
	 * it's actually ready to read chunks. If chunks_ready has
	 * been set, we can just call soup_session_unpause_message() to
	 * cause the first chunk to be read. But if it's not, we just
	 * set chunk_wanted, to let the got_headers handler below know
	 * that a chunk has already been requested.
	 */
	if (ad->chunks_ready)
		soup_session_unpause_message (ad->session, ad->msg);
	else
		ad->chunk_wanted = TRUE;

	return FALSE;
}

static void
fully_async_got_headers (SoupMessage *msg, gpointer user_data)
{
	FullyAsyncData *ad = user_data;

	debug_printf (1, "  %d %s\n", msg->status_code, msg->reason_phrase);
	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED) {
		/* Let soup handle this one; this got_headers handler
		 * will get called again next time around.
		 */
		return;
	} else if (msg->status_code != SOUP_STATUS_OK) {
		soup_test_assert_message_status (msg, SOUP_STATUS_OK);
		return;
	}

	/* OK, we're happy with the response. So, we connect to
	 * "got_chunk". If there has already been a chunk requested,
	 * we let I/O continue; but if there hasn't, we pause now
	 * until one is requested.
	 */
	ad->chunks_ready = TRUE;
	if (!ad->chunk_wanted)
		soup_session_pause_message (ad->session, msg);
}

static void
do_fast_async_test (gconstpointer data)
{
	const char *base_uri = data;
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_fully_async_test (session, base_uri, "/",
			     TRUE, SOUP_STATUS_OK);
	do_fully_async_test (session, base_uri, "/Basic/realm1/",
			     TRUE, SOUP_STATUS_UNAUTHORIZED);
	do_fully_async_test (session, base_uri, "/Basic/realm2/",
			     TRUE, SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

static void
do_slow_async_test (gconstpointer data)
{
	const char *base_uri = data;
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_fully_async_test (session, base_uri, "/",
			     FALSE, SOUP_STATUS_OK);
	do_fully_async_test (session, base_uri, "/Basic/realm1/",
			     FALSE, SOUP_STATUS_UNAUTHORIZED);
	do_fully_async_test (session, base_uri, "/Basic/realm2/",
			     FALSE, SOUP_STATUS_OK);
	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	const char *base_uri;
	int ret;

	test_init (argc, argv, NULL);
	apache_init ();

	base_uri = "http://127.0.0.1:47524/";
#ifdef HAVE_APACHE
	get_correct_response (base_uri);
#endif

	g_test_add_data_func ("/pull-api/async/fast", base_uri, do_fast_async_test);
	g_test_add_data_func ("/pull-api/async/slow", base_uri, do_slow_async_test);

	ret = g_test_run ();

#ifdef HAVE_APACHE
	g_bytes_unref (correct_response);
#endif

	test_cleanup ();
	return ret;
}
