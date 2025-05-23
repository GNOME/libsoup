/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "config.h"

#include "test-utils.h"

GBytes *full_response;
int total_length;
char *test_response;

static void
check_part (SoupMessageHeaders *headers,
	    GBytes             *body,
	    gboolean            check_start_end,
	    int                 expected_start,
	    int                 expected_end)
{
	goffset start, end, total_length;
        gsize full_response_length = g_bytes_get_size (full_response);

	debug_printf (1, "    Content-Range: %s\n",
		      soup_message_headers_get_one (headers, "Content-Range"));

	if (!soup_message_headers_get_content_range (headers, &start, &end, &total_length)) {
		soup_test_assert (FALSE, "Could not find/parse Content-Range");
		return;
	}

	if (total_length != full_response_length && total_length != -1) {
		soup_test_assert (FALSE,
				  "Unexpected total length %" G_GINT64_FORMAT " in response\n",
				  total_length);
		return;
	}

	if (check_start_end) {
		if ((expected_start >= 0 && start != expected_start) ||
		    (expected_start < 0 && start != full_response_length + expected_start)) {
			soup_test_assert (FALSE,
					  "Unexpected range start %" G_GINT64_FORMAT " in response\n",
					  start);
			return;
		}

		if ((expected_end >= 0 && end != expected_end) ||
		    (expected_end < 0 && end != full_response_length - 1)) {
			soup_test_assert (FALSE,
					  "Unexpected range end %" G_GINT64_FORMAT " in response\n",
					  end);
			return;
		}
	}

	if (end - start + 1 != g_bytes_get_size (body)) {
		soup_test_assert (FALSE, "Range length (%d) does not match body length (%d)\n",
				  (int)(end - start) + 1,
				  (int)g_bytes_get_size (body));
		return;
	}

	memcpy (test_response + start, g_bytes_get_data (body, NULL), g_bytes_get_size (body));
}

static void
do_single_range (SoupSession *session, SoupMessage *msg,
		 int start, int end, gboolean succeed)
{
	const char *content_type;
	GBytes *body;

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get_one (soup_message_get_request_headers (msg), "Range"));

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	if (!succeed) {
		soup_test_assert_message_status (msg, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
		if (soup_message_get_status (msg) != SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
			const char *content_range;

			content_range = soup_message_headers_get_one (soup_message_get_response_headers (msg),
								      "Content-Range");
			if (content_range)
				debug_printf (1, "    Content-Range: %s\n", content_range);
		}

		g_clear_pointer (&body, g_bytes_unref);
		g_object_unref (msg);
		return;
	}

	soup_test_assert_message_status (msg, SOUP_STATUS_PARTIAL_CONTENT);

	content_type = soup_message_headers_get_content_type (
		soup_message_get_response_headers (msg), NULL);
	g_assert_cmpstr (content_type, !=, "multipart/byteranges");

	check_part (soup_message_get_response_headers (msg), body, TRUE, start, end);
	g_bytes_unref (body);
	g_object_unref (msg);
}

static void
request_single_range (SoupSession *session, const char *uri,
		      int start, int end, gboolean succeed)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_headers_set_range (soup_message_get_request_headers (msg), start, end);
	do_single_range (session, msg, start, end, succeed);
}

static void
do_multi_range (SoupSession *session, SoupMessage *msg,
		int expected_return_ranges)
{
	SoupMultipart *multipart;
	const char *content_type;
	int i, length;
	GBytes *body;

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get_one (soup_message_get_request_headers (msg), "Range"));

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_PARTIAL_CONTENT);

	content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (msg), NULL);
	g_assert_cmpstr (content_type, ==, "multipart/byteranges");

	multipart = soup_multipart_new_from_message (soup_message_get_response_headers (msg), body);
	g_bytes_unref (body);

	if (!multipart) {
		soup_test_assert (FALSE, "Could not parse multipart");
		g_object_unref (msg);
		return;
	}

	length = soup_multipart_get_length (multipart);
	g_assert_cmpint (length, ==, expected_return_ranges);

	for (i = 0; i < length; i++) {
		SoupMessageHeaders *headers;
		GBytes *body;

		debug_printf (1, "  Part %d\n", i + 1);
		soup_multipart_get_part (multipart, i, &headers, &body);
		check_part (headers, body, FALSE, 0, 0);
	}

	soup_multipart_free (multipart);
	g_object_unref (msg);
}

static void
request_double_range (SoupSession *session, const char *uri,
		      int first_start, int first_end,
		      int second_start, int second_end,
		      int expected_return_ranges)
{
	SoupMessage *msg;
	SoupRange ranges[2];

	msg = soup_message_new ("GET", uri);
	ranges[0].start = first_start;
	ranges[0].end = first_end;
	ranges[1].start = second_start;
	ranges[1].end = second_end;
	soup_message_headers_set_ranges (soup_message_get_request_headers (msg), ranges, 2);

	if (expected_return_ranges == 1) {
		do_single_range (session, msg,
				 MIN (first_start, second_start),
				 MAX (first_end, second_end),
				 TRUE);
	} else
		do_multi_range (session, msg, expected_return_ranges);
}

static void
request_triple_range (SoupSession *session, const char *uri,
		      int first_start, int first_end,
		      int second_start, int second_end,
		      int third_start, int third_end,
		      int expected_return_ranges)
{
	SoupMessage *msg;
	SoupRange ranges[3];

	msg = soup_message_new ("GET", uri);
	ranges[0].start = first_start;
	ranges[0].end = first_end;
	ranges[1].start = second_start;
	ranges[1].end = second_end;
	ranges[2].start = third_start;
	ranges[2].end = third_end;
	soup_message_headers_set_ranges (soup_message_get_request_headers (msg), ranges, 3);

	if (expected_return_ranges == 1) {
		do_single_range (session, msg,
				 MIN (first_start, MIN (second_start, third_start)),
				 MAX (first_end, MAX (second_end, third_end)),
				 TRUE);
	} else
		do_multi_range (session, msg, expected_return_ranges);
}

static void
request_semi_invalid_range (SoupSession *session, const char *uri,
			    int first_good_start, int first_good_end,
			    int bad_start, int bad_end,
			    int second_good_start, int second_good_end)
{
	SoupMessage *msg;
	SoupRange ranges[3];

	msg = soup_message_new ("GET", uri);
	ranges[0].start = first_good_start;
	ranges[0].end = first_good_end;
	ranges[1].start = bad_start;
	ranges[1].end = bad_end;
	ranges[2].start = second_good_start;
	ranges[2].end = second_good_end;
	soup_message_headers_set_ranges (soup_message_get_request_headers (msg), ranges, 3);

	do_multi_range (session, msg, 2);
}

static void
do_range_test (SoupSession *session, const char *uri,
	       gboolean expect_coalesce, gboolean expect_partial_coalesce)
{
        gsize full_response_length = g_bytes_get_size (full_response);
	int twelfths = full_response_length / 12;

	memset (test_response, 0, full_response_length);

	/* We divide the response into 12 ranges and request them
	 * as follows:
	 *
	 *  0: A (first single request)
	 *  1: D (2nd part of triple request)
	 *  2: C (1st part of double request)
	 *  3: D (1st part of triple request)
	 *  4: F (trickier overlapping request)
	 *  5: C (2nd part of double request)
	 *  6: D (3rd part of triple request)
	 *  7: E (overlapping request)
	 *  8: E (overlapping request)
	 *  9: F (trickier overlapping request)
	 * 10: F (trickier overlapping request)
	 * 11: B (second and third single requests)
	 */

	/* A: 0, simple request */
	debug_printf (1, "Requesting %d-%d\n", 0 * twelfths, 1 * twelfths);
	request_single_range (session, uri,
			      0 * twelfths, 1 * twelfths,
			      TRUE);

	/* B: 11, end-relative request. These two are mostly redundant
	 * in terms of data coverage, but they may still catch
	 * Range-header-generating bugs.
	 */
	debug_printf (1, "Requesting %d-\n", 11 * twelfths);
	request_single_range (session, uri,
			      11 * twelfths, -1,
			      TRUE);
	debug_printf (1, "Requesting -%d\n", 1 * twelfths);
	request_single_range (session, uri,
			      -1 * twelfths, -1,
			      TRUE);

	/* C: 2 and 5 */
	debug_printf (1, "Requesting %d-%d,%d-%d\n",
		      2 * twelfths, 3 * twelfths,
		      5 * twelfths, 6 * twelfths);
	request_double_range (session, uri,
			      2 * twelfths, 3 * twelfths,
			      5 * twelfths, 6 * twelfths,
			      2);

	/* D: 1, 3, 6 */
	debug_printf (1, "Requesting %d-%d,%d-%d,%d-%d\n",
		      3 * twelfths, 4 * twelfths,
		      1 * twelfths, 2 * twelfths,
		      6 * twelfths, 7 * twelfths);
	request_triple_range (session, uri,
			      3 * twelfths, 4 * twelfths,
			      1 * twelfths, 2 * twelfths,
			      6 * twelfths, 7 * twelfths,
			      3);

	/* E: 7 and 8: should coalesce into a single response */
	debug_printf (1, "Requesting %d-%d,%d-%d (can coalesce)\n",
		      7 * twelfths, 8 * twelfths,
		      8 * twelfths, 9 * twelfths);
	request_double_range (session, uri,
			      7 * twelfths, 8 * twelfths,
			      8 * twelfths, 9 * twelfths,
			      expect_coalesce ? 1 : 2);

	/* F: 4, 9, 10: 9 and 10 should coalesce even though 4 was
	 * requested between them. (Also, they actually overlap in
	 * this case, as opposed to just touching.)
	 */
	debug_printf (1, "Requesting %d-%d,%d-%d,%d-%d (can partially coalesce)\n",
		      9 * twelfths, 10 * twelfths + 5,
		      4 * twelfths, 5 * twelfths,
		      10 * twelfths - 5, 11 * twelfths);
	request_triple_range (session, uri,
			      9 * twelfths, 10 * twelfths + 5,
			      4 * twelfths, 5 * twelfths,
			      10 * twelfths - 5, 11 * twelfths,
			      expect_partial_coalesce ? 2 : 3);

        soup_assert_cmpmem (g_bytes_get_data (full_response, NULL), full_response_length,
			    test_response, full_response_length);

	debug_printf (1, "Requesting (invalid) %d-%d\n",
		      (int) full_response_length + 1,
		      (int) full_response_length + 100);
	request_single_range (session, uri,
			      full_response_length + 1, full_response_length + 100,
			      FALSE);

	debug_printf (1, "Requesting (semi-invalid) 1-10,%d-%d,20-30\n",
		      (int) full_response_length + 1,
		      (int) full_response_length + 100);
	request_semi_invalid_range (session, uri,
				    1, 10,
				    full_response_length + 1, full_response_length + 100,
				    20, 30); 
}

#ifdef HAVE_APACHE
static void
do_apache_range_test (void)
{
	SoupSession *session;

	SOUP_TEST_SKIP_IF_NO_APACHE;

	session = soup_test_session_new (NULL);

	do_range_test (session, "http://127.0.0.1:47524/", TRUE, FALSE);

	soup_test_session_abort_unref (session);
}
#endif

static void
server_handler (SoupServer        *server,
		SoupServerMessage *msg,
		const char        *path,
		GHashTable        *query,
		gpointer           user_data)
{
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_message_body_append_bytes (soup_server_message_get_response_body (msg),
					full_response);
}

static void
do_libsoup_range_test (void)
{
	SoupSession *session;
	SoupServer *server;
	GUri *base_uri;
	char *base_uri_str;

	session = soup_test_session_new (NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);
	base_uri_str = g_uri_to_string (base_uri);
	do_range_test (session, base_uri_str, TRUE, TRUE);
	g_uri_unref (base_uri);
	g_free (base_uri_str);
	soup_test_server_quit_unref (server);

	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);
#ifdef HAVE_APACHE
	apache_init ();
#endif

	full_response = soup_test_get_index ();
	test_response = g_malloc0 (g_bytes_get_size (full_response));

#ifdef HAVE_APACHE
	g_test_add_func ("/ranges/apache", do_apache_range_test);
#endif
	g_test_add_func ("/ranges/libsoup", do_libsoup_range_test);

	ret = g_test_run ();

	g_free (test_response);

	test_cleanup ();
	return ret;
}
