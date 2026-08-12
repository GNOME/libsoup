/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

#include "config.h"

#include "test-utils.h"
#include "soup-message-headers-private.h"
#include "soup-misc.h"

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
		 int start, int end, SoupStatus expected_status,
		 int expected_start, int expected_end)
{
	const char *content_type;
	GBytes *body;

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get_one (soup_message_get_request_headers (msg), "Range"));

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	if (expected_status == SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
		soup_test_assert_message_status (msg, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
		if (soup_message_get_status (msg) != SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
			const char *content_range;

			content_range = soup_message_headers_get_one (soup_message_get_response_headers (msg),
								      "Content-Range");
			if (content_range)
				debug_printf (1, "    Content-Range: %s\n", content_range);
		}
	} else if (expected_status == SOUP_STATUS_OK) {
		soup_test_assert_message_status (msg, SOUP_STATUS_OK);

		content_type = soup_message_headers_get_content_type (
			soup_message_get_response_headers (msg), NULL);
		g_assert_cmpstr (content_type, !=, "multipart/byteranges");

		g_assert_false (soup_message_headers_get_content_range (
			soup_message_get_response_headers (msg), NULL, NULL, NULL));
		g_assert_cmpint (soup_message_headers_get_content_length (
			soup_message_get_response_headers (msg)), ==, g_bytes_get_size (full_response));
	} else {
		soup_test_assert_message_status (msg, SOUP_STATUS_PARTIAL_CONTENT);

		content_type = soup_message_headers_get_content_type (
			soup_message_get_response_headers (msg), NULL);
		g_assert_cmpstr (content_type, !=, "multipart/byteranges");

		check_part (soup_message_get_response_headers (msg), body, TRUE, expected_start, expected_end);
	}

	g_clear_pointer (&body, g_bytes_unref);
	g_object_unref (msg);
}

static void
request_single_range (SoupSession *session, const char *uri,
		      int start, int end, SoupStatus expected_status,
		      int expected_start, int expected_end)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_headers_set_range (soup_message_get_request_headers (msg), start, end);
	do_single_range (session, msg, start, end, expected_status, expected_start, expected_end);
}

/* This always asserts failure (either 406 or 200 with no Content-Range); it’s
 * intended to be used for passing invalid
 * Range header formats which can’t be built by calling
 * soup_message_headers_set_range(). */
static void
request_single_range_by_string (SoupSession *session, const char *uri,
			        const char *range, SoupStatus expected_status)
{
	SoupMessage *msg;
	GBytes *body;

	msg = soup_message_new ("GET", uri);
	soup_message_headers_replace (soup_message_get_request_headers (msg), "Range", range);

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get_one (soup_message_get_request_headers (msg), "Range"));

	body = soup_test_session_async_send (session, msg, NULL, NULL);

	if (expected_status == SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
		soup_test_assert_message_status (msg, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
	} else {
		const char *content_type;

		soup_test_assert_message_status (msg, SOUP_STATUS_OK);

		content_type = soup_message_headers_get_content_type (
			soup_message_get_response_headers (msg), NULL);
		g_assert_cmpstr (content_type, !=, "multipart/byteranges");

		g_assert_false (soup_message_headers_get_content_range (
			soup_message_get_response_headers (msg), NULL, NULL, NULL));
		g_assert_cmpint (soup_message_headers_get_content_length (
			soup_message_get_response_headers (msg)), ==, g_bytes_get_size (full_response));
	}

	g_clear_pointer (&body, g_bytes_unref);
	g_object_unref (msg);
}

/* Like request_single_range_by_string(), but able to check the ranges of a
 * successful 206 as well. */
static void
request_single_range_by_string_full (SoupSession *session, const char *uri,
				     const char *range, SoupStatus expected_status,
				     int expected_start, int expected_end)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_headers_replace (soup_message_get_request_headers (msg), "Range", range);

	do_single_range (session, msg, 0, 0, expected_status, expected_start, expected_end);
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
				 SOUP_STATUS_PARTIAL_CONTENT,
				 MIN (first_start, second_start),
				 MAX (first_end, second_end));
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
				 SOUP_STATUS_PARTIAL_CONTENT,
				 MIN (first_start, MIN (second_start, third_start)),
				 MAX (first_end, MAX (second_end, third_end)));
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
			      SOUP_STATUS_PARTIAL_CONTENT,
			      0 * twelfths, 1 * twelfths);

	/* B: 11, end-relative request. These two are mostly redundant
	 * in terms of data coverage, but they may still catch
	 * Range-header-generating bugs.
	 */
	debug_printf (1, "Requesting %d-\n", 11 * twelfths);
	request_single_range (session, uri,
			      11 * twelfths, -1,
			      SOUP_STATUS_PARTIAL_CONTENT,
			      11 * twelfths, -1);
	debug_printf (1, "Requesting -%d\n", 1 * twelfths);
	request_single_range (session, uri,
			      -1 * twelfths, -1,
			      SOUP_STATUS_PARTIAL_CONTENT,
			      -1 * twelfths, -1);

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
			      SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE,
			      0, 0);

	debug_printf (1, "Requesting (semi-invalid) 1-10,%d-%d,20-30\n",
		      (int) full_response_length + 1,
		      (int) full_response_length + 100);
	request_semi_invalid_range (session, uri,
				    1, 10,
				    full_response_length + 1, full_response_length + 100,
				    20, 30); 

	debug_printf (1, "Requesting (invalid end) %d-%d\n",
		      1,
		      (int) full_response_length + 1000);
	request_single_range (session, uri,
			      1, full_response_length + 1000,
			      SOUP_STATUS_PARTIAL_CONTENT,
			      1, full_response_length - 1);

	debug_printf (1, "Requesting (end before start) %d-%d\n",
		      10,
		      1);
	request_single_range (session, uri,
			      10, 1,
			      SOUP_STATUS_OK,
			      1, full_response_length);

	debug_printf (1, "Requesting (malformed suffix length) -0\n");
	request_single_range_by_string (session, uri,
					"bytes=-0",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (extra content after valid header value) 0-10\n");
	request_single_range_by_string (session, uri,
					"bytes=0-10 but with weird trailing content",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (invalid range dash) 0a10\n");
	request_single_range_by_string (session, uri,
					"bytes=0a10",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (invalid range unit) 0-10\n");
	request_single_range_by_string (session, uri,
					"horses=0-10",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (missing equals) 0-10\n");
	request_single_range_by_string (session, uri,
					"bytes 0-10",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (end before start but with whitespace) 10-1\n");
	request_single_range_by_string (session, uri,
					"bytes \t = \t 10-1",
					SOUP_STATUS_OK);

	debug_printf (1, "Requesting (delimiters but no ranges)\n");
	request_single_range_by_string (session, uri,
					"bytes=, ,,\t, ",
					SOUP_STATUS_OK);
}

/* Tests for the Range parser itself. Unlike the tests above, these don't need
 * a server, so they can use total lengths which would be impractical to
 * actually serve, and they can check the exact status which the server would
 * use rather than only the ones a client can distinguish.
 */
typedef struct {
	const char *description;
	const char *bugref;
	const char *range;
	goffset total_length;
	guint expected_status;
	int expected_n_ranges;
	SoupRange expected_ranges[3];
} RangeParsingTest;

static const RangeParsingTest range_parsing_tests[] = {
	/* Valid ranges against a ten byte body, as a baseline. */
	{ "simple range", NULL,
	  "bytes=0-4", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 4 } } },
	{ "whole body", NULL,
	  "bytes=0-9", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "open ended range", NULL,
	  "bytes=5-", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 5, 9 } } },
	{ "final byte", NULL,
	  "bytes=9-", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 9, 9 } } },
	{ "end past the body is clamped", NULL,
	  "bytes=1-100", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 1, 9 } } },
	{ "suffix range", NULL,
	  "bytes=-5", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 5, 9 } } },
	{ "single byte suffix range", NULL,
	  "bytes=-1", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 9, 9 } } },
	{ "whitespace around the ranges", NULL,
	  "bytes \t = \t 0-4", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 4 } } },

	/* Unsatisfiable and invalid ranges. */
	{ "start past the body", NULL,
	  "bytes=10-20", 10, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE, 0, { } },
	{ "end before start", NULL,
	  "bytes=10-1", 10, SOUP_STATUS_OK, 0, { } },
	{ "zero length suffix range", NULL,
	  "bytes=-0", 10, SOUP_STATUS_OK, 0, { } },
	{ "trailing garbage", NULL,
	  "bytes=0-10 but with weird trailing content", 10, SOUP_STATUS_OK, 0, { } },
	{ "invalid range dash", NULL,
	  "bytes=0a10", 10, SOUP_STATUS_OK, 0, { } },
	{ "unknown range unit", NULL,
	  "horses=0-10", 10, SOUP_STATUS_OK, 0, { } },
	{ "missing equals", NULL,
	  "bytes 0-10", 10, SOUP_STATUS_OK, 0, { } },
	{ "delimiters but no ranges", NULL,
	  "bytes=, ,,\t, ", 10, SOUP_STATUS_OK, 0, { } },

	/* A suffix length at least as long as the body selects the whole body,
	 * per RFC 9110 §14.1.2. These used to drive the range start negative,
	 * which aborted the process at the g_assert() below the parse.
	 */
	{ "suffix range the length of the body", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/516",
	  "bytes=-10", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range one longer than the body", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/516",
	  "bytes=-11", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range much longer than the body", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/548",
	  "bytes=-999999", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range of G_MININT", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/547",
	  "bytes=-2147483648", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range larger than a guint32", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/547",
	  "bytes=-4294967296", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range of G_MAXINT64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/547",
	  "bytes=-9223372036854775807", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range of G_MININT64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/547",
	  "bytes=-9223372036854775808", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "suffix range overflowing gint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=-99999999999999999999", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "oversized suffix range merged with a valid range", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/548",
	  "bytes=-999999,4-5", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },

	/* Range starts and ends which overflow the signed goffset they are
	 * parsed into. An overflowing start is treated like any other start
	 * beyond the end of the body, and an overflowing end is clamped like
	 * any other end beyond the end of the body.
	 */
	{ "start overflowing gint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=9888888888888019900-", 10, SOUP_STATUS_OK, 0, { } },
	{ "start overflowing gint64 with no dash", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=9888888888888019900", 10, SOUP_STATUS_OK, 0, { } },
	{ "start of G_MAXINT64 + 1", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=9223372036854775808-", 10, SOUP_STATUS_OK, 0, { } },
	{ "start overflowing guint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=18446744073709551616-", 10, SOUP_STATUS_OK, 0, { } },
	{ "start and end overflowing gint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=9888888888888019900-9888888888888019901", 10, SOUP_STATUS_OK, 0, { } },
	{ "end overflowing gint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=0-9888888888888019900", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },
	{ "end overflowing guint64", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/535",
	  "bytes=0-18446744073709551616", 10, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 9 } } },

	/* Zero length bodies. soup_message_headers_get_ranges() is public API,
	 * so it can be called with one even though the server never does.
	 */
	{ "range against an empty body", NULL,
	  "bytes=0-9", 0, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE, 0, { } },
	{ "suffix range against an empty body", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/548",
	  "bytes=-5", 0, SOUP_STATUS_OK, 0, { } },

	/* Merging. */
	{ "overlapping ranges are merged", NULL,
	  "bytes=0-10,5-20", 100, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 20 } } },
	{ "contained ranges are merged", NULL,
	  "bytes=0-20,5-10", 100, SOUP_STATUS_PARTIAL_CONTENT, 1, { { 0, 20 } } },
	{ "touching ranges are not merged", NULL,
	  "bytes=0-4,5-9", 100, SOUP_STATUS_PARTIAL_CONTENT, 2, { { 0, 4 }, { 5, 9 } } },
	{ "ranges are sorted", NULL,
	  "bytes=20-29,0-9", 100, SOUP_STATUS_PARTIAL_CONTENT, 2, { { 0, 9 }, { 20, 29 } } },
	{ "invalid ranges do not prevent valid ones", NULL,
	  "bytes=0-9,50-40,20-29", 100, SOUP_STATUS_PARTIAL_CONTENT, 2, { { 0, 9 }, { 20, 29 } } },

	/* The comparison function used to sort the ranges before merging them
	 * used to truncate a goffset difference to int, which flips its sign
	 * for bodies over 2GB and silently dropped ranges from the response.
	 */
	{ "ranges more than G_MAXINT apart", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/519",
	  "bytes=0-100, 2500000000-2500000100, 4999999000-4999999100", 5000000000,
	  SOUP_STATUS_PARTIAL_CONTENT, 3,
	  { { 0, 100 }, { 2500000000, 2500000100 }, { 4999999000, 4999999100 } } },
	{ "unsorted ranges more than G_MAXINT apart", "https://gitlab.gnome.org/GNOME/libsoup/-/issues/519",
	  "bytes=4999999000-4999999100, 0-100, 2500000000-2500000100", 5000000000,
	  SOUP_STATUS_PARTIAL_CONTENT, 3,
	  { { 0, 100 }, { 2500000000, 2500000100 }, { 4999999000, 4999999100 } } },
};

static void
check_parsed_ranges (const char *range,
		     goffset     total_length,
		     guint       expected_status,
		     int         expected_n_ranges,
		     const SoupRange *expected_ranges)
{
	SoupMessageHeaders *hdrs;
	SoupRange *ranges = NULL;
	int n_ranges = 0;
	guint status;
	int i;

	hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
	soup_message_headers_replace (hdrs, "Range", range);

	status = soup_message_headers_get_ranges_internal (hdrs, total_length, TRUE,
							   &ranges, &n_ranges);

	g_assert_cmpuint (status, ==, expected_status);

	if (status == SOUP_STATUS_PARTIAL_CONTENT) {
		g_assert_nonnull (ranges);
		g_assert_cmpint (n_ranges, ==, expected_n_ranges);

		for (i = 0; i < n_ranges; i++) {
			debug_printf (2, "    [%d]: %" G_GINT64_FORMAT "-%" G_GINT64_FORMAT "\n",
				      i, ranges[i].start, ranges[i].end);

			g_assert_cmpint (ranges[i].start, ==, expected_ranges[i].start);
			g_assert_cmpint (ranges[i].end, ==, expected_ranges[i].end);

			/* Whatever the input, the parsed ranges must be usable
			 * as offsets into a buffer of total_length bytes.
			 */
			g_assert_cmpint (ranges[i].start, >=, 0);
			g_assert_cmpint (ranges[i].end, >=, ranges[i].start);
			g_assert_cmpint (ranges[i].end, <, total_length);
		}
	}

	soup_message_headers_free_ranges (hdrs, ranges);
	soup_message_headers_unref (hdrs);
}

static void
do_range_parsing_test (void)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (range_parsing_tests); i++) {
		const RangeParsingTest *test = &range_parsing_tests[i];

		debug_printf (1, "%2u. %s: '%s' against %" G_GOFFSET_FORMAT " bytes\n",
			      i + 1, test->description, test->range, test->total_length);

		if (test->bugref)
			g_test_message ("Bug reference: %s", test->bugref);

		check_parsed_ranges (test->range, test->total_length,
				     test->expected_status, test->expected_n_ranges,
				     test->expected_ranges);
	}
}

/* A single Range header can list far more ranges than are reasonable to serve:
 * the only limit on the wire is the maximum request header size. */
static void
do_range_count_test (void)
{
	struct {
		int n_ranges;
		gboolean identical;
		guint expected_status;
		int expected_n_ranges;
	} tests[] = {
		/* Distinct ranges, up to and then past the limit. Going past it
		 * is rejected rather than ignored.
		 */
		{ 100, FALSE, SOUP_STATUS_PARTIAL_CONTENT, 100 },
		{ MAX_RANGES, FALSE, SOUP_STATUS_PARTIAL_CONTENT, MAX_RANGES },
		{ MAX_RANGES + 1, FALSE, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE, 0 },

		/* Identical ranges, which all merge into one. This is the
		 * shape which used to be quadratic.
		 */
		{ MAX_RANGES, TRUE, SOUP_STATUS_PARTIAL_CONTENT, 1 },
		{ MAX_RANGES + 1, TRUE, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE, 0 },
		{ 25585, TRUE, SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE, 0 },
	};
	guint i;
	int j;

	for (i = 0; i < G_N_ELEMENTS (tests); i++) {
		SoupMessageHeaders *hdrs;
		SoupRange *ranges = NULL;
		int n_ranges = 0;
		guint status;
		GString *range;

		debug_printf (1, "%2u. %d %s ranges\n", i + 1, tests[i].n_ranges,
			      tests[i].identical ? "identical" : "distinct");

		range = g_string_new ("bytes=");
		for (j = 0; j < tests[i].n_ranges; j++) {
			int start = tests[i].identical ? 0 : j * 2;

			if (j > 0)
				g_string_append_c (range, ',');
			g_string_append_printf (range, "%d-%d", start, start);
		}

		hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
		soup_message_headers_replace (hdrs, "Range", range->str);
		g_string_free (range, TRUE);

		status = soup_message_headers_get_ranges_internal (hdrs, 1000000, TRUE,
								   &ranges, &n_ranges);

		g_assert_cmpuint (status, ==, tests[i].expected_status);
		if (status == SOUP_STATUS_PARTIAL_CONTENT)
			g_assert_cmpint (n_ranges, ==, tests[i].expected_n_ranges);

		soup_message_headers_free_ranges (hdrs, ranges);
		soup_message_headers_unref (hdrs);
	}

	/* Callers which don't ask about satisfiability, such as the public
	 * soup_message_headers_get_ranges(), can't be told 416, so an
	 * over-limit header just reports no ranges to them.
	 */
	{
		SoupMessageHeaders *hdrs;
		SoupRange *ranges = NULL;
		int n_ranges = 0;
		GString *range;

		range = g_string_new ("bytes=0-0");
		for (j = 0; j < MAX_RANGES; j++)
			g_string_append (range, ",0-0");

		hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
		soup_message_headers_replace (hdrs, "Range", range->str);
		g_string_free (range, TRUE);

		g_assert_cmpuint (soup_message_headers_get_ranges_internal (hdrs, 1000000, FALSE,
									    &ranges, &n_ranges),
				  ==, SOUP_STATUS_OK);
		g_assert_false (soup_message_headers_get_ranges (hdrs, 1000000, &ranges, &n_ranges));

		soup_message_headers_free_ranges (hdrs, ranges);
		soup_message_headers_unref (hdrs);
	}
}

/* Tests for the Content-Range parser, which a client runs on a header chosen
 * by the server. A successful parse must yield offsets the caller can safely
 * use against a buffer of total_length bytes.
 */
typedef struct {
	const char *description;
	const char *content_range;
	gboolean expected_result;
	goffset expected_start, expected_end, expected_total_length;
} ContentRangeParsingTest;

static const ContentRangeParsingTest content_range_parsing_tests[] = {
	/* Valid. */
	{ "simple range", "bytes 0-9/10", TRUE, 0, 9, 10 },
	{ "partial range", "bytes 5-9/100", TRUE, 5, 9, 100 },
	{ "single byte", "bytes 0-0/1", TRUE, 0, 0, 1 },
	{ "final byte", "bytes 99-99/100", TRUE, 99, 99, 100 },
	{ "unknown total length", "bytes 0-9/*", TRUE, 0, 9, -1 },
	{ "extra space after the unit", "bytes    0-9/10", TRUE, 0, 9, 10 },
	{ "large but representable", "bytes 0-9223372036854775805/9223372036854775806",
	  TRUE, 0, 9223372036854775805, 9223372036854775806 },

	/* Malformed. */
	{ "no unit", "0-9/10", FALSE, 0, 0, 0 },
	{ "unknown unit", "horses 0-9/10", FALSE, 0, 0, 0 },
	{ "no unit separator", "bytes", FALSE, 0, 0, 0 },
	{ "missing total length", "bytes 0-9", FALSE, 0, 0, 0 },
	{ "missing dash", "bytes 09/10", FALSE, 0, 0, 0 },
	{ "missing slash", "bytes 0-9 10", FALSE, 0, 0, 0 },
	{ "trailing garbage", "bytes 0-9/10 but with more content", FALSE, 0, 0, 0 },
	{ "space before the end", "bytes 0- 9/10", FALSE, 0, 0, 0 },
	{ "space before the total length", "bytes 0-9/ 10", FALSE, 0, 0, 0 },

	/* Values a malicious server can use to drive the parsed offsets
	 * negative, or to make them inconsistent with each other.
	 */
	{ "start overflowing gint64", "bytes 9223372036854775808-9223372036854775809/9223372036854775810",
	  FALSE, 0, 0, 0 },
	{ "end overflowing gint64", "bytes 0-9223372036854775808/10", FALSE, 0, 0, 0 },
	{ "total length overflowing gint64", "bytes 0-9/9223372036854775808", FALSE, 0, 0, 0 },
	{ "all fields G_MAXUINT64", "bytes 18446744073709551615-18446744073709551615/18446744073709551615",
	  FALSE, 0, 0, 0 },
	{ "all fields overflowing guint64", "bytes 99999999999999999999-99999999999999999999/99999999999999999999",
	  FALSE, 0, 0, 0 },
	{ "negative start", "bytes -5-9/10", FALSE, 0, 0, 0 },
	{ "negative end", "bytes 0--5/10", FALSE, 0, 0, 0 },
	{ "negative total length", "bytes 0-9/-10", FALSE, 0, 0, 0 },
	{ "end before start", "bytes 10-5/100", FALSE, 0, 0, 0 },
	{ "end at the total length", "bytes 0-10/10", FALSE, 0, 0, 0 },
	{ "end past the total length", "bytes 0-100/10", FALSE, 0, 0, 0 },
	{ "start past the total length", "bytes 50-60/10", FALSE, 0, 0, 0 },
};

static void
do_content_range_parsing_test (void)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (content_range_parsing_tests); i++) {
		const ContentRangeParsingTest *test = &content_range_parsing_tests[i];
		SoupMessageHeaders *hdrs;
		goffset start = -1, end = -1, total_length = -1;
		gboolean result;

		debug_printf (1, "%2u. %s: '%s'\n", i + 1, test->description,
			      test->content_range);

		hdrs = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
		soup_message_headers_replace (hdrs, "Content-Range", test->content_range);

		result = soup_message_headers_get_content_range (hdrs, &start, &end,
								 &total_length);
		g_assert_cmpint (result, ==, test->expected_result);

		if (result) {
			g_assert_cmpint (start, ==, test->expected_start);
			g_assert_cmpint (end, ==, test->expected_end);
			g_assert_cmpint (total_length, ==, test->expected_total_length);

			/* Whatever the server sent, these must be usable as
			 * offsets into a buffer of total_length bytes.
			 */
			g_assert_cmpint (start, >=, 0);
			g_assert_cmpint (end, >=, start);
			if (total_length >= 0)
				g_assert_cmpint (end, <, total_length);
		}

		soup_message_headers_unref (hdrs);
	}
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
do_libsoup_only_range_test (SoupSession *session, const char *uri)
{
	gsize full_response_length = g_bytes_get_size (full_response);
	GString *range;
	int i;

	/* A suffix length at least as long as the body selects the whole body. */
	debug_printf (1, "Requesting (suffix range the length of the body) -%d\n",
		      (int) full_response_length);
	request_single_range (session, uri,
			      -((int) full_response_length), -1,
			      SOUP_STATUS_PARTIAL_CONTENT, 0, -1);

	debug_printf (1, "Requesting (suffix range longer than the body) -999999\n");
	request_single_range_by_string_full (session, uri, "bytes=-999999",
					     SOUP_STATUS_PARTIAL_CONTENT, 0, -1);

	debug_printf (1, "Requesting (suffix range overflowing gint64) -99999999999999999999\n");
	request_single_range_by_string_full (session, uri, "bytes=-99999999999999999999",
					     SOUP_STATUS_PARTIAL_CONTENT, 0, -1);

	/* A start which overflows gint64 is treated like any other start past
	 * the end of the body.
	 * https://gitlab.gnome.org/GNOME/libsoup/-/issues/535
	 */
	debug_printf (1, "Requesting (start overflowing gint64) 9888888888888019900-\n");
	request_single_range_by_string (session, uri, "bytes=9888888888888019900-",
					SOUP_STATUS_OK);

	/* More ranges than the server is willing to coalesce, which is
	 * rejected rather than answered with the whole body.
	 * https://gitlab.gnome.org/GNOME/libsoup/-/issues/538
	 */
	debug_printf (1, "Requesting (more ranges than the limit)\n");
	range = g_string_new ("bytes=");
	for (i = 0; i < MAX_RANGES + 1; i++)
		g_string_append (range, i > 0 ? ",0-0" : "0-0");
	request_single_range_by_string (session, uri, range->str,
					SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE);
	g_string_free (range, TRUE);
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
	do_libsoup_only_range_test (session, base_uri_str);
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
	g_test_add_func ("/ranges/parsing", do_range_parsing_test);
	g_test_add_func ("/ranges/count", do_range_count_test);
	g_test_add_func ("/ranges/content-range", do_content_range_parsing_test);

	ret = g_test_run ();

	g_free (test_response);

	test_cleanup ();
	return ret;
}
