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

SoupBuffer *full_response;
int total_length;
char *test_response;

static void
get_full_response (void)
{
	char *contents;
	gsize length;
	GError *error = NULL;

	if (!g_file_get_contents (SRCDIR "/index.txt", &contents, &length, &error)) {
		fprintf (stderr, "Could not read index.txt: %s\n",
			 error->message);
		exit (1);
	}

	full_response = soup_buffer_new (SOUP_MEMORY_TAKE, contents, length);
	debug_printf (1, "Total response length is %d\n\n", (int)length);
}

static void
check_part (SoupMessageHeaders *headers, const char *body, gsize body_len,
	    gboolean check_start_end, int expected_start, int expected_end)
{
	goffset start, end, total_length;

	debug_printf (1, "    Content-Range: %s\n",
		      soup_message_headers_get (headers, "Content-Range"));

	if (!soup_message_headers_get_content_range (headers, &start, &end, &total_length)) {
		debug_printf (1, "    Could not find/parse Content-Range\n");
		errors++;
		return;
	}

	if (total_length != full_response->length && total_length != -1) {
		debug_printf (1, "    Unexpected total length %" G_GINT64_FORMAT " in response\n",
			      total_length);
		errors++;
		return;
	}

	if (check_start_end) {
		if ((expected_start >= 0 && start != expected_start) ||
		    (expected_start < 0 && start != full_response->length + expected_start)) {
			debug_printf (1, "    Unexpected range start %" G_GINT64_FORMAT " in response\n",
				      start);
			errors++;
			return;
		}

		if ((expected_end >= 0 && end != expected_end) ||
		    (expected_end < 0 && end != full_response->length - 1)) {
			debug_printf (1, "    Unexpected range end %" G_GINT64_FORMAT " in response\n",
				      end);
			errors++;
			return;
		}
	}

	if (end - start + 1 != body_len) {
		debug_printf (1, "    Range length (%d) does not match body length (%d)\n",
			      (int)(end - start) + 1,
			      (int)body_len);
		errors++;
		return;
	}

	memcpy (test_response + start, body, body_len);
}

static void
request_single_range (SoupSession *session, char *uri,
		      int start, int end)
{
	SoupMessage *msg;

	msg = soup_message_new ("GET", uri);
	soup_message_headers_set_range (msg->request_headers, start, end);

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get (msg->request_headers, "Range"));

	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_PARTIAL_CONTENT) {
		debug_printf (1, "    Unexpected status %d %s\n",
			      msg->status_code, msg->reason_phrase);
		g_object_unref (msg);
		errors++;
		return;
	}

	check_part (msg->response_headers, msg->response_body->data,
		    msg->response_body->length, TRUE, start, end);
	g_object_unref (msg);
}

static void
request_multi_range (SoupSession *session, SoupMessage *msg)
{
	SoupMultipart *multipart;
	const char *content_type;
	int i, length;

	debug_printf (1, "    Range: %s\n",
		      soup_message_headers_get (msg->request_headers, "Range"));

	soup_session_send_message (session, msg);

	if (msg->status_code != SOUP_STATUS_PARTIAL_CONTENT) {
		debug_printf (1, "    Unexpected status %d %s\n",
			      msg->status_code, msg->reason_phrase);
		g_object_unref (msg);
		errors++;
		return;
	}

	content_type = soup_message_headers_get_content_type (msg->response_headers, NULL);
	if (!content_type || strcmp (content_type, "multipart/byteranges") != 0) {
		debug_printf (1, "    Response Content-Type (%s) was not multipart/byteranges\n",
			      content_type);
		g_object_unref (msg);
		errors++;
		return;
	}

	multipart = soup_multipart_new_from_message (msg->response_headers,
						     msg->response_body);
	if (!multipart) {
		debug_printf (1, "    Could not parse multipart\n");
		g_object_unref (msg);
		errors++;
		return;
	}

	length = soup_multipart_get_length (multipart);
	for (i = 0; i < length; i++) {
		SoupMessageHeaders *headers;
		SoupBuffer *body;

		debug_printf (1, "  Part %d\n", i + 1);
		soup_multipart_get_part (multipart, i, &headers, &body);
		check_part (headers, body->data, body->length, FALSE, 0, 0);
	}

	soup_multipart_free (multipart);
	g_object_unref (msg);
}

static void
request_double_range (SoupSession *session, char *uri,
		      int first_start, int first_end,
		      int second_start, int second_end)
{
	SoupMessage *msg;
	SoupRange ranges[2];

	msg = soup_message_new ("GET", uri);
	ranges[0].start = first_start;
	ranges[0].end = first_end;
	ranges[1].start = second_start;
	ranges[1].end = second_end;
	soup_message_headers_set_ranges (msg->request_headers, ranges, 2);

	request_multi_range (session, msg);
}

static void
request_triple_range (SoupSession *session, char *uri,
		      int first_start, int first_end,
		      int second_start, int second_end,
		      int third_start, int third_end)
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
	soup_message_headers_set_ranges (msg->request_headers, ranges, 3);

	request_multi_range (session, msg);
}

static void
do_range_test (SoupSession *session, char *uri)
{
	int sevenths = full_response->length / 7;

	memset (test_response, 0, full_response->length);

	debug_printf (1, "Requesting %d-%d\n", 0 * sevenths, 1 * sevenths);
	request_single_range (session, uri,
			      0 * sevenths, 1 * sevenths);

	/* These two are redundant in terms of data coverage (except
	 * maybe for a single byte because of rounding), but they may
	 * still catch Range-header-generating bugs.
	 */
	debug_printf (1, "Requesting %d-\n", 6 * sevenths);
	request_single_range (session, uri,
			      6 * sevenths, -1);
	debug_printf (1, "Requesting -%d\n", 1 * sevenths);
	request_single_range (session, uri,
			      -1 * sevenths, -1);

	debug_printf (1, "Requesting %d-%d,%d-%d\n",
		      2 * sevenths, 3 * sevenths,
		      5 * sevenths, 6 * sevenths);
	request_double_range (session, uri,
			      2 * sevenths, 3 * sevenths,
			      5 * sevenths, 6 * sevenths);

	debug_printf (1, "Requesting %d-%d,%d-%d,%d-%d\n",
		      3 * sevenths, 4 * sevenths,
		      1 * sevenths, 2 * sevenths,
		      4 * sevenths, 5 * sevenths);
	request_triple_range (session, uri,
			      3 * sevenths, 4 * sevenths,
			      1 * sevenths, 2 * sevenths,
			      4 * sevenths, 5 * sevenths);

	if (memcmp (full_response->data, test_response, full_response->length) != 0) {
		debug_printf (1, "\nfull_response and test_response don't match\n");
		errors++;
	}
}

static void
server_handler (SoupServer        *server,
		SoupMessage       *msg, 
		const char        *path,
		GHashTable        *query,
		SoupClientContext *client,
		gpointer           user_data)
{
	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_body_append_buffer (msg->response_body,
					 full_response);
}

int
main (int argc, char **argv)
{
	SoupSession *session;
	SoupServer *server;
	char *base_uri;

	test_init (argc, argv, NULL);
	apache_init ();

	get_full_response ();
	test_response = g_malloc0 (full_response->length);

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	debug_printf (1, "1. Testing against apache\n");
	do_range_test (session, "http://localhost:47524/");

	debug_printf (1, "\n2. Testing against SoupServer\n");
	server = soup_test_server_new (FALSE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	base_uri = g_strdup_printf ("http://localhost:%u/",
				    soup_server_get_port (server));
	do_range_test (session, base_uri);

	soup_test_session_abort_unref (session);

	soup_buffer_free (full_response);
	g_free (test_response);

	test_cleanup ();
	return errors != 0;
}
