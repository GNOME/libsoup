/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 * Copyright (C) 2011 Igalia, S.L.
 */

#include "test-utils.h"

static SoupServer *server;
static GUri *base_uri;

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *accept_encoding, *options;
	GSList *codings;
	GBytes *response = NULL;
	SoupMessageHeaders *request_headers;
	SoupMessageHeaders *response_headers;
	SoupMessageBody *response_body;

	request_headers = soup_server_message_get_request_headers (msg);
	options = soup_message_headers_get_one (request_headers,
						"X-Test-Options");
	if (!options)
		options = "";

	accept_encoding = soup_message_headers_get_list (request_headers,
							 "Accept-Encoding");
	if (accept_encoding && !soup_header_contains (options, "force-encode"))
		codings = soup_header_parse_quality_list (accept_encoding, NULL);
	else
		codings = NULL;

	response_headers = soup_server_message_get_response_headers (msg);

	if (codings) {
		gboolean claim_deflate, claim_gzip;
		const char *extension = NULL, *encoding = NULL;

		claim_deflate = g_slist_find_custom (codings, "deflate", (GCompareFunc)g_ascii_strcasecmp) != NULL;
		claim_gzip = g_slist_find_custom (codings, "gzip", (GCompareFunc)g_ascii_strcasecmp) != NULL;

		if (claim_gzip && (!claim_deflate ||
				   (!soup_header_contains (options, "prefer-deflate-zlib") &&
				    !soup_header_contains (options, "prefer-deflate-raw")))) {
			extension = "gz";
			encoding = "gzip";
		} else if (claim_deflate) {
			if (soup_header_contains (options, "prefer-deflate-raw")) {
				extension = "raw";
				encoding = "deflate";
			} else {
				extension = "zlib";
				encoding = "deflate";
			}
		}
		if (extension && encoding) {
			char *resource;

			resource = g_strdup_printf ("%s.%s", path, extension);
			response = soup_test_load_resource (resource, NULL);

			if (response) {
				soup_message_headers_append (response_headers,
							     "Content-Encoding",
							     encoding);
			}
			g_free (resource);
		}
	}

	soup_header_free_list (codings);

	if (!response)
		response = soup_test_load_resource (path, NULL);
	if (!response) {
		/* If path.gz exists but can't be read, we'll send back
		 * the error with "Content-Encoding: gzip" but there's
		 * no body, so, eh.
		 */
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		return;
	}

	if (soup_header_contains (options, "force-encode")) {
		const gchar *encoding = "gzip";

		if (soup_header_contains (options, "prefer-deflate-zlib") ||
		    soup_header_contains (options, "prefer-deflate-raw"))
			encoding = "deflate";

		soup_message_headers_replace (response_headers,
					      "Content-Encoding",
					      encoding);
	}

	/* Content-Type matches the "real" format, not the sent format */
	if (g_str_has_suffix (path, ".gz")) {
		soup_message_headers_append (response_headers,
					     "Content-Type",
					     "application/gzip");
	} else {
		soup_message_headers_append (response_headers,
					     "Content-Type",
					     "text/plain");
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);

	response_body = soup_server_message_get_response_body (msg);
	if (!soup_header_contains (options, "empty"))
		soup_message_body_append_bytes (response_body, response);
	g_bytes_unref (response);

	if (soup_header_contains (options, "trailing-junk")) {
		soup_message_body_append (response_body, SOUP_MEMORY_COPY,
					  options, strlen (options));
	}
	soup_message_body_complete (response_body);
}

typedef struct {
	SoupSession *session;
	SoupMessage *msg;
	GBytes *response;
} CodingTestData;

typedef enum {
	CODING_TEST_DEFAULT     = 0,
	CODING_TEST_NO_DECODER  = (1 << 0),
	CODING_TEST_EMPTY       = (1 << 1)
} CodingTestType;

static void
check_response (CodingTestData *data,
		const char *expected_encoding,
		const char *expected_content_type,
		GBytes *body)
{
	const char *coding, *type;

	soup_test_assert_message_status (data->msg, SOUP_STATUS_OK);

	coding = soup_message_headers_get_one (soup_message_get_response_headers (data->msg), "Content-Encoding");
	g_assert_cmpstr (coding, ==, expected_encoding);

	type = soup_message_headers_get_one (soup_message_get_response_headers (data->msg), "Content-Type");
	g_assert_cmpstr (type, ==, expected_content_type);

	g_assert_true (g_bytes_equal (body, data->response));
}

static void
setup_coding_test (CodingTestData *data, gconstpointer test_data)
{
	CodingTestType test_type = GPOINTER_TO_INT (test_data);
	SoupMessage *msg;
	GUri *uri;

	data->session = soup_test_session_new (NULL);

	uri = g_uri_parse_relative (base_uri, "/mbox", SOUP_HTTP_URI_FLAGS, NULL);

	if (test_type & CODING_TEST_EMPTY)
		data->response = g_bytes_new_static (NULL, 0);
	else {
		msg = soup_message_new_from_uri ("GET", uri);
		data->response = soup_session_send_and_read (data->session, msg, NULL, NULL);
		g_object_unref (msg);
	}

	data->msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	if (test_type & CODING_TEST_NO_DECODER)
		soup_session_remove_feature_by_type (data->session, SOUP_TYPE_CONTENT_DECODER);
}

static void
teardown_coding_test (CodingTestData *data, gconstpointer test_data)
{
	g_bytes_unref (data->response);
	g_object_unref (data->msg);

	soup_test_session_abort_unref (data->session);
}

static void
do_coding_test_plain (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, NULL, "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_gzip (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "gzip", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_gzip_metrics (CodingTestData *data, gconstpointer test_data)
{
        GBytes *body;
        SoupMessageMetrics *metrics;

        soup_message_add_flags (data->msg, SOUP_MESSAGE_COLLECT_METRICS);
        body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
        metrics = soup_message_get_metrics (data->msg);
        g_assert_nonnull (metrics);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), ==, g_bytes_get_size (body));
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), <, soup_message_metrics_get_response_body_size (metrics));
        g_bytes_unref (body);
}

static void
do_coding_test_gzip_with_junk (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("606352");
	g_test_bug ("676477");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "trailing-junk");

	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "gzip", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_gzip_bad_server (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("613361");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "force-encode");

	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);

	/* Failed content-decoding should have left the body untouched
	 * from what the server sent... which happens to be the
	 * uncompressed data.
	 */
	check_response (data, "gzip", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_deflate (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "prefer-deflate-zlib");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "deflate", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_deflate_with_junk (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("606352");
	g_test_bug ("676477");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "prefer-deflate-zlib, trailing-junk");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "deflate", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_deflate_bad_server (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("613361");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "force-encode, prefer-deflate-zlib");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "deflate", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_deflate_raw (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "prefer-deflate-raw");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "deflate", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_test_deflate_raw_bad_server (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("613361");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "force-encode, prefer-deflate-raw");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "deflate", "text/plain", body);
	g_bytes_unref (body);
}

static void
do_coding_msg_empty_test (CodingTestData *data, gconstpointer test_data)
{
	GBytes *body;

	g_test_bug ("697527");

	soup_message_headers_append (soup_message_get_request_headers (data->msg),
				     "X-Test-Options", "empty");
	body = soup_session_send_and_read (data->session, data->msg, NULL, NULL);
	check_response (data, "gzip", "text/plain", body);
	g_bytes_unref (body);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add ("/coding/message/plain", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_NO_DECODER),
		    setup_coding_test, do_coding_test_plain, teardown_coding_test);
	g_test_add ("/coding/message/gzip", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_gzip, teardown_coding_test);
        g_test_add ("/coding/message/gzip/metrics", CodingTestData,
                    GINT_TO_POINTER (CODING_TEST_DEFAULT),
                    setup_coding_test, do_coding_test_gzip_metrics, teardown_coding_test);
	g_test_add ("/coding/message/gzip/with-junk", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_gzip_with_junk, teardown_coding_test);
	g_test_add ("/coding/message/gzip/bad-server", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_gzip_bad_server, teardown_coding_test);
	g_test_add ("/coding/message/deflate", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_deflate, teardown_coding_test);
	g_test_add ("/coding/message/deflate/with-junk", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_deflate_with_junk, teardown_coding_test);
	g_test_add ("/coding/message/deflate/bad-server", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_deflate_bad_server, teardown_coding_test);
	g_test_add ("/coding/message/deflate-raw", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_deflate_raw, teardown_coding_test);
	g_test_add ("/coding/message/deflate-raw/bad-server", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_DEFAULT),
		    setup_coding_test, do_coding_test_deflate_raw_bad_server, teardown_coding_test);

	g_test_add ("/coding/message/empty", CodingTestData,
		    GINT_TO_POINTER (CODING_TEST_EMPTY),
		    setup_coding_test, do_coding_msg_empty_test, teardown_coding_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
