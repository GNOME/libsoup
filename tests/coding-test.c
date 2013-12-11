/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 * Copyright (C) 2011 Igalia, S.L.
 */

#include "test-utils.h"

SoupServer *server;
SoupURI *base_uri;

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	const char *accept_encoding, *options;
	GSList *codings;
	SoupBuffer *response = NULL;

	options = soup_message_headers_get_one (msg->request_headers,
						"X-Test-Options");
	if (!options)
		options = "";

	accept_encoding = soup_message_headers_get_list (msg->request_headers,
							 "Accept-Encoding");
	if (accept_encoding && !soup_header_contains (options, "force-encode"))
		codings = soup_header_parse_quality_list (accept_encoding, NULL);
	else
		codings = NULL;

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
				soup_message_headers_append (msg->response_headers,
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
		soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	}

	if (soup_header_contains (options, "force-encode")) {
		const gchar *encoding = "gzip";

		if (soup_header_contains (options, "prefer-deflate-zlib") ||
		    soup_header_contains (options, "prefer-deflate-raw"))
			encoding = "deflate";

		soup_message_headers_replace (msg->response_headers,
					      "Content-Encoding",
					      encoding);
	}

	/* Content-Type matches the "real" format, not the sent format */
	if (g_str_has_suffix (path, ".gz")) {
		soup_message_headers_append (msg->response_headers,
					     "Content-Type",
					     "application/gzip");
	} else {
		soup_message_headers_append (msg->response_headers,
					     "Content-Type",
					     "text/plain");
	}

	soup_message_set_status (msg, SOUP_STATUS_OK);
	soup_message_headers_set_encoding (msg->response_headers, SOUP_ENCODING_CHUNKED);

	if (!soup_header_contains (options, "empty"))
		soup_message_body_append_buffer (msg->response_body, response);
	soup_buffer_free (response);

	if (soup_header_contains (options, "trailing-junk")) {
		soup_message_body_append (msg->response_body, SOUP_MEMORY_COPY,
					  options, strlen (options));
	}
	soup_message_body_complete (msg->response_body);
}

typedef enum {
	NO_CHECK,
	EXPECT_DECODED,
	EXPECT_NOT_DECODED
} MessageContentStatus;

static void
check_response (SoupMessage *msg,
		const char *expected_encoding,
		const char *expected_content_type,
		MessageContentStatus status)
{
	const char *coding, *type;

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	coding = soup_message_headers_get_one (msg->response_headers, "Content-Encoding");
	g_assert_cmpstr (coding, ==, expected_encoding);

	if (status != NO_CHECK) {
		if (status == EXPECT_DECODED)
			g_assert_true (soup_message_get_flags (msg) & SOUP_MESSAGE_CONTENT_DECODED);
		else
			g_assert_false (soup_message_get_flags (msg) & SOUP_MESSAGE_CONTENT_DECODED);
	}

	type = soup_message_headers_get_one (msg->response_headers, "Content-Type");
	g_assert_cmpstr (type, ==, expected_content_type);
}

static void
do_coding_test (void)
{
	SoupSession *session;
	SoupMessage *msg, *msgz, *msgj, *msge, *msgzl, *msgzlj, *msgzle, *msgzlr, *msgzlre;
	SoupURI *uri;

	debug_printf (1, "SoupMessage tests\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);
	uri = soup_uri_new_with_base (base_uri, "/mbox");

	/* Plain text data, no claim */
	debug_printf (1, "  GET /mbox, plain\n");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_session_send_message (session, msg);
	check_response (msg, NULL, "text/plain", EXPECT_NOT_DECODED);

	/* Plain text data, claim gzip */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip\n");
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_DECODER);
	msgz = soup_message_new_from_uri ("GET", uri);
	soup_session_send_message (session, msgz);
	check_response (msgz, "gzip", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgz->response_body->data,
			    msgz->response_body->length);

	/* Plain text data, claim gzip w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, plus trailing junk\n");
	msgj = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgj->request_headers,
				     "X-Test-Options", "trailing-junk");
	soup_session_send_message (session, msgj);
	check_response (msgj, "gzip", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgj->response_body->data,
			    msgj->response_body->length);

	/* Plain text data, claim gzip with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, with server error\n");
	msge = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msge->request_headers,
				     "X-Test-Options", "force-encode");
	soup_session_send_message (session, msge);
	check_response (msge, "gzip", "text/plain", EXPECT_NOT_DECODED);

	/* Failed content-decoding should have left the body untouched
	 * from what the server sent... which happens to be the
	 * uncompressed data.
	 */
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msge->response_body->data,
			    msge->response_body->length);

	/* Plain text data, claim deflate */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate\n");
	msgzl = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzl->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib");
	soup_session_send_message (session, msgzl);
	check_response (msgzl, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgzl->response_body->data,
			    msgzl->response_body->length);

	/* Plain text data, claim deflate w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, plus trailing junk\n");
	msgzlj = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlj->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib, trailing-junk");
	soup_session_send_message (session, msgzlj);
	check_response (msgzlj, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgzlj->response_body->data,
			    msgzlj->response_body->length);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, with server error\n");
	msgzle = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzle->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-zlib");
	soup_session_send_message (session, msgzle);
	check_response (msgzle, "deflate", "text/plain", EXPECT_NOT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgzle->response_body->data,
			    msgzle->response_body->length);

	/* Plain text data, claim deflate (no zlib headers)*/
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data)\n");
	msgzlr = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlr->request_headers,
				     "X-Test-Options", "prefer-deflate-raw");
	soup_session_send_message (session, msgzlr);
	check_response (msgzlr, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgzlr->response_body->data,
			    msgzlr->response_body->length);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data), with server error\n");
	msgzlre = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlre->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-raw");
	soup_session_send_message (session, msgzlre);
	check_response (msgzlre, "deflate", "text/plain", EXPECT_NOT_DECODED);
	soup_assert_cmpmem (msg->response_body->data,
			    msg->response_body->length,
			    msgzlre->response_body->data,
			    msgzlre->response_body->length);

	g_object_unref (msg);
	g_object_unref (msgzlre);
	g_object_unref (msgzlr);
	g_object_unref (msgzlj);
	g_object_unref (msgzle);
	g_object_unref (msgzl);
	g_object_unref (msgz);
	g_object_unref (msgj);
	g_object_unref (msge);
	soup_uri_free (uri);

	soup_test_session_abort_unref (session);
}

static void
read_finished (GObject *stream, GAsyncResult *result, gpointer user_data)
{
	gssize *nread = user_data;
	GError *error = NULL;

	*nread = g_input_stream_read_finish (G_INPUT_STREAM (stream),
					     result, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
}

static GByteArray *
do_single_coding_req_test (SoupRequestHTTP *reqh,
			   const char *expected_encoding,
			   const char *expected_content_type,
			   MessageContentStatus status)
{
	GInputStream *stream;
	SoupMessage *msg;
	GByteArray *data;
	guchar buf[1024];
	gssize nread;
	GError *error = NULL;

	data = g_byte_array_new ();

	stream = soup_test_request_send (SOUP_REQUEST (reqh), NULL, 0, &error);
	if (!stream) {
		g_assert_no_error (error);
		g_error_free (error);
		return data;
	}

	do {
		nread = -2;
		g_input_stream_read_async (stream, buf, sizeof (buf),
					   G_PRIORITY_DEFAULT,
					   NULL, read_finished, &nread);
		while (nread == -2)
			g_main_context_iteration (NULL, TRUE);

		if (nread > 0)
			g_byte_array_append (data, buf, nread);
	} while (nread > 0);

	soup_test_request_close_stream (SOUP_REQUEST (reqh), stream, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (stream);

	msg = soup_request_http_get_message (reqh);
	check_response (msg, expected_encoding, expected_content_type, status);
	g_object_unref (msg);

	return data;
}

static void
do_coding_req_test (void)
{
	SoupSession *session;
	SoupRequestHTTP *reqh;
	SoupMessage *msg;
	SoupURI *uri;
	GByteArray *plain, *cmp;

	debug_printf (1, "\nSoupRequest tests\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	uri = soup_uri_new_with_base (base_uri, "/mbox");

	/* Plain text data, no claim */
	debug_printf (1, "  GET /mbox, plain\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	plain = do_single_coding_req_test (reqh, NULL, "text/plain", EXPECT_NOT_DECODED);
	g_object_unref (reqh);

	/* Plain text data, claim gzip */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip\n");
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_DECODER);
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	cmp = do_single_coding_req_test (reqh, "gzip", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim gzip w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, plus trailing junk\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "trailing-junk");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "gzip", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim gzip with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, with server error\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "gzip", "text/plain", EXPECT_NOT_DECODED);

	/* Failed content-decoding should have left the body untouched
	 * from what the server sent... which happens to be the
	 * uncompressed data.
	 */
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim deflate */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim deflate w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, plus trailing junk\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib, trailing-junk");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, with server error\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-zlib");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "deflate", "text/plain", EXPECT_NOT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim deflate (no zlib headers)*/
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data)\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-raw");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "deflate", "text/plain", EXPECT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data), with server error\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-raw");
	g_object_unref (msg);
	cmp = do_single_coding_req_test (reqh, "deflate", "text/plain", EXPECT_NOT_DECODED);
	soup_assert_cmpmem (plain->data, plain->len,
			    cmp->data, cmp->len);
	g_byte_array_free (cmp, TRUE);
	g_object_unref (reqh);

	g_byte_array_free (plain, TRUE);
	soup_uri_free (uri);

	soup_test_session_abort_unref (session);
}

static void
do_coding_empty_test (void)
{
	SoupSession *session;
	SoupMessage *msg;
	SoupURI *uri;
	SoupRequestHTTP *reqh;
	GByteArray *body;

	debug_printf (1, "\nEmpty allegedly-encoded body test\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_CONTENT_DECODER,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 NULL);
	uri = soup_uri_new_with_base (base_uri, "/mbox");

	debug_printf (1, "  SoupMessage\n");
	msg = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "empty");
	soup_session_send_message (session, msg);
	check_response (msg, "gzip", "text/plain", EXPECT_NOT_DECODED);
	g_object_unref (msg);

	debug_printf (1, "  SoupRequest\n");
	reqh = soup_session_request_http_uri (session, "GET", uri, NULL);
	msg = soup_request_http_get_message (reqh);
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "empty");
	g_object_unref (msg);
	body = do_single_coding_req_test (reqh, "gzip", "text/plain", EXPECT_NOT_DECODED);
	g_byte_array_free (body, TRUE);
	g_object_unref (reqh);

	soup_uri_free (uri);
	soup_test_session_abort_unref (session);
}


int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	g_test_add_func ("/coding/message", do_coding_test);
	g_test_add_func ("/coding/request", do_coding_req_test);
	g_test_add_func ("/coding/empty", do_coding_empty_test);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
