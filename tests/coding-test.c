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
	char *file = NULL, *contents;
	gsize length;

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
		const char *file_path = NULL, *encoding = NULL;

		claim_deflate = g_slist_find_custom (codings, "deflate", (GCompareFunc)g_ascii_strcasecmp) != NULL;
		claim_gzip = g_slist_find_custom (codings, "gzip", (GCompareFunc)g_ascii_strcasecmp) != NULL;

		if (claim_gzip && (!claim_deflate ||
				   (!soup_header_contains (options, "prefer-deflate-zlib") &&
				    !soup_header_contains (options, "prefer-deflate-raw")))) {
			file_path = SRCDIR "/resources%s.gz";
			encoding = "gzip";
		} else if (claim_deflate) {
			if (soup_header_contains (options, "prefer-deflate-raw")) {
				file_path = SRCDIR "/resources%s.raw";
				encoding = "deflate";
			} else {
				file_path = SRCDIR "/resources%s.zlib";
				encoding = "deflate";
			}
		}
		if (file_path && encoding) {
			file = g_strdup_printf (file_path, path);
			if (g_file_test (file, G_FILE_TEST_EXISTS)) {
				soup_message_headers_append (msg->response_headers,
							     "Content-Encoding",
							     encoding);
			} else {
				g_free (file);
				file = NULL;
			}
		}
	}

	soup_header_free_list (codings);

	if (!file)
		file = g_strdup_printf (SRCDIR "/resources%s", path);
	if (!g_file_get_contents (file, &contents, &length, NULL)) {
		/* If path.gz exists but can't be read, we'll send back
		 * the error with "Content-Encoding: gzip" but there's
		 * no body, so, eh.
		 */
		g_free (file);
		soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	}
	g_free (file);

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

	soup_message_body_append (msg->response_body,
				  SOUP_MEMORY_TAKE, contents, length);

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

	if (!SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)) {
		debug_printf (1, "    Unexpected status %d %s\n",
			      msg->status_code, msg->reason_phrase);
		errors++;
	}

	coding = soup_message_headers_get_one (msg->response_headers, "Content-Encoding");
	if (expected_encoding) {
		if (!coding || g_ascii_strcasecmp (coding, expected_encoding) != 0) {
			debug_printf (1, "    Unexpected Content-Encoding: %s\n",
				      coding ? coding : "(none)");
			errors++;
		}
	} else {
		if (coding) {
			debug_printf (1, "    Unexpected Content-Encoding: %s\n",
				      coding);
			errors++;
		}
	}

	if (status != NO_CHECK) {
		if (status == EXPECT_DECODED) {
			if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_CONTENT_DECODED)) {
				debug_printf (1, "    SOUP_MESSAGE_CONTENT_DECODED not set!\n");
				errors++;
			}
		} else {
			if (soup_message_get_flags (msg) & SOUP_MESSAGE_CONTENT_DECODED) {
				debug_printf (1, "    SOUP_MESSAGE_CONTENT_DECODED set!\n");
				errors++;
			}
		}
	}

	type = soup_message_headers_get_one (msg->response_headers, "Content-Type");
	if (!type || g_ascii_strcasecmp (type, expected_content_type) != 0) {
		debug_printf (1, "    Unexpected Content-Type: %s\n",
			      type ? type : "(none)");
		errors++;
	}
}

static void
check_msg_bodies (SoupMessage *msg1,
		  SoupMessage *msg2,
		  const char *msg1_type,
		  const char *msg2_type)
{
	if (msg1->response_body->length != msg2->response_body->length) {
		debug_printf (1, "    Message length mismatch: %lu (%s) vs %lu (%s)\n",
			      (gulong)msg1->response_body->length,
			      msg1_type,
			      (gulong)msg2->response_body->length,
			      msg2_type);
		errors++;
	} else if (memcmp (msg1->response_body->data,
			   msg2->response_body->data,
			   msg1->response_body->length) != 0) {
		debug_printf (1, "    Message data mismatch (%s/%s)\n",
			      msg1_type, msg2_type);
		errors++;
	}
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
	check_msg_bodies (msg, msgz, "plain", "compressed");

	/* Plain text data, claim gzip w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, plus trailing junk\n");
	msgj = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgj->request_headers,
				     "X-Test-Options", "trailing-junk");
	soup_session_send_message (session, msgj);
	check_response (msgj, "gzip", "text/plain", EXPECT_DECODED);
	check_msg_bodies (msg, msgj, "plain", "compressed w/ junk");

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
	check_msg_bodies (msg, msge, "plain", "mis-encoded");

	/* Plain text data, claim deflate */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate\n");
	msgzl = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzl->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib");
	soup_session_send_message (session, msgzl);
	check_response (msgzl, "deflate", "text/plain", EXPECT_DECODED);
	check_msg_bodies (msg, msgzl, "plain", "compressed");

	/* Plain text data, claim deflate w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, plus trailing junk\n");
	msgzlj = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlj->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib, trailing-junk");
	soup_session_send_message (session, msgzlj);
	check_response (msgzlj, "deflate", "text/plain", EXPECT_DECODED);
	check_msg_bodies (msg, msgzlj, "plain", "compressed w/ junk");

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, with server error\n");
	msgzle = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzle->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-zlib");
	soup_session_send_message (session, msgzle);
	check_response (msgzle, "deflate", "text/plain", EXPECT_NOT_DECODED);
	check_msg_bodies (msg, msgzle, "plain", "mis-encoded");

	/* Plain text data, claim deflate (no zlib headers)*/
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data)\n");
	msgzlr = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlr->request_headers,
				     "X-Test-Options", "prefer-deflate-raw");
	soup_session_send_message (session, msgzlr);
	check_response (msgzlr, "deflate", "text/plain", EXPECT_DECODED);
	check_msg_bodies (msg, msgzlr, "plain", "compressed");

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data), with server error\n");
	msgzlre = soup_message_new_from_uri ("GET", uri);
	soup_message_headers_append (msgzlre->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-raw");
	soup_session_send_message (session, msgzlre);
	check_response (msgzlre, "deflate", "text/plain", EXPECT_NOT_DECODED);
	check_msg_bodies (msg, msgzlre, "plain", "mis-encoded");

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
req_sent (GObject *req, GAsyncResult *result, gpointer user_data)
{
	GInputStream **stream = user_data;
	GError *error = NULL;

	*stream = soup_request_send_finish (SOUP_REQUEST (req),
					    result, &error);
	if (error) {
		debug_printf (1, "    Error sending request: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
	}
}

static void
read_finished (GObject *stream, GAsyncResult *result, gpointer user_data)
{
	gssize *nread = user_data;
	GError *error = NULL;

	*nread = g_input_stream_read_finish (G_INPUT_STREAM (stream),
					     result, &error);
	if (error) {
		debug_printf (1, "    Error reading: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
	}
}

static GByteArray *
do_single_coding_req_test (SoupRequest *req,
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

	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));

	stream = NULL;
	soup_request_send_async (req, NULL, req_sent, &stream);
	while (!stream)
		g_main_context_iteration (NULL, TRUE);

	data = g_byte_array_new ();
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

	g_input_stream_close (stream, NULL, &error);
	if (error) {
		debug_printf (1, "    error closing stream: %s\n",
			      error->message);
		g_error_free (error);
		errors++;
	}

	check_response (msg, expected_encoding, expected_content_type, status);
	g_object_unref (msg);

	return data;
}

static void
check_req_bodies (GByteArray *body1,
		  GByteArray *body2,
		  const char *msg1_type,
		  const char *msg2_type)
{
	if (body1->len != body2->len) {
		debug_printf (1, "    Message length mismatch: %lu (%s) vs %lu (%s)\n",
			      (gulong)body1->len, msg1_type,
			      (gulong)body2->len, msg2_type);
		errors++;
	} else if (memcmp (body1->data, body2->data, body1->len) != 0) {
		debug_printf (1, "    Message data mismatch (%s/%s)\n",
			      msg1_type, msg2_type);
		errors++;
	}
}

static void
do_coding_req_test (void)
{
	SoupSession *session;
	SoupRequester *requester;
	SoupRequest *req;
	SoupMessage *msg;
	SoupURI *uri;
	GByteArray *plain, *cmp;

	debug_printf (1, "\nSoupRequest tests\n");

	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC,
					 SOUP_SESSION_USE_THREAD_CONTEXT, TRUE,
					 SOUP_SESSION_ADD_FEATURE_BY_TYPE, SOUP_TYPE_REQUESTER,
					 NULL);
	requester = (SoupRequester *)soup_session_get_feature (session, SOUP_TYPE_REQUESTER);
	uri = soup_uri_new_with_base (base_uri, "/mbox");

	/* Plain text data, no claim */
	debug_printf (1, "  GET /mbox, plain\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	plain = do_single_coding_req_test (req, NULL, "text/plain", EXPECT_NOT_DECODED);
	g_object_unref (req);

	/* Plain text data, claim gzip */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip\n");
	soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_DECODER);
	req = soup_requester_request_uri (requester, uri, NULL);
	cmp = do_single_coding_req_test (req, "gzip", "text/plain", EXPECT_DECODED);
	check_req_bodies (plain, cmp, "plain", "compressed");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim gzip w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, plus trailing junk\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "trailing-junk");
	cmp = do_single_coding_req_test (req, "gzip", "text/plain", EXPECT_DECODED);
	check_req_bodies (plain, cmp, "plain", "compressed w/ junk");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim gzip with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: gzip, with server error\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode");
	cmp = do_single_coding_req_test (req, "gzip", "text/plain", EXPECT_NOT_DECODED);

	/* Failed content-decoding should have left the body untouched
	 * from what the server sent... which happens to be the
	 * uncompressed data.
	 */
	check_req_bodies (plain, cmp, "plain", "mis-encoded");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim deflate */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib");
	cmp = do_single_coding_req_test (req, "deflate", "text/plain", EXPECT_DECODED);
	check_req_bodies (plain, cmp, "plain", "compressed");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim deflate w/ junk */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, plus trailing junk\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-zlib, trailing-junk");
	cmp = do_single_coding_req_test (req, "deflate", "text/plain", EXPECT_DECODED);
	check_req_bodies (plain, cmp, "plain", "compressed w/ junk");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate, with server error\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-zlib");
	cmp = do_single_coding_req_test (req, "deflate", "text/plain", EXPECT_NOT_DECODED);
	check_req_bodies (plain, cmp, "plain", "mis-encoded");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim deflate (no zlib headers)*/
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data)\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "prefer-deflate-raw");
	cmp = do_single_coding_req_test (req, "deflate", "text/plain", EXPECT_DECODED);
	check_req_bodies (plain, cmp, "plain", "compressed");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	/* Plain text data, claim deflate with server error */
	debug_printf (1, "  GET /mbox, Accept-Encoding: deflate (raw data), with server error\n");
	req = soup_requester_request_uri (requester, uri, NULL);
	msg = soup_request_http_get_message (SOUP_REQUEST_HTTP (req));
	soup_message_headers_append (msg->request_headers,
				     "X-Test-Options", "force-encode, prefer-deflate-raw");
	cmp = do_single_coding_req_test (req, "deflate", "text/plain", EXPECT_NOT_DECODED);
	check_req_bodies (plain, cmp, "plain", "mis-encoded");
	g_byte_array_free (cmp, TRUE);
	g_object_unref (req);

	g_byte_array_free (plain, TRUE);
	soup_uri_free (uri);

	soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_uri_new ("http://127.0.0.1/");
	soup_uri_set_port (base_uri, soup_server_get_port (server));

	do_coding_test ();
	do_coding_req_test ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return errors != 0;
}
