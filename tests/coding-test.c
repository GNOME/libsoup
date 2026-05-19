/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 * Copyright (C) 2026 Igalia, S.L.
 */

#include "test-utils.h"

#if WITH_BROTLI_ENC
#include <brotli/encode.h>
#include <brotli/shared_dictionary.h>
#endif

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

/* --- Compression Dictionary Transport (dcb) tests --- */

#if WITH_BROTLI_ENC

/* A short shared dictionary and plaintext to compress with it. */
static const guint8 dcb_dictionary[] = "The quick brown fox jumps over the lazy dog";
static const gsize dcb_dictionary_size = sizeof (dcb_dictionary) - 1;

static const char dcb_plaintext[] = "The quick brown fox jumps over the lazy dog. Again!";
static const gsize dcb_plaintext_size = sizeof (dcb_plaintext) - 1;

static GBytes *
compress_with_brotli_dictionary (const guint8 *dict,
                                 gsize         dict_size,
                                 const guint8 *input,
                                 gsize         input_size)
{
        BrotliEncoderPreparedDictionary *prepared;
        BrotliEncoderState *state;
        gsize output_size;
        guint8 *output;
        BROTLI_BOOL ok;

        prepared = BrotliEncoderPrepareDictionary (BROTLI_SHARED_DICTIONARY_RAW,
                                                   dict_size, dict,
                                                   BROTLI_DEFAULT_QUALITY,
                                                   NULL, NULL, NULL);
        g_assert_nonnull (prepared);

        state = BrotliEncoderCreateInstance (NULL, NULL, NULL);
        g_assert_nonnull (state);

        BrotliEncoderAttachPreparedDictionary (state, prepared);

        output_size = BrotliEncoderMaxCompressedSize (input_size);
        output = g_malloc (output_size);

        ok = BrotliEncoderCompress (BROTLI_DEFAULT_QUALITY,
                                    BROTLI_DEFAULT_WINDOW,
                                    BROTLI_DEFAULT_MODE,
                                    input_size, input,
                                    &output_size, output);
        g_assert_true (ok);

        /* BrotliEncoderCompress does not support attached dictionaries;
         * use the streaming path instead. */
        g_free (output);
        output_size = BrotliEncoderMaxCompressedSize (input_size);
        output = g_malloc (output_size);

        {
                const guint8 *next_in = input;
                gsize available_in = input_size;
                guint8 *next_out = output;
                gsize available_out = output_size;

                ok = BrotliEncoderCompressStream (state,
                                                  BROTLI_OPERATION_FINISH,
                                                  &available_in, &next_in,
                                                  &available_out, &next_out,
                                                  NULL);
                g_assert_true (ok);
                g_assert_true (BrotliEncoderIsFinished (state));
                output_size = output_size - available_out;
        }

        BrotliEncoderDestroyInstance (state);
        BrotliEncoderDestroyPreparedDictionary (prepared);

        return g_bytes_new_take (output, output_size);
}

/* Build a dcb frame: \xffDCB + SHA-256(dict) + brotli payload */
static GBytes *
make_dcb_frame (const guint8 *dict,
                gsize         dict_size,
                GBytes       *payload)
{
        static const guint8 magic[] = { 0xff, 'D', 'C', 'B' };
        guint8 hash[32];
        gsize hash_len = sizeof (hash);
        GChecksum *checksum;
        GByteArray *frame;
        const guint8 *payload_data;
        gsize payload_size;

        checksum = g_checksum_new (G_CHECKSUM_SHA256);
        g_checksum_update (checksum, dict, (gssize)dict_size);
        g_checksum_get_digest (checksum, hash, &hash_len);
        g_checksum_free (checksum);

        frame = g_byte_array_new ();
        g_byte_array_append (frame, magic, sizeof (magic));
        g_byte_array_append (frame, hash, sizeof (hash));
        payload_data = g_bytes_get_data (payload, &payload_size);
        g_byte_array_append (frame, payload_data, payload_size);
        return g_byte_array_free_to_bytes (frame);
}

static void
dcb_server_callback (SoupServer        *server,
                     SoupServerMessage *msg,
                     const char        *path,
                     GHashTable        *query,
                     gpointer           user_data)
{
        SoupMessageHeaders *response_headers;
        GBytes *compressed;
        GBytes *framed;

        response_headers = soup_server_message_get_response_headers (msg);

        compressed = compress_with_brotli_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                      (const guint8 *)dcb_plaintext, dcb_plaintext_size);
        framed = make_dcb_frame (dcb_dictionary, dcb_dictionary_size, compressed);
        g_bytes_unref (compressed);

        soup_message_headers_append (response_headers, "Content-Encoding", "dcb");
        soup_message_headers_append (response_headers, "Content-Type", "text/plain");
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);

        SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
        soup_message_body_append_bytes (response_body, framed);
        soup_message_body_complete (response_body);
        g_bytes_unref (framed);
}

static void
dcb_bad_hash_server_callback (SoupServer        *server,
                               SoupServerMessage *msg,
                               const char        *path,
                               GHashTable        *query,
                               gpointer           user_data)
{
        static const guint8 magic[] = { 0xff, 'D', 'C', 'B' };
        static const guint8 bad_hash[32] = { 0 }; /* all zeros — intentionally wrong */
        SoupMessageHeaders *response_headers;
        GBytes *compressed;
        GByteArray *frame;
        GBytes *framed;
        const guint8 *payload_data;
        gsize payload_size;

        response_headers = soup_server_message_get_response_headers (msg);

        compressed = compress_with_brotli_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                      (const guint8 *)dcb_plaintext, dcb_plaintext_size);

        frame = g_byte_array_new ();
        g_byte_array_append (frame, magic, sizeof (magic));
        g_byte_array_append (frame, bad_hash, sizeof (bad_hash));
        payload_data = g_bytes_get_data (compressed, &payload_size);
        g_byte_array_append (frame, payload_data, payload_size);
        framed = g_byte_array_free_to_bytes (frame);
        g_bytes_unref (compressed);

        soup_message_headers_append (response_headers, "Content-Encoding", "dcb");
        soup_message_headers_append (response_headers, "Content-Type", "text/plain");
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);

        SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
        soup_message_body_append_bytes (response_body, framed);
        soup_message_body_complete (response_body);
        g_bytes_unref (framed);
}

static void
do_coding_test_dcb (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        const char *body_data;
        gsize body_size;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/dcb", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = g_bytes_new_static (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary (msg, dict);
        g_bytes_unref (dict);

        body = soup_session_send_and_read (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        soup_test_assert_message_status (msg, SOUP_STATUS_OK);

        body_data = g_bytes_get_data (body, &body_size);
        g_assert_cmpmem (body_data, body_size, dcb_plaintext, dcb_plaintext_size);

        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

static void
do_coding_test_dcb_hash_mismatch (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        GError *error = NULL;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/dcb-bad-hash", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = g_bytes_new_static (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary (msg, dict);
        g_bytes_unref (dict);

        body = soup_session_send_and_read (session, msg, NULL, &error);
        g_assert_null (body);
        g_assert_nonnull (error);
        g_clear_error (&error);

        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

static void
do_coding_test_dcb_accept_encoding (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *body;
        GBytes *dict;
        GUri *uri;
        const char *accept;

        session = soup_test_session_new (NULL);

        /* HTTP (non-TLS): dcb must NOT be advertised even with a dictionary */
        uri = g_uri_parse_relative (base_uri, "/dcb", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = g_bytes_new_static (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary (msg, dict);
        g_bytes_unref (dict);

        /* Trigger header population by queuing then cancelling */
        body = soup_session_send_and_read (session, msg, NULL, NULL);
        g_clear_pointer (&body, g_bytes_unref);
        accept = soup_message_headers_get_one (soup_message_get_request_headers (msg), "Accept-Encoding");
        g_assert_nonnull (accept);
        g_assert_true (strstr (accept, "dcb") == NULL);

        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

#endif /* WITH_BROTLI_ENC */

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
#if WITH_BROTLI_ENC
	soup_server_add_handler (server, "/dcb", dcb_server_callback, NULL, NULL);
	soup_server_add_handler (server, "/dcb-bad-hash", dcb_bad_hash_server_callback, NULL, NULL);
#endif
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

#if WITH_BROTLI_ENC
	g_test_add_data_func ("/coding/message/dcb", NULL, do_coding_test_dcb);
	g_test_add_data_func ("/coding/message/dcb/hash-mismatch", NULL, do_coding_test_dcb_hash_mismatch);
	g_test_add_data_func ("/coding/message/dcb/accept-encoding-http-only",
	                      NULL, do_coding_test_dcb_accept_encoding);
#endif

	ret = g_test_run ();

	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
