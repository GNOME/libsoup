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
static GUri *h2_base_uri;

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

/* --- Compression Dictionary Transport (dcb/dcz) tests --- */

#if defined(WITH_BROTLI_ENC) || defined(WITH_ZSTD_ENC)

/* A short shared dictionary and plaintext reused by both dcb and dcz tests. */
static const guint8 dcb_dictionary[] = "The quick brown fox jumps over the lazy dog";
static const gsize dcb_dictionary_size = sizeof (dcb_dictionary) - 1;

static const char dcb_plaintext[] = "The quick brown fox jumps over the lazy dog. Again!";
static const gsize dcb_plaintext_size = sizeof (dcb_plaintext) - 1;

/* A large plaintext (~1 MiB) to force the body to span many read chunks /
 * HTTP2 DATA frames. Caller owns the returned bytes. */
static GBytes *
make_large_plaintext (void)
{
        GByteArray *buf = g_byte_array_new ();
        for (int i = 0; i < 20000; i++)
                g_byte_array_append (buf, (const guint8 *)dcb_plaintext, dcb_plaintext_size);
        return g_byte_array_free_to_bytes (buf);
}

static GBytes *
compute_sha256_hash (const guint8 *data,
                     gsize         size)
{
        GChecksum *checksum;
        guint8 hash[32];
        gsize hash_len = sizeof (hash);

        checksum = g_checksum_new (G_CHECKSUM_SHA256);
        g_checksum_update (checksum, data, (gssize)size);
        g_checksum_get_digest (checksum, hash, &hash_len);
        g_checksum_free (checksum);

        return g_bytes_new (hash, hash_len);
}

static gboolean
on_request_compression_dictionary (SoupMessage                      *msg,
                                    SoupCompressionDictionaryRequest *request,
                                    gpointer                          user_data)
{
        GBytes *dict = g_bytes_new_static (dcb_dictionary, dcb_dictionary_size);
        soup_compression_dictionary_request_set_dictionary (request, dict);
        g_bytes_unref (dict);
        return TRUE;
}

static gboolean
complete_dictionary_async (gpointer user_data)
{
        SoupCompressionDictionaryRequest *request = user_data;
        GBytes *dict = g_bytes_new_static (dcb_dictionary, dcb_dictionary_size);
        soup_compression_dictionary_request_set_dictionary (request, dict);
        g_bytes_unref (dict);
        g_object_unref (request);
        return G_SOURCE_REMOVE;
}

static gboolean
on_request_compression_dictionary_async (SoupMessage                      *msg,
                                          SoupCompressionDictionaryRequest *request,
                                          gpointer                          user_data)
{
        g_idle_add (complete_dictionary_async, g_object_ref (request));
        return TRUE;
}

#endif /* WITH_BROTLI_ENC || WITH_ZSTD_ENC */

#if WITH_BROTLI_ENC

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
        GBytes *large = NULL;
        const guint8 *plaintext = (const guint8 *)dcb_plaintext;
        gsize plaintext_size = dcb_plaintext_size;

        if (g_str_has_suffix (path, "-large")) {
                large = make_large_plaintext ();
                plaintext = g_bytes_get_data (large, &plaintext_size);
        }

        response_headers = soup_server_message_get_response_headers (msg);

        compressed = compress_with_brotli_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                      plaintext, plaintext_size);
        framed = make_dcb_frame (dcb_dictionary, dcb_dictionary_size, compressed);
        g_clear_pointer (&large, g_bytes_unref);
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

/* Deliver the framed dcb body in a few small chunks separated in time.
 * The 36-byte dcb header alone spans several chunks, and the delays make
 * each chunk arrive in a distinct client read while the message is
 * paused waiting for the async dictionary. This feeds the content decoder a
 * partial header with no further input available. */
#define DCB_CHUNK_COUNT 4
#define DCB_CHUNK_DELAY_MS 100

typedef struct {
        SoupServerMessage *msg;
        GBytes *framed;
        gsize offset;
} DcbChunkedState;

static gsize
dcb_chunk_size (DcbChunkedState *state)
{
        gsize total = g_bytes_get_size (state->framed);
        return (total + DCB_CHUNK_COUNT - 1) / DCB_CHUNK_COUNT;
}

static gboolean
dcb_chunked_send_next (gpointer user_data)
{
        DcbChunkedState *state = user_data;
        SoupServerMessage *msg = state->msg;
        SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
        gsize total = g_bytes_get_size (state->framed);
        gsize chunk_length = MIN (dcb_chunk_size (state), total - state->offset);
        GBytes *chunk = g_bytes_new_from_bytes (state->framed, state->offset, chunk_length);

        soup_message_body_append_bytes (response_body, chunk);
        g_bytes_unref (chunk);
        state->offset += chunk_length;

        if (state->offset >= total)
                soup_message_body_complete (response_body);

        soup_server_message_unpause (msg);
        return (state->offset >= total) ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
}

static void
dcb_chunked_free_state (SoupServerMessage *msg,
                        gpointer           user_data)
{
        DcbChunkedState *state = user_data;
        g_bytes_unref (state->framed);
        g_free (state);
}

static void
dcb_chunked_server_callback (SoupServer        *server,
                             SoupServerMessage *msg,
                             const char        *path,
                             GHashTable        *query,
                             gpointer           user_data)
{
        SoupMessageHeaders *response_headers = soup_server_message_get_response_headers (msg);
        GBytes *compressed;
        DcbChunkedState *state;
        GSource *source;

        compressed = compress_with_brotli_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                      (const guint8 *)dcb_plaintext, dcb_plaintext_size);

        soup_message_headers_append (response_headers, "Content-Encoding", "dcb");
        soup_message_headers_append (response_headers, "Content-Type", "text/plain");
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);

        state = g_new0 (DcbChunkedState, 1);
        state->msg = msg;
        state->framed = make_dcb_frame (dcb_dictionary, dcb_dictionary_size, compressed);
        g_bytes_unref (compressed);

        soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);
        soup_server_message_pause (msg);
        source = g_timeout_source_new (DCB_CHUNK_DELAY_MS);
        g_source_set_callback (source, dcb_chunked_send_next, state, NULL);
        g_source_attach (source, g_main_context_get_thread_default ());
        g_source_unref (source);
        g_signal_connect (msg, "finished", G_CALLBACK (dcb_chunked_free_state), state);
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

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary), NULL);

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

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary), NULL);

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

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary), NULL);

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

/* --- Compression Dictionary Transport (dcz) tests --- */

#if WITH_ZSTD_ENC
#include <zstd.h>

/* Reuse the same dictionary and plaintext as the dcb tests */

static GBytes *
compress_with_zstd_dictionary (const guint8 *dict,
                               gsize         dict_size,
                               const guint8 *input,
                               gsize         input_size)
{
        ZSTD_CCtx *cctx;
        gsize output_size;
        void *output;
        size_t actual_size;

        cctx = ZSTD_createCCtx ();
        g_assert_nonnull (cctx);

        ZSTD_CCtx_loadDictionary (cctx, dict, dict_size);

        output_size = ZSTD_compressBound (input_size);
        output = g_malloc (output_size);

        actual_size = ZSTD_compress2 (cctx, output, output_size, input, input_size);
        g_assert_false (ZSTD_isError (actual_size));

        ZSTD_freeCCtx (cctx);

        return g_bytes_new_take (output, actual_size);
}

/* Build a dcz frame: zstd skippable frame header (8 bytes) + SHA-256(dict) + zstd payload */
static GBytes *
make_dcz_frame (const guint8 *dict,
                gsize         dict_size,
                GBytes       *payload)
{
        /* Zstd skippable frame: magic 0x184D2A5E (LE) + frame size 32 (LE) */
        static const guint8 magic[] = { 0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00 };
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
dcz_server_callback (SoupServer        *server,
                     SoupServerMessage *msg,
                     const char        *path,
                     GHashTable        *query,
                     gpointer           user_data)
{
        SoupMessageHeaders *response_headers;
        GBytes *compressed;
        GBytes *framed;

        response_headers = soup_server_message_get_response_headers (msg);

        compressed = compress_with_zstd_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                    (const guint8 *)dcb_plaintext, dcb_plaintext_size);
        framed = make_dcz_frame (dcb_dictionary, dcb_dictionary_size, compressed);
        g_bytes_unref (compressed);

        soup_message_headers_append (response_headers, "Content-Encoding", "dcz");
        soup_message_headers_append (response_headers, "Content-Type", "text/plain");
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);

        SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
        soup_message_body_append_bytes (response_body, framed);
        soup_message_body_complete (response_body);
        g_bytes_unref (framed);
}

static void
dcz_bad_hash_server_callback (SoupServer        *server,
                               SoupServerMessage *msg,
                               const char        *path,
                               GHashTable        *query,
                               gpointer           user_data)
{
        static const guint8 magic[] = { 0xff, 'D', 'C', 'Z' };
        static const guint8 bad_hash[32] = { 0 }; /* all zeros — intentionally wrong */
        SoupMessageHeaders *response_headers;
        GBytes *compressed;
        GByteArray *frame;
        GBytes *framed;
        const guint8 *payload_data;
        gsize payload_size;

        response_headers = soup_server_message_get_response_headers (msg);

        compressed = compress_with_zstd_dictionary (dcb_dictionary, dcb_dictionary_size,
                                                    (const guint8 *)dcb_plaintext, dcb_plaintext_size);

        frame = g_byte_array_new ();
        g_byte_array_append (frame, magic, sizeof (magic));
        g_byte_array_append (frame, bad_hash, sizeof (bad_hash));
        payload_data = g_bytes_get_data (compressed, &payload_size);
        g_byte_array_append (frame, payload_data, payload_size);
        framed = g_byte_array_free_to_bytes (frame);
        g_bytes_unref (compressed);

        soup_message_headers_append (response_headers, "Content-Encoding", "dcz");
        soup_message_headers_append (response_headers, "Content-Type", "text/plain");
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_message_headers_set_encoding (response_headers, SOUP_ENCODING_CHUNKED);

        SoupMessageBody *response_body = soup_server_message_get_response_body (msg);
        soup_message_body_append_bytes (response_body, framed);
        soup_message_body_complete (response_body);
        g_bytes_unref (framed);
}

static void
do_coding_test_dcz (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        const char *body_data;
        gsize body_size;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/dcz", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary), NULL);

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
do_coding_test_dcz_hash_mismatch (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        GError *error = NULL;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/dcz-bad-hash", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary), NULL);

        body = soup_session_send_and_read (session, msg, NULL, &error);
        g_assert_null (body);
        g_assert_nonnull (error);
        g_clear_error (&error);

        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

#endif /* WITH_ZSTD_ENC */

#if WITH_BROTLI_ENC
static void
do_coding_test_dcb_async (gconstpointer test_data)
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

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary_async), NULL);

        body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        soup_test_assert_message_status (msg, SOUP_STATUS_OK);

        body_data = g_bytes_get_data (body, &body_size);
        g_assert_cmpmem (body_data, body_size, dcb_plaintext, dcb_plaintext_size);

        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}
#endif /* WITH_BROTLI_ENC */

#if WITH_ZSTD_ENC
static void
do_coding_test_dcz_async (gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        const char *body_data;
        gsize body_size;

        session = soup_test_session_new (NULL);

        uri = g_uri_parse_relative (base_uri, "/dcz", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary_async), NULL);

        body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        soup_test_assert_message_status (msg, SOUP_STATUS_OK);

        body_data = g_bytes_get_data (body, &body_size);
        g_assert_cmpmem (body_data, body_size, dcb_plaintext, dcb_plaintext_size);

        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}
#endif /* WITH_ZSTD_ENC */

#if WITH_BROTLI_ENC || WITH_ZSTD_ENC
/* Over HTTP/2 the decoded body input stream is created on the first DATA
 * frame, which can arrive before the asynchronously-resolved dictionary is
 * set. This exercises the path where the decoder is created without a
 * dictionary and has it attached later via notify::dictionary. */
static void
do_coding_test_dict_async_http2 (const char *path)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *body;
        GUri *uri;
        const char *body_data;
        gsize body_size;

        if (!tls_available) {
                g_test_skip ("TLS not available");
                return;
        }

        session = soup_test_session_new (NULL);
        /* A content sniffer reads the start of the (decoded) body as soon as
         * data arrives, which for HTTP/2 happens while the message is paused
         * waiting for the dictionary. WebKit installs one by default. */
        soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

        uri = g_uri_parse_relative (h2_base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary_async), NULL);

        body = soup_test_session_async_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        soup_test_assert_message_status (msg, SOUP_STATUS_OK);
        g_assert_cmpuint (soup_message_get_http_version (msg), ==, SOUP_HTTP_2_0);

        body_data = g_bytes_get_data (body, &body_size);
        g_assert_cmpmem (body_data, body_size, dcb_plaintext, dcb_plaintext_size);

        g_bytes_unref (body);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}

/* Like the above, but reads the response via a streaming GInputStream (as
 * WebKit does with soup_session_send_async) instead of reading it all at once. */
static void
do_coding_test_dict_async_stream (GUri *uri_base, const char *path)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *dict;
        GBytes *expected = NULL;
        const char *expected_data = dcb_plaintext;
        gsize expected_size = dcb_plaintext_size;
        GUri *uri;
        GInputStream *stream;
        GByteArray *received;
        guchar buf[8];
        gssize nread;
        GError *error = NULL;

        if (g_str_has_suffix (path, "-large")) {
                expected = make_large_plaintext ();
                expected_data = g_bytes_get_data (expected, &expected_size);
        }

        session = soup_test_session_new (NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_SNIFFER);

        uri = g_uri_parse_relative (uri_base, path, SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        dict = compute_sha256_hash (dcb_dictionary, dcb_dictionary_size);
        soup_message_set_compression_dictionary_hash (msg, dict);
        g_bytes_unref (dict);
        g_signal_connect (msg, "request-compression-dictionary",
                          G_CALLBACK (on_request_compression_dictionary_async), NULL);

        stream = soup_test_request_send (session, msg, NULL, 0, &error);
        g_assert_no_error (error);
        g_assert_nonnull (stream);

        received = g_byte_array_new ();
        while ((nread = g_input_stream_read (stream, buf, sizeof (buf), NULL, &error)) > 0)
                g_byte_array_append (received, buf, nread);
        g_assert_no_error (error);
        g_assert_cmpint (nread, ==, 0);

        g_assert_cmpmem (received->data, received->len, expected_data, expected_size);

        g_clear_pointer (&expected, g_bytes_unref);
        g_byte_array_unref (received);
        g_object_unref (stream);
        g_object_unref (msg);
        soup_test_session_abort_unref (session);
}
#endif /* WITH_BROTLI_ENC || WITH_ZSTD_ENC */

#if WITH_BROTLI_ENC
static void
do_coding_test_dcb_async_http2 (gconstpointer test_data)
{
        do_coding_test_dict_async_http2 ("/dcb");
}

static void
do_coding_test_dcb_async_stream (gconstpointer test_data)
{
        do_coding_test_dict_async_stream (base_uri, "/dcb");
}

static void
do_coding_test_dcb_async_stream_http2 (gconstpointer test_data)
{
        if (!tls_available) {
                g_test_skip ("TLS not available");
                return;
        }
        do_coding_test_dict_async_stream (h2_base_uri, "/dcb");
}

static void
do_coding_test_dcb_async_stream_chunked (gconstpointer test_data)
{
        do_coding_test_dict_async_stream (base_uri, "/dcb-chunked");
}

static void
do_coding_test_dcb_async_stream_large_http2 (gconstpointer test_data)
{
        if (!tls_available) {
                g_test_skip ("TLS not available");
                return;
        }
        do_coding_test_dict_async_stream (h2_base_uri, "/dcb-large");
}
#endif

#if WITH_ZSTD_ENC
static void
do_coding_test_dcz_async_http2 (gconstpointer test_data)
{
        do_coding_test_dict_async_http2 ("/dcz");
}
#endif

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
#if WITH_BROTLI_ENC
	soup_server_add_handler (server, "/dcb", dcb_server_callback, NULL, NULL);
	soup_server_add_handler (server, "/dcb-large", dcb_server_callback, NULL, NULL);
	soup_server_add_handler (server, "/dcb-chunked", dcb_chunked_server_callback, NULL, NULL);
	soup_server_add_handler (server, "/dcb-bad-hash", dcb_bad_hash_server_callback, NULL, NULL);
#endif
#if WITH_ZSTD_ENC
	soup_server_add_handler (server, "/dcz", dcz_server_callback, NULL, NULL);
	soup_server_add_handler (server, "/dcz-bad-hash", dcz_bad_hash_server_callback, NULL, NULL);
#endif
	base_uri = soup_test_server_get_uri (server, "http", NULL);

#if WITH_BROTLI_ENC || WITH_ZSTD_ENC
	if (tls_available) {
		SoupServer *h2_server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD | SOUP_TEST_SERVER_HTTP2);
#if WITH_BROTLI_ENC
		soup_server_add_handler (h2_server, "/dcb", dcb_server_callback, NULL, NULL);
		soup_server_add_handler (h2_server, "/dcb-large", dcb_server_callback, NULL, NULL);
#endif
#if WITH_ZSTD_ENC
		soup_server_add_handler (h2_server, "/dcz", dcz_server_callback, NULL, NULL);
#endif
		h2_base_uri = soup_test_server_get_uri (h2_server, "https", "127.0.0.1");
		/* The server is owned by the test thread; keep it alive for the
		 * duration of the run and let it be torn down at process exit. */
		g_object_set_data_full (G_OBJECT (server), "h2-server", h2_server,
		                        (GDestroyNotify) soup_test_server_quit_unref);
	}
#endif

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
	g_test_add_data_func ("/coding/message/dcb/async", NULL, do_coding_test_dcb_async);
	g_test_add_data_func ("/coding/message/dcb/async-http2", NULL, do_coding_test_dcb_async_http2);
	g_test_add_data_func ("/coding/message/dcb/async-stream", NULL, do_coding_test_dcb_async_stream);
	g_test_add_data_func ("/coding/message/dcb/async-stream-http2", NULL, do_coding_test_dcb_async_stream_http2);
	g_test_add_data_func ("/coding/message/dcb/async-stream-large-http2", NULL, do_coding_test_dcb_async_stream_large_http2);
	g_test_add_data_func ("/coding/message/dcb/async-stream-chunked", NULL, do_coding_test_dcb_async_stream_chunked);
	g_test_add_data_func ("/coding/message/dcb/hash-mismatch", NULL, do_coding_test_dcb_hash_mismatch);
	g_test_add_data_func ("/coding/message/dcb/accept-encoding-http-only",
	                      NULL, do_coding_test_dcb_accept_encoding);
#endif
#if WITH_ZSTD_ENC
	g_test_add_data_func ("/coding/message/dcz", NULL, do_coding_test_dcz);
	g_test_add_data_func ("/coding/message/dcz/async", NULL, do_coding_test_dcz_async);
	g_test_add_data_func ("/coding/message/dcz/async-http2", NULL, do_coding_test_dcz_async_http2);
	g_test_add_data_func ("/coding/message/dcz/hash-mismatch", NULL, do_coding_test_dcz_hash_mismatch);
#endif

	ret = g_test_run ();

	g_uri_unref (base_uri);
	g_clear_pointer (&h2_base_uri, g_uri_unref);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
