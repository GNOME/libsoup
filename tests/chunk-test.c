/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "test-utils.h"

static SoupSession *session;
static SoupURI *base_uri;

typedef struct {
	SoupSession *session;
	SoupBuffer *chunks[3];
	int next, nwrote, nfreed;
	gboolean streaming;
} PutTestData;

static void
write_next_chunk (SoupMessage *msg, gpointer user_data)
{
	PutTestData *ptd = user_data;

	debug_printf (2, "  writing chunk %d\n", ptd->next);

	if (ptd->streaming && ptd->next > 0) {
		soup_test_assert (ptd->chunks[ptd->next - 1] == NULL,
				  "next chunk requested before last one freed");
	}

	if (ptd->next < G_N_ELEMENTS (ptd->chunks)) {
		soup_message_body_append_buffer (msg->request_body,
						 ptd->chunks[ptd->next]);
		soup_buffer_free (ptd->chunks[ptd->next]);
		ptd->next++;
	} else
		soup_message_body_complete (msg->request_body);
	soup_session_unpause_message (ptd->session, msg);
}

/* This is not a supported part of the API. Use SOUP_MESSAGE_CAN_REBUILD
 * instead.
 */
static void
write_next_chunk_streaming_hack (SoupMessage *msg, gpointer user_data)
{
	PutTestData *ptd = user_data;
	SoupBuffer *chunk;

	debug_printf (2, "  freeing chunk at %d\n", ptd->nfreed);
	chunk = soup_message_body_get_chunk (msg->request_body, ptd->nfreed);
	if (chunk) {
		ptd->nfreed += chunk->length;
		soup_message_body_wrote_chunk (msg->request_body, chunk);
		soup_buffer_free (chunk);
	} else {
		soup_test_assert (chunk,
				  "written chunk does not exist");
	}
	write_next_chunk (msg, user_data);
}

static void
wrote_body_data (SoupMessage *msg, SoupBuffer *chunk, gpointer user_data)
{
	PutTestData *ptd = user_data;

	debug_printf (2, "  wrote_body_data, %d bytes\n",
		      (int)chunk->length);
	ptd->nwrote += chunk->length;
}

static void
clear_buffer_ptr (gpointer data)
{
	SoupBuffer **buffer_ptr = data;

	debug_printf (2, "  clearing chunk\n");
	if (*buffer_ptr) {
		(*buffer_ptr)->length = 0;
		g_free ((char *)(*buffer_ptr)->data);
		*buffer_ptr = NULL;
	} else {
		soup_test_assert (*buffer_ptr,
				  "chunk is already clear");
	}
}

/* Put a chunk containing @text into *@buffer, set up so that it will
 * clear out *@buffer when the chunk is freed, allowing us to make sure
 * the set_accumulate(FALSE) is working.
 */
static void
make_put_chunk (SoupBuffer **buffer, const char *text)
{
	*buffer = soup_buffer_new_with_owner (g_strdup (text), strlen (text),
					      buffer, clear_buffer_ptr);
}

static void
setup_request_body (PutTestData *ptd)
{
	make_put_chunk (&ptd->chunks[0], "one\r\n");
	make_put_chunk (&ptd->chunks[1], "two\r\n");
	make_put_chunk (&ptd->chunks[2], "three\r\n");
	ptd->next = ptd->nwrote = ptd->nfreed = 0;
}

static void
restarted_streaming (SoupMessage *msg, gpointer user_data)
{
	PutTestData *ptd = user_data;

	debug_printf (2, "  --restarting--\n");

	/* We're streaming, and we had to restart. So the data need
	 * to be regenerated.
	 */
	setup_request_body (ptd);

	/* The 302 redirect will turn it into a GET request and
	 * reset the body encoding back to "NONE". Fix that.
	 */
	soup_message_headers_set_encoding (msg->request_headers,
					   SOUP_ENCODING_CHUNKED);
	msg->method = SOUP_METHOD_PUT;
}

static void
restarted_streaming_hack (SoupMessage *msg, gpointer user_data)
{
	restarted_streaming (msg, user_data);
	soup_message_body_truncate (msg->request_body);
}

typedef enum {
	HACKY_STREAMING  = (1 << 0),
	PROPER_STREAMING = (1 << 1),
	RESTART          = (1 << 2)
} RequestTestFlags;

static void
do_request_test (gconstpointer data)
{
	RequestTestFlags flags = GPOINTER_TO_UINT (data);
	SoupURI *uri;
	PutTestData ptd;
	SoupMessage *msg;
	const char *client_md5, *server_md5;
	GChecksum *check;
	int i, length;

	if (flags & RESTART)
		uri = soup_uri_new_with_base (base_uri, "/redirect");
	else
		uri = soup_uri_copy (base_uri);

	ptd.session = session;
	setup_request_body (&ptd);
	ptd.streaming = flags & (HACKY_STREAMING | PROPER_STREAMING);

	check = g_checksum_new (G_CHECKSUM_MD5);
	length = 0;
	for (i = 0; i < 3; i++) {
		g_checksum_update (check, (guchar *)ptd.chunks[i]->data,
				   ptd.chunks[i]->length);
		length += ptd.chunks[i]->length;
	}
	client_md5 = g_checksum_get_string (check);

	msg = soup_message_new_from_uri ("PUT", uri);
	soup_message_headers_set_encoding (msg->request_headers, SOUP_ENCODING_CHUNKED);
	soup_message_body_set_accumulate (msg->request_body, FALSE);
	if (flags & HACKY_STREAMING) {
		g_signal_connect (msg, "wrote_chunk",
				  G_CALLBACK (write_next_chunk_streaming_hack), &ptd);
		if (flags & RESTART) {
			g_signal_connect (msg, "restarted",
					  G_CALLBACK (restarted_streaming_hack), &ptd);
		}
	} else {
		g_signal_connect (msg, "wrote_chunk",
				  G_CALLBACK (write_next_chunk), &ptd);
	}

	if (flags & PROPER_STREAMING) {
		soup_message_set_flags (msg, SOUP_MESSAGE_CAN_REBUILD);
		if (flags & RESTART) {
			g_signal_connect (msg, "restarted",
					  G_CALLBACK (restarted_streaming), &ptd);
		}
	}

	g_signal_connect (msg, "wrote_headers",
			  G_CALLBACK (write_next_chunk), &ptd);
	g_signal_connect (msg, "wrote_body_data",
			  G_CALLBACK (wrote_body_data), &ptd);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_CREATED);
	g_assert_null (msg->request_body->data);
	g_assert_cmpint (msg->request_body->length, ==, length);
	g_assert_cmpint (length, ==, ptd.nwrote);

	server_md5 = soup_message_headers_get_one (msg->response_headers,
						   "Content-MD5");
	g_assert_cmpstr (client_md5, ==, server_md5);

	g_object_unref (msg);
	g_checksum_free (check);

	soup_uri_free (uri);
}

typedef struct {
	SoupBuffer *current_chunk;
	GChecksum *check;
	int length;
} GetTestData;

static SoupBuffer *
chunk_allocator (SoupMessage *msg, gsize max_len, gpointer user_data)
{
	GetTestData *gtd = user_data;

	debug_printf (2, "  allocating chunk\n");

	soup_test_assert (gtd->current_chunk == NULL,
			  "error: next chunk allocated before last one freed");
	gtd->current_chunk = soup_buffer_new_with_owner (g_malloc (6), 6,
							 &gtd->current_chunk,
							 clear_buffer_ptr);
	return gtd->current_chunk;
}

static void
got_chunk (SoupMessage *msg, SoupBuffer *chunk, gpointer user_data)
{
	GetTestData *gtd = user_data;

	debug_printf (2, "  got chunk, %d bytes\n",
		      (int)chunk->length);
	if (chunk != gtd->current_chunk) {
		debug_printf (1, "chunk mismatch! %p vs %p\n",
			      chunk, gtd->current_chunk);
	}

	g_checksum_update (gtd->check, (guchar *)chunk->data, chunk->length);
	gtd->length += chunk->length;
}

static void
do_response_test (void)
{
	GetTestData gtd;
	SoupMessage *msg;
	const char *client_md5, *server_md5;

	gtd.current_chunk = NULL;
	gtd.length = 0;
	gtd.check = g_checksum_new (G_CHECKSUM_MD5);

	msg = soup_message_new_from_uri ("GET", base_uri);
	soup_message_body_set_accumulate (msg->response_body, FALSE);
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	soup_message_set_chunk_allocator (msg, chunk_allocator, &gtd, NULL);
	G_GNUC_END_IGNORE_DEPRECATIONS;
	g_signal_connect (msg, "got_chunk",
			  G_CALLBACK (got_chunk), &gtd);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_null (msg->response_body->data);
	g_assert_cmpint (soup_message_headers_get_content_length (msg->response_headers), ==, gtd.length);

	client_md5 = g_checksum_get_string (gtd.check);
	server_md5 = soup_message_headers_get_one (msg->response_headers,
						   "Content-MD5");
	g_assert_cmpstr (client_md5, ==, server_md5);

	g_object_unref (msg);
	g_checksum_free (gtd.check);
}

/* Make sure TEMPORARY buffers are handled properly with non-accumulating
 * message bodies.
 */

static void
temp_test_wrote_chunk (SoupMessage *msg, gpointer session)
{
	SoupBuffer *chunk;

	chunk = soup_message_body_get_chunk (msg->request_body, 5);

	/* When the bug is present, the second chunk will also be
	 * discarded after the first is written, which will cause
	 * the I/O to stall since soup-message-io will think it's
	 * done, but it hasn't written Content-Length bytes yet.
	 */
	if (chunk)
		soup_buffer_free (chunk);
	else {
		soup_test_assert (chunk, "Lost second chunk");
		soup_session_abort (session);
	}

	g_signal_handlers_disconnect_by_func (msg, temp_test_wrote_chunk, session);
}

static void
do_temporary_test (void)
{
	SoupMessage *msg;
	char *client_md5;
	const char *server_md5;

	g_test_bug_base ("https://bugs.webkit.org/");
	g_test_bug ("18343");

	msg = soup_message_new_from_uri ("PUT", base_uri);
	soup_message_body_append (msg->request_body, SOUP_MEMORY_TEMPORARY,
				  "one\r\n", 5);
	soup_message_body_append (msg->request_body, SOUP_MEMORY_STATIC,
				  "two\r\n", 5);
	soup_message_body_set_accumulate (msg->request_body, FALSE);

	client_md5 = g_compute_checksum_for_string (G_CHECKSUM_MD5,
						    "one\r\ntwo\r\n", 10);
	g_signal_connect (msg, "wrote_chunk",
			  G_CALLBACK (temp_test_wrote_chunk), session);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_CREATED);

	server_md5 = soup_message_headers_get_one (msg->response_headers,
						   "Content-MD5");
	g_assert_cmpstr (client_md5, ==, server_md5);

	g_free (client_md5);
	g_object_unref (msg);
}

#define LARGE_CHUNK_SIZE 1000000

typedef struct {
	SoupBuffer *buf;
	gsize offset;
} LargeChunkData;

static void
large_wrote_body_data (SoupMessage *msg, SoupBuffer *chunk, gpointer user_data)
{
	LargeChunkData *lcd = user_data;

	soup_assert_cmpmem (chunk->data, chunk->length,
			    lcd->buf->data + lcd->offset,
			    chunk->length);
	lcd->offset += chunk->length;
}

static void
do_large_chunk_test (void)
{
	SoupMessage *msg;
	char *buf_data;
	int i;
	LargeChunkData lcd;

	msg = soup_message_new_from_uri ("PUT", base_uri);

	buf_data = g_malloc0 (LARGE_CHUNK_SIZE);
	for (i = 0; i < LARGE_CHUNK_SIZE; i++)
		buf_data[i] = i & 0xFF;
	lcd.buf = soup_buffer_new (SOUP_MEMORY_TAKE, buf_data, LARGE_CHUNK_SIZE);
	lcd.offset = 0;
	soup_message_body_append_buffer (msg->request_body, lcd.buf);
	soup_message_body_set_accumulate (msg->request_body, FALSE);

	g_signal_connect (msg, "wrote_body_data",
			  G_CALLBACK (large_wrote_body_data), &lcd);
	soup_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_CREATED);

	soup_buffer_free (lcd.buf);
	g_object_unref (msg);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SoupMessageBody *md5_body;
	char *md5;

	if (g_str_has_prefix (path, "/redirect")) {
		soup_message_set_redirect (msg, SOUP_STATUS_FOUND, "/");
		return;
	}

	if (msg->method == SOUP_METHOD_GET) {
		soup_message_set_response (msg, "text/plain",
					   SOUP_MEMORY_STATIC,
					   "three\r\ntwo\r\none\r\n",
					   strlen ("three\r\ntwo\r\none\r\n"));
		soup_buffer_free (soup_message_body_flatten (msg->response_body));
		md5_body = msg->response_body;
		soup_message_set_status (msg, SOUP_STATUS_OK);
	} else if (msg->method == SOUP_METHOD_PUT) {
		soup_message_set_status (msg, SOUP_STATUS_CREATED);
		md5_body = msg->request_body;
	} else {
		soup_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED);
		return;
	}

	md5 = g_compute_checksum_for_data (G_CHECKSUM_MD5,
					   (guchar *)md5_body->data,
					   md5_body->length);
	soup_message_headers_append (msg->response_headers,
				     "Content-MD5", md5);
	g_free (md5);
}

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	SoupServer *server;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);

	loop = g_main_loop_new (NULL, TRUE);

	base_uri = soup_test_server_get_uri (server, "http", NULL);
	session = soup_test_session_new (SOUP_TYPE_SESSION_ASYNC, NULL);

	g_test_add_data_func ("/chunks/request/unstreamed", GINT_TO_POINTER (0), do_request_test);
	g_test_add_data_func ("/chunks/request/proper-streaming", GINT_TO_POINTER (PROPER_STREAMING), do_request_test);
	g_test_add_data_func ("/chunks/request/proper-streaming/restart", GINT_TO_POINTER (PROPER_STREAMING | RESTART), do_request_test);
	g_test_add_data_func ("/chunks/request/hacky-streaming", GINT_TO_POINTER (HACKY_STREAMING), do_request_test);
	g_test_add_data_func ("/chunks/request/hacky-streaming/restart", GINT_TO_POINTER (HACKY_STREAMING | RESTART), do_request_test);
	g_test_add_func ("/chunks/response", do_response_test);
	g_test_add_func ("/chunks/temporary", do_temporary_test);
	g_test_add_func ("/chunks/large", do_large_chunk_test);

	ret = g_test_run ();

	soup_test_session_abort_unref (session);

	soup_uri_free (base_uri);

	g_main_loop_unref (loop);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
