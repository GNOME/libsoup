/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "soup-transfer.h"
#include "soup-private.h"

typedef enum {
	SOUP_READER_STATE_HEADERS,
	SOUP_READER_STATE_READ_TO_EOF,
	SOUP_READER_STATE_CONTENT_LENGTH,
	SOUP_READER_STATE_CHUNK_SIZE,
	SOUP_READER_STATE_CHUNK,
	SOUP_READER_STATE_BETWEEN_CHUNKS,
	SOUP_READER_STATE_TRAILERS
} SoupReaderState;

struct _SoupReader {
        int                    ref_count;

	SoupSocket            *sock;
	guint                  idle_tag;
	guint                  read_tag;
	guint                  err_tag;

	SoupReaderState        state;
	GByteArray            *body_buf;
	GByteArray            *meta_buf;

	SoupTransferEncoding   encoding;
	guint                  read_length;

	SoupReadHeadersDoneFn  headers_done_cb;
	SoupReadChunkFn        read_chunk_cb;
	SoupReadDoneFn         read_done_cb;
	SoupReadErrorFn        error_cb;
	gpointer               user_data;
};

/* Stops reading and releases soup-transfer's ref. */
static void
soup_transfer_read_stop (SoupReader *r)
{
	if (!r->err_tag)
		return;

	g_signal_handler_disconnect (r->sock, r->read_tag);
	r->read_tag = 0;
	g_signal_handler_disconnect (r->sock, r->err_tag);
	r->err_tag = 0;

	if (r->idle_tag) {
		g_source_remove (r->idle_tag);
		r->idle_tag = 0;
	}

	soup_transfer_read_unref (r);
}

void
soup_transfer_read_ref (SoupReader *r)
{
	r->ref_count++;
}

gboolean
soup_transfer_read_unref (SoupReader *r)
{
	r->ref_count--;
	if (r->ref_count)
		return TRUE;

	soup_transfer_read_stop (r);
	if (r->body_buf)
		g_byte_array_free (r->body_buf, TRUE);
	if (r->meta_buf)
		g_byte_array_free (r->meta_buf, TRUE);
	g_object_unref (r->sock);
	g_free (r);
	return FALSE;
}

void
soup_transfer_read_cancel (SoupReader *r)
{
	soup_transfer_read_stop (r);
	soup_transfer_read_unref (r);
}

void 
soup_transfer_read_set_callbacks (SoupReader             *r,
				  SoupReadHeadersDoneFn   headers_done_cb,
				  SoupReadChunkFn         read_chunk_cb,
				  SoupReadDoneFn          read_done_cb,
				  SoupReadErrorFn         error_cb,
				  gpointer                user_data)
{
	g_assert (read_done_cb && error_cb);

	r->headers_done_cb = headers_done_cb;
	r->read_chunk_cb = read_chunk_cb;
	r->read_done_cb = read_done_cb;
	r->error_cb = error_cb;

	r->user_data = user_data;
}

static void
issue_final_callback (SoupReader *r)
{
	char *body;
	guint len;

	if (r->body_buf) {
		/* 
		 * Null terminate. FIXME
		 */
		g_byte_array_append (r->body_buf, "\0", 1);

		body = r->body_buf->data;
		len = r->body_buf->len - 1;
		g_byte_array_free (r->body_buf, FALSE);
		r->body_buf = NULL;
	} else {
		body = NULL;
		len = 0;
	}

	soup_transfer_read_ref (r);
	soup_transfer_read_stop (r);

	(*r->read_done_cb) (body, len, r->user_data);
	soup_transfer_read_unref (r);
}

static void
reader_disconnected (SoupSocket *sock, SoupReader *r)
{
	soup_transfer_read_ref (r);
	soup_transfer_read_stop (r);

	/*
	 * Closing the connection to signify EOF is valid if content length is
	 * unknown, but only if headers have been sent.
	 */
	if (r->state == SOUP_READER_STATE_READ_TO_EOF)
		issue_final_callback (r);
	else {
		(*r->error_cb) (r->state > SOUP_READER_STATE_HEADERS,
				r->user_data);
	}

	soup_transfer_read_unref (r);
}

static gboolean
soup_reader_read_metadata (SoupReader *r, const char *boundary, int boundary_len)
{
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint nread;
	gboolean done;

	do {
		status = soup_socket_read_until (r->sock, read_buf,
						 sizeof (read_buf),
						 boundary, boundary_len,
						 &nread, &done);
		switch (status) {
		case SOUP_SOCKET_OK:
			g_byte_array_append (r->meta_buf, read_buf, nread);
			break;

		case SOUP_SOCKET_ERROR:
		case SOUP_SOCKET_EOF:
			reader_disconnected (r->sock, r);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;
		}
	} while (!done);

	return TRUE;
}

static gboolean
soup_reader_read_body_chunk (SoupReader *r, guint *size)
{
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint nread, len = sizeof (read_buf);

	while (!size || *size > 0) {
		if (size)
			len = MIN (len, *size);

		status = soup_socket_read (r->sock, read_buf, len, &nread);

		switch (status) {
		case SOUP_SOCKET_OK:
			if (!nread)
				break;

			if (r->read_chunk_cb) {
				r->read_chunk_cb (read_buf, nread,
						  r->user_data);
			}
			if (r->body_buf)
				g_byte_array_append (r->body_buf, read_buf, nread);
			if (size)
				*size -= nread;
			break;

		case SOUP_SOCKET_EOF:
			if (!size)
				return TRUE;
			/* else fall through */

		case SOUP_SOCKET_ERROR:
			reader_disconnected (r->sock, r);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;
		}
	}

	return TRUE;
}

#define SOUP_TRANSFER_EOL     "\r\n"
#define SOUP_TRANSFER_EOL_LEN 2

#define SOUP_TRANSFER_DOUBLE_EOL     "\r\n\r\n"
#define SOUP_TRANSFER_DOUBLE_EOL_LEN 4

static void
reader_read (SoupSocket *sock, SoupReader *r)
{
	soup_transfer_read_ref (r);

	while (1) {
		switch (r->state) {
		case SOUP_READER_STATE_HEADERS:
			if (!soup_reader_read_metadata (
				    r, SOUP_TRANSFER_DOUBLE_EOL,
				    SOUP_TRANSFER_DOUBLE_EOL_LEN))
				goto out;

			r->meta_buf->len -= SOUP_TRANSFER_DOUBLE_EOL_LEN;
			if (r->headers_done_cb) {
				(*r->headers_done_cb) (r->meta_buf->data,
						       r->meta_buf->len,
						       &r->encoding, 
						       &r->read_length, 
						       r->user_data);
			}
			g_byte_array_set_size (r->meta_buf, 0);

			switch (r->encoding) {
			case SOUP_TRANSFER_UNKNOWN:
				r->state = SOUP_READER_STATE_READ_TO_EOF;
				break;
			case SOUP_TRANSFER_CONTENT_LENGTH:
				r->state = SOUP_READER_STATE_CONTENT_LENGTH;
				break;
			case SOUP_TRANSFER_CHUNKED:
				r->state = SOUP_READER_STATE_CHUNK_SIZE;
				break;
			}
			break;

		case SOUP_READER_STATE_READ_TO_EOF:
			if (!soup_reader_read_body_chunk (r, NULL))
				goto out;

			goto done;
			break;

		case SOUP_READER_STATE_CONTENT_LENGTH:
			if (!soup_reader_read_body_chunk (r, &r->read_length))
				goto out;

			goto done;
			break;

		case SOUP_READER_STATE_CHUNK_SIZE:
			if (!soup_reader_read_metadata (r, SOUP_TRANSFER_EOL,
							SOUP_TRANSFER_EOL_LEN))
				goto out;

			r->read_length = strtoul (r->meta_buf->data, NULL, 16);
			g_byte_array_set_size (r->meta_buf, 0);

			if (r->read_length > 0)
				r->state = SOUP_READER_STATE_CHUNK;
			else
				r->state = SOUP_READER_STATE_TRAILERS;
			break;

		case SOUP_READER_STATE_CHUNK:
			if (!soup_reader_read_body_chunk (r, &r->read_length))
				goto out;

			r->state = SOUP_READER_STATE_BETWEEN_CHUNKS;
			break;

		case SOUP_READER_STATE_BETWEEN_CHUNKS:
			if (!soup_reader_read_metadata (r, SOUP_TRANSFER_EOL,
							SOUP_TRANSFER_EOL_LEN))
				goto out;

			g_byte_array_set_size (r->meta_buf, 0);
			r->state = SOUP_READER_STATE_CHUNK_SIZE;
			break;

		case SOUP_READER_STATE_TRAILERS:
			if (!soup_reader_read_metadata (r, SOUP_TRANSFER_EOL,
							SOUP_TRANSFER_EOL_LEN))
				goto out;

			if (r->meta_buf->len == SOUP_TRANSFER_EOL_LEN)
				goto done;

			/* FIXME: process trailers */
			g_byte_array_set_size (r->meta_buf, 0);
			break;

		}
	}

 done:
	issue_final_callback (r);

 out:
	soup_transfer_read_unref (r);
}

static gboolean
idle_read (gpointer user_data)
{
	SoupReader *r = user_data;

	r->idle_tag = 0;
	reader_read (r->sock, r);
	return FALSE;
}

/**
 * soup_transfer_read:
 * @chan: the iochannel to read from
 * @overwrite_chunks: if %TRUE, body chunks will not be preserved after
 * chunk callbacks.
 * @headers_done_cb: (optional) callback to call after headers have
 * been read.
 * @read_chunk_cb: (optional) callback to call as body data is being read
 * @read_done_cb: (mandatory) callback to call when the body has been
 * completely read
 * @error_cb: (mandatory) callback to call when an error occurs
 * @user_data: data to pass to the callbacks.
 *
 * Attempts to read a single HTTP message from @chan.
 *
 * Unless the caller calls soup_transfer_read_cancel(), either
 * @read_done_cb or @read_error_cb will eventually be called.
 *
 * Return value: a #SoupReader, which must eventually be freed by
 * calling either soup_transfer_read_unref() or
 * soup_transfer_read_cancel().
 **/
SoupReader *
soup_transfer_read (SoupSocket            *sock,
		    gboolean               overwrite_chunks,
		    SoupReadHeadersDoneFn  headers_done_cb,
		    SoupReadChunkFn        read_chunk_cb,
		    SoupReadDoneFn         read_done_cb,
		    SoupReadErrorFn        error_cb,
		    gpointer               user_data)
{
	SoupReader *reader;

	g_assert (read_done_cb && error_cb);

	reader = g_new0 (SoupReader, 1);
	reader->sock = g_object_ref (sock);
	reader->headers_done_cb = headers_done_cb;
	reader->read_chunk_cb = read_chunk_cb;
	reader->read_done_cb = read_done_cb;
	reader->error_cb = error_cb;
	reader->user_data = user_data;
	reader->encoding = SOUP_TRANSFER_UNKNOWN;

	reader->meta_buf = g_byte_array_new ();
	if (!overwrite_chunks)
		reader->body_buf = g_byte_array_new ();

	reader->read_tag =
		g_signal_connect (sock, "readable",
				  G_CALLBACK (reader_read), reader);

	reader->err_tag =
		g_signal_connect (sock, "disconnected",
				  G_CALLBACK (reader_disconnected), reader);

	reader->idle_tag = g_idle_add (idle_read, reader);

	/* Initial ref_count is 2: one reference owned by
	 * soup-transfer and one by the caller.
	 */
	reader->ref_count = 2;

	return reader;
}


struct _SoupWriter {
        int                     ref_count;

	SoupSocket             *sock;
	guint                   idle_tag;
	guint                   write_tag;
	guint                   err_tag;

	SoupTransferEncoding    encoding;
	GByteArray             *write_buf;

	gboolean                headers_done;
	int                     chunk_cnt;

	SoupWriteGetHeaderFn    get_header_cb;
	SoupWriteGetChunkFn     get_chunk_cb;
	SoupWriteDoneFn         write_done_cb;
	SoupWriteErrorFn        error_cb;
	gpointer                user_data;
};

static void
soup_transfer_write_stop (SoupWriter *w)
{
	if (!w->err_tag)
		return;

	g_signal_handler_disconnect (w->sock, w->err_tag);
	w->err_tag = 0;

	if (w->write_tag) {
		g_signal_handler_disconnect (w->sock, w->write_tag);
		w->write_tag = 0;
	}

	if (w->idle_tag) {
		g_source_remove (w->idle_tag);
		w->idle_tag = 0;
	}

	/* Give up soup-transfer's ref */
	soup_transfer_write_unref (w);
}

void
soup_transfer_write_ref (SoupWriter *w)
{
	w->ref_count++;
}

gboolean
soup_transfer_write_unref (SoupWriter *w)
{
	w->ref_count--;
	if (w->ref_count)
		return TRUE;

	soup_transfer_write_stop (w);
	g_byte_array_free (w->write_buf, TRUE);
	g_object_unref (w->sock);
	g_free (w);
	return FALSE;
}

void
soup_transfer_write_cancel (SoupWriter *w)
{
	soup_transfer_write_stop (w);
	soup_transfer_write_unref (w);
}

static void
writer_disconnected (SoupSocket *sock, SoupWriter *w)
{
	soup_transfer_write_stop (w);
	(*w->error_cb) (w->headers_done, w->user_data);
}

static gboolean 
get_header (SoupWriter *w)
{
	GString *header = NULL;

	(*w->get_header_cb) (&header, w->user_data);

	if (!header)
		return FALSE;

	g_byte_array_append (w->write_buf, header->str, header->len);
	g_string_free (header, TRUE);

	w->get_header_cb = NULL;
	return TRUE;
}

static void
write_chunk_sep (GByteArray *arr, gint len, gint chunk_cnt)
{
	gchar *hex;
	gchar *end = "0\r\n\r\n";

	/*
	 * Only prefix the chunk length with a \r\n if its not the first chunk
	 */
	if (chunk_cnt)
		g_byte_array_append (arr, "\r\n", 2);

	if (len) {
		hex = g_strdup_printf ("%x\r\n", len);
		g_byte_array_append (arr, hex, strlen (hex));
		g_free (hex);
	} else
		g_byte_array_append (arr, end, strlen (end));
}

static void
get_next_chunk (SoupWriter *w)
{
	SoupTransferStatus ret = SOUP_TRANSFER_END;
	SoupDataBuffer buf = { 0 , NULL, 0 };

	ret = (*w->get_chunk_cb) (&buf, w->user_data);

	if (buf.length) {
		if (w->encoding == SOUP_TRANSFER_CHUNKED)
			write_chunk_sep (w->write_buf, 
					 buf.length, 
					 w->chunk_cnt++);

		g_byte_array_append (w->write_buf, buf.body, buf.length);

		if (buf.owner == SOUP_BUFFER_SYSTEM_OWNED)
			g_free (buf.body);
	}

	if (ret == SOUP_TRANSFER_END) {
		if (w->encoding == SOUP_TRANSFER_CHUNKED)
			write_chunk_sep (w->write_buf, 0, w->chunk_cnt);

		w->get_chunk_cb = NULL;
	}
}

static void
writer_write (SoupSocket *sock, SoupWriter *w)
{
	SoupSocketIOStatus status;
	guint bytes_written = 0;

	/* Get the header and first data chunk (if available). */
	if (w->get_header_cb) {
		soup_transfer_write_ref (w);

		if (!get_header (w)) {
			soup_transfer_write_unref (w);
			return;
		}

		if (w->get_chunk_cb)
			get_next_chunk (w);

		if (!soup_transfer_write_unref (w))
			return;
	}

 WRITE_AGAIN:
	while (w->write_buf->len) {
		status = soup_socket_write (sock, w->write_buf->data,
					    w->write_buf->len, &bytes_written);

		switch (status) {
		case SOUP_SOCKET_EOF:
		case SOUP_SOCKET_ERROR:
			writer_disconnected (sock, w);
			return;

		case SOUP_SOCKET_WOULD_BLOCK:
			return;

		case SOUP_SOCKET_OK:
			memmove (w->write_buf->data,
				 w->write_buf->data + bytes_written,
				 w->write_buf->len - bytes_written);
			g_byte_array_set_size (w->write_buf,
					       w->write_buf->len - bytes_written);
			break;
		}
	}

	/* When we exit the above block, we are certain that the headers have
	 * been written.  
	 */
	w->headers_done = TRUE;

	/* Get the next data chunk and try again, or quit if paused. */
	if (w->get_chunk_cb) {
		soup_transfer_write_ref (w);
		get_next_chunk (w);
		if (!soup_transfer_write_unref (w))
			return;

		if (!w->write_tag)
			return;

		goto WRITE_AGAIN;
	}

	soup_transfer_write_ref (w);
	soup_transfer_write_stop (w);
	(*w->write_done_cb) (w->user_data);
	soup_transfer_write_unref (w);
}

static gboolean
idle_write (gpointer user_data)
{
	SoupWriter *w = user_data;

	w->idle_tag = 0;
	writer_write (w->sock, w);
	return FALSE;
}

static SoupWriter *
create_writer (SoupSocket             *sock,
	       SoupTransferEncoding    encoding,
	       SoupWriteDoneFn         write_done_cb,
	       SoupWriteErrorFn        error_cb,
	       gpointer                user_data)
{
	SoupWriter *writer;

	g_assert (write_done_cb && error_cb);

	writer = g_new0 (SoupWriter, 1);
	writer->sock          = g_object_ref (sock);
	writer->encoding      = encoding;
	writer->write_buf     = g_byte_array_new ();
	writer->write_done_cb = write_done_cb;
	writer->error_cb      = error_cb;
	writer->user_data     = user_data;

	writer->write_tag =
		g_signal_connect (sock, "writable",
				  G_CALLBACK (writer_write), writer);

	writer->err_tag =
		g_signal_connect (sock, "disconnected",
				  G_CALLBACK (writer_disconnected), writer);

	writer->idle_tag = g_idle_add (idle_write, writer);

	/* As with SoupReader, one reference is owned by soup-transfer
	 * and one by the caller.
	 */
	writer->ref_count = 2;

	return writer;
}

/**
 * soup_transfer_write_simple:
 * @sock: the socket to write to
 * @header: message headers (including trailing blank line)
 * @src: buffer to write
 * @write_done_cb: (mandatory) callback to call when the body has been
 * completely written
 * @error_cb: (mandatory) callback to call when an error occurs
 * @user_data: data to pass to the callbacks.
 *
 * Attempts to write a single HTTP message to @sock using identity
 * encoding and Content-Length.
 *
 * Unless the caller calls soup_transfer_write_cancel(), either
 * @write_done_cb or @write_error_cb will eventually be called.
 *
 * Return value: a #SoupWriter, which must eventually be freed by
 * calling either soup_transfer_write_unref() or
 * soup_transfer_write_cancel().
 **/
SoupWriter *
soup_transfer_write_simple (SoupSocket             *sock,
			    GString                *header,
			    const SoupDataBuffer   *src,
			    SoupWriteDoneFn         write_done_cb,
			    SoupWriteErrorFn        error_cb,
			    gpointer                user_data)
{
	SoupWriter *writer;

	writer = create_writer (sock,
				SOUP_TRANSFER_CONTENT_LENGTH,
				write_done_cb,
				error_cb,
				user_data);

	if (header) {
		g_byte_array_append (writer->write_buf, 
				     header->str, 
				     header->len);
		g_string_free (header, TRUE);
	}

	if (src && src->length)
		g_byte_array_append (writer->write_buf, 
				     src->body, 
				     src->length);

	return writer;
}

/**
 * soup_transfer_write:
 * @sock: the socket to write to
 * @encoding: HTTP encoding mechanism to use.
 * @get_header_cb: (mandatory) callback to call to get message headers
 * @get_chunk_cb: (optional) callback to call to get body chunks
 * @write_done_cb: (mandatory) callback to call when the body has been
 * completely written
 * @error_cb: (mandatory) callback to call when an error occurs
 * @user_data: data to pass to the callbacks.
 *
 * Attempts to write a single HTTP message to @sock using @encoding.
 *
 * Unless the caller calls soup_transfer_write_cancel(), either
 * @write_done_cb or @write_error_cb will eventually be called.
 *
 * Return value: a #SoupWriter, which must eventually be freed by
 * calling either soup_transfer_write_unref() or
 * soup_transfer_write_cancel().
 **/
SoupWriter *
soup_transfer_write (SoupSocket             *sock,
		     SoupTransferEncoding    encoding,
		     SoupWriteGetHeaderFn    get_header_cb,
		     SoupWriteGetChunkFn     get_chunk_cb,
		     SoupWriteDoneFn         write_done_cb,
		     SoupWriteErrorFn        error_cb,
		     gpointer                user_data)
{
	SoupWriter *writer;

	writer = create_writer (sock,
				encoding,
				write_done_cb,
				error_cb,
				user_data);

	writer->get_header_cb = get_header_cb;
	writer->get_chunk_cb = get_chunk_cb;

	return writer;
}

void  
soup_transfer_write_pause (SoupWriter *w)
{
	g_return_if_fail (w != NULL);

	if (w->write_tag) {
		g_signal_handler_disconnect (w->sock, w->write_tag);
		w->write_tag = 0;
	}
	if (w->idle_tag) {
		g_source_remove (w->idle_tag);
		w->idle_tag = 0;
	}
}

void  
soup_transfer_write_unpause (SoupWriter *w)
{
	g_return_if_fail (w != NULL);

	if (!w->write_tag) {
		w->write_tag =
			g_signal_connect (w->sock, "writable",
					  G_CALLBACK (writer_write), w);
	}
	if (!w->idle_tag)
		w->idle_tag = g_idle_add (idle_write, w);
}
