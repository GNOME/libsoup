/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
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

typedef struct {
	/* 
	 * Length remaining to be downloaded of the current chunk data. 
	 */
	guint  len;

	/* 
	 * Index into the recv buffer where this chunk's data begins.
	 * 0 if overwrite chunks is active.
	 */
	guint  idx;
} SoupTransferChunkState;

typedef struct {
	GIOChannel            *channel;
	guint                  read_tag;
	guint                  err_tag;

	/*
	 * If TRUE, a callback has been issed which references recv_buf.
	 * If the transfer is cancelled before a reference exists, the contents
	 * of recv_buf are free'd.
	 */
	gboolean               callback_issued;

	gboolean               processing;

	GByteArray            *recv_buf;
	guint                  header_len;

	gboolean               overwrite_chunks;
	guint                  content_length;

	/* 
	 * True if this is a chunked transfer 
	 */
	gboolean               is_chunked;
	SoupTransferChunkState chunk_state;

	SoupReadHeadersDoneFn  headers_done_cb;
	SoupReadChunkFn        read_chunk_cb;
	SoupReadDoneFn         read_done_cb;
	SoupReadErrorFn        error_cb;
	gpointer               user_data;
} SoupReader;

typedef struct {
	GIOChannel             *channel;
	guint                   write_tag;
	guint                   err_tag;

	gboolean                processing;

	const GString          *header;
	const SoupDataBuffer   *src;

	guint                   write_len;
	gboolean                headers_done;

	SoupWriteHeadersDoneFn  headers_done_cb;
	SoupWriteDoneFn         write_done_cb;
	SoupWriteErrorFn        error_cb;
	gpointer                user_data;
} SoupWriter;

#define IGNORE_CANCEL(t) (t)->processing = TRUE;
#define UNIGNORE_CANCEL(t) (t)->processing = FALSE;

void
soup_transfer_read_cancel (guint tag)
{
	SoupReader *r = GINT_TO_POINTER (tag);

	if (r->processing) return;

	g_source_remove (r->read_tag);
	g_source_remove (r->err_tag);

	g_byte_array_free (r->recv_buf, r->callback_issued ? FALSE : TRUE);

	g_free (r);
}

static gboolean
soup_transfer_read_error_cb (GIOChannel* iochannel,
			     GIOCondition condition,
			     SoupReader *r)
{
	gboolean body_started = r->recv_buf->len > r->header_len;

	/* 
	 * Some URIs signal end-of-file by closing the connection 
	 */
	if (body_started && !r->content_length && !r->is_chunked)
		return TRUE;

	IGNORE_CANCEL (r);
	if (r->error_cb) (*r->error_cb) (body_started, r->user_data);
	UNIGNORE_CANCEL (r);

	soup_transfer_read_cancel (GPOINTER_TO_INT (r));

	return FALSE;
}

static void
remove_block_at_index (GByteArray *arr, gint offset, gint length)
{
	gchar *data;

	g_return_if_fail (length != 0);
	g_assert (arr->len < offset + length);

	data = &arr->data [offset];

	g_memmove (data,
		   data + length,
		   arr->len - offset - length);

	g_byte_array_set_size (arr, arr->len - length);
}

static SoupTransferDone
issue_chunk_callback (SoupReader *r, gchar *data, gint len)
{
	SoupTransferDone cont = SOUP_TRANSFER_CONTINUE;

	/* 
	 * Null terminate 
	 */
	g_byte_array_append (r->recv_buf, "\0", 1);

	/* 
	 * Call chunk callback. Pass len worth of data. 
	 */
	if (r->read_chunk_cb && len) {
		SoupDataBuffer buf = { 
			SOUP_BUFFER_SYSTEM_OWNED, 
			data,
			len
		};

		r->callback_issued = TRUE;

		IGNORE_CANCEL (r);
		cont = (*r->read_chunk_cb) (&buf, r->user_data);
		UNIGNORE_CANCEL (r);
	}

	/* 
	 * Remove Null 
	 */
	g_byte_array_remove_index (r->recv_buf, r->recv_buf->len - 1);

	return cont;
}

/* 
 * Count number of hex digits, and convert to decimal. Store number of hex
 * digits read in @width.
 */
static gint
decode_hex (const gchar *src, gint *width)
{
	gint new_len = 0, j;

	*width = 0;

	while (isxdigit (*src)) {
		(*width)++;
		src++;
	}
	src -= *width;

	for (j = *width - 1; j + 1; j--) {
		if (isdigit (*src))
			new_len += (*src - 0x30) << (4*j);
		else
			new_len += (tolower (*src) - 0x57) << (4*j);
		src++;
	}

	return new_len;
}

static gboolean
decode_chunk (SoupTransferChunkState *s,
	      GByteArray             *arr,
	      gint                   *datalen) 
{
	gboolean ret = FALSE;

	*datalen = 0;

	while (TRUE) {
		gint new_len = 0;
		gint len = 0;
		gchar *i = &arr->data [s->idx + s->len];

		/*
		 * Not enough data to finish the chunk (and the smallest
		 * possible next chunk header), break 
		 */
		if (s->idx + s->len + 5 > arr->len)
			break;

		/* 
		 * Check for end of chunk header, otherwise break. Avoid
		 * trailing \r\n from previous chunk body if this is not the
		 * opening chunk.  
		 */
		if (s->len) {
			if (soup_substring_index (
					i + 2,
					arr->len - s->idx - s->len - 2,
					"\r\n") <= 0)
				break;
		} else if (soup_substring_index (arr->data,
						 arr->len, 
						 "\r\n") <= 0)
				break;

		/* 
		 * Remove trailing \r\n after previous chunk body 
		 */
		if (s->len)
			remove_block_at_index (arr, s->idx + s->len, 2);

		new_len = decode_hex (i, &len);
		g_assert (new_len >= 0);

		/* 
		 * Previous chunk is now processed, add its length to index and
		 * datalen.
		 */
		s->idx += s->len;
		*datalen += s->len;

		/* 
		 * Update length for next chunk's size 
		 */
		s->len = new_len;
		
	       	/* 
		 * FIXME: Add entity headers we find here to
		 *        req->response_headers. 
		 */
		len += soup_substring_index (&arr->data [s->idx + len],
				             arr->len - s->idx - len,
					     "\r\n");

		/* 
		 * Zero-length chunk closes transfer. Include final \r\n after
                 * empty chunk.
		 */
		if (s->len == 0) {
			len += 2;
			ret = TRUE;
		}

		/* 
		 * Remove hexified length, entity headers, and trailing \r\n 
		 */
		remove_block_at_index (arr, s->idx, len + 2);
	}

	return ret;
}

static gboolean
read_chunk (SoupReader *r, gboolean *cancelled)
{
	SoupTransferChunkState *s = &r->chunk_state;
	GByteArray *arr = r->recv_buf;
	gboolean ret;
	gint datalen;

	/* 
	 * Update datalen for any data read 
	 */
	ret = decode_chunk (&r->chunk_state, r->recv_buf, &datalen);

	if (!datalen) 
		goto CANCELLED;

	*cancelled = FALSE;
	if (issue_chunk_callback (r, 
				  arr->data, 
				  s->idx) == SOUP_TRANSFER_END) {
		*cancelled = TRUE;
		goto CANCELLED;
	}

	/* 
	 * If overwrite, remove datalen worth of data from start of buffer 
	 */
	if (r->overwrite_chunks) {
		remove_block_at_index (arr, 0, s->idx);

		s->idx = 0;
	}

 CANCELLED:
	return ret;
}

static gboolean
read_content_length (SoupReader *r, gboolean *cancelled)
{
	GByteArray *arr = r->recv_buf;

	*cancelled = FALSE;
	if (issue_chunk_callback (r, 
				  arr->data, 
				  arr->len) == SOUP_TRANSFER_END) {
		*cancelled = TRUE;
		goto CANCELLED;
	}

	/* 
	 * If overwrite, clear 
	 */
	if (r->overwrite_chunks) {
		r->content_length -= r->recv_buf->len;
		g_byte_array_set_size (arr, 0);
	}

 CANCELLED:
	return r->content_length == arr->len;
}

static gboolean
soup_transfer_read_cb (GIOChannel   *iochannel,
		       GIOCondition  condition,
		       SoupReader   *r)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gint bytes_read = 0, total_read = 0;
	gboolean read_done = FALSE;
	gboolean cancelled = FALSE;
	GIOError error;

 READ_AGAIN:
	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN) {
		if (total_read) goto PROCESS_READ;
		else return TRUE;
	}

	if (error != G_IO_ERROR_NONE) {
		if (total_read) goto PROCESS_READ;
		else {
			soup_transfer_read_error_cb (iochannel, G_IO_HUP, r);
			return FALSE;
		}
	}

	if (bytes_read) {
		g_byte_array_append (r->recv_buf, read_buf, bytes_read);
		total_read += bytes_read;
		goto READ_AGAIN;
	}

 PROCESS_READ:
	if (!r->header_len) {
		gint index = soup_substring_index (r->recv_buf->data,
						   r->recv_buf->len,
						   "\r\n\r\n");
		if (index < 0) return TRUE;

		index += 4;

		if (r->headers_done_cb) {
			GString str;
			SoupTransferDone ret;
			gint len = 0;

			str.len = index;
			str.str = alloca (index);

			strncpy (str.str, r->recv_buf->data, index);

			IGNORE_CANCEL (r);
			ret = (*r->headers_done_cb) (&str, &len, r->user_data);
			UNIGNORE_CANCEL (r);

			if (ret == SOUP_TRANSFER_END) 
				goto FINISH_READ;

			if (len == -1) 
				r->is_chunked = TRUE;
			else 
				r->content_length = len;
		}

		remove_block_at_index (r->recv_buf, 0, index);

		r->header_len = index;
	}

	if (total_read == 0)
		read_done = TRUE;
	else if (r->is_chunked)
		read_done = read_chunk (r, &cancelled);
	else
		read_done = read_content_length (r, &cancelled);

	if (cancelled) 
		goto FINISH_READ;

	if (!read_done) {
		total_read = 0;
		goto READ_AGAIN;
	}

	if (r->read_done_cb) {
		SoupDataBuffer buf = {
			SOUP_BUFFER_SYSTEM_OWNED,
			r->recv_buf->data,
			r->recv_buf->len
		};

		g_byte_array_append (r->recv_buf, "\0", 1);

		r->callback_issued = TRUE;

		IGNORE_CANCEL (r);
		(*r->read_done_cb) (&buf, r->user_data);
		UNIGNORE_CANCEL (r);
	}

 FINISH_READ:
	soup_transfer_read_cancel (GPOINTER_TO_INT (r));

	return FALSE;
}

guint
soup_transfer_read (GIOChannel            *chan,
		    gboolean               overwrite_chunks,
		    SoupReadHeadersDoneFn  headers_done_cb,
		    SoupReadChunkFn        read_chunk_cb,
		    SoupReadDoneFn         read_done_cb,
		    SoupReadErrorFn        error_cb,
		    gpointer               user_data)
{
	SoupReader *reader;

	reader = g_new0 (SoupReader, 1);
	reader->channel = chan;
	reader->overwrite_chunks = overwrite_chunks;
	reader->headers_done_cb = headers_done_cb;
	reader->read_chunk_cb = read_chunk_cb;
	reader->read_done_cb = read_done_cb;
	reader->error_cb = error_cb;
	reader->user_data = user_data;
	reader->recv_buf = g_byte_array_new ();

	reader->read_tag =
		g_io_add_watch (chan,
				G_IO_IN,
				(GIOFunc) soup_transfer_read_cb,
				reader);

	reader->err_tag =
		g_io_add_watch (chan,
				G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) soup_transfer_read_error_cb,
				reader);

	return GPOINTER_TO_INT (reader);
}

void
soup_transfer_write_cancel (guint tag)
{
	SoupWriter *w = GINT_TO_POINTER (tag);

	if (w->processing) return;

	g_source_remove (w->write_tag);
	g_source_remove (w->err_tag);

	g_free (w);
}

static gboolean
soup_transfer_write_error_cb (GIOChannel* iochannel,
			      GIOCondition condition,
			      SoupWriter *w)
{
	gboolean body_started = w->write_len > (guint) w->header->len;

	if (w->error_cb) {
		IGNORE_CANCEL (w);
		(*w->error_cb) (body_started, w->user_data);
		UNIGNORE_CANCEL (w);
	}

	soup_transfer_write_cancel (GPOINTER_TO_INT (w));

	return FALSE;
}

static gboolean
soup_transfer_write_cb (GIOChannel* iochannel,
			GIOCondition condition,
			SoupWriter *w)
{
	guint head_len, body_len, total_len, total_written, bytes_written;
	GIOError error;
	gchar *write_buf;
	guint  write_len;
	void *pipe_handler;

	head_len = w->header->len;
	body_len = w->src->length;
	total_len = head_len + body_len;
	total_written = w->write_len;

#ifdef SIGPIPE
	pipe_handler = signal (SIGPIPE, SIG_IGN);
#endif
	errno = 0;

 WRITE_AGAIN:
	if (total_written < head_len) {
		/* 
		 * Send remaining headers 
		 */
		write_buf = &w->header->str [total_written];
		write_len = head_len - total_written;
	} else {
		/* 
		 * Send rest of body 
		 */
		guint offset = total_written - head_len;
		write_buf = &w->src->body [offset];
		write_len = body_len - offset;

		if (!w->headers_done) {
			if (w->headers_done_cb) {
				IGNORE_CANCEL (w);
				(*w->headers_done_cb) (w->user_data);
				UNIGNORE_CANCEL (w);
			}
			w->headers_done = TRUE;
		}
	}

	error = g_io_channel_write (iochannel,
				    write_buf,
				    write_len,
				    &bytes_written);

	if (error == G_IO_ERROR_AGAIN) {
#ifdef SIGPIPE
		signal (SIGPIPE, pipe_handler);
#endif
		return TRUE;
	}

	if (errno != 0 || error != G_IO_ERROR_NONE) {
		soup_transfer_write_error_cb (iochannel, G_IO_HUP, w);
		goto DONE_WRITING;
	}

	total_written = (w->write_len += bytes_written);

	if (total_written != total_len)
		goto WRITE_AGAIN;

	if (w->write_done_cb) {
		IGNORE_CANCEL (w);
		(*w->write_done_cb) (w->user_data);
		UNIGNORE_CANCEL (w);
	}

	soup_transfer_write_cancel (GPOINTER_TO_INT (w));

 DONE_WRITING:

#ifdef SIGPIPE
	signal (SIGPIPE, pipe_handler);
#endif

	return FALSE;
}

guint
soup_transfer_write (GIOChannel             *chan,
		     const GString          *header,
		     const SoupDataBuffer   *src,
		     SoupWriteHeadersDoneFn  headers_done_cb,
		     SoupWriteDoneFn         write_done_cb,
		     SoupWriteErrorFn        error_cb,
		     gpointer                user_data)
{
	SoupWriter *writer;

	writer = g_new0 (SoupWriter, 1);
	writer->channel = chan;
	writer->header = header;
	writer->src = src;
	writer->headers_done_cb = headers_done_cb;
	writer->write_done_cb = write_done_cb;
	writer->error_cb = error_cb;
	writer->user_data = user_data;

	writer->write_tag =
		g_io_add_watch (chan,
				G_IO_OUT,
				(GIOFunc) soup_transfer_write_cb,
				writer);

	writer->err_tag =
		g_io_add_watch (chan,
				G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) soup_transfer_write_error_cb,
				writer);

	return GPOINTER_TO_INT (writer);
}
