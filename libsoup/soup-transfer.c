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
	GIOChannel            *channel;
	guint                  read_tag;
	guint                  err_tag;

	/* 
	 * If TRUE, a callback has been issed which references recv_buf.  
	 * If the tranfer is cancelled before a reference exists, the contents
	 * of recv_buf are free'd.
	 */
	gboolean               callback_issued;

	GByteArray            *recv_buf;
	guint                  header_len;

	gboolean               overwrite_chunks;
	guint                  content_length;
	gboolean               is_chunked;
	guint                  cur_chunk_len;
	guint                  cur_chunk_idx;

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

	const GString          *header;
	const SoupDataBuffer   *src;

	guint                   write_len;
	gboolean                headers_done;

	SoupWriteHeadersDoneFn  headers_done_cb;
	SoupWriteDoneFn         write_done_cb;
	SoupWriteErrorFn        error_cb;
	gpointer                user_data;
} SoupWriter;

#define source_remove(_src) \
        ({ if ((_src)) { g_source_remove ((_src)); (_src) = 0; }})

void
soup_transfer_read_cancel (guint tag)
{
	SoupReader *r = GINT_TO_POINTER (tag);

	source_remove (r->read_tag);
	source_remove (r->err_tag);

	g_byte_array_free (r->recv_buf, r->callback_issued ? FALSE : TRUE);

	g_free (r);
}

static gboolean 
soup_transfer_read_error_cb (GIOChannel* iochannel, 
			     GIOCondition condition, 
			     SoupReader *r)
{
	gboolean body_started = r->recv_buf->len > r->header_len;

	if (r->error_cb) (*r->error_cb) (body_started, r->user_data);

	soup_transfer_read_cancel (GPOINTER_TO_INT (r));

	return FALSE;
}

static gboolean 
soup_transfer_read_chunk (SoupReader *r) 
{
	guint chunk_idx = r->cur_chunk_idx;
	gint chunk_len = r->cur_chunk_len;
	GByteArray *arr = r->recv_buf;

	while (chunk_idx + chunk_len + 5 <= arr->len) {
		gint new_len = 0;
		gint len = 0, j;
		gchar *i = &arr->data [chunk_idx + chunk_len];

		/* remove \r\n after previous chunk body */
		if (chunk_len) {
			g_memmove (i, 
				   i + 2, 
				   arr->len - chunk_idx - chunk_len - 2);
			g_byte_array_set_size (arr, arr->len - 2);
		}

		/* Convert the size of the next chunk from hex */
		while ((tolower (*i) >= 'a' && tolower (*i) <= 'f') ||
		       (*i >= '0' && *i <= '9'))
			len++, i++;
		
		for (i -= len, j = len - 1; j + 1; i++, j--)
			new_len += (*i > '9') ? 
				(tolower (*i) - 0x57) << (4*j) :
				(tolower (*i) - 0x30) << (4*j);

		chunk_idx = chunk_idx + chunk_len;
		chunk_len = new_len;

		if (chunk_len == 0) {
			/* FIXME: Add entity headers we find here to
			          req->response_headers. */
			len += soup_substring_index (&arr->data [chunk_idx + 3],
						     arr->len - chunk_idx - 3,
						     "\r\n");
			len += 2;
		}

		/* trailing \r\n after chunk length */
		g_memmove (&arr->data [chunk_idx], 
			   &arr->data [chunk_idx + len + 2],
			   arr->len - chunk_idx - len - 2);
		g_byte_array_set_size (arr, arr->len - len - 2);

		/* zero-length chunk closes transfer */
		if (chunk_len == 0) return TRUE;
	}

	r->cur_chunk_len = chunk_len;
	r->cur_chunk_idx = chunk_idx;

	return FALSE;
}

static gboolean 
soup_transfer_read_cb (GIOChannel   *iochannel, 
		       GIOCondition  condition, 
		       SoupReader   *r)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gint bytes_read = 0;
	gboolean read_done = FALSE;
	GIOError error;
	SoupDataBuffer buf;

	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;

	if (error != G_IO_ERROR_NONE) {
		soup_transfer_read_error_cb (iochannel, G_IO_HUP, r);
		return FALSE;
	}

	if (r->header_len && r->overwrite_chunks) {
		r->cur_chunk_len -= r->recv_buf->len - r->cur_chunk_idx;
		r->cur_chunk_idx = 0;
		r->content_length -= r->recv_buf->len;
		g_byte_array_set_size (r->recv_buf, 0);
	}

	if (bytes_read) 
		g_byte_array_append (r->recv_buf, read_buf, bytes_read);

	if (!r->header_len) {
		gint index = soup_substring_index (r->recv_buf->data, 
						   r->recv_buf->len, 
						   "\r\n\r\n");
		if (index < 0) return TRUE;

		index += 4;

		if (r->headers_done_cb) {
			GString str;
			gint len;
			SoupTransferDone ret;

			str.str = g_strndup (r->recv_buf->data, index);;
			str.len = index;

			ret = (*r->headers_done_cb) (&str, &len, r->user_data);

			g_free (str.str);

			if (!ret) goto FINISH_READ;

			if (len == -1) r->is_chunked = TRUE;
			else r->content_length = len;
		}

		g_memmove (r->recv_buf->data, 
			   &r->recv_buf->data [index], 
			   r->recv_buf->len - index);
		g_byte_array_set_size (r->recv_buf, r->recv_buf->len - index);

		r->header_len = index;
	}

	/* Allow the chunk parser to strip the data stream */
	if (bytes_read == 0) 
		read_done = TRUE;
	else if (r->is_chunked) 
		read_done = soup_transfer_read_chunk (r);
	else if (r->content_length == r->recv_buf->len) 
		read_done = TRUE;

	/* Don't call chunk handlers if we didn't actually read anything */
	if (r->read_chunk_cb && bytes_read != 0) {
		gboolean cont;

		g_byte_array_append (r->recv_buf, "\0", 1);

		buf.owner = SOUP_BUFFER_SYSTEM_OWNED;
		buf.length = r->recv_buf->len - 1;
		buf.body = r->recv_buf->data;

		r->callback_issued = TRUE;

		cont = (*r->read_chunk_cb) (&buf, r->user_data);

		g_byte_array_remove_index (r->recv_buf, r->recv_buf->len - 1);

		if (!cont) goto FINISH_READ;
	}

	if (!read_done) return TRUE;

	if (r->read_done_cb) {
		g_byte_array_append (r->recv_buf, "\0", 1);

		buf.owner = SOUP_BUFFER_SYSTEM_OWNED;
		buf.length = r->recv_buf->len - 1;
		buf.body = r->recv_buf->data;

		r->callback_issued = TRUE;

		(*r->read_done_cb) (&buf, r->user_data);
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

	source_remove (w->write_tag);
	source_remove (w->err_tag);

	//g_io_channel_unref (w->channel);
	g_free (w);
}

static gboolean 
soup_transfer_write_error_cb (GIOChannel* iochannel, 
			      GIOCondition condition, 
			      SoupWriter *w)
{
	gboolean body_started = w->write_len > w->header->len;

	if (w->error_cb) (*w->error_cb) (body_started, w->user_data);

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

	pipe_handler = signal (SIGPIPE, SIG_IGN);
	errno = 0;

 WRITE_SOME_MORE:
	if (total_written < head_len) {
		/* send rest of headers */
		write_buf = &w->header->str [total_written];
		write_len = head_len - total_written;
	} else {
		/* send rest of body */
		guint offset = total_written - head_len;
		write_buf = &w->src->body [offset];
		write_len = body_len - offset;

		if (!w->headers_done) {
			if (w->headers_done_cb) 
				(*w->headers_done_cb) (w->user_data);
			w->headers_done = TRUE;
		}
	}

	error = g_io_channel_write (iochannel, 
				    write_buf, 
				    write_len, 
				    &bytes_written);

	if (error == G_IO_ERROR_AGAIN) {
		signal (SIGPIPE, pipe_handler);
		return TRUE;
	}

	if (errno != 0 || error != G_IO_ERROR_NONE) {
		soup_transfer_write_error_cb (iochannel, G_IO_HUP, w);
		goto DONE_WRITING;
	}

	total_written = (w->write_len += bytes_written);

	if (total_written != total_len) 
		goto WRITE_SOME_MORE;

	if (w->write_done_cb) (*w->write_done_cb) (w->user_data);
	soup_transfer_write_cancel (GPOINTER_TO_INT (w));

 DONE_WRITING:
	signal (SIGPIPE, pipe_handler);
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
