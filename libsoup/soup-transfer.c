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

#undef DUMP

#ifdef DUMP
static void
DUMP_READ (guchar *data, gint bytes_read) 
{
	gchar *buf = alloca (bytes_read + 1);
	memcpy (buf, data, bytes_read);
	buf[bytes_read] = '\0';
	
	g_warning ("READ %d\n----------\n%s\n----------\n", bytes_read, buf);
}
static void
DUMP_WRITE (guchar *data, gint bytes_written) 
{
	gchar *buf = alloca (bytes_written + 1);
	memcpy (buf, data, bytes_written);
	buf[bytes_written] = '\0';

	g_warning ("WRITE %d\n----------\n%s\n----------\n", bytes_written,buf);
}
#else
#  define DUMP_READ(x,y)
#  define DUMP_WRITE(x,y)
#endif

typedef struct {
	/* 
	 * Length of the current chunk data. 
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
	 * If TRUE, a callback has been issued which references recv_buf.
	 * If the transfer is cancelled before a reference exists, the contents
	 * of recv_buf are free'd.
	 */
	gboolean               callback_issued;

	gboolean              *cancelled;

	GByteArray            *recv_buf;
	guint                  header_len;

	gboolean               overwrite_chunks;

	SoupTransferEncoding   encoding;
	guint                  content_length;
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

	gboolean               *cancelled;

	SoupTransferEncoding    encoding;
	GByteArray             *write_buf;

	gboolean                headers_done;
	gint                    chunk_cnt;

	SoupWriteGetHeaderFn    get_header_cb;
	SoupWriteGetChunkFn     get_chunk_cb;
	SoupWriteDoneFn         write_done_cb;
	SoupWriteErrorFn        error_cb;
	gpointer                user_data;
} SoupWriter;

#define IGNORE_CANCEL(t, cancel_p) (t)->cancelled = cancel_p;
#define UNIGNORE_CANCEL(t) (t)->cancelled = NULL;

void
soup_transfer_read_cancel (guint tag)
{
	SoupReader *r = GINT_TO_POINTER (tag);

	if (r->cancelled) {
		*(r->cancelled) = TRUE;
		return;
	}

	if (r->read_tag)
		g_source_remove (r->read_tag);
	if (r->err_tag)
		g_source_remove (r->err_tag);

	g_byte_array_free (r->recv_buf, r->callback_issued ? FALSE : TRUE);

	g_free (r);
}

void 
soup_transfer_read_set_callbacks (guint                   tag,
				  SoupReadHeadersDoneFn   headers_done_cb,
				  SoupReadChunkFn         read_chunk_cb,
				  SoupReadDoneFn          read_done_cb,
				  SoupReadErrorFn         error_cb,
				  gpointer                user_data)
{
	SoupReader *r = GINT_TO_POINTER (tag);

	r->headers_done_cb = headers_done_cb;
	r->read_chunk_cb = read_chunk_cb;
	r->read_done_cb = read_done_cb;
	r->error_cb = error_cb;

	r->user_data = user_data;
}

static void
issue_final_callback (SoupReader *r)
{
	/* 
	 * Null terminate 
	 */
	g_byte_array_append (r->recv_buf, "\0", 1);

	if (r->read_done_cb) {
		SoupDataBuffer buf = {
			SOUP_BUFFER_SYSTEM_OWNED,
			r->recv_buf->data,
			r->recv_buf->len - 1
		};

		r->callback_issued = TRUE;

		g_source_remove (r->read_tag);
		g_source_remove (r->err_tag);
		r->read_tag = r->err_tag = 0;

		(*r->read_done_cb) (&buf, r->user_data);
	}
}

static gboolean
soup_transfer_read_error_cb (GIOChannel* iochannel,
			     GIOCondition condition,
			     SoupReader *r)
{
	gboolean body_started = r->recv_buf->len > r->header_len;
	gboolean cancelled = FALSE;

	IGNORE_CANCEL (r, &cancelled);
	/*
	 * Closing the connection to signify EOF is valid if content length is
	 * unknown, but only if headers have been sent.
	 */
	if (r->header_len && r->encoding == SOUP_TRANSFER_UNKNOWN) {
		issue_final_callback (r);
		goto CANCELLED;
	}

	if (r->error_cb) (*r->error_cb) (body_started, r->user_data);

 CANCELLED:
	UNIGNORE_CANCEL (r);
	soup_transfer_read_cancel (GPOINTER_TO_INT (r));

	return FALSE;
}

static void
remove_block_at_index (GByteArray *arr, gint offset, gint length)
{
	gchar *data;

	g_return_if_fail (length != 0);
	g_assert (arr->len >= (guint) offset + length);

	data = &arr->data [offset];

	g_memmove (data,
		   data + length,
		   arr->len - offset - length);

	g_byte_array_set_size (arr, arr->len - length);
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

		if (s->len) {
			/* We're in the middle of a chunk. If we don't
			 * have the entire chunk and the trailing CRLF
			 * yet, read more.
			 */
			if (s->idx + s->len + 2 > arr->len)
				break;

			/*
			 * Increment datalen and s->idx, and remove
			 * the trailing CRLF.
			 */
			s->idx += s->len;
			*datalen += s->len;
			remove_block_at_index (arr, s->idx, 2);

			/*
			 * Ready for the next chunk.
			 */
			s->len = 0;
		}

		/*
		 * We're at the start of a new chunk. If we don't have
		 * the complete chunk header, wait for more.
		 */
		len = soup_substring_index (&arr->data [s->idx],
					    arr->len - s->idx, 
					    "\r\n");
		if (len < 0)
			break;
		len += 2;

		new_len = strtol (&arr->data [s->idx], NULL, 16);
		g_assert (new_len >= 0);

		/*
		 * If this is the final (zero-length) chunk, we need
		 * to have all of the trailing entity headers as well.
		 */
		if (new_len == 0) {
			len = soup_substring_index (&arr->data [s->idx],
						    arr->len - s->idx, 
						    "\r\n\r\n");
			if (len < 0)
				break;

			/* 
			 * FIXME: Add entity headers we find here to
			 *        req->response_headers. 
			 */

			len += 4;
			ret = TRUE;
		}

		/* 
		 * Remove chunk header and get ready for chunk data.
		 */
		remove_block_at_index (arr, s->idx, len);
		s->len = new_len;
	}

	return ret;
}

static void
issue_chunk_callback (SoupReader *r, gchar *data, gint len, gboolean *cancelled)
{
	/* 
	 * Call chunk callback. Pass len worth of data. 
	 */
	if (r->read_chunk_cb && len) {
		SoupTransferDone cont = SOUP_TRANSFER_CONTINUE;
		SoupDataBuffer buf = { 
			SOUP_BUFFER_SYSTEM_OWNED, 
			data,
			len
		};

		r->callback_issued = TRUE;

		IGNORE_CANCEL (r, cancelled);
		cont = (*r->read_chunk_cb) (&buf, r->user_data);
		UNIGNORE_CANCEL (r);

		if (cont == SOUP_TRANSFER_END)
			*cancelled = TRUE;
	}
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

	issue_chunk_callback (r, arr->data, s->idx, cancelled);
	if (*cancelled) goto CANCELLED;

	/* 
	 * If overwrite, remove already-processed data from start
	 * of buffer 
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

	if (!arr->len)
		goto CANCELLED;

	issue_chunk_callback (r, arr->data, arr->len, cancelled);
	if (*cancelled) goto CANCELLED;

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
read_unknown (SoupReader *r, gboolean *cancelled)
{
	GByteArray *arr = r->recv_buf;

	if (!arr->len)
		goto CANCELLED;

	issue_chunk_callback (r, arr->data, arr->len, cancelled);
	if (*cancelled) goto CANCELLED;

	/* 
	 * If overwrite, clear 
	 */
	if (r->overwrite_chunks)
		g_byte_array_set_size (arr, 0);

 CANCELLED:
	/* 
	 * Keep reading until we get a zero read or HUP.
	 */
	return FALSE;
}

static gboolean
soup_transfer_read_cb (GIOChannel   *iochannel,
		       GIOCondition  condition,
		       SoupReader   *r)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gsize bytes_read = 0, total_read = 0;
	gboolean read_done = FALSE;
	gboolean cancelled = FALSE;
	GIOError error;

 READ_AGAIN:
	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN) {
		if (total_read) 
			goto PROCESS_READ;
		else return TRUE;
	}

	if (error != G_IO_ERROR_NONE) {
		if (total_read) 
			goto PROCESS_READ;
		else {
			soup_transfer_read_error_cb (iochannel, G_IO_HUP, r);
			return FALSE;
		}
	}

	if (bytes_read) {
		DUMP_READ (read_buf, bytes_read);

		g_byte_array_append (r->recv_buf, read_buf, bytes_read);
		total_read += bytes_read;

		goto READ_AGAIN;
	}

 PROCESS_READ:

	if (r->header_len == 0 && total_read == 0)
		goto FINISH_READ;

	if (r->header_len == 0) {
		gint index;

		index = soup_substring_index (r->recv_buf->data,
					      r->recv_buf->len,
					      "\r\n\r\n");
		if (index < 0) 
			return TRUE;
		else
			index += 4;

		if (r->headers_done_cb) {
			GString str;
			SoupTransferDone ret;

			str.len = index;
			str.str = alloca (index + 1);
			strncpy (str.str, r->recv_buf->data, index);
			str.str [index] = '\0';

			IGNORE_CANCEL (r, &cancelled);
			ret = (*r->headers_done_cb) (&str, 
						     &r->encoding, 
						     &r->content_length, 
						     r->user_data);
			UNIGNORE_CANCEL (r);

			if (ret == SOUP_TRANSFER_END || cancelled) 
				goto FINISH_READ;
		}

		remove_block_at_index (r->recv_buf, 0, index);
		r->header_len = index;
	}

	if (total_read == 0)
		read_done = TRUE;
	else {
		switch (r->encoding) {
		case SOUP_TRANSFER_CHUNKED:
			read_done = read_chunk (r, &cancelled);
			break;
		case SOUP_TRANSFER_CONTENT_LENGTH:
			read_done = read_content_length (r, &cancelled);
			break;
		case SOUP_TRANSFER_UNKNOWN:
			read_done = read_unknown (r, &cancelled);
			break;
		}
	}

	if (cancelled) 
		goto FINISH_READ;

	if (!read_done) {
		total_read = 0;
		goto READ_AGAIN;
	}

	IGNORE_CANCEL (r, &cancelled);
	issue_final_callback (r);
	UNIGNORE_CANCEL (r);

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
	reader->encoding = SOUP_TRANSFER_UNKNOWN;

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

	if (w->cancelled) {
		*(w->cancelled) = TRUE;
		return;
	}

	if (w->write_tag)
		g_source_remove (w->write_tag);
	g_source_remove (w->err_tag);

	g_byte_array_free (w->write_buf, TRUE);

	g_free (w);
}

static gboolean
soup_transfer_write_error_cb (GIOChannel* iochannel,
			      GIOCondition condition,
			      SoupWriter *w)
{
	if (w->error_cb) {
		gboolean cancelled;

		IGNORE_CANCEL (w, &cancelled);
		(*w->error_cb) (w->headers_done, w->user_data);
		UNIGNORE_CANCEL (w);
	}

	soup_transfer_write_cancel (GPOINTER_TO_INT (w));

	return FALSE;
}

static gboolean 
get_header (SoupWriter *w, gboolean *cancelled)
{
	GString *header = NULL;

	IGNORE_CANCEL (w, cancelled);
	(*w->get_header_cb) (&header, w->user_data);
	UNIGNORE_CANCEL (w);

	if (header) {
		g_byte_array_append (w->write_buf, header->str, header->len);
		g_string_free (header, TRUE);

		w->get_header_cb = NULL;
		return TRUE;
	}

	return FALSE;
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
get_next_chunk (SoupWriter *w, gboolean *cancelled)
{
	SoupTransferStatus ret = SOUP_TRANSFER_END;
	SoupDataBuffer buf = { 0 , NULL, 0 };

	IGNORE_CANCEL (w, cancelled);
	ret = (*w->get_chunk_cb) (&buf, w->user_data);
	UNIGNORE_CANCEL (w);

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

#ifdef SIGPIPE
#  define IGNORE_PIPE(pipe_handler) pipe_handler = signal (SIGPIPE, SIG_IGN)
#  define RESTORE_PIPE(pipe_handler) signal (SIGPIPE, pipe_handler)
#else
#  define IGNORE_PIPE(x)
#  define RESTORE_PIPE(x)
#endif

static gboolean
soup_transfer_write_cb (GIOChannel* iochannel,
			GIOCondition condition,
			SoupWriter *w)
{
	GIOError error;
	gpointer pipe_handler;
	gsize bytes_written = 0;
	gboolean cancelled = FALSE;

	/*
	 * Get the header and first data chunk (if available).
	 */
	if (w->get_header_cb) {
		if (!get_header (w, &cancelled)) {
			if (cancelled)
				goto CANCEL;
			return TRUE;
		}

		if (w->get_chunk_cb) {
			get_next_chunk (w, &cancelled);
			if (cancelled)
				goto CANCEL;
		}
	}

	IGNORE_PIPE (pipe_handler);
	errno = 0;

 WRITE_AGAIN:
	while (w->write_buf->len) {
		error = g_io_channel_write (iochannel,
					    w->write_buf->data,
					    w->write_buf->len,
					    &bytes_written);

		if (error == G_IO_ERROR_AGAIN) 
			goto WRITE_LATER;

		if (errno != 0 || error != G_IO_ERROR_NONE) {
			soup_transfer_write_error_cb (iochannel, G_IO_HUP, w);
			goto DONE_WRITING;
		}

		if (!bytes_written) 
			goto WRITE_LATER;

		DUMP_WRITE (w->write_buf->data, bytes_written);

		remove_block_at_index (w->write_buf, 0, bytes_written);
	}

	/*
	 * When we exit the above block, we are certain that the headers have
	 * been written.  
	 */
	w->headers_done = TRUE;

	/*
	 * Get the next data chunk and try again, or quit if paused.
	 */
	if (w->get_chunk_cb) {
		get_next_chunk (w, &cancelled);

		if (cancelled)
			goto CANCEL;

		if (!w->write_tag)
			goto DONE_WRITING;

		goto WRITE_AGAIN;
	}

	if (w->write_done_cb) {
		IGNORE_CANCEL (w, &cancelled);
		(*w->write_done_cb) (w->user_data);
		UNIGNORE_CANCEL (w);
	}

 CANCEL:
	soup_transfer_write_cancel (GPOINTER_TO_INT (w));

 DONE_WRITING:
	RESTORE_PIPE (pipe_handler);
	return FALSE;

 WRITE_LATER:
	RESTORE_PIPE (pipe_handler);
	return TRUE;
}

static SoupWriter *
create_writer (GIOChannel             *chan,
	       SoupTransferEncoding    encoding,
	       SoupWriteDoneFn         write_done_cb,
	       SoupWriteErrorFn        error_cb,
	       gpointer                user_data)
{
	SoupWriter *writer;

	writer = g_new0 (SoupWriter, 1);

	writer->channel       = chan;
	writer->encoding      = encoding;
	writer->write_buf     = g_byte_array_new ();
	writer->write_done_cb = write_done_cb;
	writer->error_cb      = error_cb;
	writer->user_data     = user_data;

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

	return writer;
}

guint 
soup_transfer_write_simple (GIOChannel             *chan,
			    GString                *header,
			    const SoupDataBuffer   *src,
			    SoupWriteDoneFn         write_done_cb,
			    SoupWriteErrorFn        error_cb,
			    gpointer                user_data)
{
	SoupWriter *writer;

	writer = create_writer (chan, 
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

	return GPOINTER_TO_INT (writer);
}

guint 
soup_transfer_write (GIOChannel             *chan,
		     SoupTransferEncoding    encoding,
		     SoupWriteGetHeaderFn    get_header_cb,
		     SoupWriteGetChunkFn     get_chunk_cb,
		     SoupWriteDoneFn         write_done_cb,
		     SoupWriteErrorFn        error_cb,
		     gpointer                user_data)
{
	SoupWriter *writer;

	writer = create_writer (chan, 
				encoding,
				write_done_cb,
				error_cb,
				user_data);

	writer->get_header_cb = get_header_cb;
	writer->get_chunk_cb = get_chunk_cb;

	return GPOINTER_TO_INT (writer);
}

void  
soup_transfer_write_pause (guint tag)
{
	SoupWriter *w = GINT_TO_POINTER (tag);

	g_return_if_fail (tag != 0);

	if (w->write_tag) {
		g_source_remove (w->write_tag);
		w->write_tag = 0;
	}
}

void  
soup_transfer_write_unpause (guint tag)
{
	SoupWriter *w = GINT_TO_POINTER (tag);

	g_return_if_fail (tag != 0);

	if (!w->write_tag) {
		w->write_tag =
			g_io_add_watch (w->channel,
					G_IO_OUT,
					(GIOFunc) soup_transfer_write_cb,
					w);
	}
}
