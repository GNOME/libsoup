/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-io.c: HTTP message I/O
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-private.h"

typedef struct {
	guint                     idle_tag;
	guint                     read_tag;
	guint                     err_tag;

	GByteArray               *body_buf;
	GByteArray               *meta_buf;

	SoupTransferEncoding      encoding;
	guint                     read_length;

	SoupMessageReadHeadersFn  read_headers_cb;
	SoupMessageReadChunkFn    read_chunk_cb;
	SoupMessageReadBodyFn     read_body_cb;
	SoupMessageReadErrorFn    error_cb;
	gpointer                  user_data;
} SoupMessageReadState;

/* Put these around callback invocation if there is code afterward
 * that depends on the read not having been cancelled.
 */
#define dummy_to_make_emacs_happy {
#define SOUP_MESSAGE_READ_PREPARE_FOR_CALLBACK { gboolean cancelled; g_object_ref (msg);
#define SOUP_MESSAGE_READ_RETURN_IF_CANCELLED cancelled = (msg->priv->read_state != r); g_object_unref (msg); if (cancelled) return; }
#define SOUP_MESSAGE_READ_RETURN_VAL_IF_CANCELLED(val) cancelled = (msg->priv->read_state != r); g_object_unref (msg); if (cancelled) return val; }

void
soup_message_read_cancel (SoupMessage *msg)
{
	SoupMessageReadState *r = msg->priv->read_state;

	if (!r)
		return;

	if (r->idle_tag)
		g_source_remove (r->idle_tag);
	if (r->read_tag)
		g_signal_handler_disconnect (msg->priv->socket, r->read_tag);
	if (r->err_tag)
		g_signal_handler_disconnect (msg->priv->socket, r->err_tag);

	if (r->body_buf)
		g_byte_array_free (r->body_buf, TRUE);
	if (r->meta_buf)
		g_byte_array_free (r->meta_buf, TRUE);

	g_free (r);

	msg->priv->read_state = NULL;
}

void
soup_message_read_set_callbacks (SoupMessage              *msg,
				 SoupMessageReadHeadersFn  read_headers_cb,
				 SoupMessageReadChunkFn    read_chunk_cb,
				 SoupMessageReadBodyFn     read_body_cb,
				 SoupMessageReadErrorFn    error_cb,
				 gpointer                  user_data)
{
	SoupMessageReadState *r = msg->priv->read_state;

	r->read_headers_cb = read_headers_cb;
	r->read_chunk_cb = read_chunk_cb;
	r->read_body_cb = read_body_cb;
	r->error_cb = error_cb;
	r->user_data = user_data;
}

static void
issue_final_callback (SoupMessage *msg)
{
	SoupMessageReadState *r = msg->priv->read_state;
	SoupMessageReadBodyFn read_body_cb = r->read_body_cb;
	gpointer user_data = r->user_data;
	char *body;
	guint len;

	if (r->body_buf) {
		body = r->body_buf->data;
		len = r->body_buf->len;

		g_byte_array_free (r->body_buf, FALSE);
		r->body_buf = NULL;
	} else {
		body = NULL;
		len = 0;
	}

	soup_message_read_cancel (msg);
	read_body_cb (msg, body, len, user_data);
}

static void
failed_read (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessageReadState *r = msg->priv->read_state;
	SoupMessageReadErrorFn error_cb = r->error_cb;
	gpointer user_data = r->user_data;

	/* Closing the connection to signify EOF is valid if content
	 * length is unknown, but only if headers have been sent.
	 */
	if (msg->priv->status > SOUP_MESSAGE_STATUS_READING_HEADERS &&
	    r->encoding == SOUP_TRANSFER_UNKNOWN) {
		issue_final_callback (msg);
		return;
	}

	soup_message_read_cancel (msg);
	error_cb (msg, user_data);
}

static gboolean
read_metadata (SoupMessage *msg, const char *boundary, int boundary_len)
{
	SoupMessageReadState *r = msg->priv->read_state;
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint nread;
	gboolean done;

	do {
		status = soup_socket_read_until (msg->priv->socket, read_buf,
						 sizeof (read_buf),
						 boundary, boundary_len,
						 &nread, &done);
		switch (status) {
		case SOUP_SOCKET_OK:
			g_byte_array_append (r->meta_buf, read_buf, nread);
			break;

		case SOUP_SOCKET_ERROR:
		case SOUP_SOCKET_EOF:
			failed_read (msg->priv->socket, msg);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;
		}
	} while (!done);

	return TRUE;
}

static gboolean
read_body_chunk (SoupMessage *msg, guint *size)
{
	SoupMessageReadState *r = msg->priv->read_state;
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint nread, len = sizeof (read_buf);
	gboolean read_to_eof = (r->encoding == SOUP_TRANSFER_UNKNOWN);

	while (read_to_eof || *size > 0) {
		if (!read_to_eof)
			len = MIN (len, *size);

		status = soup_socket_read (msg->priv->socket, read_buf,
					   len, &nread);

		switch (status) {
		case SOUP_SOCKET_OK:
			if (!nread)
				break;

			if (r->read_chunk_cb) {
				SOUP_MESSAGE_READ_PREPARE_FOR_CALLBACK;
				r->read_chunk_cb (msg, read_buf, nread, r->user_data);
				SOUP_MESSAGE_READ_RETURN_VAL_IF_CANCELLED (FALSE);
			}

			if (r->body_buf)
				g_byte_array_append (r->body_buf, read_buf, nread);
			*size -= nread;
			break;

		case SOUP_SOCKET_EOF:
			if (read_to_eof)
				return TRUE;
			/* else fall through */

		case SOUP_SOCKET_ERROR:
			failed_read (msg->priv->socket, msg);
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
do_read (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessageReadState *r = msg->priv->read_state;

	while (1) {
		switch (msg->priv->status) {
		case SOUP_MESSAGE_STATUS_READING_HEADERS:
			if (!read_metadata (msg, SOUP_TRANSFER_DOUBLE_EOL,
					    SOUP_TRANSFER_DOUBLE_EOL_LEN))
				return;

			r->meta_buf->len -= SOUP_TRANSFER_DOUBLE_EOL_LEN;
			if (r->read_headers_cb) {
				SOUP_MESSAGE_READ_PREPARE_FOR_CALLBACK;
				r->read_headers_cb (msg,
						    r->meta_buf->data,
						    r->meta_buf->len,
						    &r->encoding, 
						    &r->read_length,
						    r->user_data);
				SOUP_MESSAGE_READ_RETURN_IF_CANCELLED;
			}
			g_byte_array_set_size (r->meta_buf, 0);

			switch (r->encoding) {
			case SOUP_TRANSFER_UNKNOWN:
			case SOUP_TRANSFER_CONTENT_LENGTH:
				msg->priv->status =
					SOUP_MESSAGE_STATUS_READING_BODY;
				break;
			case SOUP_TRANSFER_CHUNKED:
				msg->priv->status =
					SOUP_MESSAGE_STATUS_READING_CHUNK_SIZE;
				break;
			}
			break;

		case SOUP_MESSAGE_STATUS_READING_BODY:
			if (!read_body_chunk (msg, &r->read_length))
				return;

			goto done;
			break;

		case SOUP_MESSAGE_STATUS_READING_CHUNK_SIZE:
			if (!read_metadata (msg, SOUP_TRANSFER_EOL,
					    SOUP_TRANSFER_EOL_LEN))
				return;

			r->read_length = strtoul (r->meta_buf->data, NULL, 16);
			g_byte_array_set_size (r->meta_buf, 0);

			if (r->read_length > 0) {
				msg->priv->status =
					SOUP_MESSAGE_STATUS_READING_CHUNK;
			} else {
				msg->priv->status =
					SOUP_MESSAGE_STATUS_READING_TRAILERS;
			}
			break;

		case SOUP_MESSAGE_STATUS_READING_CHUNK:
			if (!read_body_chunk (msg, &r->read_length))
				return;

			msg->priv->status =
				SOUP_MESSAGE_STATUS_READING_CHUNK_END;
			break;

		case SOUP_MESSAGE_STATUS_READING_CHUNK_END:
			if (!read_metadata (msg, SOUP_TRANSFER_EOL,
					    SOUP_TRANSFER_EOL_LEN))
				return;

			g_byte_array_set_size (r->meta_buf, 0);
			msg->priv->status =
				SOUP_MESSAGE_STATUS_READING_CHUNK_SIZE;
			break;

		case SOUP_MESSAGE_STATUS_READING_TRAILERS:
			if (!read_metadata (msg, SOUP_TRANSFER_EOL,
					    SOUP_TRANSFER_EOL_LEN))
				return;

			if (r->meta_buf->len == SOUP_TRANSFER_EOL_LEN)
				goto done;

			/* FIXME: process trailers */
			g_byte_array_set_size (r->meta_buf, 0);
			break;

		default:
			g_return_if_reached ();
		}
	}

 done:
	msg->priv->status = SOUP_MESSAGE_STATUS_FINISHED_READING;
	issue_final_callback (msg);
}

static gboolean
idle_read (gpointer user_data)
{
	SoupMessage *msg = user_data;
	SoupMessageReadState *r = msg->priv->read_state;

	g_return_val_if_fail (r != NULL, FALSE);

	r->idle_tag = 0;
	do_read (msg->priv->socket, msg);
	return FALSE;
}

void
soup_message_read (SoupMessage              *msg,
		   SoupMessageReadHeadersFn  read_headers_cb,
		   SoupMessageReadChunkFn    read_chunk_cb,
		   SoupMessageReadBodyFn     read_body_cb,
		   SoupMessageReadErrorFn    error_cb,
		   gpointer                  user_data)
{
	SoupMessageReadState *r;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (msg->priv->socket != NULL);
	g_return_if_fail (read_body_cb && error_cb);

	r = g_new0 (SoupMessageReadState, 1);
	r->read_headers_cb = read_headers_cb;
	r->read_chunk_cb = read_chunk_cb;
	r->read_body_cb = read_body_cb;
	r->error_cb = error_cb;
	r->user_data = user_data;
	r->encoding = SOUP_TRANSFER_UNKNOWN;

	r->meta_buf = g_byte_array_new ();
	if (!(msg->priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS))
		r->body_buf = g_byte_array_new ();

	r->read_tag = g_signal_connect (msg->priv->socket, "readable",
					G_CALLBACK (do_read), msg);
	r->err_tag = g_signal_connect (msg->priv->socket, "disconnected",
				       G_CALLBACK (failed_read), msg);

	r->idle_tag = g_idle_add (idle_read, msg);

	msg->priv->status = SOUP_MESSAGE_STATUS_READING_HEADERS;
	msg->priv->read_state = r;
}



typedef struct {
	guint idle_tag;
	guint write_tag;
	guint err_tag;

	GString *buf;
	SoupTransferEncoding encoding;
	const SoupDataBuffer *body;
	SoupDataBuffer chunk;
	guint nwrote;

	SoupMessageWriteGetHeaderFn get_header_cb;
	SoupMessageWriteGetChunkFn  get_chunk_cb;
	SoupMessageWriteDoneFn      write_done_cb;
	SoupMessageWriteErrorFn     error_cb;
	gpointer                    user_data;
} SoupMessageWriteState;

/* Put these around callback invocation if there is code afterward
 * that depends on the write not having been cancelled or paused.
 */
#define SOUP_MESSAGE_WRITE_PREPARE_FOR_CALLBACK { gboolean cancelled; g_object_ref (msg);
#define SOUP_MESSAGE_WRITE_RETURN_IF_CANCELLED cancelled = (msg->priv->write_state != w); g_object_unref (msg); if (cancelled || !w->write_tag) return; }

void
soup_message_write_cancel (SoupMessage *msg)
{
	SoupMessageWriteState *w = msg->priv->write_state;

	if (!w)
		return;

	if (w->idle_tag)
		g_source_remove (w->idle_tag);
	if (w->err_tag)
		g_signal_handler_disconnect (msg->priv->socket, w->err_tag);
	if (w->write_tag)
		g_signal_handler_disconnect (msg->priv->socket, w->write_tag);

	g_string_free (w->buf, TRUE);

	g_free (w);

	msg->priv->write_state = NULL;
}

static void
failed_write (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessageWriteState *w = msg->priv->write_state;
	SoupMessageWriteErrorFn error_cb = w->error_cb;
	gpointer user_data = w->user_data;

	soup_message_write_cancel (msg);
	error_cb (msg, user_data);
}

static gboolean
write_data (SoupMessage *msg, const char *data, guint len)
{
	SoupMessageWriteState *w = msg->priv->write_state;
	SoupSocketIOStatus status;
	guint nwrote;

	while (len - w->nwrote) {
		status = soup_socket_write (msg->priv->socket,
					    data + w->nwrote,
					    len - w->nwrote,
					    &nwrote);
		switch (status) {
		case SOUP_SOCKET_EOF:
		case SOUP_SOCKET_ERROR:
			failed_write (msg->priv->socket, msg);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;

		case SOUP_SOCKET_OK:
			w->nwrote += nwrote;
			break;
		}
	}

	return TRUE;
}

static void
do_write (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessageWriteState *w = msg->priv->write_state;
	SoupMessageWriteDoneFn write_done_cb = w->write_done_cb;
	gpointer user_data = w->user_data;

	while (1) {
		switch (msg->priv->status) {
		case SOUP_MESSAGE_STATUS_WRITING_HEADERS:
			if (w->get_header_cb) {
				SOUP_MESSAGE_WRITE_PREPARE_FOR_CALLBACK;
				w->get_header_cb (msg, w->buf, user_data);
				SOUP_MESSAGE_WRITE_RETURN_IF_CANCELLED;

				w->get_header_cb = NULL;
				w->nwrote = 0;
			}

			if (!write_data (msg, w->buf->str, w->buf->len))
				return;

			g_string_truncate (w->buf, 0);
			w->nwrote = 0;
			if (w->encoding == SOUP_TRANSFER_CHUNKED) {
				msg->priv->status =
					SOUP_MESSAGE_STATUS_WRITING_CHUNK_SIZE;
			} else {
				msg->priv->status =
					SOUP_MESSAGE_STATUS_WRITING_BODY;
			}
			break;

		case SOUP_MESSAGE_STATUS_WRITING_BODY:
			if (!write_data (msg, w->body->body,
					 w->body->length))
				return;

			goto done;

		case SOUP_MESSAGE_STATUS_WRITING_CHUNK_SIZE:
			if (!w->buf->len) {
				gboolean got_chunk;

				SOUP_MESSAGE_WRITE_PREPARE_FOR_CALLBACK;
				got_chunk = w->get_chunk_cb (msg,
							     &w->chunk,
							     user_data);
				SOUP_MESSAGE_WRITE_RETURN_IF_CANCELLED;

				if (!got_chunk) {
					/* No more chunks. Write the
					 * 0-length chunk to signify
					 * the end.
					 */
					w->chunk.length = 0;
					w->get_chunk_cb = NULL;
				}

				g_string_append_printf (w->buf, "%x\r\n",
							w->chunk.length);
				w->nwrote = 0;
			}

			if (!write_data (msg, w->buf->str, w->buf->len))
				return;

			g_string_truncate (w->buf, 0);
			w->nwrote = 0;
			msg->priv->status = SOUP_MESSAGE_STATUS_WRITING_CHUNK;
			/* fall through */

		case SOUP_MESSAGE_STATUS_WRITING_CHUNK:
			if (!write_data (msg, w->chunk.body,
					 w->chunk.length))
				return;

			if (w->chunk.owner == SOUP_BUFFER_SYSTEM_OWNED)
				g_free (w->chunk.body);
			memset (&w->chunk, 0, sizeof (SoupDataBuffer));

			w->nwrote = 0;
			msg->priv->status = SOUP_MESSAGE_STATUS_WRITING_CHUNK_END;
			/* fall through */

		case SOUP_MESSAGE_STATUS_WRITING_CHUNK_END:
			if (!write_data (msg, SOUP_TRANSFER_EOL,
					 SOUP_TRANSFER_EOL_LEN))
				return;

			w->nwrote = 0;
			if (w->get_chunk_cb) {
				msg->priv->status =
					SOUP_MESSAGE_STATUS_WRITING_CHUNK_SIZE;
				break;
			}

			msg->priv->status =
				SOUP_MESSAGE_STATUS_WRITING_TRAILERS;
			/* fall through */

		case SOUP_MESSAGE_STATUS_WRITING_TRAILERS:
			if (!write_data (msg, SOUP_TRANSFER_EOL,
					 SOUP_TRANSFER_EOL_LEN))
				return;

			goto done;

		default:
			g_return_if_reached ();
		}
	}

 done:
	msg->priv->status = SOUP_MESSAGE_STATUS_FINISHED_WRITING;
	soup_message_write_cancel (msg);
	write_done_cb (msg, user_data);
}

static gboolean
idle_write (gpointer user_data)
{
	SoupMessage *msg = user_data;
	SoupMessageWriteState *w = msg->priv->write_state;

	w->idle_tag = 0;
	do_write (msg->priv->socket, msg);
	return FALSE;
}

static SoupMessageWriteState *
create_writer (SoupMessage                 *msg,
	       SoupTransferEncoding         encoding,
	       SoupMessageWriteGetHeaderFn  get_header_cb,
	       SoupMessageWriteDoneFn       write_done_cb,
	       SoupMessageWriteErrorFn      error_cb,
	       gpointer                     user_data)
{
	SoupMessageWriteState *w;

	w = g_new0 (SoupMessageWriteState, 1);
	w->encoding      = encoding;
	w->buf           = g_string_new (NULL);
	w->get_header_cb = get_header_cb;
	w->write_done_cb = write_done_cb;
	w->error_cb      = error_cb;
	w->user_data     = user_data;

	w->write_tag =
		g_signal_connect (msg->priv->socket, "writable",
				  G_CALLBACK (do_write), msg);
	w->err_tag =
		g_signal_connect (msg->priv->socket, "disconnected",
				  G_CALLBACK (failed_write), msg);

	w->idle_tag = g_idle_add (idle_write, msg);

	msg->priv->status = SOUP_MESSAGE_STATUS_WRITING_HEADERS;
	msg->priv->write_state = w;

	return w;
}

void
soup_message_write_simple (SoupMessage                 *msg,
			   const SoupDataBuffer        *body,
			   SoupMessageWriteGetHeaderFn  get_header_cb,
			   SoupMessageWriteDoneFn       write_done_cb,
			   SoupMessageWriteErrorFn      error_cb,
			   gpointer                     user_data)
{
	SoupMessageWriteState *w;

	w = create_writer (msg, SOUP_TRANSFER_CONTENT_LENGTH,
			   get_header_cb, write_done_cb,
			   error_cb, user_data);

	w->body = body;
}

void
soup_message_write (SoupMessage                 *msg,
		    SoupTransferEncoding         encoding,
		    SoupMessageWriteGetHeaderFn  get_header_cb,
		    SoupMessageWriteGetChunkFn   get_chunk_cb,
		    SoupMessageWriteDoneFn       write_done_cb,
		    SoupMessageWriteErrorFn      error_cb,
		    gpointer                     user_data)
{
	SoupMessageWriteState *w;

	w = create_writer (msg, encoding, get_header_cb,
			   write_done_cb, error_cb, user_data);
	w->get_chunk_cb = get_chunk_cb;
}

void  
soup_message_write_pause (SoupMessage *msg)
{
	SoupMessageWriteState *w;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	w = msg->priv->write_state;
	g_return_if_fail (w != NULL);

	if (w->write_tag) {
		g_signal_handler_disconnect (msg->priv->socket, w->write_tag);
		w->write_tag = 0;
	}
	if (w->idle_tag) {
		g_source_remove (w->idle_tag);
		w->idle_tag = 0;
	}
}

void  
soup_message_write_unpause (SoupMessage *msg)
{
	SoupMessageWriteState *w;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	w = msg->priv->write_state;
	if (!w)
		return;

	if (!w->write_tag) {
		w->write_tag = g_signal_connect (msg->priv->socket, "writable",
						 G_CALLBACK (do_write), msg);
	}
	if (!w->idle_tag)
		w->idle_tag = g_idle_add (idle_write, msg);
}
