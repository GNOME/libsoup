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

#include "soup-connection.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-socket.h"
#include "soup-ssl.h"

typedef enum {
	SOUP_MESSAGE_IO_CLIENT,
	SOUP_MESSAGE_IO_SERVER
} SoupMessageIOMode;

typedef enum {
	SOUP_MESSAGE_IO_STATE_NOT_STARTED,
	SOUP_MESSAGE_IO_STATE_HEADERS,
	SOUP_MESSAGE_IO_STATE_BLOCKING,
	SOUP_MESSAGE_IO_STATE_BODY,
	SOUP_MESSAGE_IO_STATE_CHUNK_SIZE,
	SOUP_MESSAGE_IO_STATE_CHUNK,
	SOUP_MESSAGE_IO_STATE_CHUNK_END,
	SOUP_MESSAGE_IO_STATE_TRAILERS,
	SOUP_MESSAGE_IO_STATE_DONE
} SoupMessageIOState;

typedef struct {
	SoupSocket           *sock;
	SoupConnection       *conn;
	SoupMessageIOMode     mode;

	SoupMessageIOState    read_state;
	SoupTransferEncoding  read_encoding;
	GByteArray           *read_buf;
	GByteArray           *read_meta_buf;
	SoupDataBuffer       *read_body;
	guint                 read_length;

	SoupMessageIOState    write_state;
	SoupTransferEncoding  write_encoding;
	GString              *write_buf;
	SoupDataBuffer       *write_body;
	guint                 written;

	guint read_tag, write_tag, err_tag;

	SoupMessageGetHeadersFn   get_headers_cb;
	SoupMessageParseHeadersFn parse_headers_cb;
	gpointer                  user_data;
} SoupMessageIOData;
	

/* Put these around callback invocation if there is code afterward
 * that depends on the IO having not been cancelled.
 */
#define dummy_to_make_emacs_happy {
#define SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK { gboolean cancelled; g_object_ref (msg);
#define SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED cancelled = (priv->io_data != io); g_object_unref (msg); if (cancelled || !io->read_tag || !io->write_tag) return; }
#define SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED(val) cancelled = (priv->io_data != io); g_object_unref (msg); if (cancelled || !io->read_tag || !io->write_tag) return val; }

#define RESPONSE_BLOCK_SIZE 8192

static void
io_cleanup (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	if (!io)
		return;

	soup_message_io_stop (msg);

	if (io->sock)
		g_object_unref (io->sock);
	if (io->conn)
		g_object_unref (io->conn);

	if (io->read_buf)
		g_byte_array_free (io->read_buf, TRUE);
	g_byte_array_free (io->read_meta_buf, TRUE);

	g_string_free (io->write_buf, TRUE);

	g_free (io);
	priv->io_data = NULL;
}

/**
 * soup_message_io_stop:
 * @msg: a #SoupMessage
 *
 * Immediately stops I/O on msg; if the connection would be left in an
 * inconsistent state, it will be closed.
 **/
void
soup_message_io_stop (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	if (!io)
		return;

	if (io->read_tag) {
		g_signal_handler_disconnect (io->sock, io->read_tag);
		io->read_tag = 0;
	}
	if (io->write_tag) {
		g_signal_handler_disconnect (io->sock, io->write_tag);
		io->write_tag = 0;
	}
	if (io->err_tag) {
		g_signal_handler_disconnect (io->sock, io->err_tag);
		io->err_tag = 0;
	}

	if (io->read_state != SOUP_MESSAGE_IO_STATE_DONE)
		soup_socket_disconnect (io->sock);
	else if (io->conn)
		soup_connection_release (io->conn);
}

#define SOUP_MESSAGE_IO_EOL            "\r\n"
#define SOUP_MESSAGE_IO_EOL_LEN        2
#define SOUP_MESSAGE_IO_DOUBLE_EOL     "\r\n\r\n"
#define SOUP_MESSAGE_IO_DOUBLE_EOL_LEN 4

static void
soup_message_io_finished (SoupMessage *msg)
{
	g_object_ref (msg);
	io_cleanup (msg);
	if (SOUP_MESSAGE_IS_STARTING (msg))
		soup_message_restarted (msg);
	else
		soup_message_finished (msg);
	g_object_unref (msg);
}


static void
io_error (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	/* Closing the connection to signify EOF is sometimes ok */
	if (io->read_state == SOUP_MESSAGE_IO_STATE_BODY &&
	    io->read_encoding == SOUP_TRANSFER_UNKNOWN) {
		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
		soup_message_io_finished (msg);
		return;
	}

	if (!SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code)) {
		GError *err = g_object_get_data (G_OBJECT (sock),
						 "SoupSocket-last_error");

		if (err && err->domain == SOUP_SSL_ERROR) {
			soup_message_set_status_full (msg,
						      SOUP_STATUS_SSL_FAILED,
						      err->message);
		} else
			soup_message_set_status (msg, SOUP_STATUS_IO_ERROR);
	}

	soup_message_io_finished (msg);
}

static gboolean
read_metadata (SoupMessage *msg, const char *boundary)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint boundary_len = strlen (boundary);
	gsize nread;
	gboolean done;

	do {
		status = soup_socket_read_until (io->sock, read_buf,
						 sizeof (read_buf),
						 boundary, boundary_len,
						 &nread, &done);
		switch (status) {
		case SOUP_SOCKET_OK:
			g_byte_array_append (io->read_meta_buf, read_buf, nread);
			break;

		case SOUP_SOCKET_ERROR:
		case SOUP_SOCKET_EOF:
			io_error (io->sock, msg);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;
		}
	} while (!done);

	return TRUE;
}

static gboolean
read_body_chunk (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupSocketIOStatus status;
	char read_buf[RESPONSE_BLOCK_SIZE];
	guint len = sizeof (read_buf);
	gboolean read_to_eof = (io->read_encoding == SOUP_TRANSFER_UNKNOWN);
	gsize nread;

	while (read_to_eof || io->read_length > 0) {
		if (!read_to_eof)
			len = MIN (len, io->read_length);

		status = soup_socket_read (io->sock, read_buf, len, &nread);

		switch (status) {
		case SOUP_SOCKET_OK:
			if (!nread)
				break;

			io->read_body->owner  = SOUP_BUFFER_STATIC;
			io->read_body->body   = read_buf;
			io->read_body->length = nread;

			SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
			soup_message_got_chunk (msg);
			SOUP_MESSAGE_IO_RETURN_VAL_IF_CANCELLED_OR_PAUSED (FALSE);

			memset (io->read_body, 0, sizeof (SoupDataBuffer));

			if (io->read_buf)
				g_byte_array_append (io->read_buf, read_buf, nread);
			io->read_length -= nread;
			break;

		case SOUP_SOCKET_EOF:
			if (read_to_eof)
				return TRUE;
			/* else fall through */

		case SOUP_SOCKET_ERROR:
			io_error (io->sock, msg);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
write_data (SoupMessage *msg, const char *data, guint len)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	SoupSocketIOStatus status;
	gsize nwrote;

	while (len > io->written) {
		status = soup_socket_write (io->sock,
					    data + io->written,
					    len - io->written,
					    &nwrote);
		switch (status) {
		case SOUP_SOCKET_EOF:
		case SOUP_SOCKET_ERROR:
			io_error (io->sock, msg);
			return FALSE;

		case SOUP_SOCKET_WOULD_BLOCK:
			return FALSE;

		case SOUP_SOCKET_OK:
			io->written += nwrote;
			break;
		}
	}

	io->written = 0;
	return TRUE;
}

static inline SoupMessageIOState
io_body_state (SoupTransferEncoding encoding)
{
	if (encoding == SOUP_TRANSFER_CHUNKED)
		return SOUP_MESSAGE_IO_STATE_CHUNK_SIZE;
	else
		return SOUP_MESSAGE_IO_STATE_BODY;
}

static void io_read (SoupSocket *sock, SoupMessage *msg);

/*
 * There are two request/response formats: the basic request/response,
 * possibly with one or more unsolicited informational responses (such
 * as the WebDAV "102 Processing" response):
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BODY     / R:NOT_STARTED    ->  R:BODY     / W:NOT_STARTED
 *     [W:DONE     / R:HEADERS (1xx)  <-  R:DONE     / W:HEADERS (1xx) ...]
 *      W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 *     
 * and the "Expect: 100-continue" request/response, in which each
 * writer has to pause and wait for the other at some point:
 *
 *     Client                            Server
 *      W:HEADERS  / R:NOT_STARTED    ->  R:HEADERS  / W:NOT_STARTED
 *      W:BLOCKING / R:HEADERS (100)  <-  R:BLOCKING / W:HEADERS (100)
 *      W:BODY     / R:BLOCKING       ->  R:BODY     / W:BLOCKING
 *      W:DONE     / R:HEADERS        <-  R:DONE     / W:HEADERS
 *      W:DONE     / R:BODY           <-  R:DONE     / W:BODY
 *      W:DONE     / R:DONE               R:DONE     / W:DONE
 */

static void
io_write (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

 write_more:
	switch (io->write_state) {
	case SOUP_MESSAGE_IO_STATE_NOT_STARTED:
		return;


	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!io->write_buf->len) {
			io->get_headers_cb (msg, io->write_buf,
					    &io->write_encoding,
					    io->user_data);
			if (!io->write_buf->len) {
				soup_message_io_pause (msg);
				return;
			}
		}

		if (!write_data (msg, io->write_buf->str, io->write_buf->len))
			return;

		g_string_truncate (io->write_buf, 0);

		if (io->mode == SOUP_MESSAGE_IO_SERVER &&
		    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			if (msg->status_code == SOUP_STATUS_CONTINUE) {
				/* Stop and wait for the body now */
				io->write_state =
					SOUP_MESSAGE_IO_STATE_BLOCKING;
			} else {
				/* We just wrote a 1xx response
				 * header, so stay in STATE_HEADERS.
				 * (The caller will pause us from the
				 * wrote_informational callback if he
				 * is not ready to send the final
				 * response.)
				 */
			}
		} else if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
			   priv->msg_flags & SOUP_MESSAGE_EXPECT_CONTINUE) {
			/* Need to wait for the Continue response */
			io->write_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
			io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
		} else
			io->write_state = io_body_state (io->write_encoding);

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		if (SOUP_STATUS_IS_INFORMATIONAL (msg->status_code))
			soup_message_wrote_informational (msg);
		else
			soup_message_wrote_headers (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		break;


	case SOUP_MESSAGE_IO_STATE_BLOCKING:
		io_read (sock, msg);

		/* If io_read reached a point where we could write
		 * again, it would have recursively called io_write.
		 * So (a) we don't need to try to keep writing, and
		 * (b) we can't anyway, because msg may have been
		 * destroyed.
		 */
		return;


	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!write_data (msg, io->write_body->body,
				 io->write_body->length))
			return;

		io->write_state = SOUP_MESSAGE_IO_STATE_DONE;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_wrote_body (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		break;


	case SOUP_MESSAGE_IO_STATE_CHUNK_SIZE:
		if (!io->write_buf->len) {
			SoupDataBuffer *chunk;

			SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
			chunk = soup_message_pop_chunk (msg);
			SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;

			if (!chunk) {
				soup_message_io_pause (msg);
				return;
			}
			memcpy (io->write_body, chunk, sizeof (SoupDataBuffer));
			g_free (chunk);

			g_string_append_printf (io->write_buf, "%x\r\n",
						io->write_body->length);
		}

		if (!write_data (msg, io->write_buf->str, io->write_buf->len))
			return;

		g_string_truncate (io->write_buf, 0);

		if (io->write_body->length == 0) {
			/* The last chunk has no CHUNK_END... */
			io->write_state = SOUP_MESSAGE_IO_STATE_TRAILERS;
			break;
		}

		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK;
		/* fall through */


	case SOUP_MESSAGE_IO_STATE_CHUNK:
		if (!write_data (msg, io->write_body->body,
				 io->write_body->length))
			return;

		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK_END;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_wrote_chunk (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		/* fall through */


	case SOUP_MESSAGE_IO_STATE_CHUNK_END:
		if (!write_data (msg, SOUP_MESSAGE_IO_EOL,
				 SOUP_MESSAGE_IO_EOL_LEN))
			return;

		if (io->write_body->owner == SOUP_BUFFER_SYSTEM_OWNED)
			g_free (io->write_body->body);
		memset (io->write_body, 0, sizeof (SoupDataBuffer));

		io->write_state = SOUP_MESSAGE_IO_STATE_CHUNK_SIZE;
		break;


	case SOUP_MESSAGE_IO_STATE_TRAILERS:
		if (!write_data (msg, SOUP_MESSAGE_IO_EOL,
				 SOUP_MESSAGE_IO_EOL_LEN))
			return;

		io->write_state = SOUP_MESSAGE_IO_STATE_DONE;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_wrote_body (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		/* fall through */


	case SOUP_MESSAGE_IO_STATE_DONE:
		if (io->mode == SOUP_MESSAGE_IO_CLIENT) {
			io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io_read (sock, msg);
		} else
			soup_message_io_finished (msg);
		return;


	default:
		g_return_if_reached ();
	}

	goto write_more;
}

static void
io_read (SoupSocket *sock, SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;
	guint status;

 read_more:
	switch (io->read_state) {
	case SOUP_MESSAGE_IO_STATE_NOT_STARTED:
		return;


	case SOUP_MESSAGE_IO_STATE_HEADERS:
		if (!read_metadata (msg, SOUP_MESSAGE_IO_DOUBLE_EOL))
			return;

		io->read_meta_buf->len -= SOUP_MESSAGE_IO_EOL_LEN;
		io->read_meta_buf->data[io->read_meta_buf->len] = '\0';
		status = io->parse_headers_cb (msg, io->read_meta_buf->data,
					       io->read_meta_buf->len,
					       &io->read_encoding,
					       &io->read_length,
					       io->user_data);
		g_byte_array_set_size (io->read_meta_buf, 0);

		if (status != SOUP_STATUS_OK) {
			/* Either we couldn't parse the headers, or they
			 * indicated something that would mean we wouldn't
			 * be able to parse the body. (Eg, unknown
			 * Transfer-Encoding.). Skip the rest of the
			 * reading, and make sure the connection gets
			 * closed when we're done.
			 */
			soup_message_set_status (msg, status);
			soup_message_add_header (msg->request_headers,
						 "Connection", "close");
			io->read_state = SOUP_MESSAGE_IO_STATE_DONE;
			break;
		}

		if (io->mode == SOUP_MESSAGE_IO_CLIENT &&
		    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			if (msg->status_code == SOUP_STATUS_CONTINUE &&
			    io->write_state == SOUP_MESSAGE_IO_STATE_BLOCKING) {
				/* Pause the reader, unpause the writer */
				io->read_state =
					SOUP_MESSAGE_IO_STATE_BLOCKING;
				io->write_state =
					io_body_state (io->write_encoding);
			} else {
				/* Just stay in HEADERS */
				io->read_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			}
		} else if (io->mode == SOUP_MESSAGE_IO_SERVER &&
			   (priv->msg_flags & SOUP_MESSAGE_EXPECT_CONTINUE)) {
			/* The client requested a Continue response. */
			io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io->read_state = SOUP_MESSAGE_IO_STATE_BLOCKING;
		} else
			io->read_state = io_body_state (io->read_encoding);

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		if (SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
			soup_message_got_informational (msg);
			soup_message_cleanup_response (msg);
		} else
			soup_message_got_headers (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		break;


	case SOUP_MESSAGE_IO_STATE_BLOCKING:
		io_write (sock, msg);

		/* As in the io_write case, we *must* return here. */
		return;


	case SOUP_MESSAGE_IO_STATE_BODY:
		if (!read_body_chunk (msg))
			return;

	got_body:
		if (io->read_buf) {
			io->read_body->owner = SOUP_BUFFER_SYSTEM_OWNED;
			io->read_body->body = io->read_buf->data;
			io->read_body->length = io->read_buf->len;

			g_byte_array_free (io->read_buf, FALSE);
			io->read_buf = NULL;
		}

		io->read_state = SOUP_MESSAGE_IO_STATE_DONE;

		SOUP_MESSAGE_IO_PREPARE_FOR_CALLBACK;
		soup_message_got_body (msg);
		SOUP_MESSAGE_IO_RETURN_IF_CANCELLED_OR_PAUSED;
		break;


	case SOUP_MESSAGE_IO_STATE_CHUNK_SIZE:
		if (!read_metadata (msg, SOUP_MESSAGE_IO_EOL))
			return;

		io->read_length = strtoul (io->read_meta_buf->data, NULL, 16);
		g_byte_array_set_size (io->read_meta_buf, 0);

		if (io->read_length > 0)
			io->read_state = SOUP_MESSAGE_IO_STATE_CHUNK;
		else
			io->read_state = SOUP_MESSAGE_IO_STATE_TRAILERS;
		break;


	case SOUP_MESSAGE_IO_STATE_CHUNK:
		if (!read_body_chunk (msg))
			return;

		io->read_state = SOUP_MESSAGE_IO_STATE_CHUNK_END;
		break;


	case SOUP_MESSAGE_IO_STATE_CHUNK_END:
		if (!read_metadata (msg, SOUP_MESSAGE_IO_EOL))
			return;

		g_byte_array_set_size (io->read_meta_buf, 0);
		io->read_state = SOUP_MESSAGE_IO_STATE_CHUNK_SIZE;
		break;


	case SOUP_MESSAGE_IO_STATE_TRAILERS:
		if (!read_metadata (msg, SOUP_MESSAGE_IO_EOL))
			return;

		if (io->read_meta_buf->len == SOUP_MESSAGE_IO_EOL_LEN)
			goto got_body;

		/* FIXME: process trailers */
		g_byte_array_set_size (io->read_meta_buf, 0);
		break;


	case SOUP_MESSAGE_IO_STATE_DONE:
		if (io->mode == SOUP_MESSAGE_IO_SERVER) {
			io->write_state = SOUP_MESSAGE_IO_STATE_HEADERS;
			io_write (sock, msg);
		} else
			soup_message_io_finished (msg);
		return;


	default:
		g_return_if_reached ();
	}

	goto read_more;
}

static SoupMessageIOData *
new_iostate (SoupMessage *msg, SoupSocket *sock, SoupMessageIOMode mode,
	     SoupMessageGetHeadersFn get_headers_cb,
	     SoupMessageParseHeadersFn parse_headers_cb,
	     gpointer user_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io;

	io = g_new0 (SoupMessageIOData, 1);
	io->sock = g_object_ref (sock);
	io->mode = mode;
	io->get_headers_cb   = get_headers_cb;
	io->parse_headers_cb = parse_headers_cb;
	io->user_data        = user_data;

	io->read_encoding    = SOUP_TRANSFER_UNKNOWN;
	io->write_encoding   = SOUP_TRANSFER_UNKNOWN;

	io->read_meta_buf    = g_byte_array_new ();
	if (!(priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS))
		io->read_buf = g_byte_array_new ();
	io->write_buf        = g_string_new (NULL);

	io->read_tag  = g_signal_connect (io->sock, "readable",
					  G_CALLBACK (io_read), msg);
	io->write_tag = g_signal_connect (io->sock, "writable",
					  G_CALLBACK (io_write), msg);
	io->err_tag   = g_signal_connect (io->sock, "disconnected",
					  G_CALLBACK (io_error), msg);

	io->read_state  = SOUP_MESSAGE_IO_STATE_NOT_STARTED;
	io->write_state = SOUP_MESSAGE_IO_STATE_NOT_STARTED;

	if (priv->io_data)
		io_cleanup (msg);
	priv->io_data = io;
	return io;
}

/**
 * soup_message_io_client:
 * @msg: a #SoupMessage
 * @sock: socket to send @msg across
 * @conn: the connection that owns @sock (or %NULL)
 * @get_headers_cb: callback function to generate request headers
 * @parse_headers_cb: callback function to parse response headers
 * @user_data: data to pass to the callbacks
 *
 * Begins the process of sending @msg across @sock.
 *
 * Don't call this. Use soup_message_send_request().
 **/
void
soup_message_io_client (SoupMessage *msg, SoupSocket *sock,
			SoupConnection *conn,
			SoupMessageGetHeadersFn get_headers_cb,
			SoupMessageParseHeadersFn parse_headers_cb,
			gpointer user_data)
{
	SoupMessageIOData *io;

	io = new_iostate (msg, sock, SOUP_MESSAGE_IO_CLIENT,
			  get_headers_cb, parse_headers_cb, user_data);

	if (conn)
		io->conn = g_object_ref (conn);

	io->read_body       = &msg->response;
	io->write_body      = &msg->request;

	io->write_state     = SOUP_MESSAGE_IO_STATE_HEADERS;
	io_write (sock, msg);
}

/**
 * soup_message_io_server:
 * @msg: an empty #SoupServerMessage
 * @sock: socket to receive a request on
 * @get_headers_cb: callback function to generate response headers
 * @parse_headers_cb: callback function to parse request headers
 * @user_data: data to pass to the callbacks
 *
 * Begins the process of receiving a request from @sock into @msg.
 *
 * Don't use this. Use soup_message_receive_request() instead.
 **/
void
soup_message_io_server (SoupMessage *msg, SoupSocket *sock,
			SoupMessageGetHeadersFn get_headers_cb,
			SoupMessageParseHeadersFn parse_headers_cb,
			gpointer user_data)
{
	SoupMessageIOData *io;

	io = new_iostate (msg, sock, SOUP_MESSAGE_IO_SERVER,
			  get_headers_cb, parse_headers_cb, user_data);

	io->read_body       = &msg->request;
	io->write_body      = &msg->response;

	io->read_state      = SOUP_MESSAGE_IO_STATE_HEADERS;
	io_read (sock, msg);
}

/**
 * soup_message_io_pause:
 * @msg: a #SoupMessage
 *
 * Pauses I/O on @msg.
 **/
void  
soup_message_io_pause (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	g_return_if_fail (io != NULL);

	if (io->write_tag) {
		g_signal_handler_disconnect (io->sock, io->write_tag);
		io->write_tag = 0;
	}
	if (io->read_tag) {
		g_signal_handler_disconnect (io->sock, io->read_tag);
		io->read_tag = 0;
	}
}

/**
 * soup_message_io_unpause:
 * @msg: a #SoupMessage
 *
 * Resumes I/O on @msg.
 **/
void  
soup_message_io_unpause (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageIOData *io = priv->io_data;

	g_return_if_fail (io != NULL);

	if (io->write_tag || io->read_tag)
		return;

	io->write_tag = g_signal_connect (io->sock, "writable",
					  G_CALLBACK (io_write), msg);
	io->read_tag = g_signal_connect (io->sock, "readable",
					 G_CALLBACK (io_read), msg);

	if (io->write_state != SOUP_MESSAGE_IO_STATE_NOT_STARTED &&
	    io->write_state != SOUP_MESSAGE_IO_STATE_BLOCKING)
		io_write (io->sock, msg);
	else
		io_read (io->sock, msg);
}
