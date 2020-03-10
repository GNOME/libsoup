/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-websocket-connection.c: This file was originally part of Cockpit.
 *
 * Copyright 2013, 2014 Red Hat, Inc.
 *
 * Cockpit is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * Cockpit is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <string.h>

#include "soup-websocket-connection.h"
#include "soup-enum-types.h"
#include "soup-io-stream.h"
#include "soup-uri.h"
#include "soup-websocket-extension.h"

/*
 * SECTION:websocketconnection
 * @title: SoupWebsocketConnection
 * @short_description: A WebSocket connection
 *
 * A #SoupWebsocketConnection is a WebSocket connection to a peer.
 * This API is modeled after the W3C API for interacting with
 * WebSockets.
 *
 * The #SoupWebsocketConnection:state property will indicate the
 * state of the connection.
 *
 * Use soup_websocket_connection_send() to send a message to the peer.
 * When a message is received the #SoupWebsocketConnection::message
 * signal will fire.
 *
 * The soup_websocket_connection_close() function will perform an
 * orderly close of the connection. The
 * #SoupWebsocketConnection::closed signal will fire once the
 * connection closes, whether it was initiated by this side or the
 * peer.
 *
 * Connect to the #SoupWebsocketConnection::closing signal to detect
 * when either peer begins closing the connection.
 */

/**
 * SoupWebsocketConnection:
 *
 * A class representing a WebSocket connection.
 *
 * Since: 2.50
 */

/**
 * SoupWebsocketConnectionClass:
 * @message: default handler for the #SoupWebsocketConnection::message signal
 * @error: default handler for the #SoupWebsocketConnection::error signal
 * @closing: the default handler for the #SoupWebsocketConnection:closing signal
 * @closed: default handler for the #SoupWebsocketConnection::closed signal
 * @pong: default handler for the #SoupWebsocketConnection::pong signal
 *
 * The abstract base class for #SoupWebsocketConnection
 *
 * Since: 2.50
 */

enum {
	PROP_0,
	PROP_IO_STREAM,
	PROP_CONNECTION_TYPE,
	PROP_URI,
	PROP_ORIGIN,
	PROP_PROTOCOL,
	PROP_STATE,
	PROP_MAX_INCOMING_PAYLOAD_SIZE,
	PROP_KEEPALIVE_INTERVAL,
	PROP_EXTENSIONS
};

enum {
	MESSAGE,
	ERROR,
	CLOSING,
	CLOSED,
	PONG,
	NUM_SIGNALS
};

static guint signals[NUM_SIGNALS] = { 0, };

typedef enum {
	SOUP_WEBSOCKET_QUEUE_NORMAL = 0,
	SOUP_WEBSOCKET_QUEUE_URGENT = 1 << 0,
	SOUP_WEBSOCKET_QUEUE_LAST = 1 << 1,
} SoupWebsocketQueueFlags;

typedef struct {
	GBytes *data;
	gsize sent;
	gsize amount;
	SoupWebsocketQueueFlags flags;
	gboolean pending;
} Frame;

struct _SoupWebsocketConnectionPrivate {
	GIOStream *io_stream;
	SoupWebsocketConnectionType connection_type;
	SoupURI *uri;
	char *origin;
	char *protocol;
	guint64 max_incoming_payload_size;
	guint keepalive_interval;

	gushort peer_close_code;
	char *peer_close_data;
	gboolean close_sent;
	gboolean close_received;
	gboolean dirty_close;
	GSource *close_timeout;

	GMainContext *main_context;

	gboolean io_closing;
	gboolean io_closed;

	GPollableInputStream *input;
	GSource *input_source;
	GByteArray *incoming;

	GPollableOutputStream *output;
	GSource *output_source;
	GQueue outgoing;

	/* Current message being assembled */
	guint8 message_opcode;
	GByteArray *message_data;

	GSource *keepalive_timeout;

	GList *extensions;
};

#define MAX_INCOMING_PAYLOAD_SIZE_DEFAULT   128 * 1024
#define READ_BUFFER_SIZE 1024
#define MASK_LENGTH 4

G_DEFINE_TYPE_WITH_PRIVATE (SoupWebsocketConnection, soup_websocket_connection, G_TYPE_OBJECT)

static void queue_frame (SoupWebsocketConnection *self, SoupWebsocketQueueFlags flags,
			 gpointer data, gsize len, gsize amount);

static void emit_error_and_close (SoupWebsocketConnection *self,
				  GError *error, gboolean prejudice);

static void protocol_error_and_close (SoupWebsocketConnection *self);

static gboolean on_web_socket_input (GObject *pollable_stream,
				     gpointer user_data);
static gboolean on_web_socket_output (GObject *pollable_stream,
				      gpointer user_data);

/* Code below is based on g_utf8_validate() implementation,
 * but handling NULL characters as valid, as expected by
 * WebSockets and compliant with RFC 3629.
 */
#define VALIDATE_BYTE(mask, expect)                             \
        G_STMT_START {                                          \
          if (G_UNLIKELY((*(guchar *)p & (mask)) != (expect)))  \
                  return FALSE;                                 \
        } G_STMT_END

/* see IETF RFC 3629 Section 4 */
static gboolean
utf8_validate (const char *str,
               gsize max_len)

{
        const gchar *p;

        for (p = str; ((p - str) < max_len); p++) {
                if (*(guchar *)p < 128)
                        /* done */;
                else {
                        if (*(guchar *)p < 0xe0) { /* 110xxxxx */
                                if (G_UNLIKELY (max_len - (p - str) < 2))
                                        return FALSE;

                                if (G_UNLIKELY (*(guchar *)p < 0xc2))
                                        return FALSE;
                        } else {
                                if (*(guchar *)p < 0xf0) { /* 1110xxxx */
                                        if (G_UNLIKELY (max_len - (p - str) < 3))
                                                return FALSE;

                                        switch (*(guchar *)p++ & 0x0f) {
                                        case 0:
                                                VALIDATE_BYTE(0xe0, 0xa0); /* 0xa0 ... 0xbf */
                                                break;
                                        case 0x0d:
                                                VALIDATE_BYTE(0xe0, 0x80); /* 0x80 ... 0x9f */
                                                break;
                                        default:
                                                VALIDATE_BYTE(0xc0, 0x80); /* 10xxxxxx */
                                        }
                                } else if (*(guchar *)p < 0xf5) { /* 11110xxx excluding out-of-range */
                                        if (G_UNLIKELY (max_len - (p - str) < 4))
                                                return FALSE;

                                        switch (*(guchar *)p++ & 0x07) {
                                        case 0:
                                                VALIDATE_BYTE(0xc0, 0x80); /* 10xxxxxx */
                                                if (G_UNLIKELY((*(guchar *)p & 0x30) == 0))
                                                        return FALSE;
                                                break;
                                        case 4:
                                                VALIDATE_BYTE(0xf0, 0x80); /* 0x80 ... 0x8f */
                                                break;
                                        default:
                                                VALIDATE_BYTE(0xc0, 0x80); /* 10xxxxxx */
                                        }
                                        p++;
                                        VALIDATE_BYTE(0xc0, 0x80); /* 10xxxxxx */
                                } else {
                                        return FALSE;
                                }
                        }

                        p++;
                        VALIDATE_BYTE(0xc0, 0x80); /* 10xxxxxx */
                }
        }

        return TRUE;
}

#undef VALIDATE_BYTE

static void
frame_free (gpointer data)
{
	Frame *frame = data;

	if (frame) {
		g_bytes_unref (frame->data);
		g_slice_free (Frame, frame);
	}
}

static void
soup_websocket_connection_init (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv;

	pv = self->pv = soup_websocket_connection_get_instance_private (self);

	pv->incoming = g_byte_array_sized_new (1024);
	g_queue_init (&pv->outgoing);
	pv->main_context = g_main_context_ref_thread_default ();
}

static void
on_iostream_closed (GObject *source,
                    GAsyncResult *result,
                    gpointer user_data)
{
	SoupWebsocketConnection *self = user_data;
	SoupWebsocketConnectionPrivate *pv = self->pv;
	GError *error = NULL;

	/* We treat connection as closed even if close fails */
	pv->io_closed = TRUE;
	g_io_stream_close_finish (pv->io_stream, result, &error);

	if (error) {
		g_debug ("error closing web socket stream: %s", error->message);
		if (!pv->dirty_close)
			g_signal_emit (self, signals[ERROR], 0, error);
		pv->dirty_close = TRUE;
		g_error_free (error);
	}

	g_assert (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_CLOSED);
	g_debug ("closed: completed io stream close");
	g_signal_emit (self, signals[CLOSED], 0);

	g_object_unref (self);
}

static void
soup_websocket_connection_start_input_source (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->input_source)
		return;

	pv->input_source = g_pollable_input_stream_create_source (pv->input, NULL);
	g_source_set_callback (pv->input_source, (GSourceFunc)on_web_socket_input, self, NULL);
	g_source_attach (pv->input_source, pv->main_context);
}

static void
soup_websocket_connection_stop_input_source (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->input_source) {
		g_debug ("stopping input source");
		g_source_destroy (pv->input_source);
		g_source_unref (pv->input_source);
		pv->input_source = NULL;
	}
}

static void
soup_websocket_connection_start_output_source (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->output_source)
		return;

	pv->output_source = g_pollable_output_stream_create_source (pv->output, NULL);
	g_source_set_callback (pv->output_source, (GSourceFunc)on_web_socket_output, self, NULL);
	g_source_attach (pv->output_source, pv->main_context);
}

static void
soup_websocket_connection_stop_output_source (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->output_source) {
		g_debug ("stopping output source");
		g_source_destroy (pv->output_source);
		g_source_unref (pv->output_source);
		pv->output_source = NULL;
	}
}

static void
keepalive_stop_timeout (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->keepalive_timeout) {
		g_source_destroy (pv->keepalive_timeout);
		g_source_unref (pv->keepalive_timeout);
		pv->keepalive_timeout = NULL;
	}
}

static void
close_io_stop_timeout (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	if (pv->close_timeout) {
		g_source_destroy (pv->close_timeout);
		g_source_unref (pv->close_timeout);
		pv->close_timeout = NULL;
	}
}

static void
close_io_stream (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	keepalive_stop_timeout (self);
	close_io_stop_timeout (self);

	if (!pv->io_closing) {
		soup_websocket_connection_stop_input_source (self);
		soup_websocket_connection_stop_output_source (self);
		pv->io_closing = TRUE;
		g_debug ("closing io stream");
		g_io_stream_close_async (pv->io_stream, G_PRIORITY_DEFAULT,
					 NULL, on_iostream_closed, g_object_ref (self));
	}

	g_object_notify (G_OBJECT (self), "state");
}

static void
shutdown_wr_io_stream (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	GSocket *socket;
	GIOStream *base_iostream;
	GError *error = NULL;

	soup_websocket_connection_stop_output_source (self);

	base_iostream = SOUP_IS_IO_STREAM (pv->io_stream) ?
		soup_io_stream_get_base_iostream (SOUP_IO_STREAM (pv->io_stream)) :
		pv->io_stream;

	if (G_IS_SOCKET_CONNECTION (base_iostream)) {
		socket = g_socket_connection_get_socket (G_SOCKET_CONNECTION (base_iostream));
		g_socket_shutdown (socket, FALSE, TRUE, &error);
		if (error != NULL) {
			g_debug ("error shutting down io stream: %s", error->message);
			g_error_free (error);
		}
	}

	g_object_notify (G_OBJECT (self), "state");
}

static gboolean
on_timeout_close_io (gpointer user_data)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (user_data);
	SoupWebsocketConnectionPrivate *pv = self->pv;

	pv->close_timeout = 0;

	g_debug ("peer did not close io when expected");
	close_io_stream (self);

	return FALSE;
}

static void
close_io_after_timeout (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	const int timeout = 5;

	if (pv->close_timeout)
		return;

	g_debug ("waiting %d seconds for peer to close io", timeout);
	pv->close_timeout = g_timeout_source_new_seconds (timeout);
	g_source_set_callback (pv->close_timeout, on_timeout_close_io, self, NULL);
	g_source_attach (pv->close_timeout, pv->main_context);
}

static void
xor_with_mask (const guint8 *mask,
	       guint8 *data,
	       gsize len)
{
	gsize n;

	/* Do the masking */
	for (n = 0; n < len; n++)
		data[n] ^= mask[n & 3];
}

static void
send_message (SoupWebsocketConnection *self,
	      SoupWebsocketQueueFlags flags,
	      guint8 opcode,
	      const guint8 *data,
	      gsize length)
{
	gsize buffered_amount;
	GByteArray *bytes;
	gsize frame_len;
	guint8 *outer;
	guint8 mask_offset;
	GBytes *filtered_bytes;
	GList *l;
	GError *error = NULL;

	if (!(soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_OPEN)) {
		g_debug ("Ignoring message since the connection is closed or is closing");
		return;
	}

	bytes = g_byte_array_sized_new (14 + length);
	outer = bytes->data;
	outer[0] = 0x80 | opcode;

	filtered_bytes = g_bytes_new_static (data, length);
	for (l = self->pv->extensions; l != NULL; l = g_list_next (l)) {
		SoupWebsocketExtension *extension;

		extension = (SoupWebsocketExtension *)l->data;
		filtered_bytes = soup_websocket_extension_process_outgoing_message (extension, outer, filtered_bytes, &error);
		if (error) {
			g_byte_array_free (bytes, TRUE);
			emit_error_and_close (self, error, FALSE);
			return;
		}
	}

	data = g_bytes_get_data (filtered_bytes, &length);
	buffered_amount = length;

	/* If control message, check payload size */
	if (opcode & 0x08) {
		if (length > 125) {
			g_warning ("WebSocket control message payload exceeds size limit");
			protocol_error_and_close (self);
			g_byte_array_free (bytes, TRUE);
			g_bytes_unref (filtered_bytes);
			return;
		}

		buffered_amount = 0;
	}

	if (length < 126) {
		outer[1] = (0xFF & length); /* mask | 7-bit-len */
		bytes->len = 2;
	} else if (length < 65536) {
		outer[1] = 126; /* mask | 16-bit-len */
		outer[2] = (length >> 8) & 0xFF;
		outer[3] = (length >> 0) & 0xFF;
		bytes->len = 4;
	} else {
		outer[1] = 127; /* mask | 64-bit-len */
#if GLIB_SIZEOF_SIZE_T > 4
		outer[2] = (length >> 56) & 0xFF;
		outer[3] = (length >> 48) & 0xFF;
		outer[4] = (length >> 40) & 0xFF;
		outer[5] = (length >> 32) & 0xFF;
#else
		outer[2] = outer[3] = outer[4] = outer[5] = 0;
#endif
		outer[6] = (length >> 24) & 0xFF;
		outer[7] = (length >> 16) & 0xFF;
		outer[8] = (length >> 8) & 0xFF;
		outer[9] = (length >> 0) & 0xFF;
		bytes->len = 10;
	}

	/* The server side doesn't need to mask, so we don't. There's
	 * probably a client somewhere that's not expecting it.
	 */
	if (self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_CLIENT) {
		guint32 rnd = g_random_int ();
		outer[1] |= 0x80;
		mask_offset = bytes->len;
		memcpy (outer + mask_offset, &rnd, sizeof (rnd));
		bytes->len += MASK_LENGTH;
	}

	g_byte_array_append (bytes, data, length);

	if (self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_CLIENT)
		xor_with_mask (bytes->data + mask_offset, bytes->data + mask_offset + MASK_LENGTH, length);

	frame_len = bytes->len;
	queue_frame (self, flags, g_byte_array_free (bytes, FALSE),
		     frame_len, buffered_amount);
	g_bytes_unref (filtered_bytes);
	g_debug ("queued %d frame of len %u", (int)opcode, (guint)frame_len);
}

static void
send_close (SoupWebsocketConnection *self,
	    SoupWebsocketQueueFlags flags,
	    gushort code,
	    const char *reason)
{
	/* Note that send_message truncates as expected */
	char buffer[128];
	gsize len = 0;

	if (code != 0) {
		buffer[len++] = code >> 8;
		buffer[len++] = code & 0xFF;
		if (reason)
			len += g_strlcpy (buffer + len, reason, sizeof (buffer) - len);
	}

	send_message (self, flags, 0x08, (guint8 *)buffer, len);
	self->pv->close_sent = TRUE;

	keepalive_stop_timeout (self);
}

static void
emit_error_and_close (SoupWebsocketConnection *self,
		      GError *error,
		      gboolean prejudice)
{
	gboolean ignore = FALSE;
	gushort code;

	if (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_CLOSED) {
		g_error_free (error);
		return;
	}

	if (error && error->domain == SOUP_WEBSOCKET_ERROR)
		code = error->code;
	else
		code = SOUP_WEBSOCKET_CLOSE_GOING_AWAY;

	self->pv->dirty_close = TRUE;
	g_signal_emit (self, signals[ERROR], 0, error);
	g_error_free (error);

	/* If already closing, just ignore this stuff */
	switch (soup_websocket_connection_get_state (self)) {
	case SOUP_WEBSOCKET_STATE_CLOSED:
		ignore = TRUE;
		break;
	case SOUP_WEBSOCKET_STATE_CLOSING:
		ignore = !prejudice;
		break;
	default:
		break;
	}

	if (ignore) {
		g_debug ("already closing/closed, ignoring error");
	} else if (prejudice) {
		g_debug ("forcing close due to error");
		close_io_stream (self);
	} else {
		g_debug ("requesting close due to error");
		send_close (self, SOUP_WEBSOCKET_QUEUE_URGENT | SOUP_WEBSOCKET_QUEUE_LAST, code, NULL);
	}
}

static void
protocol_error_and_close_full (SoupWebsocketConnection *self,
                               gboolean prejudice)
{
	GError *error;

	error = g_error_new_literal (SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR,
				     self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER ?
				     "Received invalid WebSocket response from the client" :
				     "Received invalid WebSocket response from the server");
	emit_error_and_close (self, error, prejudice);
}

static void
protocol_error_and_close (SoupWebsocketConnection *self)
{
	protocol_error_and_close_full (self, FALSE);
}

static void
bad_data_error_and_close (SoupWebsocketConnection *self)
{
	GError *error;

	error = g_error_new_literal (SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_CLOSE_BAD_DATA,
				     self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER ?
				     "Received invalid WebSocket data from the client" :
				     "Received invalid WebSocket data from the server");
	emit_error_and_close (self, error, FALSE);
}

static void
too_big_error_and_close (SoupWebsocketConnection *self,
                         guint64 payload_len)
{
	GError *error;

	error = g_error_new_literal (SOUP_WEBSOCKET_ERROR,
				     SOUP_WEBSOCKET_CLOSE_TOO_BIG,
				     self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER ?
				     "Received extremely large WebSocket data from the client" :
				     "Received extremely large WebSocket data from the server");
	g_debug ("%s is trying to frame of size %" G_GUINT64_FORMAT " or greater, but max supported size is %" G_GUINT64_FORMAT,
		 self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER ? "server" : "client",
	         payload_len, self->pv->max_incoming_payload_size);
	emit_error_and_close (self, error, TRUE);
}

static void
close_connection (SoupWebsocketConnection *self,
                  gushort                  code,
                  const char              *data)
{
	SoupWebsocketQueueFlags flags;
	SoupWebsocketConnectionPrivate *pv;

	pv = self->pv;

	if (pv->close_sent) {
		g_debug ("close code already sent");
		return;
	}

	/* Validate the closing code received by the peer */
	switch (code) {
	case SOUP_WEBSOCKET_CLOSE_NORMAL:
	case SOUP_WEBSOCKET_CLOSE_GOING_AWAY:
	case SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR:
	case SOUP_WEBSOCKET_CLOSE_UNSUPPORTED_DATA:
	case SOUP_WEBSOCKET_CLOSE_BAD_DATA:
	case SOUP_WEBSOCKET_CLOSE_POLICY_VIOLATION:
	case SOUP_WEBSOCKET_CLOSE_TOO_BIG:
		break;
	case SOUP_WEBSOCKET_CLOSE_NO_EXTENSION:
		if (pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER) {
			g_debug ("Wrong closing code %d received for a server connection",
			         code);
		}
		break;
	case SOUP_WEBSOCKET_CLOSE_SERVER_ERROR:
		if (pv->connection_type != SOUP_WEBSOCKET_CONNECTION_SERVER) {
			g_debug ("Wrong closing code %d received for a non server connection",
			         code);
		}
		break;
	case SOUP_WEBSOCKET_CLOSE_NO_STATUS:
		/* This is special case to send a close message with no body */
		code = 0;
		break;
	default:
		if (code < 3000) {
			g_debug ("Wrong closing code %d received", code);
			protocol_error_and_close (self);
			return;
		}
	}

	g_signal_emit (self, signals[CLOSING], 0);

	if (pv->close_received)
		g_debug ("responding to close request");

	flags = 0;
	if (pv->close_received)
		flags |= SOUP_WEBSOCKET_QUEUE_LAST;
	send_close (self, flags, code, data);
	close_io_after_timeout (self);
}

static void
receive_close (SoupWebsocketConnection *self,
	       const guint8 *data,
	       gsize len)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;

	pv->peer_close_code = 0;
	g_free (pv->peer_close_data);
	pv->peer_close_data = NULL;
	pv->close_received = TRUE;

	switch (len) {
	case 0:
		/* Send a clean close when having an empty payload */
		pv->peer_close_code = SOUP_WEBSOCKET_CLOSE_NO_STATUS;
		close_connection (self, 1000, NULL);
		return;
	case 1:
		/* Send a protocol error since the close code is incomplete */
		protocol_error_and_close (self);
		return;
	default:
		/* Store the code/data payload */
		pv->peer_close_code = (guint16)data[0] << 8 | data[1];
		break;
	}

	if (len > 2) {
		data += 2;
		len -= 2;
		
		if (!utf8_validate ((const char *)data, len)) {
			g_debug ("received non-UTF8 close data: %d '%.*s' %d", (int)len, (int)len, (char *)data, (int)data[0]);
			protocol_error_and_close (self);
			return;
		}

		pv->peer_close_data = g_strndup ((char *)data, len);
	}

	/* Once we receive close response on server, close immediately */
	if (pv->close_sent) {
		shutdown_wr_io_stream (self);
		if (pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER)
			close_io_stream (self);
	} else {
		close_connection (self, pv->peer_close_code, pv->peer_close_data);
	}
}

static void
receive_ping (SoupWebsocketConnection *self,
                      const guint8 *data,
                      gsize len)
{
	/* Send back a pong with same data */
	g_debug ("received ping, responding");
	send_message (self, SOUP_WEBSOCKET_QUEUE_URGENT, 0x0A, data, len);
}

static void
receive_pong (SoupWebsocketConnection *self,
                      const guint8 *data,
                      gsize len)
{
	GByteArray *bytes;

	g_debug ("received pong message");

	bytes = g_byte_array_sized_new (len + 1);
	g_byte_array_append (bytes, data, len);
	/* Always null terminate, as a convenience */
	g_byte_array_append (bytes, (guchar *)"\0", 1);
	/* But don't include the null terminator in the byte count */
	bytes->len--;

	g_signal_emit (self, signals[PONG], 0, bytes);
	g_byte_array_unref (bytes);

}

static void
process_contents (SoupWebsocketConnection *self,
		  gboolean control,
		  gboolean fin,
		  guint8 opcode,
		  GBytes *payload_data)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	GBytes *message;
	gconstpointer payload;
	gsize payload_len;

	payload = g_bytes_get_data (payload_data, &payload_len);

	if (pv->close_sent && pv->close_received)
		return;

	if (control) {
		/* Control frames must never be fragmented */
		if (!fin) {
			g_debug ("received fragmented control frame");
			protocol_error_and_close (self);
			return;
		}

		g_debug ("received control frame %d with %d payload", (int)opcode, (int)payload_len);

		switch (opcode) {
		case 0x08:
			receive_close (self, payload, payload_len);
			break;
		case 0x09:
			receive_ping (self, payload, payload_len);
			break;
		case 0x0A:
			receive_pong (self, payload, payload_len);
			break;
		default:
			g_debug ("received unsupported control frame: %d", (int)opcode);
			protocol_error_and_close (self);
			return;
		}
	} else if (pv->close_received) {
		g_debug ("received message after close was received");
	} else {
		/* A message frame */

		if (!fin && opcode) {
			/* Initial fragment of a message */
			if (pv->message_data) {
				g_debug ("received out of order initial message fragment");
				protocol_error_and_close (self);
				return;
			}
			g_debug ("received initial fragment frame %d with %d payload", (int)opcode, (int)payload_len);
		} else if (!fin && !opcode) {
			/* Middle fragment of a message */
			if (!pv->message_data) {
				g_debug ("received out of order middle message fragment");
				protocol_error_and_close (self);
				return;
			}
			g_debug ("received middle fragment frame with %d payload", (int)payload_len);
		} else if (fin && !opcode) {
			/* Last fragment of a message */
			if (!pv->message_data) {
				g_debug ("received out of order ending message fragment");
				protocol_error_and_close (self);
				return;
			}
			g_debug ("received last fragment frame with %d payload", (int)payload_len);
		} else {
			/* An unfragmented message */
			g_assert (opcode != 0);
			if (pv->message_data) {
				g_debug ("received unfragmented message when fragment was expected");
				protocol_error_and_close (self);
				return;
			}
			g_debug ("received frame %d with %d payload", (int)opcode, (int)payload_len);
		}

		if (opcode) {
			pv->message_opcode = opcode;
			pv->message_data = g_byte_array_sized_new (payload_len + 1);
		}

		switch (pv->message_opcode) {
		case 0x01:
		case 0x02:
			g_byte_array_append (pv->message_data, payload, payload_len);
			break;
		default:
			g_debug ("received unknown data frame: %d", (int)opcode);
			protocol_error_and_close (self);
			return;
		}

		/* Actually deliver the message? */
		if (fin) {
			if (pv->message_opcode == 0x01 &&
			    !utf8_validate((const char *)pv->message_data->data,
					   pv->message_data->len)) {

				g_debug ("received invalid non-UTF8 text data");

				/* Discard the entire message */
				g_byte_array_unref (pv->message_data);
				pv->message_data = NULL;
				pv->message_opcode = 0;

				bad_data_error_and_close (self);
				return;
			}

			/* Always null terminate, as a convenience */
			g_byte_array_append (pv->message_data, (guchar *)"\0", 1);

			/* But don't include the null terminator in the byte count */
			pv->message_data->len--;

			opcode = pv->message_opcode;
			message = g_byte_array_free_to_bytes (pv->message_data);
			pv->message_data = NULL;
			pv->message_opcode = 0;
			g_debug ("message: delivering %d with %d length",
				 (int)opcode, (int)g_bytes_get_size (message));
			g_signal_emit (self, signals[MESSAGE], 0, (int)opcode, message);
			g_bytes_unref (message);
		}
	}
}

static gboolean
process_frame (SoupWebsocketConnection *self)
{
	guint8 *header;
	guint8 *payload;
	guint64 payload_len;
	guint8 *mask;
	gboolean fin;
	gboolean control;
	gboolean masked;
	guint8 opcode;
	gsize len;
	gsize at;
	GBytes *filtered_bytes;
	GList *l;
	GError *error = NULL;

	len = self->pv->incoming->len;
	if (len < 2)
		return FALSE; /* need more data */

	header = self->pv->incoming->data;
	fin = ((header[0] & 0x80) != 0);
	control = header[0] & 0x08;
	opcode = header[0] & 0x0f;
	masked = ((header[1] & 0x80) != 0);

	if (self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_CLIENT && masked) {
		/* A server MUST NOT mask any frames that it sends to the client.
		 * A client MUST close a connection if it detects a masked frame.
		 */
		g_debug ("A server must not mask any frames that it sends to the client.");
		protocol_error_and_close (self);
		return FALSE;
	}

	if (self->pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER && !masked) {
		/* The server MUST close the connection upon receiving a frame
		 * that is not masked.
		 */
		g_debug ("The client should always mask frames");
		protocol_error_and_close (self);
                return FALSE;
        }

	switch (header[1] & 0x7f) {
	case 126:
		/* If 126, the following 2 bytes interpreted as a 16-bit
		 * unsigned integer are the payload length.
		 */
		at = 4;
		if (len < at)
			return FALSE; /* need more data */
		payload_len = (((guint16)header[2] << 8) |
			       ((guint16)header[3] << 0));

		/* The minimal number of bytes MUST be used to encode the length. */
		if (payload_len <= 125) {
			protocol_error_and_close (self);
			return FALSE;
		}
		break;
	case 127:
		/* If 127, the following 8 bytes interpreted as a 64-bit
		 * unsigned integer (the most significant bit MUST be 0)
		 * are the payload length.
		 */
		at = 10;
		if (len < at)
			return FALSE; /* need more data */
		payload_len = (((guint64)header[2] << 56) |
			       ((guint64)header[3] << 48) |
			       ((guint64)header[4] << 40) |
			       ((guint64)header[5] << 32) |
			       ((guint64)header[6] << 24) |
			       ((guint64)header[7] << 16) |
			       ((guint64)header[8] << 8) |
			       ((guint64)header[9] << 0));

		/* The minimal number of bytes MUST be used to encode the length. */
		if (payload_len <= G_MAXUINT16) {
			protocol_error_and_close (self);
			return FALSE;
		}
		break;
	default:
		payload_len = header[1] & 0x7f;
		at = 2;
		break;
	}

	/* Safety valve */
	if (self->pv->max_incoming_payload_size > 0 &&
	    payload_len >= self->pv->max_incoming_payload_size) {
		too_big_error_and_close (self, payload_len);
		return FALSE;
	}

	if (len < at + payload_len)
		return FALSE; /* need more data */

	payload = header + at;

	if (masked) {
		mask = header + at;
		payload += 4;
		at += 4;

		if (len < at + payload_len)
			return FALSE; /* need more data */

		xor_with_mask (mask, payload, payload_len);
	}

	filtered_bytes = g_bytes_new_static (payload, payload_len);
	for (l = self->pv->extensions; l != NULL; l = g_list_next (l)) {
		SoupWebsocketExtension *extension;

		extension = (SoupWebsocketExtension *)l->data;
		filtered_bytes = soup_websocket_extension_process_incoming_message (extension, self->pv->incoming->data, filtered_bytes, &error);
		if (error) {
			emit_error_and_close (self, error, FALSE);
			return FALSE;
		}
	}

	/* After being processed by extensions reserved bits must be 0 */
	if (header[0] & 0x70) {
		protocol_error_and_close (self);
		g_bytes_unref (filtered_bytes);

		return FALSE;
	}

	/* Note that now that we've unmasked, we've modified the buffer, we can
	 * only return below via discarding or processing the message
	 */
	process_contents (self, control, fin, opcode, filtered_bytes);
	g_bytes_unref (filtered_bytes);

	/* Move past the parsed frame */
	g_byte_array_remove_range (self->pv->incoming, 0, at + payload_len);

	return TRUE;
}

static void
process_incoming (SoupWebsocketConnection *self)
{
	while (process_frame (self))
		;
}

static void
soup_websocket_connection_read (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	GError *error = NULL;
	gboolean end = FALSE;
	gssize count;
	gsize len;

	soup_websocket_connection_stop_input_source (self);

	do {
		len = pv->incoming->len;
		g_byte_array_set_size (pv->incoming, len + READ_BUFFER_SIZE);

		count = g_pollable_input_stream_read_nonblocking (pv->input,
								  pv->incoming->data + len,
								  READ_BUFFER_SIZE, NULL, &error);
		if (count < 0) {
			if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
				g_error_free (error);
				count = 0;
			} else {
				emit_error_and_close (self, error, TRUE);
				return;
			}
		} else if (count == 0) {
			end = TRUE;
		}

		pv->incoming->len = len + count;
	} while (count > 0);

	process_incoming (self);

	if (end) {
		if (!pv->close_sent || !pv->close_received) {
			pv->dirty_close = TRUE;
			g_debug ("connection unexpectedly closed by peer");
		} else {
			g_debug ("peer has closed socket");
		}

		close_io_stream (self);
		return;
	}

	if (!pv->io_closing)
		soup_websocket_connection_start_input_source (self);
}

static gboolean
on_web_socket_input (GObject *pollable_stream,
		     gpointer user_data)
{
	soup_websocket_connection_read (SOUP_WEBSOCKET_CONNECTION (user_data));

	return G_SOURCE_REMOVE;
}

static void
soup_websocket_connection_write (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	const guint8 *data;
	GError *error = NULL;
	Frame *frame;
	gssize count;
	gsize len;

	soup_websocket_connection_stop_output_source (self);

	if (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_CLOSED) {
		g_debug ("Ignoring message since the connection is closed");
		return;
	}

	frame = g_queue_peek_head (&pv->outgoing);

	/* No more frames to send */
	if (frame == NULL)
		return;

	data = g_bytes_get_data (frame->data, &len);
	g_assert (len > 0);
	g_assert (len > frame->sent);

	count = g_pollable_output_stream_write_nonblocking (pv->output,
							    data + frame->sent,
							    len - frame->sent,
							    NULL, &error);

	if (count < 0) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			g_clear_error (&error);
			count = 0;

			g_debug ("failed to send frame because it would block, marking as pending");
			frame->pending = TRUE;
		} else {
			emit_error_and_close (self, error, TRUE);
			return;
		}
	}

	frame->sent += count;
	if (frame->sent >= len) {
		g_debug ("sent frame");
		g_queue_pop_head (&pv->outgoing);

		if (frame->flags & SOUP_WEBSOCKET_QUEUE_LAST) {
			if (pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER) {
				close_io_stream (self);
			} else {
				shutdown_wr_io_stream (self);
				close_io_after_timeout (self);
			}
		}
		frame_free (frame);

		if (g_queue_is_empty (&pv->outgoing))
			return;
	}

	soup_websocket_connection_start_output_source (self);
}

static gboolean
on_web_socket_output (GObject *pollable_stream,
		      gpointer user_data)
{
	soup_websocket_connection_write (SOUP_WEBSOCKET_CONNECTION (user_data));

	return G_SOURCE_REMOVE;
}

static void
queue_frame (SoupWebsocketConnection *self,
	     SoupWebsocketQueueFlags flags,
	     gpointer data,
	     gsize len,
	     gsize amount)
{
	SoupWebsocketConnectionPrivate *pv = self->pv;
	Frame *frame;

	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	g_return_if_fail (pv->close_sent == FALSE);
	g_return_if_fail (data != NULL);
	g_return_if_fail (len > 0);

	frame = g_slice_new0 (Frame);
	frame->data = g_bytes_new_take (data, len);
	frame->amount = amount;
	frame->flags = flags;

	/* If urgent put at front of queue */
	if (flags & SOUP_WEBSOCKET_QUEUE_URGENT) {
		GList *l;

		/* Find out the first frame that is not urgent or partially sent or pending */
		for (l = g_queue_peek_head_link (&pv->outgoing); l != NULL; l = l->next) {
			Frame *prev = l->data;

			if (!(prev->flags & SOUP_WEBSOCKET_QUEUE_URGENT) &&
			    prev->sent == 0 && !prev->pending)
				break;
		}

		g_queue_insert_before (&pv->outgoing, l, frame);
	} else {
		g_queue_push_tail (&pv->outgoing, frame);
	}

	soup_websocket_connection_write (self);
}

static void
soup_websocket_connection_constructed (GObject *object)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (object);
	SoupWebsocketConnectionPrivate *pv = self->pv;
	GInputStream *is;
	GOutputStream *os;

	G_OBJECT_CLASS (soup_websocket_connection_parent_class)->constructed (object);

	g_return_if_fail (pv->io_stream != NULL);

	is = g_io_stream_get_input_stream (pv->io_stream);
	g_return_if_fail (G_IS_POLLABLE_INPUT_STREAM (is));
	pv->input = G_POLLABLE_INPUT_STREAM (is);
	g_return_if_fail (g_pollable_input_stream_can_poll (pv->input));

	os = g_io_stream_get_output_stream (pv->io_stream);
	g_return_if_fail (G_IS_POLLABLE_OUTPUT_STREAM (os));
	pv->output = G_POLLABLE_OUTPUT_STREAM (os);
	g_return_if_fail (g_pollable_output_stream_can_poll (pv->output));

	soup_websocket_connection_start_input_source (self);
}

static void
soup_websocket_connection_get_property (GObject *object,
					guint prop_id,
					GValue *value,
					GParamSpec *pspec)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (object);
	SoupWebsocketConnectionPrivate *pv = self->pv;

	switch (prop_id) {
	case PROP_IO_STREAM:
		g_value_set_object (value, soup_websocket_connection_get_io_stream (self));
		break;

	case PROP_CONNECTION_TYPE:
		g_value_set_enum (value, soup_websocket_connection_get_connection_type (self));
		break;

	case PROP_URI:
		g_value_set_boxed (value, soup_websocket_connection_get_uri (self));
		break;

	case PROP_ORIGIN:
		g_value_set_string (value, soup_websocket_connection_get_origin (self));
		break;

	case PROP_PROTOCOL:
		g_value_set_string (value, soup_websocket_connection_get_protocol (self));
		break;

	case PROP_STATE:
		g_value_set_enum (value, soup_websocket_connection_get_state (self));
		break;

	case PROP_MAX_INCOMING_PAYLOAD_SIZE:
		g_value_set_uint64 (value, pv->max_incoming_payload_size);
		break;

	case PROP_KEEPALIVE_INTERVAL:
		g_value_set_uint (value, pv->keepalive_interval);
		break;

	case PROP_EXTENSIONS:
		g_value_set_pointer (value, pv->extensions);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_websocket_connection_set_property (GObject *object,
					guint prop_id,
					const GValue *value,
					GParamSpec *pspec)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (object);
	SoupWebsocketConnectionPrivate *pv = self->pv;

	switch (prop_id) {
	case PROP_IO_STREAM:
		g_return_if_fail (pv->io_stream == NULL);
		pv->io_stream = g_value_dup_object (value);
		break;

	case PROP_CONNECTION_TYPE:
		pv->connection_type = g_value_get_enum (value);
		break;

	case PROP_URI:
		g_return_if_fail (pv->uri == NULL);
		pv->uri = g_value_dup_boxed (value);
		break;

	case PROP_ORIGIN:
		g_return_if_fail (pv->origin == NULL);
		pv->origin = g_value_dup_string (value);
		break;

	case PROP_PROTOCOL:
		g_return_if_fail (pv->protocol == NULL);
		pv->protocol = g_value_dup_string (value);
		break;

	case PROP_MAX_INCOMING_PAYLOAD_SIZE:
		pv->max_incoming_payload_size = g_value_get_uint64 (value);
		break;

	case PROP_KEEPALIVE_INTERVAL:
		soup_websocket_connection_set_keepalive_interval (self,
		                                                  g_value_get_uint (value));
		break;

	case PROP_EXTENSIONS:
		pv->extensions = g_value_get_pointer (value);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_websocket_connection_dispose (GObject *object)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (object);

	self->pv->dirty_close = TRUE;
	close_io_stream (self);

	G_OBJECT_CLASS (soup_websocket_connection_parent_class)->dispose (object);
}

static void
soup_websocket_connection_finalize (GObject *object)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (object);
	SoupWebsocketConnectionPrivate *pv = self->pv;

	g_free (pv->peer_close_data);

	g_main_context_unref (pv->main_context);

	if (pv->incoming)
		g_byte_array_free (pv->incoming, TRUE);
	while (!g_queue_is_empty (&pv->outgoing))
		frame_free (g_queue_pop_head (&pv->outgoing));

	g_clear_object (&pv->io_stream);
	g_assert (!pv->input_source);
	g_assert (!pv->output_source);
	g_assert (pv->io_closing);
	g_assert (pv->io_closed);
	g_assert (!pv->close_timeout);
	g_assert (!pv->keepalive_timeout);

	if (pv->message_data)
		g_byte_array_free (pv->message_data, TRUE);

	if (pv->uri)
		soup_uri_free (pv->uri);
	g_free (pv->origin);
	g_free (pv->protocol);

	g_list_free_full (pv->extensions, g_object_unref);

	G_OBJECT_CLASS (soup_websocket_connection_parent_class)->finalize (object);
}

static void
soup_websocket_connection_class_init (SoupWebsocketConnectionClass *klass)
{
	GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

	gobject_class->constructed = soup_websocket_connection_constructed;
	gobject_class->get_property = soup_websocket_connection_get_property;
	gobject_class->set_property = soup_websocket_connection_set_property;
	gobject_class->dispose = soup_websocket_connection_dispose;
	gobject_class->finalize = soup_websocket_connection_finalize;

	/**
	 * SoupWebsocketConnection:io-stream:
	 *
	 * The underlying IO stream the WebSocket is communicating
	 * over.
	 *
	 * The input and output streams must be pollable streams.
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_IO_STREAM,
					 g_param_spec_object ("io-stream",
							      "I/O Stream",
							      "Underlying I/O stream",
							      G_TYPE_IO_STREAM,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:connection-type:
	 *
	 * The type of connection (client/server).
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_CONNECTION_TYPE,
					 g_param_spec_enum ("connection-type",
							    "Connection type",
							    "Connection type (client/server)",
							    SOUP_TYPE_WEBSOCKET_CONNECTION_TYPE,
							    SOUP_WEBSOCKET_CONNECTION_UNKNOWN,
							    G_PARAM_READWRITE |
							    G_PARAM_CONSTRUCT_ONLY |
							    G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:uri:
	 *
	 * The URI of the WebSocket.
	 *
	 * For servers this represents the address of the WebSocket,
	 * and for clients it is the address connected to.
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_URI,
					 g_param_spec_boxed ("uri",
							     "URI",
							     "The WebSocket URI",
							     SOUP_TYPE_URI,
							     G_PARAM_READWRITE |
							     G_PARAM_CONSTRUCT_ONLY |
							     G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:origin:
	 *
	 * The client's Origin.
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_ORIGIN,
					 g_param_spec_string ("origin",
							      "Origin",
							      "The WebSocket origin",
							      NULL,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:protocol:
	 *
	 * The chosen protocol, or %NULL if a protocol was not agreed
	 * upon.
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_PROTOCOL,
					 g_param_spec_string ("protocol",
							      "Protocol",
							      "The chosen WebSocket protocol",
							      NULL,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:state:
	 *
	 * The current state of the WebSocket.
	 *
	 * Since: 2.50
	 */
	g_object_class_install_property (gobject_class, PROP_STATE,
					 g_param_spec_enum ("state",
							    "State",
							    "State ",
							    SOUP_TYPE_WEBSOCKET_STATE,
							    SOUP_WEBSOCKET_STATE_OPEN,
							    G_PARAM_READABLE |
							    G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:max-incoming-payload-size:
	 *
	 * The maximum payload size for incoming packets the protocol expects
	 * or 0 to not limit it.
	 *
	 * Since: 2.56
	 */
	g_object_class_install_property (gobject_class, PROP_MAX_INCOMING_PAYLOAD_SIZE,
					 g_param_spec_uint64 ("max-incoming-payload-size",
							      "Max incoming payload size",
							      "Max incoming payload size ",
							      0,
							      G_MAXUINT64,
							      MAX_INCOMING_PAYLOAD_SIZE_DEFAULT,
							      G_PARAM_READWRITE |
							      G_PARAM_CONSTRUCT |
							      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection:keepalive-interval:
	 *
	 * Interval in seconds on when to send a ping message which will
	 * serve as a keepalive message. If set to 0 the keepalive message is
	 * disabled.
	 *
	 * Since: 2.58
	 */
	g_object_class_install_property (gobject_class, PROP_KEEPALIVE_INTERVAL,
					 g_param_spec_uint ("keepalive-interval",
					                    "Keepalive interval",
					                    "Keepalive interval",
					                    0,
					                    G_MAXUINT,
					                    0,
					                    G_PARAM_READWRITE |
					                    G_PARAM_CONSTRUCT |
					                    G_PARAM_STATIC_STRINGS));

        /**
         * SoupWebsocketConnection:extensions:
         *
         * List of #SoupWebsocketExtension objects that are active in the connection.
         *
         * Since: 2.68
         */
        g_object_class_install_property (gobject_class, PROP_EXTENSIONS,
                                         g_param_spec_pointer ("extensions",
                                                               "Active extensions",
                                                               "The list of active extensions",
                                                               G_PARAM_READWRITE |
                                                               G_PARAM_CONSTRUCT_ONLY |
                                                               G_PARAM_STATIC_STRINGS));

	/**
	 * SoupWebsocketConnection::message:
	 * @self: the WebSocket
	 * @type: the type of message contents
	 * @message: the message data
	 *
	 * Emitted when we receive a message from the peer.
	 *
	 * As a convenience, the @message data will always be
	 * NUL-terminated, but the NUL byte will not be included in
	 * the length count.
	 *
	 * Since: 2.50
	 */
	signals[MESSAGE] = g_signal_new ("message",
					 SOUP_TYPE_WEBSOCKET_CONNECTION,
					 G_SIGNAL_RUN_FIRST,
					 G_STRUCT_OFFSET (SoupWebsocketConnectionClass, message),
					 NULL, NULL, g_cclosure_marshal_generic,
					 G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_BYTES);

	/**
	 * SoupWebsocketConnection::error:
	 * @self: the WebSocket
	 * @error: the error that occured
	 *
	 * Emitted when an error occurred on the WebSocket. This may
	 * be fired multiple times. Fatal errors will be followed by
	 * the #SoupWebsocketConnection::closed signal being emitted.
	 *
	 * Since: 2.50
	 */
	signals[ERROR] = g_signal_new ("error",
				       SOUP_TYPE_WEBSOCKET_CONNECTION,
				       G_SIGNAL_RUN_FIRST,
				       G_STRUCT_OFFSET (SoupWebsocketConnectionClass, error),
				       NULL, NULL, g_cclosure_marshal_generic,
				       G_TYPE_NONE, 1, G_TYPE_ERROR);

	/**
	 * SoupWebsocketConnection::closing:
	 * @self: the WebSocket
	 *
	 * This signal will be emitted during an orderly close.
	 *
	 * Since: 2.50
	 */
	signals[CLOSING] = g_signal_new ("closing",
					 SOUP_TYPE_WEBSOCKET_CONNECTION,
					 G_SIGNAL_RUN_LAST,
					 G_STRUCT_OFFSET (SoupWebsocketConnectionClass, closing),
					 NULL, NULL, g_cclosure_marshal_generic,
					 G_TYPE_NONE, 0);

	/**
	 * SoupWebsocketConnection::closed:
	 * @self: the WebSocket
	 *
	 * Emitted when the connection has completely closed, either
	 * due to an orderly close from the peer, one initiated via
	 * soup_websocket_connection_close() or a fatal error
	 * condition that caused a close.
	 *
	 * This signal will be emitted once.
	 *
	 * Since: 2.50
	 */
	signals[CLOSED] = g_signal_new ("closed",
					SOUP_TYPE_WEBSOCKET_CONNECTION,
					G_SIGNAL_RUN_FIRST,
					G_STRUCT_OFFSET (SoupWebsocketConnectionClass, closed),
					NULL, NULL, g_cclosure_marshal_generic,
					G_TYPE_NONE, 0);

	/**
	 * SoupWebsocketConnection::pong:
	 * @self: the WebSocket
	 * @message: the application data (if any)
	 *
	 * Emitted when we receive a Pong frame (solicited or
	 * unsolicited) from the peer.
	 *
	 * As a convenience, the @message data will always be
	 * NUL-terminated, but the NUL byte will not be included in
	 * the length count.
	 *
	 * Since: 2.60
	 */
	signals[PONG] = g_signal_new ("pong",
				      SOUP_TYPE_WEBSOCKET_CONNECTION,
				      G_SIGNAL_RUN_FIRST,
				      G_STRUCT_OFFSET (SoupWebsocketConnectionClass, pong),
				      NULL, NULL, g_cclosure_marshal_generic,
				      G_TYPE_NONE, 1, G_TYPE_BYTES);
}

/**
 * soup_websocket_connection_new:
 * @stream: a #GIOStream connected to the WebSocket server
 * @uri: the URI of the connection
 * @type: the type of connection (client/side)
 * @origin: (allow-none): the Origin of the client
 * @protocol: (allow-none): the subprotocol in use
 *
 * Creates a #SoupWebsocketConnection on @stream. This should be
 * called after completing the handshake to begin using the WebSocket
 * protocol.
 *
 * Returns: a new #SoupWebsocketConnection
 *
 * Since: 2.50
 */
SoupWebsocketConnection *
soup_websocket_connection_new (GIOStream                    *stream,
			       SoupURI                      *uri,
			       SoupWebsocketConnectionType   type,
			       const char                   *origin,
			       const char                   *protocol)
{
	return soup_websocket_connection_new_with_extensions (stream, uri, type, origin, protocol, NULL);
}

/**
 * soup_websocket_connection_new_with_extensions:
 * @stream: a #GIOStream connected to the WebSocket server
 * @uri: the URI of the connection
 * @type: the type of connection (client/side)
 * @origin: (allow-none): the Origin of the client
 * @protocol: (allow-none): the subprotocol in use
 * @extensions: (element-type SoupWebsocketExtension) (transfer full): a #GList of #SoupWebsocketExtension objects
 *
 * Creates a #SoupWebsocketConnection on @stream with the given active @extensions.
 * This should be called after completing the handshake to begin using the WebSocket
 * protocol.
 *
 * Returns: a new #SoupWebsocketConnection
 *
 * Since: 2.68
 */
SoupWebsocketConnection *
soup_websocket_connection_new_with_extensions (GIOStream                    *stream,
                                               SoupURI                      *uri,
                                               SoupWebsocketConnectionType   type,
                                               const char                   *origin,
                                               const char                   *protocol,
                                               GList                        *extensions)
{
        g_return_val_if_fail (G_IS_IO_STREAM (stream), NULL);
        g_return_val_if_fail (uri != NULL, NULL);
        g_return_val_if_fail (type != SOUP_WEBSOCKET_CONNECTION_UNKNOWN, NULL);

        return g_object_new (SOUP_TYPE_WEBSOCKET_CONNECTION,
                             "io-stream", stream,
                             "uri", uri,
                             "connection-type", type,
                             "origin", origin,
                             "protocol", protocol,
                             "extensions", extensions,
                             NULL);
}

/**
 * soup_websocket_connection_get_io_stream:
 * @self: the WebSocket
 *
 * Get the I/O stream the WebSocket is communicating over.
 *
 * Returns: (transfer none): the WebSocket's I/O stream.
 *
 * Since: 2.50
 */
GIOStream *
soup_websocket_connection_get_io_stream (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

	return self->pv->io_stream;
}

/**
 * soup_websocket_connection_get_connection_type:
 * @self: the WebSocket
 *
 * Get the connection type (client/server) of the connection.
 *
 * Returns: the connection type
 *
 * Since: 2.50
 */
SoupWebsocketConnectionType
soup_websocket_connection_get_connection_type (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), SOUP_WEBSOCKET_CONNECTION_UNKNOWN);

	return self->pv->connection_type;
}

/**
 * soup_websocket_connection_get_uri:
 * @self: the WebSocket
 *
 * Get the URI of the WebSocket.
 *
 * For servers this represents the address of the WebSocket, and
 * for clients it is the address connected to.
 *
 * Returns: (transfer none): the URI
 *
 * Since: 2.50
 */
SoupURI *
soup_websocket_connection_get_uri (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

	return self->pv->uri;
}

/**
 * soup_websocket_connection_get_origin:
 * @self: the WebSocket
 *
 * Get the origin of the WebSocket.
 *
 * Returns: (nullable): the origin, or %NULL
 *
 * Since: 2.50
 */
const char *
soup_websocket_connection_get_origin (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

	return self->pv->origin;
}

/**
 * soup_websocket_connection_get_protocol:
 * @self: the WebSocket
 *
 * Get the protocol chosen via negotiation with the peer.
 *
 * Returns: (nullable): the chosen protocol, or %NULL
 *
 * Since: 2.50
 */
const char *
soup_websocket_connection_get_protocol (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

	return self->pv->protocol;
}

/**
 * soup_websocket_connection_get_extensions:
 * @self: the WebSocket
 *
 * Get the extensions chosen via negotiation with the peer.
 *
 * Returns: (element-type SoupWebsocketExtension) (transfer none): a #GList of #SoupWebsocketExtension objects
 *
 * Since: 2.68
 */
GList *
soup_websocket_connection_get_extensions (SoupWebsocketConnection *self)
{
        g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

        return self->pv->extensions;
}

/**
 * soup_websocket_connection_get_state:
 * @self: the WebSocket
 *
 * Get the current state of the WebSocket.
 *
 * Returns: the state
 *
 * Since: 2.50
 */
SoupWebsocketState
soup_websocket_connection_get_state (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), 0);

	if (self->pv->io_closed)
		return SOUP_WEBSOCKET_STATE_CLOSED;
	else if (self->pv->io_closing || self->pv->close_sent)
		return SOUP_WEBSOCKET_STATE_CLOSING;
	else
		return SOUP_WEBSOCKET_STATE_OPEN;
}

/**
 * soup_websocket_connection_get_close_code:
 * @self: the WebSocket
 *
 * Get the close code received from the WebSocket peer.
 *
 * This only becomes valid once the WebSocket is in the
 * %SOUP_WEBSOCKET_STATE_CLOSED state. The value will often be in the
 * #SoupWebsocketCloseCode enumeration, but may also be an application
 * defined close code.
 *
 * Returns: the close code or zero.
 *
 * Since: 2.50
 */
gushort
soup_websocket_connection_get_close_code (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), 0);

	return self->pv->peer_close_code;
}

/**
 * soup_websocket_connection_get_close_data:
 * @self: the WebSocket
 *
 * Get the close data received from the WebSocket peer.
 *
 * This only becomes valid once the WebSocket is in the
 * %SOUP_WEBSOCKET_STATE_CLOSED state. The data may be freed once
 * the main loop is run, so copy it if you need to keep it around.
 *
 * Returns: the close data or %NULL
 *
 * Since: 2.50
 */
const char *
soup_websocket_connection_get_close_data (SoupWebsocketConnection *self)
{
	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), NULL);

	return self->pv->peer_close_data;
}

/**
 * soup_websocket_connection_send_text:
 * @self: the WebSocket
 * @text: the message contents
 *
 * Send a %NULL-terminated text (UTF-8) message to the peer. If you need
 * to send text messages containing %NULL characters use
 * soup_websocket_connection_send_message() instead.
 *
 * The message is queued to be sent and will be sent when the main loop
 * is run.
 *
 * Since: 2.50
 */
void
soup_websocket_connection_send_text (SoupWebsocketConnection *self,
				     const char *text)
{
	gsize length;

	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	g_return_if_fail (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_OPEN);
	g_return_if_fail (text != NULL);

	length = strlen (text);
        g_return_if_fail (utf8_validate (text, length));

	send_message (self, SOUP_WEBSOCKET_QUEUE_NORMAL, 0x01, (const guint8 *) text, length);
}

/**
 * soup_websocket_connection_send_binary:
 * @self: the WebSocket
 * @data: (array length=length) (element-type guint8) (nullable): the message contents
 * @length: the length of @data
 *
 * Send a binary message to the peer. If @length is 0, @data may be %NULL.
 *
 * The message is queued to be sent and will be sent when the main loop
 * is run.
 *
 * Since: 2.50
 */
void
soup_websocket_connection_send_binary (SoupWebsocketConnection *self,
				       gconstpointer data,
				       gsize length)
{
	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	g_return_if_fail (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_OPEN);
	g_return_if_fail (data != NULL || length == 0);

	send_message (self, SOUP_WEBSOCKET_QUEUE_NORMAL, 0x02, data, length);
}

/**
 * soup_websocket_connection_send_message:
 * @self: the WebSocket
 * @type: the type of message contents
 * @message: the message data as #GBytes
 *
 * Send a message of the given @type to the peer. Note that this method,
 * allows to send text messages containing %NULL characters.
 *
 * The message is queued to be sent and will be sent when the main loop
 * is run.
 *
 * Since: 2.68
 */
void
soup_websocket_connection_send_message (SoupWebsocketConnection *self,
                                        SoupWebsocketDataType type,
                                        GBytes *message)
{
        gconstpointer data;
        gsize length;

        g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
        g_return_if_fail (soup_websocket_connection_get_state (self) == SOUP_WEBSOCKET_STATE_OPEN);
        g_return_if_fail (message != NULL);

        data = g_bytes_get_data (message, &length);
        g_return_if_fail (type != SOUP_WEBSOCKET_DATA_TEXT || utf8_validate ((const char *)data, length));

        send_message (self, SOUP_WEBSOCKET_QUEUE_NORMAL, (int)type, data, length);
}

/**
 * soup_websocket_connection_close:
 * @self: the WebSocket
 * @code: close code
 * @data: (allow-none): close data
 *
 * Close the connection in an orderly fashion.
 *
 * Note that until the #SoupWebsocketConnection::closed signal fires, the connection
 * is not yet completely closed. The close message is not even sent until the
 * main loop runs.
 *
 * The @code and @data are sent to the peer along with the close request.
 * If @code is %SOUP_WEBSOCKET_CLOSE_NO_STATUS a close message with no body
 * (without code and data) is sent.
 * Note that the @data must be UTF-8 valid.
 *
 * Since: 2.50
 */
void
soup_websocket_connection_close (SoupWebsocketConnection *self,
				 gushort code,
				 const char *data)
{
	SoupWebsocketConnectionPrivate *pv;

	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	pv = self->pv;
	g_return_if_fail (!pv->close_sent);

	g_return_if_fail (code != SOUP_WEBSOCKET_CLOSE_ABNORMAL &&
			  code != SOUP_WEBSOCKET_CLOSE_TLS_HANDSHAKE);
	if (pv->connection_type == SOUP_WEBSOCKET_CONNECTION_SERVER)
		g_return_if_fail (code != SOUP_WEBSOCKET_CLOSE_NO_EXTENSION);
	else
		g_return_if_fail (code != SOUP_WEBSOCKET_CLOSE_SERVER_ERROR);

	close_connection (self, code, data);
}

/**
 * soup_websocket_connection_get_max_incoming_payload_size:
 * @self: the WebSocket
 *
 * Gets the maximum payload size allowed for incoming packets.
 *
 * Returns: the maximum payload size.
 *
 * Since: 2.56
 */
guint64
soup_websocket_connection_get_max_incoming_payload_size (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv;

	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), MAX_INCOMING_PAYLOAD_SIZE_DEFAULT);
	pv = self->pv;

	return pv->max_incoming_payload_size;
}

/**
 * soup_websocket_connection_set_max_incoming_payload_size:
 * @self: the WebSocket
 * @max_incoming_payload_size: the maximum payload size
 *
 * Sets the maximum payload size allowed for incoming packets. It
 * does not limit the outgoing packet size.
 *
 * Since: 2.56
 */
void
soup_websocket_connection_set_max_incoming_payload_size (SoupWebsocketConnection *self,
                                                         guint64                  max_incoming_payload_size)
{
	SoupWebsocketConnectionPrivate *pv;

	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	pv = self->pv;

	if (pv->max_incoming_payload_size != max_incoming_payload_size) {
		pv->max_incoming_payload_size = max_incoming_payload_size;
		g_object_notify (G_OBJECT (self), "max-incoming-payload-size");
	}
}

/**
 * soup_websocket_connection_get_keepalive_interval:
 * @self: the WebSocket
 *
 * Gets the keepalive interval in seconds or 0 if disabled.
 *
 * Returns: the keepalive interval.
 *
 * Since: 2.58
 */
guint
soup_websocket_connection_get_keepalive_interval (SoupWebsocketConnection *self)
{
	SoupWebsocketConnectionPrivate *pv;

	g_return_val_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self), 0);
	pv = self->pv;

	return pv->keepalive_interval;
}

static gboolean
on_queue_ping (gpointer user_data)
{
	SoupWebsocketConnection *self = SOUP_WEBSOCKET_CONNECTION (user_data);
	static const char ping_payload[] = "libsoup";

	g_debug ("sending ping message");

	send_message (self, SOUP_WEBSOCKET_QUEUE_NORMAL, 0x09,
		      (guint8 *) ping_payload, strlen(ping_payload));

	return G_SOURCE_CONTINUE;
}

/**
 * soup_websocket_connection_set_keepalive_interval:
 * @self: the WebSocket
 * @interval: the interval to send a ping message or 0 to disable it
 *
 * Sets the interval in seconds on when to send a ping message which will serve
 * as a keepalive message. If set to 0 the keepalive message is disabled.
 *
 * Since: 2.58
 */
void
soup_websocket_connection_set_keepalive_interval (SoupWebsocketConnection *self,
                                                  guint                    interval)
{
	SoupWebsocketConnectionPrivate *pv;

	g_return_if_fail (SOUP_IS_WEBSOCKET_CONNECTION (self));
	pv = self->pv;

	if (pv->keepalive_interval != interval) {
		pv->keepalive_interval = interval;
		g_object_notify (G_OBJECT (self), "keepalive-interval");

		keepalive_stop_timeout (self);

		if (interval > 0) {
			pv->keepalive_timeout = g_timeout_source_new_seconds (interval);
			g_source_set_callback (pv->keepalive_timeout, on_queue_ping, self, NULL);
			g_source_attach (pv->keepalive_timeout, pv->main_context);
		}
	}
}
