/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-message-io-data.c: HTTP message I/O data
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n-lib.h>

#include "soup-message-io-data.h"
#include "soup-message-private.h"
#include "soup-server-message-private.h"
#include "soup.h"

#define RESPONSE_BLOCK_SIZE 8192
#define HEADER_SIZE_LIMIT (100 * 1024)

void
soup_message_io_data_cleanup (SoupMessageIOData *io)
{
	if (io->io_source) {
		g_source_destroy (io->io_source);
		g_source_unref (io->io_source);
		io->io_source = NULL;
	}

	if (io->body_istream)
		g_object_unref (io->body_istream);
	if (io->body_ostream)
		g_object_unref (io->body_ostream);

	g_byte_array_free (io->read_header_buf, TRUE);

	g_string_free (io->write_buf, TRUE);

	if (io->async_wait) {
		g_cancellable_cancel (io->async_wait);
		g_clear_object (&io->async_wait);
	}
	g_clear_error (&io->async_error);
}

gboolean
soup_message_io_data_read_headers (SoupMessageIOData     *io,
                                   SoupFilterInputStream *istream,
                                   gboolean               blocking,
                                   GCancellable          *cancellable,
                                   gushort               *extra_bytes,
                                   GError               **error)
{
	gssize nread, old_len;
	gboolean got_lf;

	while (1) {
		old_len = io->read_header_buf->len;
		g_byte_array_set_size (io->read_header_buf, old_len + RESPONSE_BLOCK_SIZE);
		nread = soup_filter_input_stream_read_line (istream,
							    io->read_header_buf->data + old_len,
							    RESPONSE_BLOCK_SIZE,
							    blocking,
							    &got_lf,
							    cancellable, error);
		io->read_header_buf->len = old_len + MAX (nread, 0);
		if (nread == 0) {
			if (io->read_header_buf->len > 0) {
                                if (extra_bytes)
					*extra_bytes = 0;
				break;
                        }

			g_set_error_literal (error, G_IO_ERROR,
					     G_IO_ERROR_PARTIAL_INPUT,
					     _("Connection terminated unexpectedly"));
		}
		if (nread <= 0)
			return FALSE;

		if (got_lf) {
			if (nread == 1 && old_len >= 2 &&
			    !strncmp ((char *)io->read_header_buf->data +
				      io->read_header_buf->len - 2,
				      "\n\n", 2)) {
				io->read_header_buf->len--;
                                if (extra_bytes)
                                        *extra_bytes = 1;
				break;
			} else if (nread == 2 && old_len >= 3 &&
				 !strncmp ((char *)io->read_header_buf->data +
					   io->read_header_buf->len - 3,
					   "\n\r\n", 3)) {
				io->read_header_buf->len -= 2;
                                if (extra_bytes)
                                        *extra_bytes = 2;
				break;
			}
		}

		if (io->read_header_buf->len > HEADER_SIZE_LIMIT) {
			g_set_error_literal (error, G_IO_ERROR,
					     G_IO_ERROR_PARTIAL_INPUT,
					     _("Header too big"));
			return FALSE;
		}
	}

	io->read_header_buf->data[io->read_header_buf->len] = '\0';
	return TRUE;
}

static gboolean
message_io_is_paused (GObject *msg)
{
	if (SOUP_IS_MESSAGE (msg))
		return soup_message_is_io_paused (SOUP_MESSAGE (msg));

	if (SOUP_IS_SERVER_MESSAGE (msg))
		return soup_server_message_is_io_paused (SOUP_SERVER_MESSAGE (msg));

	return FALSE;
}

static gboolean
message_io_source_check (GSource *source)
{
	SoupMessageIOSource *message_source = (SoupMessageIOSource *)source;

	if (message_source->paused) {
		if (message_io_is_paused (message_source->msg))
			return FALSE;
		return TRUE;
	} else
		return FALSE;
}

GSource *
soup_message_io_data_get_source (SoupMessageIOData      *io,
				 GObject                *msg,
                                 GInputStream           *istream,
                                 GOutputStream          *ostream,
				 GCancellable           *cancellable,
				 SoupMessageIOSourceFunc callback,
				 gpointer                user_data)
{
	GSource *base_source, *source;

	if (!io) {
		base_source = g_timeout_source_new (0);
	} else if (io->paused) {
		base_source = cancellable ? g_cancellable_source_new (cancellable) : NULL;
	} else if (io->async_wait) {
		base_source = g_cancellable_source_new (io->async_wait);
	} else if (SOUP_MESSAGE_IO_STATE_POLLABLE (io->read_state)) {
		GPollableInputStream *stream;

		if (io->body_istream)
			stream = G_POLLABLE_INPUT_STREAM (io->body_istream);
                else if (istream)
                        stream = G_POLLABLE_INPUT_STREAM (istream);
                else
                        g_assert_not_reached ();
		base_source = g_pollable_input_stream_create_source (stream, cancellable);
	} else if (SOUP_MESSAGE_IO_STATE_POLLABLE (io->write_state)) {
		GPollableOutputStream *stream;

		if (io->body_ostream)
			stream = G_POLLABLE_OUTPUT_STREAM (io->body_ostream);
                else if (ostream)
                        stream = G_POLLABLE_OUTPUT_STREAM (ostream);
                else
                        g_assert_not_reached ();
		base_source = g_pollable_output_stream_create_source (stream, cancellable);
	} else
		base_source = g_timeout_source_new (0);

        source = soup_message_io_source_new (base_source, msg, io && io->paused, message_io_source_check);
	g_source_set_static_name (source, "SoupMessageIOData");
	g_source_set_callback (source, (GSourceFunc) callback, user_data, NULL);
	return source;
}

void
soup_message_io_data_pause (SoupMessageIOData *io)
{
	if (io->io_source) {
		g_source_destroy (io->io_source);
		g_source_unref (io->io_source);
		io->io_source = NULL;
	}

	io->paused = TRUE;
}

void
soup_message_io_data_unpause (SoupMessageIOData *io)
{
        io->paused = FALSE;
}
