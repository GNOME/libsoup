/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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
#define HEADER_SIZE_LIMIT (64 * 1024)

void
soup_message_io_data_cleanup (SoupMessageIOData *io)
{
	if (io->io_source) {
		g_source_destroy (io->io_source);
		g_source_unref (io->io_source);
		io->io_source = NULL;
	}

	if (io->iostream)
		g_object_unref (io->iostream);
	if (io->body_istream)
		g_object_unref (io->body_istream);
	if (io->body_ostream)
		g_object_unref (io->body_ostream);
	if (io->async_context)
		g_main_context_unref (io->async_context);

	g_byte_array_free (io->read_header_buf, TRUE);

	g_string_free (io->write_buf, TRUE);

	if (io->async_wait) {
		g_cancellable_cancel (io->async_wait);
		g_clear_object (&io->async_wait);
	}
	g_clear_error (&io->async_error);
}

gboolean
soup_message_io_data_read_headers (SoupMessageIOData *io,
				   gboolean           blocking,
				   GCancellable      *cancellable,
				   GError           **error)
{
	gssize nread, old_len;
	gboolean got_lf;

	while (1) {
		old_len = io->read_header_buf->len;
		g_byte_array_set_size (io->read_header_buf, old_len + RESPONSE_BLOCK_SIZE);
		nread = soup_filter_input_stream_read_line (io->istream,
							    io->read_header_buf->data + old_len,
							    RESPONSE_BLOCK_SIZE,
							    blocking,
							    &got_lf,
							    cancellable, error);
		io->read_header_buf->len = old_len + MAX (nread, 0);
		if (nread == 0) {
			if (io->read_header_buf->len > 0)
				break;

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
				break;
			} else if (nread == 2 && old_len >= 3 &&
				 !strncmp ((char *)io->read_header_buf->data +
					   io->read_header_buf->len - 3,
					   "\n\r\n", 3)) {
				io->read_header_buf->len -= 2;
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

typedef struct {
	GSource source;
	GObject *msg;
	gboolean paused;
} SoupMessageIOSource;

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

static gboolean
message_io_source_prepare (GSource *source,
			   gint    *timeout)
{
	*timeout = -1;
	return message_io_source_check (source);
}

static gboolean
message_io_source_dispatch (GSource     *source,
			    GSourceFunc  callback,
			    gpointer     user_data)
{
	SoupMessageIOSourceFunc func = (SoupMessageIOSourceFunc)callback;
	SoupMessageIOSource *message_source = (SoupMessageIOSource *)source;

	return (*func) (message_source->msg, user_data);
}

static void
message_io_source_finalize (GSource *source)
{
	SoupMessageIOSource *message_source = (SoupMessageIOSource *)source;

	g_object_unref (message_source->msg);
}

static gboolean
message_io_source_closure_callback (GObject *msg,
				    gpointer data)
{
	GClosure *closure = data;
	GValue param = G_VALUE_INIT;
	GValue result_value = G_VALUE_INIT;
	gboolean result;

	g_value_init (&result_value, G_TYPE_BOOLEAN);

	g_value_init (&param, G_TYPE_OBJECT);
	g_value_set_object (&param, msg);

	g_closure_invoke (closure, &result_value, 1, &param, NULL);

	result = g_value_get_boolean (&result_value);
	g_value_unset (&result_value);
	g_value_unset (&param);

	return result;
}

static GSourceFuncs message_io_source_funcs =
{
	message_io_source_prepare,
	message_io_source_check,
	message_io_source_dispatch,
	message_io_source_finalize,
	(GSourceFunc)message_io_source_closure_callback,
	(GSourceDummyMarshal)g_cclosure_marshal_generic,
};

GSource *
soup_message_io_data_get_source (SoupMessageIOData     *io,
				 GObject                *msg,
				 GCancellable           *cancellable,
				 SoupMessageIOSourceFunc callback,
				 gpointer                user_data)
{
	GSource *base_source, *source;
	SoupMessageIOSource *message_source;

	if (!io) {
		base_source = g_timeout_source_new (0);
	} else if (io->paused) {
		base_source = NULL;
	} else if (io->async_wait) {
		base_source = g_cancellable_source_new (io->async_wait);
	} else if (SOUP_MESSAGE_IO_STATE_POLLABLE (io->read_state)) {
		GPollableInputStream *istream;

		if (io->body_istream)
			istream = G_POLLABLE_INPUT_STREAM (io->body_istream);
		else
			istream = G_POLLABLE_INPUT_STREAM (io->istream);
		base_source = g_pollable_input_stream_create_source (istream, cancellable);
	} else if (SOUP_MESSAGE_IO_STATE_POLLABLE (io->write_state)) {
		GPollableOutputStream *ostream;

		if (io->body_ostream)
			ostream = G_POLLABLE_OUTPUT_STREAM (io->body_ostream);
		else
			ostream = G_POLLABLE_OUTPUT_STREAM (io->ostream);
		base_source = g_pollable_output_stream_create_source (ostream, cancellable);
	} else
		base_source = g_timeout_source_new (0);

	source = g_source_new (&message_io_source_funcs, sizeof (SoupMessageIOSource));
	g_source_set_name (source, "SoupMessageIOSource");
	message_source = (SoupMessageIOSource *)source;
	message_source->msg = g_object_ref (msg);
	message_source->paused = io && io->paused;

	if (base_source) {
		g_source_set_dummy_callback (base_source);
		g_source_add_child_source (source, base_source);
		g_source_unref (base_source);
	}
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
