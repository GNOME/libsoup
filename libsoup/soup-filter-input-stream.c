/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-filter-input-stream.c
 *
 * Copyright 2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-filter-input-stream.h"
#include "soup.h"

/* This is essentially a subset of GDataInputStream, except that we
 * can do the equivalent of "fill_nonblocking()" on it. (We could use
 * an actual GDataInputStream, and implement the nonblocking semantics
 * via fill_async(), but that would be more work...)
 */

struct _SoupFilterInputStreamPrivate {
	GByteArray *buf;
	gboolean need_more;
	gboolean in_read_until;
};

static void soup_filter_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupFilterInputStream, soup_filter_input_stream, G_TYPE_FILTER_INPUT_STREAM,
                         G_ADD_PRIVATE (SoupFilterInputStream)
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						soup_filter_input_stream_pollable_init))

static void
soup_filter_input_stream_init (SoupFilterInputStream *stream)
{
	stream->priv = soup_filter_input_stream_get_instance_private (stream);
}

static void
soup_filter_input_stream_finalize (GObject *object)
{
	SoupFilterInputStream *fstream = SOUP_FILTER_INPUT_STREAM (object);

	g_clear_pointer (&fstream->priv->buf, g_byte_array_unref);

	G_OBJECT_CLASS (soup_filter_input_stream_parent_class)->finalize (object);
}

static gssize
read_from_buf (SoupFilterInputStream *fstream, gpointer buffer, gsize count)
{
	GByteArray *buf = fstream->priv->buf;

	if (buf->len < count)
		count = buf->len;
	memcpy (buffer, buf->data, count);

	if (count == buf->len) {
		g_byte_array_free (buf, TRUE);
		fstream->priv->buf = NULL;
	} else {
		memmove (buf->data, buf->data + count,
			 buf->len - count);
		g_byte_array_set_size (buf, buf->len - count);
	}

	return count;
}

static gssize
soup_filter_input_stream_read_fn (GInputStream  *stream,
				  void          *buffer,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupFilterInputStream *fstream = SOUP_FILTER_INPUT_STREAM (stream);

	if (!fstream->priv->in_read_until)
		fstream->priv->need_more = FALSE;

	if (fstream->priv->buf && !fstream->priv->in_read_until) {
		return read_from_buf (fstream, buffer, count);
	} else {
		return g_pollable_stream_read (G_FILTER_INPUT_STREAM (fstream)->base_stream,
					       buffer, count,
					       TRUE, cancellable, error);
	}
}

static gboolean
soup_filter_input_stream_is_readable (GPollableInputStream *stream)
{
	SoupFilterInputStream *fstream = SOUP_FILTER_INPUT_STREAM (stream);

	if (fstream->priv->buf && !fstream->priv->need_more)
		return TRUE;
	else
		return g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (fstream)->base_stream));
}

static gssize
soup_filter_input_stream_read_nonblocking (GPollableInputStream  *stream,
					   void                  *buffer,
					   gsize                  count,
					   GError               **error)
{
	SoupFilterInputStream *fstream = SOUP_FILTER_INPUT_STREAM (stream);

	if (!fstream->priv->in_read_until)
		fstream->priv->need_more = FALSE;

	if (fstream->priv->buf && !fstream->priv->in_read_until) {
		return read_from_buf (fstream, buffer, count);
	} else {
		return g_pollable_stream_read (G_FILTER_INPUT_STREAM (fstream)->base_stream,
					       buffer, count,
					       FALSE, NULL, error);
	}
}

static GSource *
soup_filter_input_stream_create_source (GPollableInputStream *stream,
					GCancellable         *cancellable)
{
	SoupFilterInputStream *fstream = SOUP_FILTER_INPUT_STREAM (stream);
	GSource *base_source, *pollable_source;

	if (fstream->priv->buf && !fstream->priv->need_more)
		base_source = g_timeout_source_new (0);
	else
		base_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (fstream)->base_stream), cancellable);

	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_filter_input_stream_class_init (SoupFilterInputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (stream_class);

	object_class->finalize = soup_filter_input_stream_finalize;

	input_stream_class->read_fn = soup_filter_input_stream_read_fn;
}

static void
soup_filter_input_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
					gpointer                       interface_data)
{
	pollable_interface->is_readable = soup_filter_input_stream_is_readable;
	pollable_interface->read_nonblocking = soup_filter_input_stream_read_nonblocking;
	pollable_interface->create_source = soup_filter_input_stream_create_source;
}

GInputStream *
soup_filter_input_stream_new (GInputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_FILTER_INPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}

gssize
soup_filter_input_stream_read_line (SoupFilterInputStream  *fstream,
				    void                   *buffer,
				    gsize                   length,
				    gboolean                blocking,
				    gboolean               *got_line,
				    GCancellable           *cancellable,
				    GError                **error)
{
	return soup_filter_input_stream_read_until (fstream, buffer, length,
						    "\n", 1, blocking,
						    TRUE, got_line,
						    cancellable, error);
}

gssize
soup_filter_input_stream_read_until (SoupFilterInputStream  *fstream,
				     void                   *buffer,
				     gsize                   length,
				     const void             *boundary,
				     gsize                   boundary_length,
				     gboolean                blocking,
				     gboolean                include_boundary,
				     gboolean               *got_boundary,
				     GCancellable           *cancellable,
				     GError                **error)
{
	gssize nread, read_length;
	guint8 *p, *buf, *end;
	gboolean eof = FALSE;
	GError *my_error = NULL;

	g_return_val_if_fail (SOUP_IS_FILTER_INPUT_STREAM (fstream), -1);
	g_return_val_if_fail (!include_boundary || (boundary_length < length), -1);

	*got_boundary = FALSE;
	fstream->priv->need_more = FALSE;

	if (!fstream->priv->buf || fstream->priv->buf->len < boundary_length) {
		guint prev_len;

	fill_buffer:
		if (!fstream->priv->buf)
			fstream->priv->buf = g_byte_array_new ();
		prev_len = fstream->priv->buf->len;
		g_byte_array_set_size (fstream->priv->buf, length);
		buf = fstream->priv->buf->data;

		fstream->priv->in_read_until = TRUE;
		nread = g_pollable_stream_read (G_INPUT_STREAM (fstream),
						buf + prev_len, length - prev_len,
						blocking,
						cancellable, &my_error);
		fstream->priv->in_read_until = FALSE;
		if (nread <= 0) {
			if (prev_len)
				fstream->priv->buf->len = prev_len;
			else {
				g_byte_array_free (fstream->priv->buf, TRUE);
				fstream->priv->buf = NULL;
			}

			if (nread == 0 && prev_len)
				eof = TRUE;
			else {
				if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
					fstream->priv->need_more = TRUE;
				if (my_error)
					g_propagate_error (error, my_error);

				return nread;
			}

			if (my_error)
				g_propagate_error (error, my_error);
		} else
			fstream->priv->buf->len = prev_len + nread;
	} else
		buf = fstream->priv->buf->data;

	/* Scan for the boundary within the range we can possibly return. */
	if (include_boundary)
		end = buf + MIN (fstream->priv->buf->len, length) - boundary_length;
	else
		end = buf + MIN (fstream->priv->buf->len - boundary_length, length);
	for (p = buf; p <= end; p++) {
		if (*p == *(guint8*)boundary &&
		    !memcmp (p, boundary, boundary_length)) {
			if (include_boundary)
				p += boundary_length;
			*got_boundary = TRUE;
			break;
		}
	}

	if (!*got_boundary && fstream->priv->buf->len < length && !eof)
		goto fill_buffer;

	if (eof && !*got_boundary)
		read_length = MIN (fstream->priv->buf->len, length);
	else
		read_length = p - buf;
	return read_from_buf (fstream, buffer, read_length);
}
