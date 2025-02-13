/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#include "test-utils.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-filter-input-stream.h"

typedef struct {
	GFilterInputStream grandparent;

	gpointer *soup_filter_input_stream_private;

	gboolean is_readable;
} SlowInputStream;

typedef struct {
	GFilterInputStreamClass grandparent;
} SlowInputStreamClass;

GType slow_input_stream_get_type (void);
static void slow_pollable_input_stream_init (GPollableInputStreamInterface *pollable_interface,
					     gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SlowInputStream, slow_input_stream,
			 SOUP_TYPE_FILTER_INPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM, slow_pollable_input_stream_init);
			 )

static void
slow_input_stream_init (SlowInputStream *sis)
{
}

static gssize
slow_input_stream_read (GInputStream  *stream,
			void          *buffer,
			gsize          count,
			GCancellable  *cancellable,
			GError       **error)
{
	return g_input_stream_read (G_FILTER_INPUT_STREAM (stream)->base_stream,
				    buffer, 1, cancellable, error);
}

static void
slow_input_stream_class_init (SlowInputStreamClass *sisclass)
{
	GInputStreamClass *input_stream_class = G_INPUT_STREAM_CLASS (sisclass);

	input_stream_class->read_fn = slow_input_stream_read;
}

static gboolean
slow_input_stream_is_readable (GPollableInputStream *stream)
{
	return ((SlowInputStream *)stream)->is_readable;
}

static gssize
slow_input_stream_read_nonblocking (GPollableInputStream  *stream,
				    void                  *buffer,
				    gsize                  count,
				    GError               **error)
{
	if (((SlowInputStream *)stream)->is_readable) {
		((SlowInputStream *)stream)->is_readable = FALSE;
		return slow_input_stream_read (G_INPUT_STREAM (stream), buffer, count,
					       NULL, error);
	} else {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
				     "would block");
		return -1;
	}
}

static GSource *
slow_input_stream_create_source (GPollableInputStream *stream,
				 GCancellable *cancellable)
{
	GSource *base_source, *pollable_source;

	((SlowInputStream *)stream)->is_readable = TRUE;
	base_source = g_timeout_source_new (0);
	g_source_set_dummy_callback (base_source);

	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
slow_pollable_input_stream_init (GPollableInputStreamInterface *pollable_interface,
				 gpointer interface_data)
{
	pollable_interface->is_readable = slow_input_stream_is_readable;
	pollable_interface->read_nonblocking = slow_input_stream_read_nonblocking;
	pollable_interface->create_source = slow_input_stream_create_source;
}

typedef struct {
	GFilterOutputStream parent;

	gboolean is_writable;
} SlowOutputStream;

typedef struct {
	GFilterOutputStreamClass parent;
} SlowOutputStreamClass;

GType slow_output_stream_get_type (void);

static void slow_pollable_output_stream_init (GPollableOutputStreamInterface *pollable_interface,
					      gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SlowOutputStream, slow_output_stream,
			 G_TYPE_FILTER_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM, slow_pollable_output_stream_init);
			 )

static void
slow_output_stream_init (SlowOutputStream *sis)
{
}

static gssize
slow_output_stream_write (GOutputStream  *stream,
			  const void     *buffer,
			  gsize           count,
			  GCancellable   *cancellable,
			  GError        **error)
{
	return g_output_stream_write (G_FILTER_OUTPUT_STREAM (stream)->base_stream,
				      buffer, 1, cancellable, error);
}

static void
slow_output_stream_class_init (SlowOutputStreamClass *sisclass)
{
	GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (sisclass);

	output_stream_class->write_fn = slow_output_stream_write;
}

static gboolean
slow_output_stream_is_writable (GPollableOutputStream *stream)
{
	return ((SlowOutputStream *)stream)->is_writable;
}

static gssize
slow_output_stream_write_nonblocking (GPollableOutputStream  *stream,
				      const void             *buffer,
				      gsize                   count,
				      GError                **error)
{
	if (((SlowOutputStream *)stream)->is_writable) {
		((SlowOutputStream *)stream)->is_writable = FALSE;
		return slow_output_stream_write (G_OUTPUT_STREAM (stream), buffer, count,
						 NULL, error);
	} else {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
				     "would block");
		return -1;
	}
}

static GSource *
slow_output_stream_create_source (GPollableOutputStream *stream,
				  GCancellable *cancellable)
{
	GSource *base_source, *pollable_source;

	((SlowOutputStream *)stream)->is_writable = TRUE;
	base_source = g_timeout_source_new (0);
	g_source_set_dummy_callback (base_source);

	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
slow_pollable_output_stream_init (GPollableOutputStreamInterface *pollable_interface,
				  gpointer interface_data)
{
	pollable_interface->is_writable = slow_output_stream_is_writable;
	pollable_interface->write_nonblocking = slow_output_stream_write_nonblocking;
	pollable_interface->create_source = slow_output_stream_create_source;
}

typedef struct {
	GFilterOutputStream parent;

	gboolean is_broken;
} BreakingOutputStream;

typedef struct {
	GFilterOutputStreamClass parent;
} BreakingOutputStreamClass;

GType breaking_output_stream_get_type (void);

static void breaking_pollable_output_stream_init (GPollableOutputStreamInterface *pollable_interface,
						  gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (BreakingOutputStream, breaking_output_stream,
			 G_TYPE_FILTER_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM, breaking_pollable_output_stream_init);
			 )

static void
breaking_output_stream_init (BreakingOutputStream *sis)
{
}

static gssize
breaking_output_stream_write (GOutputStream  *stream,
			      const void     *buffer,
			      gsize           count,
			      GCancellable   *cancellable,
			      GError        **error)
{
	if (((BreakingOutputStream *)stream)->is_broken) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed");
		return -1;
	}

	if (count > 128) {
		((BreakingOutputStream *)stream)->is_broken = TRUE;
		count /= 2;
	}
	return g_output_stream_write (G_FILTER_OUTPUT_STREAM (stream)->base_stream,
				      buffer, count, cancellable, error);
}

static void
breaking_output_stream_class_init (BreakingOutputStreamClass *sisclass)
{
	GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (sisclass);

	output_stream_class->write_fn = breaking_output_stream_write;
}

static gboolean
breaking_output_stream_is_writable (GPollableOutputStream *stream)
{
	return TRUE;
}

static gssize
breaking_output_stream_write_nonblocking (GPollableOutputStream  *stream,
					  const void             *buffer,
					  gsize                   count,
					  GError                **error)
{
	if (((BreakingOutputStream *)stream)->is_broken) {
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "failed");
		return -1;
	}

	if (count > 128) {
		((BreakingOutputStream *)stream)->is_broken = TRUE;
		count /= 2;
	}
	return g_pollable_output_stream_write_nonblocking (G_POLLABLE_OUTPUT_STREAM (G_FILTER_OUTPUT_STREAM (stream)->base_stream),
							   buffer, count, NULL, error);
}

static GSource *
breaking_output_stream_create_source (GPollableOutputStream *stream,
				      GCancellable *cancellable)
{
	GSource *base_source, *pollable_source;

	base_source = g_timeout_source_new (0);
	g_source_set_dummy_callback (base_source);

	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
breaking_pollable_output_stream_init (GPollableOutputStreamInterface *pollable_interface,
				  gpointer interface_data)
{
	pollable_interface->is_writable = breaking_output_stream_is_writable;
	pollable_interface->write_nonblocking = breaking_output_stream_write_nonblocking;
	pollable_interface->create_source = breaking_output_stream_create_source;
}

#define CHUNK_SIZE 1024

static GString *
chunkify (GBytes *data)
{
	GString *gstr;
	int i, size;

	gstr = g_string_new (NULL);
	for (i = 0; i < g_bytes_get_size (data); i += CHUNK_SIZE) {
		size = MIN (CHUNK_SIZE, g_bytes_get_size (data) - i);
		g_string_append_printf (gstr, "%x\r\n", size);
		g_string_append_len (gstr, (char*)g_bytes_get_data (data, NULL) + i, size);
		g_string_append (gstr, "\r\n");
	}
	g_string_append (gstr, "0\r\n\r\n");

	return gstr;
}

static void
do_io_tests (void)
{
	GInputStream *imem, *islow, *in;
	GOutputStream *omem, *oslow, *out;
	GMemoryOutputStream *mem;
	GBytes *raw_contents;
        gsize raw_contents_length;
        const guchar *raw_contents_data;
	char *buf;
	GString *chunkified;
	GError *error = NULL;
	gssize nread, nwrote, total;
	gssize chunk_length, chunk_total;

	raw_contents = soup_test_get_index ();
        raw_contents_data = g_bytes_get_data (raw_contents, &raw_contents_length);
	chunkified = chunkify (raw_contents);

	debug_printf (1, "  sync read\n");

	imem = g_memory_input_stream_new_from_data (chunkified->str, chunkified->len, NULL);
	islow = g_object_new (slow_input_stream_get_type (),
			      "base-stream", imem,
			      "close-base-stream", TRUE,
			      NULL);
	in = g_object_new (SOUP_TYPE_BODY_INPUT_STREAM,
			   "base-stream", islow,
			   "close-base-stream", TRUE,
			   "encoding", SOUP_ENCODING_CHUNKED,
			   NULL);
	g_object_unref (imem);
	g_object_unref (islow);

	buf = g_malloc (raw_contents_length);
	total = 0;
	while (TRUE) {
		nread = g_input_stream_read (in, buf + total,
					     raw_contents_length - total,
					     NULL, &error);
		g_assert_no_error (error);
		g_clear_error (&error);
		if (nread > 0)
			total += nread;
		else
			break;
	}

	g_input_stream_close (in, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (in);

	soup_assert_cmpmem (buf, total, g_bytes_get_data (raw_contents, NULL), raw_contents_length);
	g_free (buf);

	debug_printf (1, "  async read\n");

	imem = g_memory_input_stream_new_from_data (chunkified->str, chunkified->len, NULL);
	islow = g_object_new (slow_input_stream_get_type (),
			      "base-stream", imem,
			      "close-base-stream", TRUE,
			      NULL);
	in = g_object_new (SOUP_TYPE_BODY_INPUT_STREAM,
			   "base-stream", islow,
			   "close-base-stream", TRUE,
			   "encoding", SOUP_ENCODING_CHUNKED,
			   NULL);
	g_object_unref (imem);
	g_object_unref (islow);

	buf = g_malloc (raw_contents_length);
	total = 0;
	while (TRUE) {
		nread = g_pollable_input_stream_read_nonblocking (G_POLLABLE_INPUT_STREAM (in),
								  buf + total,
								  raw_contents_length - total,
								  NULL, &error);
		if (nread == -1 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			GSource *source;

			g_clear_error (&error);
			source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (in), NULL);
			g_source_set_dummy_callback (source);
			g_source_attach (source, NULL);
			while (!g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (in)))
				g_main_context_iteration (NULL, TRUE);
			g_source_destroy (source);
			g_source_unref (source);
			continue;
		} else if (nread == -1) {
			g_assert_no_error (error);
			g_clear_error (&error);
			break;
		} else if (nread == 0)
			break;
		else
			total += nread;
	}

	g_input_stream_close (in, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);
	g_object_unref (in);

	soup_assert_cmpmem (buf, total, raw_contents_data, raw_contents_length);
	g_free (buf);

	debug_printf (1, "  sync write\n");

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (slow_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (SOUP_TYPE_BODY_OUTPUT_STREAM,
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = chunk_length = chunk_total = 0;
	while (total < raw_contents_length) {
		if (chunk_total == chunk_length) {
			chunk_length = MIN (CHUNK_SIZE, raw_contents_length - total);
			chunk_total = 0;
		}
		nwrote = g_output_stream_write (out, raw_contents_data + total,
						chunk_length - chunk_total, NULL, &error);
		g_assert_no_error (error);
		g_clear_error (&error);
		if (nwrote > 0) {
			total += nwrote;
			chunk_total += nwrote;
		} else
			break;
	}

	g_output_stream_close (out, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	mem = G_MEMORY_OUTPUT_STREAM (omem);
	soup_assert_cmpmem (g_memory_output_stream_get_data (mem),
			    g_memory_output_stream_get_data_size (mem),
			    chunkified->str, chunkified->len);

	g_object_unref (out);
	g_free (buf);

	debug_printf (1, "  async write\n");

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (slow_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (SOUP_TYPE_BODY_OUTPUT_STREAM,
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = chunk_length = chunk_total = 0;
	while (total < raw_contents_length) {
		if (chunk_total == chunk_length) {
			chunk_length = MIN (CHUNK_SIZE, raw_contents_length - total);
			chunk_total = 0;
		}
		nwrote = g_pollable_output_stream_write_nonblocking (G_POLLABLE_OUTPUT_STREAM (out),
								     raw_contents_data + total,
								     chunk_length - chunk_total,
								     NULL, &error);
		if (nwrote == -1 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			GSource *source;

			g_clear_error (&error);
			source = g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (out), NULL);
			g_source_set_dummy_callback (source);
			g_source_attach (source, NULL);
			while (!g_pollable_output_stream_is_writable (G_POLLABLE_OUTPUT_STREAM (out)))
				g_main_context_iteration (NULL, TRUE);
			g_source_destroy (source);
			g_source_unref (source);
			continue;
		} else if (nwrote == -1) {
			g_assert_no_error (error);
			g_clear_error (&error);
			break;
		} else {
			total += nwrote;
			chunk_total += nwrote;
		}
	}

	g_output_stream_close (out, NULL, &error);
	g_assert_no_error (error);
	g_clear_error (&error);

	mem = G_MEMORY_OUTPUT_STREAM (omem);
	soup_assert_cmpmem (g_memory_output_stream_get_data (mem),
			    g_memory_output_stream_get_data_size (mem),
			    chunkified->str, chunkified->len);

	g_object_unref (out);
	g_free (buf);

	debug_printf (1, "  failed write\n");
	/* this succeeds if it doesn't critical */

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (breaking_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (SOUP_TYPE_BODY_OUTPUT_STREAM,
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = 0;
	while (total < raw_contents_length) {
		nwrote = g_output_stream_write (out, raw_contents_data + total,
						raw_contents_length - total, NULL, NULL);
		if (nwrote == -1)
			break;
		else
			total += nwrote;
	}

	g_assert_cmpint (total, !=, raw_contents_length);

	g_output_stream_close (out, NULL, NULL);
	g_object_unref (out);

	g_free (buf);

	g_string_free (chunkified, TRUE);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/chunk-io", do_io_tests);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
