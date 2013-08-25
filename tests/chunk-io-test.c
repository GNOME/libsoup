/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#include "test-utils.h"

static void
force_io_streams_init (void)
{
	SoupServer *server;
	SoupSession *session;
	guint port;
	SoupURI *base_uri;
	SoupMessage *msg;

	/* Poke libsoup enough to cause SoupBodyInputStream and
	 * SoupBodyOutputStream to get defined, so we can find them
	 * via g_type_from_name() later.
	 */

	server = soup_test_server_new (TRUE);
	port = 	soup_server_get_port (server);

	base_uri = soup_uri_new ("http://127.0.0.1");
	soup_uri_set_port (base_uri, port);

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	msg = soup_message_new_from_uri ("POST", base_uri);
	soup_session_send_message (session, msg);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);
}

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
			 g_type_from_name ("SoupFilterInputStream"),
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
			 g_type_from_name ("GFilterOutputStream"),
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
			 g_type_from_name ("GFilterOutputStream"),
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
chunkify (const char *str, gsize length)
{
	GString *gstr;
	int i, size;

	gstr = g_string_new (NULL);
	for (i = 0; i < length; i += CHUNK_SIZE) {
		size = MIN (CHUNK_SIZE, length - i);
		g_string_append_printf (gstr, "%x\r\n", size);
		g_string_append_len (gstr, str + i, size);
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
	char *raw_contents, *buf;
	gsize raw_length;
	GString *chunkified;
	GError *error = NULL;
	gssize nread, nwrote, total;
	gssize chunk_length, chunk_total;

	debug_printf (1, "\nI/O tests\n");

	if (!g_file_get_contents (SRCDIR "/index.txt", &raw_contents, &raw_length, &error)) {
		g_printerr ("Could not read index.txt: %s\n",
			    error->message);
		exit (1);
	}

	chunkified = chunkify (raw_contents, raw_length);

	debug_printf (1, "  sync read\n");

	imem = g_memory_input_stream_new_from_data (chunkified->str, chunkified->len, NULL);
	islow = g_object_new (slow_input_stream_get_type (),
			      "base-stream", imem,
			      "close-base-stream", TRUE,
			      NULL);
	in = g_object_new (g_type_from_name ("SoupBodyInputStream"),
			   "base-stream", islow,
			   "close-base-stream", TRUE,
			   "encoding", SOUP_ENCODING_CHUNKED,
			   NULL);
	g_object_unref (imem);
	g_object_unref (islow);

	buf = g_malloc (raw_length);
	total = 0;
	while (TRUE) {
		nread = g_input_stream_read (in, buf + total, raw_length - total,
					     NULL, &error);
		if (nread == -1) {
			debug_printf (1, "  Error reading stream: %s\n", error->message);
			g_clear_error (&error);
			errors++;
			break;
		} else if (nread == 0)
			break;
		else
			total += nread;
	}

	g_input_stream_close (in, NULL, &error);
	if (error) {
		debug_printf (1, "  Error closing input stream: %s\n", error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (in);

	if (total == raw_length) {
		if (memcmp (buf, raw_contents, raw_length) != 0) {
			debug_printf (1, "  mismatch when reading\n");
			errors++;
		}
	} else {
		debug_printf (1, "  incorrect read length: %d vs %d\n",
			      (int) total, (int) raw_length);
		errors++;
	}
	g_free (buf);

	debug_printf (1, "  async read\n");

	imem = g_memory_input_stream_new_from_data (chunkified->str, chunkified->len, NULL);
	islow = g_object_new (slow_input_stream_get_type (),
			      "base-stream", imem,
			      "close-base-stream", TRUE,
			      NULL);
	in = g_object_new (g_type_from_name ("SoupBodyInputStream"),
			   "base-stream", islow,
			   "close-base-stream", TRUE,
			   "encoding", SOUP_ENCODING_CHUNKED,
			   NULL);
	g_object_unref (imem);
	g_object_unref (islow);

	buf = g_malloc (raw_length);
	total = 0;
	while (TRUE) {
		nread = g_pollable_input_stream_read_nonblocking (G_POLLABLE_INPUT_STREAM (in),
								  buf + total, raw_length - total,
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
			debug_printf (1, "  Error reading stream: %s\n", error->message);
			g_clear_error (&error);
			errors++;
			break;
		} else if (nread == 0)
			break;
		else
			total += nread;
	}

	g_input_stream_close (in, NULL, &error);
	if (error) {
		debug_printf (1, "  Error closing input stream: %s\n", error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (in);

	if (total == raw_length) {
		if (memcmp (buf, raw_contents, raw_length) != 0) {
			debug_printf (1, "  mismatch when reading\n");
			errors++;
		}
	} else {
		debug_printf (1, "  incorrect read length: %d vs %d\n",
			      (int) total, (int) raw_length);
		errors++;
	}
	g_free (buf);

	debug_printf (1, "  sync write\n");

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (slow_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (g_type_from_name ("SoupBodyOutputStream"),
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = chunk_length = chunk_total = 0;
	while (total < raw_length) {
		if (chunk_total == chunk_length) {
			chunk_length = MIN (CHUNK_SIZE, raw_length - total);
			chunk_total = 0;
		}
		nwrote = g_output_stream_write (out, raw_contents + total,
						chunk_length - chunk_total, NULL, &error);
		if (nwrote == -1) {
			debug_printf (1, "  Error writing stream: %s\n", error->message);
			g_clear_error (&error);
			errors++;
			break;
		} else {
			total += nwrote;
			chunk_total += nwrote;
		}
	}

	g_output_stream_close (out, NULL, &error);
	if (error) {
		debug_printf (1, "  Error closing output stream: %s\n", error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (out);

	if (total == raw_length) {
		if (memcmp (buf, chunkified->str, chunkified->len) != 0) {
			debug_printf (1, "  mismatch when writing\n");
			g_print ("%.*s\n", (int)chunkified->len, buf);
			errors++;
		}
	}
	g_free (buf);

	debug_printf (1, "  async write\n");

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (slow_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (g_type_from_name ("SoupBodyOutputStream"),
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = chunk_length = chunk_total = 0;
	while (total < raw_length) {
		if (chunk_total == chunk_length) {
			chunk_length = MIN (CHUNK_SIZE, raw_length - total);
			chunk_total = 0;
		}
		nwrote = g_pollable_output_stream_write_nonblocking (G_POLLABLE_OUTPUT_STREAM (out),
								     raw_contents + total,
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
			debug_printf (1, "  Error writing stream: %s\n", error->message);
			g_clear_error (&error);
			errors++;
			break;
		} else {
			total += nwrote;
			chunk_total += nwrote;
		}
	}

	g_output_stream_close (out, NULL, &error);
	if (error) {
		debug_printf (1, "  Error closing output stream: %s\n", error->message);
		g_clear_error (&error);
		errors++;
	}
	g_object_unref (out);

	if (total == raw_length) {
		if (memcmp (buf, chunkified->str, chunkified->len) != 0) {
			debug_printf (1, "  mismatch when writing\n");
			errors++;
		}
	}
	g_free (buf);

	debug_printf (1, "  failed write\n");
	/* this succeeds if it doesn't critical */

	buf = g_malloc (chunkified->len);
	omem = g_memory_output_stream_new (buf, chunkified->len, NULL, NULL);
	oslow = g_object_new (breaking_output_stream_get_type (),
			      "base-stream", omem,
			      "close-base-stream", TRUE,
			      NULL);
	out = g_object_new (g_type_from_name ("SoupBodyOutputStream"),
			    "base-stream", oslow,
			    "close-base-stream", TRUE,
			    "encoding", SOUP_ENCODING_CHUNKED,
			    NULL);
	g_object_unref (omem);
	g_object_unref (oslow);

	total = 0;
	while (total < nwrote) {
		nwrote = g_output_stream_write (out, raw_contents + total,
						raw_length - total, NULL, NULL);
		if (nwrote == -1)
			break;
		else
			total += nwrote;
	}

	if (total == raw_length) {
		debug_printf (1, "  breaking stream didn't break?\n");
		errors++;
	}

	g_output_stream_close (out, NULL, NULL);
	g_object_unref (out);

	g_free (buf);

	g_string_free (chunkified, TRUE);
	g_free (raw_contents);
}

int
main (int argc, char **argv)
{
	test_init (argc, argv, NULL);

	force_io_streams_init ();

	do_io_tests ();

	test_cleanup ();
	return errors != 0;
}
