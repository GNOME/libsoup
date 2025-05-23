/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-body-output-stream.c
 *
 * Copyright 2012 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-body-output-stream.h"
#include "soup.h"

typedef enum {
	SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_SIZE,
	SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_END,
	SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK,
	SOUP_BODY_OUTPUT_STREAM_STATE_TRAILERS,
	SOUP_BODY_OUTPUT_STREAM_STATE_DONE
} SoupBodyOutputStreamState;

struct _SoupBodyOutputStream {
	GFilterOutputStream parent_instance;
};

typedef struct {
	GOutputStream *base_stream;
	char           buf[20];

	SoupEncoding   encoding;
	goffset        write_length;
	goffset        written;
	SoupBodyOutputStreamState chunked_state;
	gboolean       eof;
} SoupBodyOutputStreamPrivate;

enum {
	PROP_0,

	PROP_ENCODING,
	PROP_CONTENT_LENGTH,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

enum {
	WROTE_DATA,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void soup_body_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupBodyOutputStream, soup_body_output_stream, G_TYPE_FILTER_OUTPUT_STREAM,
                               G_ADD_PRIVATE (SoupBodyOutputStream)
			       G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
						      soup_body_output_stream_pollable_init))


static void
soup_body_output_stream_init (SoupBodyOutputStream *stream)
{
}

static void
soup_body_output_stream_constructed (GObject *object)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (object);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	priv->base_stream = g_filter_output_stream_get_base_stream (G_FILTER_OUTPUT_STREAM (bostream));
}

static void
soup_body_output_stream_set_property (GObject *object, guint prop_id,
				      const GValue *value, GParamSpec *pspec)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (object);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	switch (prop_id) {
	case PROP_ENCODING:
		priv->encoding = g_value_get_enum (value);
		if (priv->encoding == SOUP_ENCODING_CHUNKED)
			priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_SIZE;
		break;
	case PROP_CONTENT_LENGTH:
		priv->write_length = g_value_get_uint64 (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_body_output_stream_get_property (GObject *object, guint prop_id,
				      GValue *value, GParamSpec *pspec)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (object);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	switch (prop_id) {
	case PROP_ENCODING:
		g_value_set_enum (value, priv->encoding);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_body_output_stream_wrote_data (SoupBodyOutputStream *bostream,
                                    const void           *buffer,
                                    gsize                 count)
{
	g_signal_emit (bostream, signals[WROTE_DATA], 0, buffer, count, FALSE);
}

static void
soup_body_output_stream_wrote_metadata (SoupBodyOutputStream *bostream,
                                        const void           *buffer,
                                        gsize                 count)
{
	g_signal_emit (bostream, signals[WROTE_DATA], 0, buffer, count, TRUE);
}

static gssize
soup_body_output_stream_write_raw (SoupBodyOutputStream  *bostream,
				   const void            *buffer,
				   gsize                  count,
				   gboolean               blocking,
				   GCancellable          *cancellable,
				   GError               **error)
{
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);
	gssize nwrote, my_count;

	/* If the caller tries to write too much to a Content-Length
	 * encoded stream, we truncate at the right point, but keep
	 * accepting additional data until they stop.
	 */
	if (priv->write_length) {
		my_count = MIN (count, priv->write_length - priv->written);
		if (my_count == 0) {
			priv->eof = TRUE;
			return count;
		}
	} else
		my_count = count;

	nwrote = g_pollable_stream_write (priv->base_stream,
					  buffer, my_count,
					  blocking, cancellable, error);

	if (nwrote > 0 && priv->write_length) {
		priv->written += nwrote;
		soup_body_output_stream_wrote_data (bostream, buffer, nwrote);
	}

	if (nwrote == my_count && my_count != count)
		nwrote = count;

	return nwrote;
}

static gssize
soup_body_output_stream_write_chunked (SoupBodyOutputStream  *bostream,
				       const void            *buffer,
				       gsize                  count,
				       gboolean               blocking,
				       GCancellable          *cancellable,
				       GError               **error)
{
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);
	char *buf = priv->buf;
	gssize nwrote, len;

again:
	len = strlen (buf);
	if (len) {
		nwrote = g_pollable_stream_write (priv->base_stream,
						  buf, len, blocking,
						  cancellable, error);
                if (nwrote > 0)
                        soup_body_output_stream_wrote_metadata (bostream, buf, nwrote);

		if (nwrote < 0)
			return nwrote;
		memmove (buf, buf + nwrote, len + 1 - nwrote);
		goto again;
	}

	switch (priv->chunked_state) {
	case SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_SIZE:
		g_snprintf (buf, sizeof (priv->buf),
			    "%lx\r\n", (gulong)count);

		if (count > 0)
			priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK;
		else
			priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_TRAILERS;
		break;

	case SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK:
		nwrote = g_pollable_stream_write (priv->base_stream,
						  buffer, count, blocking,
						  cancellable, error);
		if (nwrote > 0)
			soup_body_output_stream_wrote_data (bostream, buffer, nwrote);

		if (nwrote < (gssize)count)
			return nwrote;

		priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_END;
		break;

	case SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_END:
                g_strlcpy (buf, "\r\n", sizeof (priv->buf));
		priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_DONE;
		break;

	case SOUP_BODY_OUTPUT_STREAM_STATE_TRAILERS:
                g_strlcpy (buf, "\r\n", sizeof (priv->buf));
		priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_DONE;
		break;

	case SOUP_BODY_OUTPUT_STREAM_STATE_DONE:
		priv->chunked_state = SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_SIZE;
		return count;
	}

	goto again;
}

static gssize
soup_body_output_stream_write_fn (GOutputStream  *stream,
				  const void     *buffer,
				  gsize           count,
				  GCancellable   *cancellable,
				  GError        **error)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (stream);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	if (priv->eof)
		return count;

	switch (priv->encoding) {
	case SOUP_ENCODING_CHUNKED:
		return soup_body_output_stream_write_chunked (bostream, buffer, count,
							      TRUE, cancellable, error);

	default:
		return soup_body_output_stream_write_raw (bostream, buffer, count,
							  TRUE, cancellable, error);
	}
}

static gboolean
soup_body_output_stream_close_fn (GOutputStream  *stream,
				  GCancellable   *cancellable,
				  GError        **error)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (stream);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	if (priv->encoding == SOUP_ENCODING_CHUNKED &&
	    priv->chunked_state == SOUP_BODY_OUTPUT_STREAM_STATE_CHUNK_SIZE) {
		if (soup_body_output_stream_write_chunked (bostream, NULL, 0, TRUE, cancellable, error) == -1)
			return FALSE;
	}

	return G_OUTPUT_STREAM_CLASS (soup_body_output_stream_parent_class)->close_fn (stream, cancellable, error);
}

static gboolean
soup_body_output_stream_is_writable (GPollableOutputStream *stream)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (stream);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	return priv->eof ||
		g_pollable_output_stream_is_writable (G_POLLABLE_OUTPUT_STREAM (priv->base_stream));
}

static gssize
soup_body_output_stream_write_nonblocking (GPollableOutputStream  *stream,
					   const void             *buffer,
					   gsize                   count,
					   GError                **error)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (stream);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);

	if (priv->eof)
		return count;

	switch (priv->encoding) {
	case SOUP_ENCODING_CHUNKED:
		return soup_body_output_stream_write_chunked (bostream, buffer, count,
							      FALSE, NULL, error);

	default:
		return soup_body_output_stream_write_raw (bostream, buffer, count,
							  FALSE, NULL, error);
	}
}

static GSource *
soup_body_output_stream_create_source (GPollableOutputStream *stream,
				       GCancellable *cancellable)
{
	SoupBodyOutputStream *bostream = SOUP_BODY_OUTPUT_STREAM (stream);
        SoupBodyOutputStreamPrivate *priv = soup_body_output_stream_get_instance_private (bostream);
	GSource *base_source, *pollable_source;

	if (priv->eof)
		base_source = g_timeout_source_new (0);
	else
		base_source = g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (priv->base_stream), cancellable);
	g_source_set_dummy_callback (base_source);

	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_body_output_stream_class_init (SoupBodyOutputStreamClass *stream_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (stream_class);
	GOutputStreamClass *output_stream_class = G_OUTPUT_STREAM_CLASS (stream_class);

	object_class->constructed = soup_body_output_stream_constructed;
	object_class->set_property = soup_body_output_stream_set_property;
	object_class->get_property = soup_body_output_stream_get_property;

	output_stream_class->write_fn = soup_body_output_stream_write_fn;
	output_stream_class->close_fn = soup_body_output_stream_close_fn;

        /**
         * SoupBodyOutputStream::wrote-data:
         * @stream: the stream
         * @buffer: the write buffer
         * @count: the bytes written
         * @is_metadata: whether the data being written is control data
         *
         * Emitted every time data is written in a [type@BodyOutputStream]
         */
        signals[WROTE_DATA] =
                g_signal_new ("wrote-data",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 3,
                              G_TYPE_POINTER,
                              G_TYPE_UINT,
                              G_TYPE_BOOLEAN);

        properties[PROP_ENCODING] =
		g_param_spec_enum ("encoding",
				   "Encoding",
				   "Message body encoding",
				   SOUP_TYPE_ENCODING,
				   SOUP_ENCODING_NONE,
				   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_STRINGS);

        properties[PROP_CONTENT_LENGTH] =
		g_param_spec_uint64 ("content-length",
				     "Content-Length",
				     "Message body Content-Length",
				     0, G_MAXUINT64, 0,
				     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

static void
soup_body_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface,
				       gpointer interface_data)
{
	pollable_interface->is_writable = soup_body_output_stream_is_writable;
	pollable_interface->write_nonblocking = soup_body_output_stream_write_nonblocking;
	pollable_interface->create_source = soup_body_output_stream_create_source;
}

GOutputStream *
soup_body_output_stream_new (GOutputStream *base_stream,
			     SoupEncoding   encoding,
			     goffset        content_length)
{
	return g_object_new (SOUP_TYPE_BODY_OUTPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     "encoding", encoding,
			     "content-length", content_length,
			     NULL);
}
