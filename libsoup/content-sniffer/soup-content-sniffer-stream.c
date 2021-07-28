/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-content-sniffer-stream.c
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-content-sniffer-stream.h"
#include "soup.h"

enum {
	PROP_0,

	PROP_SNIFFER,
	PROP_MESSAGE,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupContentSnifferStream {
	GFilterInputStream parent_instance;
};

typedef struct {
	SoupContentSniffer *sniffer;
	SoupMessage *msg;

	guchar *buffer;
	gsize buffer_nread;
	gboolean sniffing;
	GError *error;

	char *sniffed_type;
	GHashTable *sniffed_params;
} SoupContentSnifferStreamPrivate;

#define BUFFER_SIZE 512

static void soup_content_sniffer_stream_pollable_init (GPollableInputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupContentSnifferStream, soup_content_sniffer_stream, G_TYPE_FILTER_INPUT_STREAM,
                               G_ADD_PRIVATE (SoupContentSnifferStream)
			       G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_INPUT_STREAM,
						      soup_content_sniffer_stream_pollable_init))

static void
soup_content_sniffer_stream_finalize (GObject *object)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	g_clear_object (&priv->sniffer);
	g_clear_object (&priv->msg);
	g_free (priv->buffer);
	g_clear_error (&priv->error);
	g_free (priv->sniffed_type);
	g_clear_pointer (&priv->sniffed_params, g_hash_table_unref);

	G_OBJECT_CLASS (soup_content_sniffer_stream_parent_class)->finalize (object);
}

static void
soup_content_sniffer_stream_set_property (GObject *object, guint prop_id,
					  const GValue *value, GParamSpec *pspec)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	switch (prop_id) {
	case PROP_SNIFFER:
		priv->sniffer = g_value_dup_object (value);
		break;
	case PROP_MESSAGE:
		priv->msg = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_content_sniffer_stream_get_property (GObject *object, guint prop_id,
					  GValue *value, GParamSpec *pspec)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (object);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	switch (prop_id) {
	case PROP_SNIFFER:
		g_value_set_object (value, priv->sniffer);
		break;
	case PROP_MESSAGE:
		g_value_set_object (value, priv->msg);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gssize
read_and_sniff (GInputStream *stream, gboolean blocking,
		GCancellable *cancellable, GError **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);
	gssize nread;
	GError *my_error = NULL;
	GBytes *buf;

        if (!priv->buffer)
                priv->buffer = g_malloc (BUFFER_SIZE);

	do {
		nread = g_pollable_stream_read (G_FILTER_INPUT_STREAM (stream)->base_stream,
						priv->buffer + priv->buffer_nread,
						BUFFER_SIZE - priv->buffer_nread,
						blocking, cancellable, &my_error);
		if (nread <= 0)
			break;
		priv->buffer_nread += nread;
	} while (priv->buffer_nread < BUFFER_SIZE);

	/* If we got EAGAIN or cancellation before filling the buffer,
	 * just return that right away. Likewise if we got any other
	 * error without ever reading any data. Otherwise, save the
	 * error to return after we're done sniffing.
	 */
	if (my_error) {
		if (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK) ||
		    g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
		    priv->buffer_nread == 0) {
			g_propagate_error (error, my_error);
			return -1;
		} else
			priv->error = my_error;
	}

	/* Sniff, then return the data */
	buf = g_bytes_new_static (priv->buffer, priv->buffer_nread);
	priv->sniffed_type =
		soup_content_sniffer_sniff (priv->sniffer, priv->msg, buf,
					    &priv->sniffed_params);
	g_bytes_unref (buf);
	priv->sniffing = FALSE;

	return priv->buffer_nread;
}	

static gssize
read_internal (GInputStream  *stream,
	       void          *buffer,
	       gsize          count,
	       gboolean       blocking,
	       GCancellable  *cancellable,
	       GError       **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);
	gssize nread;

	if (priv->error) {
		g_propagate_error (error, priv->error);
		priv->error = NULL;
		return -1;
	}

	if (priv->sniffing) {
		nread = read_and_sniff (stream, blocking, cancellable, error);
		if (nread <= 0)
			return nread;
	}

	if (priv->buffer) {
		nread = MIN (count, priv->buffer_nread);
		if (buffer)
			memcpy (buffer, priv->buffer, nread);
		if (nread == priv->buffer_nread) {
			g_free (priv->buffer);
			priv->buffer = NULL;
		} else {
			/* FIXME, inefficient */
			memmove (priv->buffer,
				 priv->buffer + nread,
				 priv->buffer_nread - nread);
			priv->buffer_nread -= nread;
		}
	} else {
		nread = g_pollable_stream_read (G_FILTER_INPUT_STREAM (stream)->base_stream,
						buffer, count, blocking,
						cancellable, error);
	}
	return nread;
}

static gssize
soup_content_sniffer_stream_read (GInputStream  *stream,
				  void          *buffer,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	return read_internal (stream, buffer, count, TRUE,
			      cancellable, error);
}

static gssize
soup_content_sniffer_stream_skip (GInputStream  *stream,
				  gsize          count,
				  GCancellable  *cancellable,
				  GError       **error)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);
	gssize nskipped;

	if (priv->sniffing) {
		/* Read into the internal buffer... */
		nskipped = soup_content_sniffer_stream_read (stream, NULL, 0, cancellable, error);
		if (nskipped == -1)
			return -1;
		/* Now fall through */
	}

	if (priv->buffer) {
		nskipped = MIN (count, priv->buffer_nread);
		if (nskipped == priv->buffer_nread) {
			g_free (priv->buffer);
			priv->buffer = NULL;
		} else {
			/* FIXME */
			memmove (priv->buffer,
				 priv->buffer + nskipped,
				 priv->buffer_nread - nskipped);
			priv->buffer_nread -= nskipped;
		}
	} else {
		nskipped = G_INPUT_STREAM_CLASS (soup_content_sniffer_stream_parent_class)->
			skip (stream, count, cancellable, error);
	}
	return nskipped;
}

static gboolean
soup_content_sniffer_stream_can_poll (GPollableInputStream *pollable)
{
	GInputStream *base_stream = G_FILTER_INPUT_STREAM (pollable)->base_stream;

	return G_IS_POLLABLE_INPUT_STREAM (base_stream) &&
		g_pollable_input_stream_can_poll (G_POLLABLE_INPUT_STREAM (base_stream));
}


static gboolean
soup_content_sniffer_stream_is_readable (GPollableInputStream *stream)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	if (priv->error ||
	    (!priv->sniffing && priv->buffer))
		return TRUE;

	return g_pollable_input_stream_is_readable (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (stream)->base_stream));
}

static gssize
soup_content_sniffer_stream_read_nonblocking (GPollableInputStream  *stream,
					      void                  *buffer,
					      gsize                  count,
					      GError               **error)
{
	return read_internal (G_INPUT_STREAM (stream), buffer, count,
			      FALSE, NULL, error);
}

static GSource *
soup_content_sniffer_stream_create_source (GPollableInputStream *stream,
					   GCancellable         *cancellable)
{
	SoupContentSnifferStream *sniffer = SOUP_CONTENT_SNIFFER_STREAM (stream);
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);
	GSource *base_source, *pollable_source;

	if (priv->error ||
	    (!priv->sniffing && priv->buffer))
		base_source = g_timeout_source_new (0);
	else
		base_source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (G_FILTER_INPUT_STREAM (stream)->base_stream), cancellable);

	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_content_sniffer_stream_init (SoupContentSnifferStream *sniffer)
{
	SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);
	priv->sniffing = TRUE;
}

static void
soup_content_sniffer_stream_class_init (SoupContentSnifferStreamClass *sniffer_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (sniffer_class);
	GInputStreamClass *input_stream_class =
		G_INPUT_STREAM_CLASS (sniffer_class);
 
	object_class->finalize = soup_content_sniffer_stream_finalize;
	object_class->set_property = soup_content_sniffer_stream_set_property;
	object_class->get_property = soup_content_sniffer_stream_get_property;

	input_stream_class->read_fn = soup_content_sniffer_stream_read;
	input_stream_class->skip = soup_content_sniffer_stream_skip;

        properties[PROP_SNIFFER] =
		g_param_spec_object ("sniffer",
				     "Sniffer",
				     "The stream's SoupContentSniffer",
				     SOUP_TYPE_CONTENT_SNIFFER,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);
        properties[PROP_MESSAGE] =
		g_param_spec_object ("message",
				     "Message",
				     "The stream's SoupMessage",
				     SOUP_TYPE_MESSAGE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

static void
soup_content_sniffer_stream_pollable_init (GPollableInputStreamInterface *pollable_interface,
					   gpointer                       interface_data)
{
	pollable_interface->can_poll = soup_content_sniffer_stream_can_poll;
	pollable_interface->is_readable = soup_content_sniffer_stream_is_readable;
	pollable_interface->read_nonblocking = soup_content_sniffer_stream_read_nonblocking;
	pollable_interface->create_source = soup_content_sniffer_stream_create_source;
}

gboolean
soup_content_sniffer_stream_is_ready (SoupContentSnifferStream  *sniffer,
				      gboolean                   blocking,
				      GCancellable              *cancellable,
				      GError                   **error)
{
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	if (!priv->sniffing)
		return TRUE;

	return read_and_sniff (G_INPUT_STREAM (sniffer), blocking,
			       cancellable, error) != -1;
}

const char *
soup_content_sniffer_stream_sniff (SoupContentSnifferStream  *sniffer,
				   GHashTable               **params)
{
        SoupContentSnifferStreamPrivate *priv = soup_content_sniffer_stream_get_instance_private (sniffer);

	if (params)
		*params = priv->sniffed_params;
	return priv->sniffed_type;
}
