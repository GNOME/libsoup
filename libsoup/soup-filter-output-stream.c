/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-filter-output-stream.c
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-filter-output-stream.h"
#include "soup.h"

/* This is just GFilterOutputStream + GPollableOutputStream */

static void soup_filter_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface, gpointer interface_data);

G_DEFINE_TYPE_WITH_CODE (SoupFilterOutputStream, soup_filter_output_stream, G_TYPE_FILTER_OUTPUT_STREAM,
			 G_IMPLEMENT_INTERFACE (G_TYPE_POLLABLE_OUTPUT_STREAM,
						soup_filter_output_stream_pollable_init))

static void
soup_filter_output_stream_init (SoupFilterOutputStream *stream)
{
}

static gboolean
soup_filter_output_stream_is_writable (GPollableOutputStream *stream)
{
	return g_pollable_output_stream_is_writable (G_POLLABLE_OUTPUT_STREAM (G_FILTER_OUTPUT_STREAM (stream)->base_stream));
}

static gssize
soup_filter_output_stream_write_nonblocking (GPollableOutputStream  *stream,
					     const void             *buffer,
					     gsize                   count,
					     GError                **error)
{
	return g_pollable_stream_write (G_FILTER_OUTPUT_STREAM (stream)->base_stream,
					buffer, count,
					FALSE, NULL, error);
}

static GSource *
soup_filter_output_stream_create_source (GPollableOutputStream *stream,
					 GCancellable          *cancellable)
{
	GSource *base_source, *pollable_source;

	base_source = g_pollable_output_stream_create_source (G_POLLABLE_OUTPUT_STREAM (G_FILTER_OUTPUT_STREAM (stream)->base_stream), cancellable);

	g_source_set_dummy_callback (base_source);
	pollable_source = g_pollable_source_new (G_OBJECT (stream));
	g_source_add_child_source (pollable_source, base_source);
	g_source_unref (base_source);

	return pollable_source;
}

static void
soup_filter_output_stream_class_init (SoupFilterOutputStreamClass *stream_class)
{
}

static void
soup_filter_output_stream_pollable_init (GPollableOutputStreamInterface *pollable_interface,
					gpointer                       interface_data)
{
	pollable_interface->is_writable = soup_filter_output_stream_is_writable;
	pollable_interface->write_nonblocking = soup_filter_output_stream_write_nonblocking;
	pollable_interface->create_source = soup_filter_output_stream_create_source;
}

GOutputStream *
soup_filter_output_stream_new (GOutputStream *base_stream)
{
	return g_object_new (SOUP_TYPE_FILTER_OUTPUT_STREAM,
			     "base-stream", base_stream,
			     "close-base-stream", FALSE,
			     NULL);
}
