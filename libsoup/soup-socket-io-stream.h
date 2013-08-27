/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#ifndef __SOUP_SOCKET_IO_STREAM_H__
#define __SOUP_SOCKET_IO_STREAM_H__ 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SOCKET_IO_STREAM            (soup_socket_io_stream_get_type ())
#define SOUP_SOCKET_IO_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOCKET_IO_STREAM, SoupSocketIOStream))
#define SOUP_SOCKET_IO_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOCKET_IO_STREAM, SoupSocketIOStreamClass))
#define SOUP_IS_SOCKET_IO_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOCKET_IO_STREAM))
#define SOUP_IS_SOCKET_IO_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SOCKET_IO_STREAM))
#define SOUP_SOCKET_IO_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOCKET_IO_STREAM, SoupSocketIOStreamClass))

typedef struct _SoupSocketIOStreamPrivate SoupSocketIOStreamPrivate;

typedef struct {
	GIOStream parent;

	SoupSocketIOStreamPrivate *priv;
} SoupSocketIOStream;

typedef struct {
	GIOStreamClass parent_class;

} SoupSocketIOStreamClass;

GType soup_socket_io_stream_get_type (void);

GIOStream *soup_socket_io_stream_new (GIOStream *base_iostream);

G_END_DECLS

#endif /* __SOUP_SOCKET_IO_STREAM_H__ */
