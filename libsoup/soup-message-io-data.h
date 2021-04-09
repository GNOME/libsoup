/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_MESSAGE_IO_DATA_H__
#define __SOUP_MESSAGE_IO_DATA_H__ 1

#include "soup-filter-input-stream.h"
#include "soup-message-headers.h"

typedef enum {
	SOUP_MESSAGE_IO_STATE_NOT_STARTED,
	SOUP_MESSAGE_IO_STATE_ANY = SOUP_MESSAGE_IO_STATE_NOT_STARTED,
	SOUP_MESSAGE_IO_STATE_HEADERS,
	SOUP_MESSAGE_IO_STATE_BLOCKING,
	SOUP_MESSAGE_IO_STATE_BODY_START,
	SOUP_MESSAGE_IO_STATE_BODY,
	SOUP_MESSAGE_IO_STATE_BODY_DATA,
	SOUP_MESSAGE_IO_STATE_BODY_FLUSH,
	SOUP_MESSAGE_IO_STATE_BODY_DONE,
	SOUP_MESSAGE_IO_STATE_FINISHING,
	SOUP_MESSAGE_IO_STATE_DONE
} SoupMessageIOState;

#define SOUP_MESSAGE_IO_STATE_ACTIVE(state) \
	(state != SOUP_MESSAGE_IO_STATE_NOT_STARTED && \
	 state != SOUP_MESSAGE_IO_STATE_BLOCKING && \
	 state != SOUP_MESSAGE_IO_STATE_DONE)
#define SOUP_MESSAGE_IO_STATE_POLLABLE(state) \
	(SOUP_MESSAGE_IO_STATE_ACTIVE (state) && \
	 state != SOUP_MESSAGE_IO_STATE_BODY_DONE)

typedef enum {
	SOUP_MESSAGE_IO_COMPLETE,
        SOUP_MESSAGE_IO_INTERRUPTED,
        SOUP_MESSAGE_IO_STOLEN
} SoupMessageIOCompletion;

typedef void (*SoupMessageIOCompletionFn) (GObject                *msg,
					   SoupMessageIOCompletion completion,
					   gpointer                user_data);

typedef struct {
	GIOStream              *iostream;
	SoupFilterInputStream  *istream;
	GInputStream           *body_istream;
	GOutputStream          *ostream;
	GOutputStream          *body_ostream;

	SoupMessageIOState    read_state;
	SoupEncoding          read_encoding;
	GByteArray           *read_header_buf;
	goffset               read_length;

	SoupMessageIOState    write_state;
	SoupEncoding          write_encoding;
	GString              *write_buf;
	GBytes               *write_chunk;
	goffset               write_body_offset;
	goffset               write_length;
	goffset               written;

	GSource *io_source;
	gboolean paused;

	GCancellable *async_wait;
	GError       *async_error;

	SoupMessageIOCompletionFn   completion_cb;
	gpointer                    completion_data;

#ifdef HAVE_SYSPROF
	gint64 begin_time_nsec;
#endif
} SoupMessageIOData;

void     soup_message_io_data_cleanup      (SoupMessageIOData *io);

gboolean soup_message_io_data_read_headers (SoupMessageIOData *io,
					    gboolean           blocking,
					    GCancellable      *cancellable,
                                            gushort           *extra_bytes,
					    GError           **error);

typedef gboolean (*SoupMessageIOSourceFunc) (GObject *msg,
					     gpointer user_data);

GSource *soup_message_io_data_get_source   (SoupMessageIOData      *io,
					    GObject                *msg,
					    GCancellable           *cancellable,
					    SoupMessageIOSourceFunc callback,
					    gpointer                user_data);

void    soup_message_io_data_pause         (SoupMessageIOData      *io);
void    soup_message_io_data_unpause       (SoupMessageIOData      *io);


#endif /* __SOUP_MESSAGE_IO_DATA_H__ */
