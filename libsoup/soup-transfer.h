/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_TRANSFER_H
#define SOUP_TRANSFER_H 1

#include <glib.h>

#include <libsoup/soup-message.h>

typedef enum {
	SOUP_TRANSFER_END = 0,
	SOUP_TRANSFER_CONTINUE,
} SoupTransferDone;

#define SOUP_TRANSFER_CHUNKED -1

typedef SoupTransferDone (*SoupReadHeadersDoneFn) (const GString *headers,
						   guint         *content_len,
						   gpointer       user_data);

typedef SoupTransferDone (*SoupReadChunkFn) (const SoupDataBuffer *data,
					     gpointer              user_data);

typedef void (*SoupReadDoneFn) (const SoupDataBuffer *data,
				gpointer              user_data);

typedef void (*SoupReadErrorFn) (gboolean headers_done, gpointer user_data);

guint soup_transfer_read  (GIOChannel             *chan,
			   gboolean                overwrite_chunks,
			   SoupReadHeadersDoneFn   headers_done_cb,
			   SoupReadChunkFn         read_chunk_cb,
			   SoupReadDoneFn          read_done_cb,
			   SoupReadErrorFn         error_cb,
			   gpointer                user_data);

void  soup_transfer_read_cancel (guint tag);

typedef void (*SoupWriteHeadersDoneFn) (gpointer user_data);

typedef void (*SoupWriteDoneFn) (gpointer user_data);

typedef void (*SoupWriteErrorFn) (gboolean headers_done, gpointer user_data);

guint soup_transfer_write (GIOChannel             *chan,
			   const GString          *header,
			   const SoupDataBuffer   *src,
			   SoupWriteHeadersDoneFn  headers_done_cb,
			   SoupWriteDoneFn         write_done_cb,
			   SoupWriteErrorFn        error_cb,
			   gpointer                user_data);

void  soup_transfer_write_cancel (guint tag);

#endif /*SOUP_TRANSFER_H*/
