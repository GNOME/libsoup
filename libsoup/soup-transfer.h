/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifndef SOUP_TRANSFER_H
#define SOUP_TRANSFER_H 1

#include <glib.h>

#include <libsoup/soup-message.h>

typedef enum {
	SOUP_TRANSFER_END = 0,
	SOUP_TRANSFER_CONTINUE,
} SoupTransferDone;

typedef enum {
	SOUP_TRANSFER_UNKNOWN = 0,
	SOUP_TRANSFER_CHUNKED,
	SOUP_TRANSFER_CONTENT_LENGTH,
} SoupTransferEncoding;

typedef struct _SoupReader SoupReader;
typedef struct _SoupWriter SoupWriter;

typedef void (*SoupReadHeadersDoneFn) (const GString        *headers,
				       SoupTransferEncoding *encoding,
				       gint                 *content_len,
				       gpointer              user_data);

typedef void (*SoupReadChunkFn) (const SoupDataBuffer *data,
				 gpointer              user_data);

typedef void (*SoupReadDoneFn) (const SoupDataBuffer *data,
				gpointer              user_data);

typedef void (*SoupReadErrorFn) (gboolean headers_done, gpointer user_data);

SoupReader *soup_transfer_read  (GIOChannel             *chan,
				 gboolean                overwrite_chunks,
				 SoupReadHeadersDoneFn   headers_done_cb,
				 SoupReadChunkFn         read_chunk_cb,
				 SoupReadDoneFn          read_done_cb,
				 SoupReadErrorFn         error_cb,
				 gpointer                user_data);

void     soup_transfer_read_ref    (SoupReader *r);
gboolean soup_transfer_read_unref  (SoupReader *r);
void     soup_transfer_read_cancel (SoupReader *r);

void  soup_transfer_read_set_callbacks (SoupReader             *r,
					SoupReadHeadersDoneFn   headers_done_cb,
					SoupReadChunkFn         read_chunk_cb,
					SoupReadDoneFn          read_done_cb,
					SoupReadErrorFn         error_cb,
					gpointer                user_data);


typedef void (*SoupWriteDoneFn) (gpointer user_data);

typedef void (*SoupWriteErrorFn) (gboolean headers_done, gpointer user_data);

SoupWriter *soup_transfer_write_simple (GIOChannel             *chan,
					GString                *header,
					const SoupDataBuffer   *src,
					SoupWriteDoneFn         write_done_cb,
					SoupWriteErrorFn        error_cb,
					gpointer                user_data);

typedef void (*SoupWriteGetHeaderFn) (GString  **out_hdr,
				      gpointer   user_data);

typedef SoupTransferDone (*SoupWriteGetChunkFn) (SoupDataBuffer *out_next,
						 gpointer        user_data);

SoupWriter *soup_transfer_write (GIOChannel             *chan,
				 SoupTransferEncoding    encoding,
				 SoupWriteGetHeaderFn    get_header_cb,
				 SoupWriteGetChunkFn     get_chunk_cb,
				 SoupWriteDoneFn         write_done_cb,
				 SoupWriteErrorFn        error_cb,
				 gpointer                user_data);

void  soup_transfer_write_pause (SoupWriter *w);

void  soup_transfer_write_unpause (SoupWriter *w);

void     soup_transfer_write_ref    (SoupWriter *w);
gboolean soup_transfer_write_unref  (SoupWriter *w);
void     soup_transfer_write_cancel (SoupWriter *w);

#endif /*SOUP_TRANSFER_H*/
