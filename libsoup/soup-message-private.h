/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_PRIVATE_H
#define SOUP_MESSAGE_PRIVATE_H 1

#include <libsoup/soup-message.h>
#include <libsoup/soup-context.h>

typedef enum {
	SOUP_MESSAGE_STATUS_IDLE,
	SOUP_MESSAGE_STATUS_QUEUED,
        SOUP_MESSAGE_STATUS_CONNECTING,
	SOUP_MESSAGE_STATUS_FINISHED,

	SOUP_MESSAGE_STATUS_WRITING_HEADERS,
	SOUP_MESSAGE_STATUS_WRITING_BODY,
	SOUP_MESSAGE_STATUS_WRITING_CHUNK_SIZE,
	SOUP_MESSAGE_STATUS_WRITING_CHUNK,
	SOUP_MESSAGE_STATUS_WRITING_CHUNK_END,
	SOUP_MESSAGE_STATUS_WRITING_TRAILERS,
	SOUP_MESSAGE_STATUS_FINISHED_WRITING,

	SOUP_MESSAGE_STATUS_READING_HEADERS,
	SOUP_MESSAGE_STATUS_READING_BODY,
	SOUP_MESSAGE_STATUS_READING_CHUNK_SIZE,
	SOUP_MESSAGE_STATUS_READING_CHUNK,
	SOUP_MESSAGE_STATUS_READING_CHUNK_END,
	SOUP_MESSAGE_STATUS_READING_TRAILERS,
	SOUP_MESSAGE_STATUS_FINISHED_READING

} SoupMessageStatus;

#define SOUP_MESSAGE_IS_STARTING(msg) (msg->priv->status == SOUP_MESSAGE_STATUS_QUEUED || msg->priv->status == SOUP_MESSAGE_STATUS_CONNECTING)
#define SOUP_MESSAGE_IS_WRITING(msg) (msg->priv->status >= SOUP_MESSAGE_STATUS_WRITING_HEADERS && msg->priv->status <= SOUP_MESSAGE_STATUS_WRITING_TRAILERS)
#define SOUP_MESSAGE_IS_READING(msg) (msg->priv->status >= SOUP_MESSAGE_STATUS_READING_HEADERS && msg->priv->status <= SOUP_MESSAGE_STATUS_READING_TRAILERS)


struct SoupMessagePrivate {
	SoupMessageStatus  status;

	SoupConnectId      connect_tag;
	gpointer           read_state;
	gpointer           write_state;

	guint              retries;

	SoupCallbackFn     callback;
	gpointer           user_data;

	guint              msg_flags;

	GSList            *content_handlers;

	SoupHttpVersion    http_version;

	SoupContext       *context;
	SoupConnection    *connection;
	SoupSocket        *socket;
};

void             soup_message_issue_callback (SoupMessage      *req);
void             soup_message_run_handlers   (SoupMessage      *msg,
					      SoupHandlerPhase  invoke_phase);

void             soup_message_cleanup        (SoupMessage      *req);

gboolean         soup_message_is_keepalive   (SoupMessage      *msg);

void             soup_message_set_context    (SoupMessage      *msg,
					      SoupContext      *new_ctx);
void             soup_message_set_connection (SoupMessage      *msg,
					      SoupConnection   *conn);
SoupConnection  *soup_message_get_connection (SoupMessage      *msg);
SoupSocket      *soup_message_get_socket     (SoupMessage      *msg);


typedef void (*SoupMessageReadHeadersFn) (SoupMessage          *msg,
					  char                 *headers,
					  guint                 header_len,
					  SoupTransferEncoding *encoding,
					  int                  *content_len);

typedef void (*SoupMessageReadChunkFn)   (SoupMessage          *msg,
					  const char           *chunk,
					  guint                 len);

typedef void (*SoupMessageReadBodyFn)    (SoupMessage          *msg,
					  char                 *body,
					  guint                 len);

typedef void (*SoupMessageReadErrorFn)   (SoupMessage          *msg);


void soup_message_read               (SoupMessage              *msg,
				      SoupMessageReadHeadersFn  read_headers_cb,
				      SoupMessageReadChunkFn    read_chunk_cb,
				      SoupMessageReadBodyFn     read_body_cb,
				      SoupMessageReadErrorFn    error_cb);
void soup_message_read_set_callbacks (SoupMessage              *msg,
				      SoupMessageReadHeadersFn  read_headers_cb,
				      SoupMessageReadChunkFn    read_chunk_cb,
				      SoupMessageReadBodyFn     read_body_cb,
				      SoupMessageReadErrorFn    error_cb);
void soup_message_read_cancel        (SoupMessage *msg);


typedef void     (*SoupMessageWriteGetHeaderFn) (SoupMessage    *msg,
						 GString        *out_hdr);

typedef gboolean (*SoupMessageWriteGetChunkFn)  (SoupMessage    *msg,
						 SoupDataBuffer *out_next);

typedef void     (*SoupMessageWriteDoneFn)      (SoupMessage    *msg);

typedef void     (*SoupMessageWriteErrorFn)     (SoupMessage    *msg);

void soup_message_write         (SoupMessage                 *msg,
				 SoupTransferEncoding         encoding,
				 SoupMessageWriteGetHeaderFn  get_header_cb,
				 SoupMessageWriteGetChunkFn   get_chunk_cb,
				 SoupMessageWriteDoneFn       write_done_cb,
				 SoupMessageWriteErrorFn      error_cb);
void soup_message_write_simple  (SoupMessage                 *msg,
				 const SoupDataBuffer        *body,
				 SoupMessageWriteGetHeaderFn  get_header_cb,
				 SoupMessageWriteDoneFn       write_done_cb,
				 SoupMessageWriteErrorFn      error_cb);
void soup_message_write_cancel  (SoupMessage                 *msg);

void soup_message_write_pause   (SoupMessage                 *msg);
void soup_message_write_unpause (SoupMessage                 *msg);


#endif /* SOUP_MESSAGE_PRIVATE_H */
