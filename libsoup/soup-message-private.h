/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_PRIVATE_H
#define SOUP_MESSAGE_PRIVATE_H 1

#include <libsoup/soup-message.h>

typedef enum {
	SOUP_MESSAGE_STATUS_IDLE,
	SOUP_MESSAGE_STATUS_QUEUED,
        SOUP_MESSAGE_STATUS_CONNECTING,
        SOUP_MESSAGE_STATUS_RUNNING,
	SOUP_MESSAGE_STATUS_FINISHED,
} SoupMessageStatus;

#define SOUP_MESSAGE_IS_STARTING(msg) (msg->priv->status == SOUP_MESSAGE_STATUS_QUEUED || msg->priv->status == SOUP_MESSAGE_STATUS_CONNECTING)

struct SoupMessagePrivate {
	SoupMessageStatus  status;

	gpointer           io_data;

	guint              msg_flags;

	GSList            *chunks, *last_chunk;

	GSList            *content_handlers;

	SoupHttpVersion    http_version;

	SoupUri           *uri;
};

void             soup_message_run_handlers   (SoupMessage      *msg,
					      SoupHandlerPhase  invoke_phase);

void             soup_message_cleanup        (SoupMessage      *req);

gboolean         soup_message_is_keepalive   (SoupMessage      *msg);

void             soup_message_set_uri        (SoupMessage      *msg,
					      const SoupUri    *uri);


typedef void     (*SoupMessageGetHeadersFn)  (SoupMessage      *msg,
					      GString          *headers,
					      SoupTransferEncoding *encoding,
					      gpointer          user_data);
typedef guint    (*SoupMessageParseHeadersFn)(SoupMessage      *msg,
					      char             *headers,
					      guint             header_len,
					      SoupTransferEncoding *encoding,
					      guint            *content_len,
					      gpointer          user_data);

void soup_message_io_client  (SoupMessage               *msg,
			      SoupSocket                *sock,
			      SoupMessageGetHeadersFn    get_headers_cb,
			      SoupMessageParseHeadersFn  parse_headers_cb,
			      gpointer                   user_data);
void soup_message_io_server  (SoupMessage               *msg,
			      SoupSocket                *sock,
			      SoupMessageGetHeadersFn    get_headers_cb,
			      SoupMessageParseHeadersFn  parse_headers_cb,
			      gpointer                   user_data);

void soup_message_io_cancel  (SoupMessage *msg);

#endif /* SOUP_MESSAGE_PRIVATE_H */
