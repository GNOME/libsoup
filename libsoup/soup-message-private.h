/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_PRIVATE_H
#define SOUP_MESSAGE_PRIVATE_H 1

#include <libsoup/soup-message.h>

typedef struct {
	gpointer           io_data;

	guint              msg_flags;

	GSList            *chunks, *last_chunk;

	GSList            *content_handlers;

	SoupHttpVersion    http_version;

	SoupUri           *uri;
} SoupMessagePrivate;
#define SOUP_MESSAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_MESSAGE, SoupMessagePrivate))

void             soup_message_run_handlers     (SoupMessage      *msg,
						SoupHandlerPhase  phase);

void             soup_message_cleanup_response (SoupMessage      *req);


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

void soup_message_send_request_internal (SoupMessage       *req,
					 SoupSocket        *sock,
					 SoupConnection    *conn,
					 gboolean           via_proxy);

void soup_message_io_client  (SoupMessage               *msg,
			      SoupSocket                *sock,
			      SoupConnection            *conn,
			      SoupMessageGetHeadersFn    get_headers_cb,
			      SoupMessageParseHeadersFn  parse_headers_cb,
			      gpointer                   user_data);
void soup_message_io_server  (SoupMessage               *msg,
			      SoupSocket                *sock,
			      SoupMessageGetHeadersFn    get_headers_cb,
			      SoupMessageParseHeadersFn  parse_headers_cb,
			      gpointer                   user_data);

#endif /* SOUP_MESSAGE_PRIVATE_H */
