/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_PRIVATE_H
#define SOUP_MESSAGE_PRIVATE_H 1

#include <libsoup/soup-message.h>

struct SoupMessagePrivate {
	gpointer           io_data;

	guint              msg_flags;

	GSList            *chunks, *last_chunk;

	GSList            *content_handlers;

	SoupHttpVersion    http_version;

	SoupUri           *uri;
};

void             soup_message_run_handlers     (SoupMessage      *msg,
						SoupHandlerPhase  phase);

void             soup_message_cleanup          (SoupMessage      *req);
void             soup_message_cleanup_response (SoupMessage      *req);

gboolean         soup_message_is_keepalive     (SoupMessage      *msg);


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

#endif /* SOUP_MESSAGE_PRIVATE_H */
