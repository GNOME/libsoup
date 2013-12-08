/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-client-io.c: client-side request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-socket-private.h"

static guint
parse_response_headers (SoupMessage *msg,
			SoupHTTPInputStream *http,
			gpointer user_data,
			GError **error)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupHTTPVersion version;

	g_free (msg->reason_phrase);
	msg->reason_phrase = NULL;
	if (!soup_http_input_stream_parse_response_headers (http,
							    msg->method,
							    &version,
							    &msg->status_code,
							    &msg->reason_phrase,
							    msg->response_headers,
							    error))
		return SOUP_STATUS_MALFORMED;

	g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_STATUS_CODE);
	g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_REASON_PHRASE);

	if (version < priv->http_version) {
		priv->http_version = version;
		g_object_notify (G_OBJECT (msg), SOUP_MESSAGE_HTTP_VERSION);
	}

	return SOUP_STATUS_OK;
}

static void
get_request_headers (SoupMessage          *msg,
		     SoupHTTPOutputStream *http,
		     gpointer              user_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupMessageQueueItem *item = user_data;
	SoupEncoding encoding;

	encoding = soup_message_headers_get_encoding (msg->request_headers);
	if ((encoding == SOUP_ENCODING_CONTENT_LENGTH ||
	     encoding == SOUP_ENCODING_NONE) &&
	    (msg->request_body->length > 0 ||
	     soup_message_headers_get_one (msg->request_headers, "Content-Type")) &&
	    !soup_message_headers_get_content_length (msg->request_headers)) {
		soup_message_headers_set_content_length (msg->request_headers,
							 msg->request_body->length);
	}

	soup_http_output_stream_build_request_headers (http,
						       soup_connection_is_via_proxy (item->conn),
						       msg->method,
						       soup_message_get_uri (msg),
						       priv->http_version,
						       msg->request_headers);
}

void
soup_message_send_request (SoupMessageQueueItem      *item,
			   SoupMessageCompletionFn    completion_cb,
			   gpointer                   user_data)
{
	GMainContext *async_context;
	GIOStream *iostream;

	if (!SOUP_IS_SESSION_SYNC (item->session)) {
		async_context = soup_session_get_async_context (item->session);
		if (!async_context)
			async_context = g_main_context_default ();
	} else
		async_context = NULL;
	iostream = soup_socket_get_iostream (soup_connection_get_socket (item->conn));

	soup_message_io_client (item, iostream, async_context,
				get_request_headers,
				parse_response_headers,
				item,
				completion_cb, user_data);
}
