/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-server-io.c: server-side request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-message-private.h"
#include "soup-address.h"
#include "soup-auth.h"
#include "soup-context.h"
#include "soup-headers.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-server-message.h"
#include "soup-server.h"
#include "soup-socket.h"

static SoupKnownErrorCode
parse_request_headers (SoupMessage *msg, char *headers, guint headers_len,
		       SoupTransferEncoding *encoding, guint *content_len,
		       gpointer sock)
{
	SoupContext *ctx;
	char *req_path = NULL, *url;
	const char *length, *enc, *req_host;
	SoupServer *server;

	if (!soup_headers_parse_request (headers, headers_len,
					 msg->request_headers,
					 (char **) &msg->method,
					 &req_path,
					 &msg->priv->http_version))
		return SOUP_ERROR_BAD_REQUEST;

	/* Handle request body encoding */
	length = soup_message_get_header (msg->request_headers,
					  "Content-Length");
	enc = soup_message_get_header (msg->request_headers,
				       "Transfer-Encoding");

	if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			*encoding = SOUP_TRANSFER_CHUNKED;
		else {
			g_warning ("Unknown encoding type in HTTP request.");
			g_free (req_path);
			return SOUP_ERROR_NOT_IMPLEMENTED;
		}
	} else if (length) {
		int len;
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		len = atoi (length);
		if (len < 0) {
			g_free (req_path);
			return SOUP_ERROR_BAD_REQUEST;
		}
		*content_len = len;
	} else {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
	}

	/* Generate correct context for request */
	server = soup_server_message_get_server (SOUP_SERVER_MESSAGE (msg));
	req_host = soup_message_get_header (msg->request_headers, "Host");

	if (*req_path != '/') {
		/* Check for absolute URI */
		SoupUri *absolute;

		absolute = soup_uri_new (req_path);
		if (absolute) {
			url = g_strdup (req_path);
			soup_uri_free (absolute);
		} else {
			g_free (req_path);
			return SOUP_ERROR_BAD_REQUEST;
		}
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s:%d%s",
				       soup_server_get_protocol (server) == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       req_host, soup_server_get_port (server),
				       req_path);
	} else if (msg->priv->http_version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (sock);
		const char *host = soup_address_get_physical (addr);

		url = g_strdup_printf ("%s://%s:%d%s",
				       soup_server_get_protocol (server) == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       host, soup_server_get_port (server),
				       req_path);
	} else {
		g_free (req_path);
		return SOUP_ERROR_BAD_REQUEST;
	}

	ctx = soup_context_get (url);
	g_free (url);
	g_free (req_path);

	if (!ctx)
		return SOUP_ERROR_BAD_REQUEST;

	soup_message_set_context (msg, ctx);
	g_object_unref (ctx);

	return SOUP_ERROR_OK;
}

static void
write_header (gpointer name, gpointer value, gpointer headers)
{
	g_string_append_printf (headers, "%s: %s\r\n",
				(char *)name, (char *)value);
}

static void
get_response_headers (SoupMessage *msg, GString *headers,
		      SoupTransferEncoding *encoding,
		      gpointer user_data)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (msg);

	g_string_append_printf (headers, "HTTP/1.1 %d %s\r\n",
				msg->errorcode, msg->errorphrase);

	soup_message_foreach_header (msg->response_headers,
				     write_header, headers);

	*encoding = soup_server_message_get_encoding (smsg);
	if (*encoding == SOUP_TRANSFER_CONTENT_LENGTH) {
		g_string_append_printf (headers, "Content-Length: %d\r\n",
					msg->response.length);
	} else if (*encoding == SOUP_TRANSFER_CHUNKED)
		g_string_append (headers, "Transfer-Encoding: chunked\r\n");

	g_string_append (headers, "\r\n");
}

void
soup_message_read_request (SoupMessage *req, SoupSocket *sock)
{
	soup_message_io_server (req, sock,
				get_response_headers,
				parse_request_headers,
				sock);
}
