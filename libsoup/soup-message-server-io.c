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
#include "soup-headers.h"
#include "soup-server-message.h"
#include "soup-server.h"
#include "soup-socket.h"

static guint
parse_request_headers (SoupMessage *msg, char *headers, guint headers_len,
		       SoupTransferEncoding *encoding, guint *content_len,
		       gpointer sock)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupUri *uri;
	char *req_path = NULL, *url;
	const char *expect, *req_host;
	SoupServer *server;

	if (!soup_headers_parse_request (headers, headers_len,
					 msg->request_headers,
					 (char **) &msg->method,
					 &req_path,
					 &priv->http_version))
		return SOUP_STATUS_BAD_REQUEST;

	expect = soup_message_get_header (msg->request_headers, "Expect");
	if (expect && !strcmp (expect, "100-continue"))
		priv->msg_flags |= SOUP_MESSAGE_EXPECT_CONTINUE;

	/* Handle request body encoding */
	*encoding = soup_message_get_request_encoding (msg, content_len);
	if (*encoding == SOUP_TRANSFER_NONE) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
	} else if (*encoding == SOUP_TRANSFER_UNKNOWN) {
		if (soup_message_get_header (msg->request_headers, "Transfer-Encoding"))
			return SOUP_STATUS_NOT_IMPLEMENTED;
		else
			return SOUP_STATUS_BAD_REQUEST;
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
			return SOUP_STATUS_BAD_REQUEST;
		}
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s:%d%s",
				       soup_server_get_protocol (server) == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       req_host, soup_server_get_port (server),
				       req_path);
	} else if (priv->http_version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (sock);
		const char *host = soup_address_get_physical (addr);

		url = g_strdup_printf ("%s://%s:%d%s",
				       soup_server_get_protocol (server) == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       host, soup_server_get_port (server),
				       req_path);
	} else {
		g_free (req_path);
		return SOUP_STATUS_BAD_REQUEST;
	}

	uri = soup_uri_new (url);
	g_free (url);
	g_free (req_path);

	if (!uri)
		return SOUP_STATUS_BAD_REQUEST;

	soup_message_set_uri (msg, uri);
	soup_uri_free (uri);

	return SOUP_STATUS_OK;
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
	SoupTransferEncoding claimed_encoding;

	g_string_append_printf (headers, "HTTP/1.1 %d %s\r\n",
				msg->status_code, msg->reason_phrase);

	soup_message_foreach_header (msg->response_headers,
				     write_header, headers);

	*encoding = soup_message_get_response_encoding (msg, NULL);

	claimed_encoding = soup_server_message_get_encoding (smsg);
	if (claimed_encoding == SOUP_TRANSFER_CONTENT_LENGTH) {
		g_string_append_printf (headers, "Content-Length: %d\r\n",
					msg->response.length);
	} else if (claimed_encoding == SOUP_TRANSFER_CHUNKED)
		g_string_append (headers, "Transfer-Encoding: chunked\r\n");

	g_string_append (headers, "\r\n");
}

/**
 * soup_message_read_request:
 * @req: an empty #SoupServerMessage
 * @sock: socket to receive the request on
 *
 * Begins the process of receiving a request from @sock into @req.
 **/
void
soup_message_read_request (SoupMessage *req, SoupSocket *sock)
{
	soup_message_io_server (req, sock,
				get_response_headers,
				parse_request_headers,
				sock);
}
