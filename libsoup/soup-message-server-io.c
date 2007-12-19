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
		       SoupEncoding *encoding, gpointer sock)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupURI *uri;
	char *req_method, *req_path, *url;
	const char *req_host;
	SoupServer *server;
	guint status;

	status = soup_headers_parse_request (headers, headers_len,
					     msg->request_headers,
					     &req_method,
					     &req_path,
					     &priv->http_version);
	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		return status;

	g_object_set (G_OBJECT (msg),
		      SOUP_MESSAGE_METHOD, req_method,
		      NULL);
	g_free (req_method);



	/* Handle request body encoding */
	*encoding = soup_message_headers_get_encoding (msg->request_headers);
	if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
		if (soup_message_headers_find (msg->request_headers, "Transfer-Encoding"))
			return SOUP_STATUS_NOT_IMPLEMENTED;
		else
			return SOUP_STATUS_BAD_REQUEST;
	}

	/* Generate correct context for request */
	server = soup_server_message_get_server (SOUP_SERVER_MESSAGE (msg));
	req_host = soup_message_headers_find (msg->request_headers, "Host");

	if (*req_path != '/') {
		/* Check for absolute URI */
		SoupURI *absolute;

		absolute = soup_uri_new (req_path);
		if (absolute) {
			url = g_strdup (req_path);
			soup_uri_free (absolute);
		} else {
			g_free (req_path);
			return SOUP_STATUS_BAD_REQUEST;
		}
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s%s",
				       soup_server_is_https (server) ? "https" : "http",
				       req_host, req_path);
	} else if (priv->http_version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (sock);
		const char *host = soup_address_get_physical (addr);

		url = g_strdup_printf ("%s://%s:%d%s",
				       soup_server_is_https (server) ? "https" : "http",
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
write_header (const char *name, const char *value, gpointer headers)
{
	g_string_append_printf (headers, "%s: %s\r\n", name, value);
}

static void
get_response_headers (SoupMessage *msg, GString *headers,
		      SoupEncoding *encoding, gpointer user_data)
{
	SoupEncoding claimed_encoding;

	g_string_append_printf (headers, "HTTP/1.1 %d %s\r\n",
				msg->status_code, msg->reason_phrase);

	claimed_encoding = soup_message_headers_get_encoding (msg->response_headers);
	if ((msg->method == SOUP_METHOD_HEAD ||
	     msg->status_code  == SOUP_STATUS_NO_CONTENT ||
	     msg->status_code  == SOUP_STATUS_NOT_MODIFIED ||
	     SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) ||
	    (msg->method == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)))
		*encoding = SOUP_ENCODING_NONE;
	else
		*encoding = claimed_encoding;

	if (claimed_encoding == SOUP_ENCODING_CONTENT_LENGTH &&
	    !soup_message_headers_get_content_length (msg->response_headers)) {
		gsize content_length = soup_message_body_get_length (msg->response_body);

		soup_message_headers_set_content_length (msg->response_headers,
							 content_length);
	}

	soup_message_headers_foreach (msg->response_headers,
				      write_header, headers);
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
