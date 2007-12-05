/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-client-io.c: client-side request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "soup-message-private.h"
#include "soup-auth.h"
#include "soup-headers.h"
#include "soup-uri.h"

static guint
parse_response_headers (SoupMessage *req,
			char *headers, guint headers_len,
			SoupTransferEncoding *encoding,
			guint *content_len,
			gpointer user_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (req);
	SoupHTTPVersion version;

	g_free((char*)req->reason_phrase);
	req->reason_phrase = NULL;
	if (!soup_headers_parse_response (headers, headers_len,
					  req->response_headers,
					  &version,
					  &req->status_code,
					  (char **) &req->reason_phrase))
		return SOUP_STATUS_MALFORMED;

	if (version < priv->http_version)
		priv->http_version = version;

	*encoding = soup_message_get_response_encoding (req, content_len);
	if (*encoding == SOUP_TRANSFER_NONE) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
	} else if (*encoding == SOUP_TRANSFER_UNKNOWN)
		return SOUP_STATUS_MALFORMED;

	return SOUP_STATUS_OK;
}

static void 
add_header (const char *name, const char *value, gpointer data)
{
	GString *headers = data;
	g_string_append_printf (headers, "%s: %s\r\n", name, value);
}

static void
get_request_headers (SoupMessage *req, GString *header,
		     SoupTransferEncoding *encoding,
		     gpointer user_data)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (req);
	gboolean proxy = GPOINTER_TO_UINT (user_data);
	const SoupUri *uri = soup_message_get_uri (req);
	const char *expect;
	char *uri_string;

	if (!strcmp (req->method, "CONNECT")) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri->host, uri->port);
	} else {
		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		uri_string = soup_uri_to_string (uri, !proxy);
	}

	if (priv->http_version == SOUP_HTTP_1_0) {
		g_string_append_printf (header, "%s %s HTTP/1.0\r\n",
					req->method, uri_string);
	} else {
		g_string_append_printf (header, "%s %s HTTP/1.1\r\n",
					req->method, uri_string);
		if (soup_uri_uses_default_port (uri)) {
			g_string_append_printf (header, "Host: %s\r\n",
						uri->host);
		} else {
			g_string_append_printf (header, "Host: %s:%d\r\n",
						uri->host, uri->port);
		}
	}
	g_free (uri_string);

	if (req->request.length > 0) {
		g_string_append_printf (header, "Content-Length: %d\r\n",
					req->request.length);
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
	}

	soup_message_headers_foreach (req->request_headers, add_header, header);
	g_string_append (header, "\r\n");

	/* FIXME: parsing */
	expect = soup_message_headers_find (req->request_headers, "Expect");
	if (expect && !g_ascii_strcasecmp (expect, "100-continue"))
		priv->msg_flags |= SOUP_MESSAGE_EXPECT_CONTINUE;
}

void
soup_message_send_request (SoupMessage *req, SoupSocket *sock,
			   SoupConnection *conn, gboolean is_via_proxy)
{
	soup_message_cleanup_response (req);
	soup_message_io_client (req, sock, conn,
				get_request_headers,
				parse_response_headers,
				GUINT_TO_POINTER (is_via_proxy));
}
