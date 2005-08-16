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
	const char *length, *enc;
	SoupHttpVersion version;
	GHashTable *resp_hdrs;
	SoupMethodId meth_id;

	if (!soup_headers_parse_response (headers, headers_len,
					  req->response_headers,
					  &version,
					  &req->status_code,
					  (char **) &req->reason_phrase))
		return SOUP_STATUS_MALFORMED;

	if (version < req->priv->http_version)
		req->priv->http_version = version;

	meth_id   = soup_method_get_id (req->method);
	resp_hdrs = req->response_headers;

	/* 
	 * Special case zero body handling for:
	 *   - HEAD requests (where content-length must be ignored) 
	 *   - CONNECT requests (no body expected) 
	 *   - No Content (204) responses (no message-body allowed)
	 *   - Reset Content (205) responses (no entity allowed)
	 *   - Not Modified (304) responses (no message-body allowed)
	 *   - 1xx Informational responses (where no body is allowed)
	 */
	if (meth_id == SOUP_METHOD_ID_HEAD ||
	    meth_id == SOUP_METHOD_ID_CONNECT ||
	    req->status_code  == SOUP_STATUS_NO_CONTENT || 
	    req->status_code  == SOUP_STATUS_RESET_CONTENT || 
	    req->status_code  == SOUP_STATUS_NOT_MODIFIED || 
	    SOUP_STATUS_IS_INFORMATIONAL (req->status_code)) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
		return SOUP_STATUS_OK;
	}

	/* 
	 * Handle Chunked encoding.  Prefer Chunked over a Content-Length to
	 * support broken Traffic-Server proxies that supply both.  
	 */
	enc = soup_message_get_header (resp_hdrs, "Transfer-Encoding");
	if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0) {
			*encoding = SOUP_TRANSFER_CHUNKED;
			return SOUP_STATUS_OK;
		} else
			return SOUP_STATUS_MALFORMED;
	}

	/* 
	 * Handle Content-Length encoding 
	 */
	length = soup_message_get_header (resp_hdrs, "Content-Length");
	if (length) {
		int len;

		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		len = atoi (length);
		if (len < 0)
			return SOUP_STATUS_MALFORMED;
		else
			*content_len = len;
	}

	return SOUP_STATUS_OK;
}

static void 
add_header (gpointer name, gpointer value, gpointer data)
{
	GString *headers = data;

	g_string_append_printf (headers, "%s: %s\r\n",
				(char *)name, (char *)value);
}

static void
get_request_headers (SoupMessage *req, GString *header,
		     SoupTransferEncoding *encoding,
		     gpointer user_data)
{
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

	if (req->priv->http_version == SOUP_HTTP_1_0) {
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
		if (!soup_message_get_header (req->request_headers,
					      "Content-Type")) {
			g_string_append (header, "Content-Type: text/xml; "
					 "charset=utf-8\r\n");
		}
		g_string_append_printf (header, "Content-Length: %d\r\n",
					req->request.length);
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
	}

	soup_message_foreach_header (req->request_headers, add_header, header);
	g_string_append (header, "\r\n");

	expect = soup_message_get_header (req->request_headers, "Expect");
	if (expect && !strcmp (expect, "100-continue"))
		req->priv->msg_flags |= SOUP_MESSAGE_EXPECT_CONTINUE;
}

/**
 * soup_message_send_request:
 * @req: a #SoupMessage
 * @sock: the #SoupSocket to send @req on
 * @is_via_proxy: %TRUE if @sock is a connection to a proxy server
 * rather than a direct connection to the desired HTTP server
 *
 * Begins the process of sending @msg across @sock. (If @sock is
 * synchronous, then soup_message_send_request() won't return until
 * the response has been received.)
 **/
void
soup_message_send_request (SoupMessage *req, SoupSocket *sock,
			   gboolean is_via_proxy)
{
	soup_message_send_request_internal (req, sock, NULL, is_via_proxy);
}

void
soup_message_send_request_internal (SoupMessage *req, SoupSocket *sock,
				    SoupConnection *conn, gboolean is_via_proxy)
{
	soup_message_cleanup_response (req);
	soup_message_io_client (req, sock, conn,
				get_request_headers,
				parse_response_headers,
				GUINT_TO_POINTER (is_via_proxy));
}
