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
#include "soup-context.h"
#include "soup-headers.h"
#include "soup-misc.h"
#include "soup-private.h"

static SoupKnownErrorCode
parse_response_headers_cb (SoupMessage *req,
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
					  &req->errorcode,
					  (char **) &req->errorphrase))
		return SOUP_ERROR_MALFORMED;

	meth_id   = soup_method_get_id (req->method);
	resp_hdrs = req->response_headers;

	req->errorclass = soup_error_get_class (req->errorcode);

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
	    req->errorcode  == SOUP_ERROR_NO_CONTENT || 
	    req->errorcode  == SOUP_ERROR_RESET_CONTENT || 
	    req->errorcode  == SOUP_ERROR_NOT_MODIFIED || 
	    req->errorclass == SOUP_ERROR_CLASS_INFORMATIONAL) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
		return SOUP_ERROR_OK;
	}

	/* 
	 * Handle Chunked encoding.  Prefer Chunked over a Content-Length to
	 * support broken Traffic-Server proxies that supply both.  
	 */
	enc = soup_message_get_header (resp_hdrs, "Transfer-Encoding");
	if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0) {
			*encoding = SOUP_TRANSFER_CHUNKED;
			return SOUP_ERROR_OK;
		} else
			return SOUP_ERROR_MALFORMED;
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
			return SOUP_ERROR_MALFORMED;
		else
			*content_len = len;
	}

	return SOUP_ERROR_OK;
}

void
soup_message_read_response (SoupMessage            *msg,
			    SoupMessageCallbackFn   read_headers_cb,
			    SoupMessageReadChunkFn  read_chunk_cb,
			    SoupMessageCallbackFn   read_body_cb,
			    SoupMessageCallbackFn   read_error_cb,
			    gpointer                user_data)
{
	soup_message_read (msg, &msg->response, parse_response_headers_cb,
			   read_headers_cb, read_chunk_cb, read_body_cb,
			   read_error_cb, user_data);
}


static void
encode_http_auth (SoupMessage *msg, GString *header, gboolean proxy_auth)
{
	SoupAuth *auth;
	SoupContext *ctx;
	char *token;

	ctx = proxy_auth ? soup_get_proxy () : msg->priv->context;

	auth = soup_context_lookup_auth (ctx, msg);
	if (!auth)
		return;
	if (!soup_auth_is_authenticated (auth) &&
	    !soup_context_authenticate_auth (ctx, auth))
		return;

	token = soup_auth_get_authorization (auth, msg);
	if (token) {
		g_string_sprintfa (header, "%s: %s\r\n",
				   proxy_auth ? 
					"Proxy-Authorization" : 
					"Authorization",
				   token);
		g_free (token);
	}
}

static void 
add_header (gpointer name, gpointer value, gpointer data)
{
	GString *headers = data;

	g_string_append_printf (headers, "%s: %s\r\n",
				(char *)name, (char *)value);
}

static void
get_request_header_cb (SoupMessage *req, GString *header, gpointer user_data)
{
	const SoupUri *uri = soup_message_get_uri (req);
	char *uri_string;
	gboolean proxy = GPOINTER_TO_UINT (user_data);

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
	}

	encode_http_auth (req, header, FALSE);
	if (proxy)
		encode_http_auth (req, header, TRUE);

	soup_message_foreach_header (req->request_headers, add_header, header);
	g_string_append (header, "\r\n");
}

void
soup_message_write_request (SoupMessage *req, gboolean is_via_proxy,
			    SoupMessageCallbackFn write_done_cb,
			    SoupMessageCallbackFn write_error_cb,
			    gpointer user_data)
{
	soup_message_write_simple (req, &req->request,
				   get_request_header_cb,
				   GUINT_TO_POINTER (is_via_proxy),
				   write_done_cb, write_error_cb, user_data);
}
