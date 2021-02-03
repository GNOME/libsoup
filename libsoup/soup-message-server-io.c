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

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup-socket-private.h"

static SoupURI *
parse_connect_authority (const char *req_path)
{
	SoupURI *uri;
	char *fake_uri;

	fake_uri = g_strdup_printf ("http://%s", req_path);
	uri = soup_uri_new (fake_uri);
	g_free (fake_uri);

	if (uri->user || uri->password ||
	    uri->query || uri->fragment ||
	    !uri->host ||
	    (uri->port == 0) ||
	    (strcmp (uri->path, "/") != 0)) {
		soup_uri_free (uri);
		return NULL;
	}

	return uri;
}

static guint
parse_request_headers (SoupMessage *msg, char *headers, guint headers_len,
		       SoupEncoding *encoding, gpointer sock, GError **error)
{
	char *req_method, *req_path, *url;
	SoupHTTPVersion version;
	const char *req_host;
	guint status;
	SoupURI *uri;

	status = soup_headers_parse_request (headers, headers_len,
					     msg->request_headers,
					     &req_method,
					     &req_path,
					     &version);
	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		if (status == SOUP_STATUS_MALFORMED) {
			g_set_error_literal (error, SOUP_REQUEST_ERROR,
					     SOUP_REQUEST_ERROR_PARSING,
					     _("Could not parse HTTP request"));
		}
		return status;
	}

	g_object_set (G_OBJECT (msg),
		      SOUP_MESSAGE_METHOD, req_method,
		      SOUP_MESSAGE_HTTP_VERSION, version,
		      NULL);
	g_free (req_method);

	/* Handle request body encoding */
	*encoding = soup_message_headers_get_encoding (msg->request_headers);
	if (*encoding == SOUP_ENCODING_UNRECOGNIZED) {
		g_free (req_path);
		if (soup_message_headers_get_list (msg->request_headers, "Transfer-Encoding"))
			return SOUP_STATUS_NOT_IMPLEMENTED;
		else
			return SOUP_STATUS_BAD_REQUEST;
	}

	/* Generate correct context for request */
	req_host = soup_message_headers_get_one (msg->request_headers, "Host");
	if (req_host && strchr (req_host, '/')) {
		g_free (req_path);
		return SOUP_STATUS_BAD_REQUEST;
	}

	if (!strcmp (req_path, "*") && req_host) {
		/* Eg, "OPTIONS * HTTP/1.1" */
		url = g_strdup_printf ("%s://%s",
				       soup_socket_is_ssl (sock) ? "https" : "http",
				       req_host);
		uri = soup_uri_new (url);
		if (uri)
			soup_uri_set_path (uri, "*");
		g_free (url);
	} else if (msg->method == SOUP_METHOD_CONNECT) {
		/* Authority */
		uri = parse_connect_authority (req_path);
	} else if (*req_path != '/') {
		/* Absolute URI */
		uri = soup_uri_new (req_path);
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s%s",
				       soup_socket_is_ssl (sock) ? "https" : "http",
				       req_host, req_path);
		uri = soup_uri_new (url);
		g_free (url);
	} else if (soup_message_get_http_version (msg) == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (sock);

		uri = soup_uri_new (NULL);
		soup_uri_set_scheme (uri, soup_socket_is_ssl (sock) ?
				     SOUP_URI_SCHEME_HTTPS :
				     SOUP_URI_SCHEME_HTTP);
		soup_uri_set_host (uri, soup_address_get_physical (addr));
		soup_uri_set_port (uri, soup_address_get_port (addr));
		soup_uri_set_path (uri, req_path);
	} else
		uri = NULL;

	g_free (req_path);

	if (!uri || !uri->host) {
		if (uri)
			soup_uri_free (uri);
		return SOUP_STATUS_BAD_REQUEST;
	}

	soup_message_set_uri (msg, uri);
	soup_uri_free (uri);

	return SOUP_STATUS_OK;
}

static void
handle_partial_get (SoupMessage *msg)
{
	SoupRange *ranges;
	int nranges;
	SoupBuffer *full_response;
	guint status;

	/* Make sure the message is set up right for us to return a
	 * partial response; it has to be a GET, the status must be
	 * 200 OK (and in particular, NOT already 206 Partial
	 * Content), and the SoupServer must have already filled in
	 * the response body
	 */
	if (msg->method != SOUP_METHOD_GET ||
	    msg->status_code != SOUP_STATUS_OK ||
	    soup_message_headers_get_encoding (msg->response_headers) !=
	    SOUP_ENCODING_CONTENT_LENGTH ||
	    msg->response_body->length == 0 ||
	    !soup_message_body_get_accumulate (msg->response_body))
		return;

	/* Oh, and there has to have been a valid Range header on the
	 * request, of course.
	 */
	status = soup_message_headers_get_ranges_internal (msg->request_headers,
							   msg->response_body->length,
							   TRUE,
							   &ranges, &nranges);
	if (status == SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE) {
		soup_message_set_status (msg, status);
		soup_message_body_truncate (msg->response_body);
		return;
	} else if (status != SOUP_STATUS_PARTIAL_CONTENT)
		return;

	full_response = soup_message_body_flatten (msg->response_body);
	if (!full_response) {
		soup_message_headers_free_ranges (msg->request_headers, ranges);
		return;
	}

	soup_message_set_status (msg, SOUP_STATUS_PARTIAL_CONTENT);
	soup_message_body_truncate (msg->response_body);

	if (nranges == 1) {
		SoupBuffer *range_buf;

		/* Single range, so just set Content-Range and fix the body. */

		soup_message_headers_set_content_range (msg->response_headers,
							ranges[0].start,
							ranges[0].end,
							full_response->length);
		range_buf = soup_buffer_new_subbuffer (full_response,
						       ranges[0].start,
						       ranges[0].end - ranges[0].start + 1);
		soup_message_body_append_buffer (msg->response_body, range_buf);
		soup_buffer_free (range_buf);
	} else {
		SoupMultipart *multipart;
		SoupMessageHeaders *part_headers;
		SoupBuffer *part_body;
		const char *content_type;
		int i;

		/* Multiple ranges, so build a multipart/byteranges response
		 * to replace msg->response_body with.
		 */

		multipart = soup_multipart_new ("multipart/byteranges");
		content_type = soup_message_headers_get_one (msg->response_headers,
							     "Content-Type");
		for (i = 0; i < nranges; i++) {
			part_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_MULTIPART);
			if (content_type) {
				soup_message_headers_append (part_headers,
							     "Content-Type",
							     content_type);
			}
			soup_message_headers_set_content_range (part_headers,
								ranges[i].start,
								ranges[i].end,
								full_response->length);
			part_body = soup_buffer_new_subbuffer (full_response,
							       ranges[i].start,
							       ranges[i].end - ranges[i].start + 1);
			soup_multipart_append_part (multipart, part_headers,
						    part_body);
			soup_message_headers_free (part_headers);
			soup_buffer_free (part_body);
		}

		soup_multipart_to_message (multipart, msg->response_headers,
					   msg->response_body);
		soup_multipart_free (multipart);
	}

	soup_buffer_free (full_response);
	soup_message_headers_free_ranges (msg->request_headers, ranges);
}

static void
get_response_headers (SoupMessage *msg, GString *headers,
		      SoupEncoding *encoding, gpointer user_data)
{
	SoupEncoding claimed_encoding;
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (msg->status_code == 0)
		soup_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);

	handle_partial_get (msg);

	g_string_append_printf (headers, "HTTP/1.%c %d %s\r\n",
				soup_message_get_http_version (msg) == SOUP_HTTP_1_0 ? '0' : '1',
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


	/* Per rfc 7230:
	 * A server MUST NOT send a Content-Length header field in any response
	 * with a status code of 1xx (Informational) or 204 (No Content).
	 */

	if (msg->status_code  == SOUP_STATUS_NO_CONTENT ||
	    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) {
		soup_message_headers_remove (msg->response_headers, "Content-Length");
	} else if (claimed_encoding == SOUP_ENCODING_CONTENT_LENGTH &&
	    !soup_message_headers_get_content_length (msg->response_headers)) {
		soup_message_headers_set_content_length (msg->response_headers,
							 msg->response_body->length);
	}

	soup_message_headers_iter_init (&iter, msg->response_headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_string_append_printf (headers, "%s: %s\r\n", name, value);
	g_string_append (headers, "\r\n");
}

void
soup_message_read_request (SoupMessage               *msg,
			   SoupSocket                *sock,
			   gboolean                   use_thread_context,
			   SoupMessageCompletionFn    completion_cb,
			   gpointer                   user_data)
{
	GMainContext *async_context;
	GIOStream *iostream;

	if (use_thread_context)
		async_context = g_main_context_ref_thread_default ();
	else {
		g_object_get (sock,
			      SOUP_SOCKET_ASYNC_CONTEXT, &async_context,
			      NULL);
		if (!async_context)
			async_context = g_main_context_ref (g_main_context_default ());
	}

	iostream = soup_socket_get_iostream (sock);

	soup_message_io_server (msg, iostream, async_context,
				get_response_headers,
				parse_request_headers,
				sock,
				completion_cb, user_data);
	g_main_context_unref (async_context);
}
