/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-server-io.c: server-side request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup-socket-private.h"

static guint
parse_request_headers (SoupMessage          *msg,
		       SoupHTTPInputStream  *http,
		       gpointer              sock,
		       GError              **error)
{
	char *req_method;
	SoupHTTPVersion version;
	guint status;
	SoupURI *uri;

	status = soup_http_input_stream_parse_request_headers (http, sock,
							       &req_method,
							       &uri,
							       &version,
							       msg->request_headers,
							       error);
	if (!SOUP_STATUS_IS_SUCCESSFUL (status))
		return status;

	g_object_set (G_OBJECT (msg),
		      SOUP_MESSAGE_METHOD, req_method,
		      SOUP_MESSAGE_HTTP_VERSION, version,
		      NULL);
	g_free (req_method);

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
get_response_headers (SoupMessage          *msg,
		      SoupHTTPOutputStream *http,
		      gpointer              user_data)
{
	handle_partial_get (msg);

	if (soup_message_headers_get_encoding (msg->response_headers) == SOUP_ENCODING_CONTENT_LENGTH &&
	    !soup_message_headers_get_content_length (msg->response_headers)) {
		soup_message_headers_set_content_length (msg->response_headers,
							 msg->response_body->length);
	}

	soup_http_output_stream_build_response_headers (http, msg->method,
							soup_message_get_http_version (msg),
							msg->status_code,
							msg->reason_phrase,
							msg->response_headers);
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
