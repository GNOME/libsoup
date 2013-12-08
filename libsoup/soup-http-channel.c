/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http-channel.c
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-http-channel.h"
#include "soup.h"
#include "soup-misc-private.h"

/**
 * SECTION:soup-http-channel
 * @short_description: Channel for a single HTTP request/response
 *
 * #SoupHTTPChannel is an abstract type representing a communication
 * channel for handling a single HTTP request and response.
 */

G_DEFINE_ABSTRACT_TYPE (SoupHTTPChannel, soup_http_channel, G_TYPE_OBJECT)

enum {
	PROP_0,

	PROP_MESSAGE,
	PROP_MODE
};

typedef struct {
	SoupMessage *msg;
	SoupHTTPChannelMode mode;

} SoupHTTPChannelPrivate;
#define SOUP_HTTP_CHANNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP_CHANNEL, SoupHTTPChannelPrivate))

static void
soup_http_channel_init (SoupHTTPChannel *channel)
{
}

static void
soup_http_channel_set_property (GObject *object, guint prop_id,
				const GValue *value, GParamSpec *pspec)
{
	SoupHTTPChannelPrivate *priv = SOUP_HTTP_CHANNEL_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MESSAGE:
		priv->msg = g_value_dup_object (value);
		break;
	case PROP_MODE:
		priv->mode = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_http_channel_get_property (GObject *object, guint prop_id,
				GValue *value, GParamSpec *pspec)
{
	SoupHTTPChannelPrivate *priv = SOUP_HTTP_CHANNEL_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MESSAGE:
		g_value_set_object (value, priv->msg);
		break;
	case PROP_MODE:
		g_value_set_int (value, priv->mode);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_http_channel_dispose (GObject *object)
{
	SoupHTTPChannelPrivate *priv = SOUP_HTTP_CHANNEL_GET_PRIVATE (object);

	g_clear_object (&priv->msg);

	G_OBJECT_CLASS (soup_http_channel_parent_class)->dispose (object);
}

static void
soup_http_channel_class_init (SoupHTTPChannelClass *channel_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (channel_class);

	g_type_class_add_private (channel_class, sizeof (SoupHTTPChannelPrivate));

	object_class->set_property = soup_http_channel_set_property;
	object_class->get_property = soup_http_channel_get_property;
	object_class->dispose      = soup_http_channel_dispose;

	g_object_class_install_property (
		 object_class, PROP_MESSAGE,
		 g_param_spec_object (SOUP_HTTP_CHANNEL_MESSAGE,
				      "SoupMessage",
				      "The channel's SoupMessage",
				      SOUP_TYPE_MESSAGE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS |
				      G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		 object_class, PROP_MODE,
		 /* We don't parse private headers for enum types, so use int */
		 g_param_spec_int (SOUP_HTTP_CHANNEL_MODE,
				   "Mode",
				   "The channel's SoupHTTPChannelMode",
				   -1, G_MAXINT, -1,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS |
				   G_PARAM_CONSTRUCT_ONLY));
}

gboolean
soup_http_channel_read_headers (SoupHTTPChannel      *channel,
				gboolean              blocking,
				GCancellable         *cancellable,
				GError              **error)
{
	if (SOUP_HTTP_CHANNEL_GET_PRIVATE (channel)->mode == SOUP_HTTP_CHANNEL_CLIENT) {
		return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->
			read_response_headers (channel, blocking, cancellable, error);
	} else {
		return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->
			read_request_headers (channel, blocking, cancellable, error);
	}
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

gboolean
soup_http_channel_write_headers (SoupHTTPChannel      *channel,
				 gboolean              blocking,
				 GCancellable         *cancellable,
				 GError              **error)
{
	SoupHTTPChannelPrivate *priv = SOUP_HTTP_CHANNEL_GET_PRIVATE (channel);

	if (SOUP_HTTP_CHANNEL_GET_PRIVATE (channel)->mode == SOUP_HTTP_CHANNEL_CLIENT) {
		SoupEncoding encoding;

		/* Fix up unspecified encoding */
		encoding = soup_message_headers_get_encoding (priv->msg->request_headers);
		if ((encoding == SOUP_ENCODING_CONTENT_LENGTH ||
		     encoding == SOUP_ENCODING_NONE) &&
		    (priv->msg->request_body->length > 0 ||
		     soup_message_headers_get_one (priv->msg->request_headers, "Content-Type")) &&
		    !soup_message_headers_get_content_length (priv->msg->request_headers)) {
			soup_message_headers_set_content_length (priv->msg->request_headers,
								 priv->msg->request_body->length);
		}

		return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->
			write_request_headers (channel, blocking, cancellable, error);
	} else {
		handle_partial_get (priv->msg);

		/* Fix up unspecified encoding */
		if (soup_message_headers_get_encoding (priv->msg->response_headers) == SOUP_ENCODING_CONTENT_LENGTH &&
		    !soup_message_headers_get_content_length (priv->msg->response_headers)) {
			soup_message_headers_set_content_length (priv->msg->response_headers,
								 priv->msg->response_body->length);
		}

		return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->
			write_response_headers (channel, blocking, cancellable, error);
	}
}

GInputStream *
soup_http_channel_get_body_input_stream (SoupHTTPChannel *channel)
{
	return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->get_body_input_stream (channel);
}

GOutputStream *
soup_http_channel_get_body_output_stream (SoupHTTPChannel *channel)
{
	return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->get_body_output_stream (channel);
}

GSource *
soup_http_channel_create_oneshot_source (SoupHTTPChannel  *channel,
					 GIOCondition      cond,
					 GCancellable     *cancellable)
{
	g_return_val_if_fail (cond == G_IO_IN || cond == G_IO_OUT, NULL);

	return SOUP_HTTP_CHANNEL_GET_CLASS (channel)->create_oneshot_source (channel, cond, cancellable);
}

SoupMessage *
soup_http_channel_get_message (SoupHTTPChannel *channel)
{
	return SOUP_HTTP_CHANNEL_GET_PRIVATE (channel)->msg;
}

SoupHTTPChannelMode
soup_http_channel_get_mode (SoupHTTPChannel *channel)
{
	return SOUP_HTTP_CHANNEL_GET_PRIVATE (channel)->mode;
}
