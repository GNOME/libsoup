/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-content-decoder.c
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <gio/gio.h>

#include "soup-content-decoder.h"
#include "soup-coding-gzip.h"
#include "soup-enum-types.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-session-feature.h"
#include "soup-uri.h"

/**
 * SECTION:soup-content-decoder
 * @short_description: Content-Encoding handler
 *
 * #SoupContentDecoder handles the "Accept-Encoding" header on
 * outgoing messages, and the "Content-Encoding" header on incoming
 * ones. If you add it to a session with soup_session_add_feature() or
 * soup_session_add_feature_by_type(), the session will automatically
 * use Content-Encoding as appropriate.
 *
 * (Note that currently there is no way to (automatically) use
 * Content-Encoding when sending a request body, or to pick specific
 * encoding types to support.)
 *
 * If #SoupContentDecoder successfully decodes the Content-Encoding,
 * it will set the %SOUP_MESSAGE_CONTENT_DECODED flag on the message,
 * and the message body and the chunks in the #SoupMessage::got_chunk
 * signals will contain the decoded data; however, the message headers
 * will be unchanged (and so "Content-Encoding" will still be present,
 * "Content-Length" will describe the original encoded length, etc).
 *
 * If "Content-Encoding" contains any encoding types that
 * #SoupContentDecoder doesn't recognize, then none of the encodings
 * will be decoded (and the %SOUP_MESSAGE_CONTENT_DECODED flag will
 * not be set).
 *
 * Since: 2.28.2
 **/

struct _SoupContentDecoderPrivate {
	GHashTable *codings;
};

static void soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static void request_queued (SoupSessionFeature *feature, SoupSession *session, SoupMessage *msg);
static void request_unqueued (SoupSessionFeature *feature, SoupSession *session, SoupMessage *msg);

G_DEFINE_TYPE_WITH_CODE (SoupContentDecoder, soup_content_decoder, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_content_decoder_session_feature_init))

/* This is constant for now */
#define ACCEPT_ENCODING_HEADER "gzip"

static void
soup_content_decoder_init (SoupContentDecoder *decoder)
{
	decoder->priv = G_TYPE_INSTANCE_GET_PRIVATE (decoder,
						     SOUP_TYPE_CONTENT_DECODER,
						     SoupContentDecoderPrivate);

	decoder->priv->codings = g_hash_table_new (g_str_hash, g_str_equal);
	/* Hardcoded for now */
	g_hash_table_insert (decoder->priv->codings, "gzip",
			     GSIZE_TO_POINTER (SOUP_TYPE_CODING_GZIP));
}

static void
soup_content_decoder_class_init (SoupContentDecoderClass *decoder_class)
{
  g_type_class_add_private (decoder_class, sizeof (SoupContentDecoderPrivate));
}

static void
soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					   gpointer interface_data)
{
	feature_interface->request_queued = request_queued;
	feature_interface->request_unqueued = request_unqueued;
}

static void
soup_content_decoder_got_headers_cb (SoupMessage *msg, SoupContentDecoder *decoder)
{
	SoupMessagePrivate *msgpriv = SOUP_MESSAGE_GET_PRIVATE (msg);
	const char *header;
	GSList *encodings, *e;
	GType coding_type;
	SoupCoding *coding; 

	header = soup_message_headers_get_list (msg->response_headers,
						"Content-Encoding");
	if (!header)
		return;

	/* OK, really, no one is ever going to use more than one
	 * encoding, but we'll be robust.
	 */
	encodings = soup_header_parse_list (header);
	if (!encodings)
		return;

	for (e = encodings; e; e = e->next) {
		if (!g_hash_table_lookup (decoder->priv->codings, e->data)) {
			soup_header_free_list (encodings);
			return;
		}
	}

	msgpriv->decoders = NULL;
	for (e = encodings; e; e = e->next) {
		coding_type = (GType) GPOINTER_TO_SIZE (g_hash_table_lookup (decoder->priv->codings, e->data));
		coding = g_object_new (coding_type,
				       SOUP_CODING_DIRECTION, SOUP_CODING_DECODE,
				       NULL);

		/* Content-Encoding lists the codings in the order
		 * they were applied in, so we put decoders in reverse
		 * order so the last-applied will be the first
		 * decoded.
		 */
		msgpriv->decoders = g_slist_prepend (msgpriv->decoders, coding);
	}
	soup_header_free_list (encodings);

	soup_message_set_flags (msg, msgpriv->msg_flags | SOUP_MESSAGE_CONTENT_DECODED);
}

static void
request_queued (SoupSessionFeature *feature, SoupSession *session,
		SoupMessage *msg)
{
	SoupContentDecoder *decoder = SOUP_CONTENT_DECODER (feature);

	if (!soup_message_headers_get_one (msg->request_headers,
					   "Accept-Encoding")) {
		soup_message_headers_append (msg->request_headers,
					     "Accept-Encoding",
					     ACCEPT_ENCODING_HEADER);
	}

	g_signal_connect (msg, "got-headers",
			  G_CALLBACK (soup_content_decoder_got_headers_cb),
			  decoder);
}

static void
request_unqueued (SoupSessionFeature *feature, SoupSession *session,
		  SoupMessage *msg)
{
	g_signal_handlers_disconnect_by_func (msg, soup_content_decoder_got_headers_cb, feature);
}
