/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-content-decoder.c
 *
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-content-decoder.h"
#include "soup-converter-wrapper.h"
#include "soup-session-feature-private.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-headers.h"
#include "soup-uri-utils-private.h"
#ifdef WITH_BROTLI
#include "soup-brotli-decompressor.h"
#endif

/**
 * SoupContentDecoder:
 *
 * Handles decoding of HTTP messages.
 *
 * [class@ContentDecoder] handles adding the "Accept-Encoding" header on
 * outgoing messages, and processing the "Content-Encoding" header on
 * incoming ones. Currently it supports the "gzip", "deflate", and "br"
 * content codings.
 *
 * A [class@ContentDecoder] will automatically be
 * added to the session by default. (You can use
 * [method@Session.remove_feature_by_type] if you don't
 * want this.)
 *
 * If [class@ContentDecoder] successfully decodes the Content-Encoding,
 * the message body will contain the decoded data; however, the message headers
 * will be unchanged (and so "Content-Encoding" will still be present,
 * "Content-Length" will describe the original encoded length, etc).
 *
 * If "Content-Encoding" contains any encoding types that
 * [class@ContentDecoder] doesn't recognize, then none of the encodings
 * will be decoded.
 *
 * (Note that currently there is no way to (automatically) use
 * Content-Encoding when sending a request body, or to pick specific
 * encoding types to support.)
 **/

struct _SoupContentDecoder {
	GObject parent;
};

typedef struct {
	GHashTable *decoders;
} SoupContentDecoderPrivate;

typedef GConverter * (*SoupContentDecoderCreator) (void);

static void soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static SoupContentProcessorInterface *soup_content_decoder_default_content_processor_interface;
static void soup_content_decoder_content_processor_init (SoupContentProcessorInterface *interface, gpointer interface_data);


G_DEFINE_FINAL_TYPE_WITH_CODE (SoupContentDecoder, soup_content_decoder, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupContentDecoder)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						      soup_content_decoder_session_feature_init)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_CONTENT_PROCESSOR,
						      soup_content_decoder_content_processor_init))

static GSList *
soup_content_decoder_get_decoders_for_msg (SoupContentDecoder *decoder, SoupMessage *msg)
{
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (decoder);
	const char *header;
	GSList *encodings, *e, *decoders = NULL;
	SoupContentDecoderCreator converter_creator;
	GConverter *converter;

	header = soup_message_headers_get_list_common (soup_message_get_response_headers (msg),
                                                       SOUP_HEADER_CONTENT_ENCODING);
	if (!header)
		return NULL;

	/* Workaround for an apache bug (bgo 613361) */
	if (!g_ascii_strcasecmp (header, "gzip") ||
	    !g_ascii_strcasecmp (header, "x-gzip")) {
		const char *content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (msg), NULL);

		if (content_type &&
		    (!g_ascii_strcasecmp (content_type, "application/gzip") ||
		     !g_ascii_strcasecmp (content_type, "application/x-gzip")))
			return NULL;
	}

	/* OK, really, no one is ever going to use more than one
	 * encoding, but we'll be robust.
	 */
	encodings = soup_header_parse_list (header);
	if (!encodings)
		return NULL;

	for (e = encodings; e; e = e->next) {
		if (!g_hash_table_lookup (priv->decoders, e->data)) {
			soup_header_free_list (encodings);
			return NULL;
		}
	}

	for (e = encodings; e; e = e->next) {
		converter_creator = g_hash_table_lookup (priv->decoders, e->data);
		converter = converter_creator ();

		/* Content-Encoding lists the codings in the order
		 * they were applied in, so we put decoders in reverse
		 * order so the last-applied will be the first
		 * decoded.
		 */
		decoders = g_slist_prepend (decoders, converter);
	}
	soup_header_free_list (encodings);

	return decoders;
}

static GInputStream*
soup_content_decoder_content_processor_wrap_input (SoupContentProcessor *processor,
						   GInputStream *base_stream,
						   SoupMessage *msg,
						   GError **error)
{
	GSList *decoders, *d;
	GInputStream *istream;

	decoders = soup_content_decoder_get_decoders_for_msg (SOUP_CONTENT_DECODER (processor), msg);
	if (!decoders)
		return NULL;

	istream = g_object_ref (base_stream);
	for (d = decoders; d; d = d->next) {
		GConverter *decoder, *wrapper;
		GInputStream *filter;

		decoder = d->data;
		wrapper = soup_converter_wrapper_new (decoder, msg);
		filter = g_object_new (G_TYPE_CONVERTER_INPUT_STREAM,
				       "base-stream", istream,
				       "converter", wrapper,
				       NULL);
		g_object_unref (istream);
		g_object_unref (wrapper);
		istream = filter;
	}

	g_slist_free_full (decoders, g_object_unref);

	return istream;
}

static void
soup_content_decoder_content_processor_init (SoupContentProcessorInterface *processor_interface,
					     gpointer interface_data)
{
	soup_content_decoder_default_content_processor_interface =
		g_type_default_interface_peek (SOUP_TYPE_CONTENT_PROCESSOR);

	processor_interface->processing_stage = SOUP_STAGE_CONTENT_ENCODING;
	processor_interface->wrap_input = soup_content_decoder_content_processor_wrap_input;
}

static GConverter *
gzip_decoder_creator (void)
{
	return (GConverter *)g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP);
}

static GConverter *
zlib_decoder_creator (void)
{
	return (GConverter *)g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_ZLIB);
}

#ifdef WITH_BROTLI
static GConverter *
brotli_decoder_creator (void)
{
	return (GConverter *)soup_brotli_decompressor_new ();
}
#endif

static void
soup_content_decoder_init (SoupContentDecoder *decoder)
{
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (decoder);

	priv->decoders = g_hash_table_new (g_str_hash, g_str_equal);
	/* Hardcoded for now */
	g_hash_table_insert (priv->decoders, "gzip",
			     gzip_decoder_creator);
	g_hash_table_insert (priv->decoders, "x-gzip",
			     gzip_decoder_creator);
	g_hash_table_insert (priv->decoders, "deflate",
			     zlib_decoder_creator);
#ifdef WITH_BROTLI
	g_hash_table_insert (priv->decoders, "br",
			     brotli_decoder_creator);
#endif
}

static void
soup_content_decoder_finalize (GObject *object)
{
	SoupContentDecoder *decoder = SOUP_CONTENT_DECODER (object);
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (decoder);

	g_hash_table_destroy (priv->decoders);

	G_OBJECT_CLASS (soup_content_decoder_parent_class)->finalize (object);
}

static void
soup_content_decoder_class_init (SoupContentDecoderClass *decoder_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (decoder_class);

	object_class->finalize = soup_content_decoder_finalize;
}

static void
soup_content_decoder_request_queued (SoupSessionFeature *feature,
				     SoupMessage        *msg)
{
	if (!soup_message_headers_get_one_common (soup_message_get_request_headers (msg),
                                                  SOUP_HEADER_ACCEPT_ENCODING)) {
                const char *header = "gzip, deflate";

#ifdef WITH_BROTLI
                /* brotli is only enabled over TLS connections
                 * as other browsers have found that some networks have expectations
                 * regarding the encoding of HTTP messages and this may break those
                 * expectations. Firefox and Chromium behave similarly.
                 */
                if (soup_uri_is_https (soup_message_get_uri (msg)))
                        header = "gzip, deflate, br";
#endif

		soup_message_headers_append_common (soup_message_get_request_headers (msg),
                                                    SOUP_HEADER_ACCEPT_ENCODING, header);
	}
}

static void
soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					   gpointer interface_data)
{
	feature_interface->request_queued = soup_content_decoder_request_queued;
}
