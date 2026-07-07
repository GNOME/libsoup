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
#include "soup-compression-dictionary-decoder.h"
#include "soup-compression-dictionary-request-private.h"
#include "soup-converter-wrapper.h"
#include "soup-session-feature-private.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-headers.h"
#include "soup-uri-utils-private.h"
#include "soup-session.h"
#ifdef WITH_BROTLI
#include "soup-brotli-decompressor.h"
#endif
#ifdef WITH_ZSTD
#include "soup-zstd-decompressor.h"
#endif

#ifdef WITH_BROTLI
#define SOUP_ACCEPT_BR ", br"
#define SOUP_ACCEPT_DCB ", dcb"
#else
#define SOUP_ACCEPT_BR ""
#define SOUP_ACCEPT_DCB ""
#endif
#ifdef WITH_ZSTD
#define SOUP_ACCEPT_ZSTD ", zstd"
#define SOUP_ACCEPT_DCZ ", dcz"
#else
#define SOUP_ACCEPT_ZSTD ""
#define SOUP_ACCEPT_DCZ ""
#endif

/**
 * SoupContentDecoder:
 *
 * Handles decoding of HTTP messages.
 *
 * [class@ContentDecoder] handles adding the "Accept-Encoding" header on
 * outgoing messages, and processing the "Content-Encoding" header on
 * incoming ones. Currently it supports the "gzip", "deflate", "br", and "zstd"
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
	GHashTable   *decoders;
	SoupSession  *session;
} SoupContentDecoderPrivate;

typedef GConverter * (*SoupContentDecoderCreator) (void);

#if defined(WITH_BROTLI) || defined(WITH_ZSTD)
static SoupCompressionDictionaryDecoder *
soup_content_decoder_create_dictionary_decoder (SoupMessageHeaders *response_headers)
{
#ifdef WITH_BROTLI
	if (soup_message_headers_header_contains_common (response_headers, SOUP_HEADER_CONTENT_ENCODING, "dcb"))
		return (SoupCompressionDictionaryDecoder *)soup_brotli_decompressor_new ();
#endif
#ifdef WITH_ZSTD
	if (soup_message_headers_header_contains_common (response_headers, SOUP_HEADER_CONTENT_ENCODING, "dcz"))
		return (SoupCompressionDictionaryDecoder *)soup_zstd_decompressor_new ();
#endif
	return NULL;
}
#endif

static void soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static SoupContentProcessorInterface *soup_content_decoder_default_content_processor_interface;
static void soup_content_decoder_content_processor_init (SoupContentProcessorInterface *interface, gpointer interface_data);


G_DEFINE_FINAL_TYPE_WITH_CODE (SoupContentDecoder, soup_content_decoder, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupContentDecoder)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						      soup_content_decoder_session_feature_init)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_CONTENT_PROCESSOR,
						      soup_content_decoder_content_processor_init))

static void
soup_content_decoder_got_headers (SoupMessage        *msg,
				   SoupContentDecoder *decoder)
{
#if defined(WITH_BROTLI) || defined(WITH_ZSTD)
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (decoder);
	SoupCompressionDictionaryRequest *request;
	gboolean handled;

	/* Only act if not already resolved. */
	if (soup_message_get_compression_dictionary_request (msg))
		return;

	/* Create the decoder now that we know the coding and bind it to the
	 * request's dictionary. It is retrieved later in wrap_input(), which may
	 * run before the dictionary is resolved (e.g. over HTTP/2, where the
	 * body stream is set up on the first DATA frame). */
	SoupMessageHeaders *response_headers = soup_message_get_response_headers (msg);
	SoupCompressionDictionaryDecoder *dict_decoder =
		soup_content_decoder_create_dictionary_decoder (response_headers);
	if (!dict_decoder)
		return;

	request = soup_compression_dictionary_request_new (priv->session, msg);
	soup_compression_dictionary_request_set_decoder (request, dict_decoder);
	g_object_unref (dict_decoder);

	g_signal_emit_by_name (msg, "request-compression-dictionary", request, &handled);

	if (!handled) {
		g_object_unref (request);
		return;
	}

	soup_message_set_compression_dictionary_request (msg, request);

	if (!soup_compression_dictionary_request_is_completed (request)) {
		soup_compression_dictionary_request_set_paused (request);
                g_debug("content-decoder: Pausing message to wait for SoupMessage::request-compression-dictionary");
		soup_session_pause_message (priv->session, msg);

                if (G_OBJECT(request)->ref_count == 1)
                        g_critical ("SoupMessage::request-compression-dictionary was handled but SoupCompressionDictionaryRequest was not referenced");
	}

	g_object_unref (request);
#endif
}

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

	/* For dictionary codings (dcb/dcz) the decoder was created and bound to
	 * the dictionary in soup_content_decoder_got_headers(). Reuse that
	 * instance so the dictionary (resolved either synchronously or
	 * asynchronously) is applied to it. Reaching a dcb/dcz entry implies the
	 * matching decoder was built in, since the loop above bails out for any
	 * coding not registered in priv->decoders. */
	SoupCompressionDictionaryRequest *dict_request = soup_message_get_compression_dictionary_request (msg);

	for (e = encodings; e; e = e->next) {
		if (g_str_equal (e->data, "dcb") || g_str_equal (e->data, "dcz")) {
			SoupCompressionDictionaryDecoder *dict_decoder = dict_request ?
				soup_compression_dictionary_request_get_decoder (dict_request) : NULL;

			if (!dict_decoder) {
				soup_header_free_list (encodings);
				g_slist_free_full (decoders, g_object_unref);
				return NULL;
			}

			converter = (GConverter *)g_object_ref (dict_decoder);
		} else {
			converter_creator = g_hash_table_lookup (priv->decoders, e->data);
			converter = converter_creator ();
		}

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

#ifdef WITH_ZSTD
static GConverter *
zstd_decoder_creator (void)
{
	return (GConverter *)soup_zstd_decompressor_new ();
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
	g_hash_table_insert (priv->decoders, "dcb",
			     brotli_decoder_creator);
#endif
#ifdef WITH_ZSTD
	g_hash_table_insert (priv->decoders, "zstd",
			     zstd_decoder_creator);
	g_hash_table_insert (priv->decoders, "dcz",
			     zstd_decoder_creator);
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

static char *
bytes_to_available_dictionary_header (GBytes *hash)
{
        gsize hash_len;
        const guchar *hash_data = g_bytes_get_data (hash, &hash_len);
        char *b64 = g_base64_encode (hash_data, hash_len);
        char *result = g_strdup_printf (":%s:", b64);
        g_free (b64);
        return result;
}

static void
soup_content_decoder_attach (SoupSessionFeature *feature,
		              SoupSession        *session)
{
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (SOUP_CONTENT_DECODER (feature));
        priv->session = session;
}

static void
soup_content_decoder_detach (SoupSessionFeature *feature,
		              SoupSession        *session)
{
        SoupContentDecoderPrivate *priv = soup_content_decoder_get_instance_private (SOUP_CONTENT_DECODER (feature));
        priv->session = NULL;
}

static void
soup_content_decoder_request_queued (SoupSessionFeature *feature,
				     SoupMessage        *msg)
{
	SoupMessageHeaders *request_headers = soup_message_get_request_headers (msg);

	if (!soup_message_headers_get_one_common (request_headers, SOUP_HEADER_ACCEPT_ENCODING)) {
		GString *accept_encoding = g_string_new ("gzip, deflate");

#if defined(WITH_BROTLI) || defined(WITH_ZSTD)
		/* brotli and zstd are only enabled over TLS connections
		 * as other browsers have found that some networks have expectations
		 * regarding the encoding of HTTP messages and this may break those
		 * expectations. Firefox and Chromium behave similarly.
		 */
		if (soup_uri_is_https (soup_message_get_uri (msg))) {
#if defined(WITH_BROTLI)
			g_string_append (accept_encoding, SOUP_ACCEPT_BR);
#endif
#if defined(WITH_ZSTD)
			g_string_append (accept_encoding, SOUP_ACCEPT_ZSTD);
#endif
			 

			/* Advertise dictionary encodings only when a shared dictionary has been set */
			GBytes *dict_hash = soup_message_get_compression_dictionary_hash (msg);
			if (dict_hash) {
				g_debug("Compression-dictionary hash set, Accepting Encodings");
				char *avail_dict = bytes_to_available_dictionary_header (dict_hash);
#if defined(WITH_BROTLI)
				g_string_append (accept_encoding, SOUP_ACCEPT_DCB);
#endif
#if defined(WITH_ZSTD)
				g_string_append (accept_encoding, SOUP_ACCEPT_DCZ);
#endif
				soup_message_headers_append (request_headers, "Available-Dictionary", avail_dict);
				g_free (avail_dict);
			}
		}
#endif

		soup_message_headers_append_common (request_headers,
						    SOUP_HEADER_ACCEPT_ENCODING, accept_encoding->str,
						    SOUP_HEADER_VALUE_TRUSTED);
		g_string_free (accept_encoding, TRUE);
	}

	g_signal_connect_object (msg, "got-headers",
			         G_CALLBACK (soup_content_decoder_got_headers),
			         feature, 0);
}

static void
soup_content_decoder_request_unqueued (SoupSessionFeature *feature,
				        SoupMessage        *msg)
{
        g_signal_handlers_disconnect_by_func (msg,
                                              G_CALLBACK (soup_content_decoder_got_headers),
                                              feature);
        soup_message_set_compression_dictionary_request (msg, NULL);
}

static void
soup_content_decoder_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					   gpointer interface_data)
{
	feature_interface->attach          = soup_content_decoder_attach;
	feature_interface->detach          = soup_content_decoder_detach;
	feature_interface->request_queued   = soup_content_decoder_request_queued;
	feature_interface->request_unqueued = soup_content_decoder_request_unqueued;
}
