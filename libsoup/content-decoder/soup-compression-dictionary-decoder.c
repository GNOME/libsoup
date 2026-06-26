/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-compression-dictionary-decoder.c
 *
 * Copyright (C) 2026 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-compression-dictionary-decoder.h"

/*
 * SoupCompressionDictionaryDecoder:
 *
 * Interface implemented by [iface@Gio.Converter] decoders that decompress
 * using a shared dictionary (the "dcb" and "dcz" content codings).
 *
 * The dictionary is often not known when the decoder is created (it may be
 * resolved asynchronously), so it is provided later via
 * [method@CompressionDictionaryDecoder.set_dictionary]. It must be set before
 * any data is decompressed.
 */

G_DEFINE_INTERFACE (SoupCompressionDictionaryDecoder, soup_compression_dictionary_decoder, G_TYPE_OBJECT)

static void
soup_compression_dictionary_decoder_default_init (SoupCompressionDictionaryDecoderInterface *iface)
{
}

/*
 * soup_compression_dictionary_decoder_set_dictionary:
 * @decoder: a #SoupCompressionDictionaryDecoder
 * @dictionary: (transfer none): the raw dictionary bytes
 *
 * Sets the dictionary used to decompress the response. Must be called before
 * any data is decompressed.
 */
void
soup_compression_dictionary_decoder_set_dictionary (SoupCompressionDictionaryDecoder *decoder,
						    GBytes                           *dictionary)
{
	g_return_if_fail (SOUP_IS_COMPRESSION_DICTIONARY_DECODER (decoder));
	g_return_if_fail (dictionary != NULL);

	SOUP_COMPRESSION_DICTIONARY_DECODER_GET_IFACE (decoder)->set_dictionary (decoder, dictionary);
}
