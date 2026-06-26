/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-compression-dictionary-decoder.h
 *
 * Copyright (C) 2026 Igalia S.L.
 */

#pragma once

#include <glib-object.h>

G_BEGIN_DECLS

#define SOUP_TYPE_COMPRESSION_DICTIONARY_DECODER (soup_compression_dictionary_decoder_get_type ())
G_DECLARE_INTERFACE (SoupCompressionDictionaryDecoder, soup_compression_dictionary_decoder, SOUP, COMPRESSION_DICTIONARY_DECODER, GObject)

struct _SoupCompressionDictionaryDecoderInterface {
	GTypeInterface parent_iface;

	void (*set_dictionary) (SoupCompressionDictionaryDecoder *decoder,
				GBytes                           *dictionary);
};

void soup_compression_dictionary_decoder_set_dictionary (SoupCompressionDictionaryDecoder *decoder,
							 GBytes                           *dictionary);

G_END_DECLS
