/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-compression-dictionary-request.h
 *
 * Copyright (C) 2025 Igalia S.L.
 */

#pragma once

#include <glib-object.h>
#include "soup-version.h"

G_BEGIN_DECLS

#define SOUP_TYPE_COMPRESSION_DICTIONARY_REQUEST (soup_compression_dictionary_request_get_type ())

SOUP_AVAILABLE_IN_3_8
G_DECLARE_FINAL_TYPE (SoupCompressionDictionaryRequest, soup_compression_dictionary_request,
                      SOUP, COMPRESSION_DICTIONARY_REQUEST, GObject)

SOUP_AVAILABLE_IN_3_8
void soup_compression_dictionary_request_set_dictionary (SoupCompressionDictionaryRequest *request,
                                                         GBytes                           *dictionary);

SOUP_AVAILABLE_IN_3_8
void soup_compression_dictionary_request_cancel (SoupCompressionDictionaryRequest *request);

G_END_DECLS
