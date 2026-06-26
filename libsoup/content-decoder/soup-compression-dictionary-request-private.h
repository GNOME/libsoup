/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-compression-dictionary-request-private.h
 *
 * Copyright (C) 2025 Igalia S.L.
 */

#pragma once

#include "soup-compression-dictionary-request.h"
#include "soup-compression-dictionary-decoder.h"

G_BEGIN_DECLS

typedef struct _SoupSession SoupSession;
typedef struct _SoupMessage SoupMessage;

SoupCompressionDictionaryRequest *soup_compression_dictionary_request_new        (SoupSession                      *session,
                                                                                  SoupMessage                      *msg);
void                              soup_compression_dictionary_request_set_paused (SoupCompressionDictionaryRequest *request);
GBytes                           *soup_compression_dictionary_request_get_dictionary (SoupCompressionDictionaryRequest *request);
gboolean                          soup_compression_dictionary_request_is_completed   (SoupCompressionDictionaryRequest *request);
void                              soup_compression_dictionary_request_set_decoder (SoupCompressionDictionaryRequest *request,
                                                                                   SoupCompressionDictionaryDecoder *decoder);
SoupCompressionDictionaryDecoder *soup_compression_dictionary_request_get_decoder (SoupCompressionDictionaryRequest *request);

G_END_DECLS
