/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#pragma once

#include "soup-types.h"
#include "content-sniffer/soup-content-sniffer.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONTENT_SNIFFER_STREAM (soup_content_sniffer_stream_get_type ())
G_DECLARE_FINAL_TYPE (SoupContentSnifferStream, soup_content_sniffer_stream, SOUP, CONTENT_SNIFFER_STREAM, GFilterInputStream)

gboolean      soup_content_sniffer_stream_is_ready (SoupContentSnifferStream  *sniffer,
						    gboolean                   blocking,
						    GCancellable              *cancellable,
						    GError                   **error);
const char   *soup_content_sniffer_stream_sniff    (SoupContentSnifferStream  *sniffer,
						    GHashTable               **params);


G_END_DECLS
