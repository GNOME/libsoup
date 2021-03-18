/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2012 Collabora Ltd.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-headers.h"

G_BEGIN_DECLS

#define SOUP_TYPE_MULTIPART_INPUT_STREAM (soup_multipart_input_stream_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupMultipartInputStream, soup_multipart_input_stream, SOUP, MULTIPART_INPUT_STREAM, GFilterInputStream)

SOUP_AVAILABLE_IN_ALL
SoupMultipartInputStream *soup_multipart_input_stream_new              (SoupMessage               *msg,
							                GInputStream              *base_stream);

SOUP_AVAILABLE_IN_ALL
GInputStream             *soup_multipart_input_stream_next_part        (SoupMultipartInputStream  *multipart,
									GCancellable	          *cancellable,
									GError                   **error);

SOUP_AVAILABLE_IN_ALL
void                      soup_multipart_input_stream_next_part_async  (SoupMultipartInputStream  *multipart,
									int                        io_priority,
								        GCancellable              *cancellable,
								        GAsyncReadyCallback        callback,
								        gpointer                   data);

SOUP_AVAILABLE_IN_ALL
GInputStream             *soup_multipart_input_stream_next_part_finish (SoupMultipartInputStream  *multipart,
									GAsyncResult              *result,
									GError                   **error);

SOUP_AVAILABLE_IN_ALL
SoupMessageHeaders       *soup_multipart_input_stream_get_headers      (SoupMultipartInputStream  *multipart);


G_END_DECLS
