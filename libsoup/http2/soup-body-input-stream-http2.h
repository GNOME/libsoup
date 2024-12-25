
#pragma once

#include "soup-types.h"

#define SOUP_TYPE_BODY_INPUT_STREAM_HTTP2 (soup_body_input_stream_http2_get_type ())
G_DECLARE_FINAL_TYPE (SoupBodyInputStreamHttp2, soup_body_input_stream_http2, SOUP, BODY_INPUT_STREAM_HTTP2, GInputStream)

GInputStream * soup_body_input_stream_http2_new        (void);

gsize          soup_body_input_stream_http2_get_buffer_size (SoupBodyInputStreamHttp2 *stream);

void           soup_body_input_stream_http2_add_data   (SoupBodyInputStreamHttp2 *stream,
                                                        const guint8             *data,
                                                        gsize                     size);

void           soup_body_input_stream_http2_complete   (SoupBodyInputStreamHttp2 *stream);

/* This is only used for tests */
gboolean       soup_body_input_stream_http2_is_blocked (SoupBodyInputStreamHttp2 *stream);

G_END_DECLS
