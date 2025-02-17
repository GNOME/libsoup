/*
 * Copyright 2022 Igalia, S.L.
 */

#pragma once

#include <nghttp2/nghttp2.h>

#define NGCHECK(stm)                                                                             \
        G_STMT_START {                                                                           \
                int return_code = stm;                                                           \
                if (return_code == NGHTTP2_ERR_NOMEM)                                            \
                        g_abort ();                                                              \
                else if (return_code < 0)                                                        \
                        g_debug ("Unhandled NGHTTP2 Error: %s", nghttp2_strerror (return_code)); \
        } G_STMT_END

#define MAKE_NV(NAME, VALUE, VALUELEN)                                                           \
        {                                                                                        \
                (uint8_t *)(NAME), (uint8_t *)(VALUE), strlen (NAME), VALUELEN, NGHTTP2_NV_FLAG_NONE \
        }

#define MAKE_NV2(NAME, VALUE)                                                                          \
        {                                                                                              \
                (uint8_t *)(NAME), (uint8_t *)(VALUE), strlen (NAME), strlen (VALUE), NGHTTP2_NV_FLAG_NONE \
        }

#define MAKE_NV3(NAME, VALUE, FLAGS)                                                     \
        {                                                                                \
                (uint8_t *)(NAME), (uint8_t *)(VALUE), strlen (NAME), strlen (VALUE),  FLAGS \
        }


typedef enum {
        STATE_NONE,
        STATE_WRITE_HEADERS,
        STATE_WRITE_DATA,
        STATE_WRITE_DONE,
        STATE_READ_HEADERS,
        STATE_READ_DATA_START,
        STATE_READ_DATA,
        STATE_READ_DONE,
} SoupHTTP2IOState;

const char *soup_http2_io_state_to_string (SoupHTTP2IOState state);
const char *soup_http2_frame_type_to_string (nghttp2_frame_type type);
const char *soup_http2_headers_category_to_string (nghttp2_headers_category catergory);

void soup_http2_debug_init (void);
