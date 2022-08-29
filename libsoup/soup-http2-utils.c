/*
 * Copyright 2022 Igalia, S.L.
 */

#include <glib.h>

#include "soup-http2-utils.h"

const char *
soup_http2_io_state_to_string (SoupHTTP2IOState state)
{
        switch (state) {
        case STATE_NONE:
                return "NONE";
        case STATE_WRITE_HEADERS:
                return "WRITE_HEADERS";
        case STATE_WRITE_DATA:
                return "WRITE_DATA";
        case STATE_WRITE_DONE:
                return "WRITE_DONE";
        case STATE_READ_HEADERS:
                return "READ_HEADERS";
        case STATE_READ_DATA_START:
                return "READ_DATA_START";
        case STATE_READ_DATA:
                return "READ_DATA";
        case STATE_READ_DONE:
                return "READ_DONE";
        }
        g_assert_not_reached ();
        return "";
}

const char *
soup_http2_frame_type_to_string (nghttp2_frame_type type)
{
        switch (type) {
        case NGHTTP2_DATA:
                return "DATA";
        case NGHTTP2_HEADERS:
                return "HEADERS";
        case NGHTTP2_PRIORITY:
                return "PRIORITY";
        case NGHTTP2_RST_STREAM:
                return "RST_STREAM";
        case NGHTTP2_SETTINGS:
                return "SETTINGS";
        case NGHTTP2_PING:
                return "PING";
        case NGHTTP2_GOAWAY:
                return "GOAWAY";
        case NGHTTP2_WINDOW_UPDATE:
                return "WINDOW_UPDATE";
        /* LCOV_EXCL_START */
        case NGHTTP2_PUSH_PROMISE:
                return "PUSH_PROMISE";
        case NGHTTP2_CONTINUATION:
                return "CONTINUATION";
        case NGHTTP2_ALTSVC:
                return "ALTSVC";
        case NGHTTP2_ORIGIN:
                return "ORIGIN";
        default:
                g_warn_if_reached ();
                return "UNKNOWN";
        /* LCOV_EXCL_STOP */
        }
}

const char *
soup_http2_headers_category_to_string (nghttp2_headers_category catergory)
{
        switch (catergory) {
        case NGHTTP2_HCAT_REQUEST:
                return "REQUEST";
        case NGHTTP2_HCAT_RESPONSE:
                return "RESPONSE";
        case NGHTTP2_HCAT_PUSH_RESPONSE:
                return "PUSH_RESPONSE";
        case NGHTTP2_HCAT_HEADERS:
                return "HEADERS";
        }
        g_assert_not_reached ();
        return "";
}

G_GNUC_PRINTF(1, 0)
static void
debug_nghttp2 (const char *format,
               va_list     args)
{
        char *message;
        gsize len;

        if (g_log_writer_default_would_drop (G_LOG_LEVEL_DEBUG, "nghttp2"))
                return;

        message = g_strdup_vprintf (format, args);
        len = strlen (message);
        if (len >= 1 && message[len - 1] == '\n')
                message[len - 1] = '\0';
        g_log ("nghttp2", G_LOG_LEVEL_DEBUG, "[NGHTTP2] %s", message);
        g_free (message);
}

void
soup_http2_debug_init (void)
{
        static gsize nghttp2_debug_init = 0;
        if (g_once_init_enter (&nghttp2_debug_init)) {
                nghttp2_set_debug_vprintf_callback(debug_nghttp2);
                g_once_init_leave (&nghttp2_debug_init, 1);
        }

}
