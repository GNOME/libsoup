/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension-deflate.c
 *
 * Copyright (C) 2019 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-websocket-extension-deflate.h"
#include <zlib.h>

typedef struct {
        z_stream zstream;
        gboolean no_context_takeover;
} Deflater;

typedef struct {
        z_stream zstream;
        gboolean uncompress_ongoing;
} Inflater;

#define BUFFER_SIZE 4096

typedef enum {
        PARAM_SERVER_NO_CONTEXT_TAKEOVER   = 1 << 0,
        PARAM_CLIENT_NO_CONTEXT_TAKEOVER   = 1 << 1,
        PARAM_SERVER_MAX_WINDOW_BITS       = 1 << 2,
        PARAM_CLIENT_MAX_WINDOW_BITS       = 1 << 3
} ParamFlags;

typedef struct {
        ParamFlags flags;
        gushort server_max_window_bits;
        gushort client_max_window_bits;
} Params;

struct _SoupWebsocketExtensionDeflate {
	SoupWebsocketExtension parent;
};

typedef struct {
        Params params;

        gboolean enabled;

        Deflater deflater;
        Inflater inflater;
} SoupWebsocketExtensionDeflatePrivate;

/**
 * SoupWebsocketExtensionDeflate:
 *
 * A SoupWebsocketExtensionDeflate is a [class@WebsocketExtension]
 * implementing permessage-deflate (RFC 7692).
 *
 * This extension is used by default in a [class@Session] when [class@WebsocketExtensionManager]
 * feature is present, and always used by [class@Server].
 */

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupWebsocketExtensionDeflate, soup_websocket_extension_deflate, SOUP_TYPE_WEBSOCKET_EXTENSION)

static void
soup_websocket_extension_deflate_init (SoupWebsocketExtensionDeflate *basic)
{
}

static void
soup_websocket_extension_deflate_finalize (GObject *object)
{
        SoupWebsocketExtensionDeflatePrivate *priv = soup_websocket_extension_deflate_get_instance_private (SOUP_WEBSOCKET_EXTENSION_DEFLATE (object));

	if (priv->enabled) {
		deflateEnd (&priv->deflater.zstream);
		inflateEnd (&priv->inflater.zstream);
	}

        G_OBJECT_CLASS (soup_websocket_extension_deflate_parent_class)->finalize (object);
}

static gboolean
parse_window_bits (const char *value,
                   gushort    *out)
{
        guint64 int_value;
        char *end = NULL;

        if (!value || !*value)
                return FALSE;

        int_value = g_ascii_strtoull (value, &end, 10);
        if (*end != '\0')
                return FALSE;

        if (int_value < 8 || int_value > 15)
                return FALSE;

        *out = (gushort)int_value;
        return TRUE;
}

static gboolean
return_invalid_param_error (GError    **error,
                            const char *param)
{
        g_set_error (error,
                     SOUP_WEBSOCKET_ERROR,
                     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                     "Invalid parameter '%s' in permessage-deflate extension header",
                     param);
        return FALSE;
}

static gboolean
return_invalid_param_value_error (GError    **error,
                                  const char *param)
{
        g_set_error (error,
                     SOUP_WEBSOCKET_ERROR,
                     SOUP_WEBSOCKET_ERROR_BAD_HANDSHAKE,
                     "Invalid value of parameter '%s' in permessage-deflate extension header",
                     param);
        return FALSE;
}

static gboolean
parse_params (GHashTable *params,
              Params     *out,
              GError    **error)
{
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init (&iter, params);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
                if (g_str_equal ((char *)key, "server_no_context_takeover")) {
                        if (value)
                                return return_invalid_param_value_error(error, "server_no_context_takeover");

                        out->flags |= PARAM_SERVER_NO_CONTEXT_TAKEOVER;
                } else if (g_str_equal ((char *)key, "client_no_context_takeover")) {
                        if (value)
                                return return_invalid_param_value_error(error, "client_no_context_takeover");

                        out->flags |= PARAM_CLIENT_NO_CONTEXT_TAKEOVER;
                } else if (g_str_equal ((char *)key, "server_max_window_bits")) {
                        if (!parse_window_bits ((char *)value, &out->server_max_window_bits))
                                return return_invalid_param_value_error(error, "server_max_window_bits");

                        out->flags |= PARAM_SERVER_MAX_WINDOW_BITS;
                } else if (g_str_equal ((char *)key, "client_max_window_bits")) {
                        if (value) {
                                if (!parse_window_bits ((char *)value, &out->client_max_window_bits))
                                        return return_invalid_param_value_error(error, "client_max_window_bits");
                        } else {
                                out->client_max_window_bits = 15;
                        }
                        out->flags |= PARAM_CLIENT_MAX_WINDOW_BITS;
                } else {
                        return return_invalid_param_error (error, (char *)key);
                }
        }

        return TRUE;
}

static gboolean
soup_websocket_extension_deflate_configure (SoupWebsocketExtension     *extension,
                                            SoupWebsocketConnectionType connection_type,
                                            GHashTable                 *params,
                                            GError                    **error)
{
        gushort deflater_max_window_bits;
        gushort inflater_max_window_bits;
        SoupWebsocketExtensionDeflatePrivate *priv;

        priv = soup_websocket_extension_deflate_get_instance_private (SOUP_WEBSOCKET_EXTENSION_DEFLATE (extension));

        if (params && !parse_params (params, &priv->params, error))
                return FALSE;

        switch (connection_type) {
        case SOUP_WEBSOCKET_CONNECTION_CLIENT:
                priv->deflater.no_context_takeover = priv->params.flags & PARAM_CLIENT_NO_CONTEXT_TAKEOVER;
                deflater_max_window_bits = priv->params.flags & PARAM_CLIENT_MAX_WINDOW_BITS ? priv->params.client_max_window_bits : 15;
                inflater_max_window_bits = priv->params.flags & PARAM_SERVER_MAX_WINDOW_BITS ? priv->params.server_max_window_bits : 15;
                break;
        case SOUP_WEBSOCKET_CONNECTION_SERVER:
                priv->deflater.no_context_takeover = priv->params.flags & PARAM_SERVER_NO_CONTEXT_TAKEOVER;
                deflater_max_window_bits = priv->params.flags & PARAM_SERVER_MAX_WINDOW_BITS ? priv->params.server_max_window_bits : 15;
                inflater_max_window_bits = priv->params.flags & PARAM_CLIENT_MAX_WINDOW_BITS ? priv->params.client_max_window_bits : 15;
                break;
        default:
                g_assert_not_reached ();
        }

        /* zlib is unable to compress with window_bits=8, so use 9
         * instead. This is compatible with decompressing using
         * window_bits=8.
         */
        deflater_max_window_bits = MAX (deflater_max_window_bits, 9);

        /* In case of failing to initialize zlib deflater/inflater,
         * we return TRUE without setting enabled = TRUE, so that the
         * hanshake doesn't fail.
         */
        if (deflateInit2 (&priv->deflater.zstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -deflater_max_window_bits, 8, Z_DEFAULT_STRATEGY) != Z_OK)
                return TRUE;

        if (inflateInit2 (&priv->inflater.zstream, -inflater_max_window_bits) != Z_OK) {
		deflateEnd (&priv->deflater.zstream);
                return TRUE;
	}

        priv->enabled = TRUE;

        return TRUE;
}

static char *
soup_websocket_extension_deflate_get_request_params (SoupWebsocketExtension *extension)
{
        return g_strdup ("; client_max_window_bits");
}

static char *
soup_websocket_extension_deflate_get_response_params (SoupWebsocketExtension *extension)
{
        GString *params;
        SoupWebsocketExtensionDeflatePrivate *priv;

        priv = soup_websocket_extension_deflate_get_instance_private (SOUP_WEBSOCKET_EXTENSION_DEFLATE (extension));
	if (!priv->enabled)
		return NULL;

        if (priv->params.flags == 0)
                return NULL;

        params = g_string_new (NULL);

        if (priv->params.flags & PARAM_SERVER_NO_CONTEXT_TAKEOVER)
                params = g_string_append (params, "; server_no_context_takeover");
        if (priv->params.flags & PARAM_CLIENT_NO_CONTEXT_TAKEOVER)
                params = g_string_append (params, "; client_no_context_takeover");
        if (priv->params.flags & PARAM_SERVER_MAX_WINDOW_BITS)
                g_string_append_printf (params, "; server_max_window_bits=%u", priv->params.server_max_window_bits);
        if (priv->params.flags & PARAM_CLIENT_MAX_WINDOW_BITS)
		g_string_append_printf (params, "; client_max_window_bits=%u", priv->params.client_max_window_bits);

        return g_string_free (params, FALSE);
}

static void
deflater_reset (Deflater *deflater)
{
        if (deflater->no_context_takeover)
                deflateReset (&deflater->zstream);
}

static GBytes *
soup_websocket_extension_deflate_process_outgoing_message (SoupWebsocketExtension *extension,
                                                           guint8                 *header,
                                                           GBytes                 *payload,
                                                           GError                **error)
{
        const guint8 *payload_data;
        gsize payload_length;
        guint max_length;
        gboolean control;
        GByteArray *buffer;
        gsize bytes_written;
        int result;
        gboolean in_sync_flush;
        SoupWebsocketExtensionDeflatePrivate *priv;

        priv = soup_websocket_extension_deflate_get_instance_private (SOUP_WEBSOCKET_EXTENSION_DEFLATE (extension));

        if (!priv->enabled)
                return payload;

        control = header[0] & 0x08;

        /* Do not compress control frames */
        if (control)
                return payload;

        payload_data = g_bytes_get_data (payload, &payload_length);
        if (payload_length == 0)
                return payload;

        /* Mark the frame as compressed using reserved bit 1 (0x40) */
        header[0] |= 0x40;

        buffer = g_byte_array_new ();
        max_length = deflateBound(&priv->deflater.zstream, payload_length);

        priv->deflater.zstream.next_in = (void *)payload_data;
        priv->deflater.zstream.avail_in = payload_length;

        bytes_written = 0;
        priv->deflater.zstream.avail_out = 0;

        do {
                gsize write_remaining;

                if (priv->deflater.zstream.avail_out == 0) {
                        guint write_position;

                        priv->deflater.zstream.avail_out = max_length;
                        write_position = buffer->len;
                        g_byte_array_set_size (buffer, buffer->len + max_length);
                        priv->deflater.zstream.next_out = buffer->data + write_position;

                        /* Use a fixed value for buffer increments */
                        max_length = BUFFER_SIZE;
                }

                write_remaining = buffer->len - bytes_written;
                in_sync_flush = priv->deflater.zstream.avail_in == 0;
                result = deflate (&priv->deflater.zstream, in_sync_flush ? Z_SYNC_FLUSH : Z_NO_FLUSH);
                bytes_written += write_remaining - priv->deflater.zstream.avail_out;
        } while (result == Z_OK);

        g_bytes_unref (payload);

        if (result != Z_BUF_ERROR || bytes_written < 4) {
                g_set_error_literal (error,
                                     SOUP_WEBSOCKET_ERROR,
                                     SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR,
                                     "Failed to compress outgoing frame");
                g_byte_array_unref (buffer);
                deflater_reset (&priv->deflater);
                return NULL;
        }

        /* Remove 4 octets (that are 0x00 0x00 0xff 0xff) from the tail end. */
        g_byte_array_set_size (buffer, bytes_written - 4);

        deflater_reset (&priv->deflater);

        return g_byte_array_free_to_bytes (buffer);
}

static GBytes *
soup_websocket_extension_deflate_process_incoming_message (SoupWebsocketExtension *extension,
                                                           guint8                 *header,
                                                           GBytes                 *payload,
                                                           GError                **error)
{
        const guint8 *payload_data;
        gsize payload_length;
        gboolean fin, control, compressed;
        GByteArray *buffer;
        gsize bytes_read, bytes_written;
        int result;
        gboolean tail_added = FALSE;
        SoupWebsocketExtensionDeflatePrivate *priv;

        priv = soup_websocket_extension_deflate_get_instance_private (SOUP_WEBSOCKET_EXTENSION_DEFLATE (extension));

        if (!priv->enabled)
                return payload;

        control = header[0] & 0x08;

        /* Do not uncompress control frames */
        if (control)
                return payload;

        compressed = header[0] & 0x40;
        if (!priv->inflater.uncompress_ongoing && !compressed)
                return payload;

        if (priv->inflater.uncompress_ongoing && compressed) {
                g_set_error_literal (error,
                                     SOUP_WEBSOCKET_ERROR,
                                     SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR,
                                     "Received a non-first frame with RSV1 flag set");
                g_bytes_unref (payload);
                return NULL;
        }

        /* Remove the compressed flag */
        header[0] &= ~0x40;

        fin = header[0] & 0x80;
        payload_data = g_bytes_get_data (payload, &payload_length);
        if (payload_length == 0 && ((!priv->inflater.uncompress_ongoing && fin) || (priv->inflater.uncompress_ongoing && !fin)))
                return payload;

        priv->inflater.uncompress_ongoing = !fin;

        buffer = g_byte_array_new ();

        bytes_read = 0;
        priv->inflater.zstream.next_in = (void *)payload_data;
        priv->inflater.zstream.avail_in = payload_length;

        bytes_written = 0;
        priv->inflater.zstream.avail_out = 0;

        do {
                gsize read_remaining;
                gsize write_remaining;

                if (priv->inflater.zstream.avail_out == 0) {
                        guint current_position;

                        priv->inflater.zstream.avail_out = BUFFER_SIZE;
                        current_position = buffer->len;
                        g_byte_array_set_size (buffer, buffer->len + BUFFER_SIZE);
                        priv->inflater.zstream.next_out = buffer->data + current_position;
                }

                if (priv->inflater.zstream.avail_in == 0 && !tail_added && fin) {
                        /* Append 4 octets of 0x00 0x00 0xff 0xff to the tail end */
                        priv->inflater.zstream.next_in = (void *)"\x00\x00\xff\xff";
                        priv->inflater.zstream.avail_in = 4;
                        bytes_read = 0;
                        tail_added = TRUE;
                }

                read_remaining = tail_added ? 4 : payload_length - bytes_read;
                write_remaining = buffer->len - bytes_written;
                result = inflate (&priv->inflater.zstream, tail_added ? Z_FINISH : Z_NO_FLUSH);
                bytes_read += read_remaining - priv->inflater.zstream.avail_in;
                bytes_written += write_remaining - priv->inflater.zstream.avail_out;
                if (!tail_added && result == Z_STREAM_END) {
                        /* Received a block with BFINAL set to 1. Reset decompression state. */
                        result = inflateReset (&priv->inflater.zstream);
                }

                if ((!fin && bytes_read == payload_length) || (fin && tail_added && bytes_read == 4))
                        break;
        } while (result == Z_OK || result == Z_BUF_ERROR);

        g_bytes_unref (payload);

        if (result != Z_OK && result != Z_BUF_ERROR) {
                priv->inflater.uncompress_ongoing = FALSE;
                g_set_error_literal (error,
                                     SOUP_WEBSOCKET_ERROR,
                                     SOUP_WEBSOCKET_CLOSE_PROTOCOL_ERROR,
                                     "Failed to uncompress incoming frame");
                g_byte_array_unref (buffer);

                return NULL;
        }

        g_byte_array_set_size (buffer, bytes_written);

        return g_byte_array_free_to_bytes (buffer);
}

static void
soup_websocket_extension_deflate_class_init (SoupWebsocketExtensionDeflateClass *klass)
{
        SoupWebsocketExtensionClass *extension_class = SOUP_WEBSOCKET_EXTENSION_CLASS (klass);
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        extension_class->name = "permessage-deflate";

        extension_class->configure = soup_websocket_extension_deflate_configure;
        extension_class->get_request_params = soup_websocket_extension_deflate_get_request_params;
        extension_class->get_response_params = soup_websocket_extension_deflate_get_response_params;
        extension_class->process_outgoing_message = soup_websocket_extension_deflate_process_outgoing_message;
        extension_class->process_incoming_message = soup_websocket_extension_deflate_process_incoming_message;

        object_class->finalize = soup_websocket_extension_deflate_finalize;
}
