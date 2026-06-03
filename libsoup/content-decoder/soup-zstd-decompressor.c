/* soup-zstd-decompressor.c
 *
 * Copyright 2026 Igalia S.L.
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <zstd.h>
#include <gio/gio.h>
#include <string.h>

#include "soup-zstd-decompressor.h"

/* dcz framing: zstd skippable frame (magic 0x184D2A5E LE + 4-byte size 32 LE)
 * followed by 32-byte SHA-256 hash of the dictionary.
 * Total header = 8 + 32 = 40 bytes. */
static const guint8 DCZ_MAGIC[] = { 0x5e, 0x2a, 0x4d, 0x18, 0x20, 0x00, 0x00, 0x00 };
#define DCZ_HEADER_SIZE (sizeof (DCZ_MAGIC) + 32)

struct _SoupZstdDecompressor
{
	GObject parent_instance;
	ZSTD_DStream *dstream;
	GError *last_error;
	GBytes *dictionary;
	gboolean header_consumed;
	gsize header_buf_filled;
	guint8 header_buf[DCZ_HEADER_SIZE];
};

static void soup_zstd_decompressor_iface_init (GConverterIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupZstdDecompressor, soup_zstd_decompressor, G_TYPE_OBJECT,
                               G_IMPLEMENT_INTERFACE (G_TYPE_CONVERTER, soup_zstd_decompressor_iface_init))

SoupZstdDecompressor *
soup_zstd_decompressor_new (void)
{
	return g_object_new (SOUP_TYPE_ZSTD_DECOMPRESSOR, NULL);
}

SoupZstdDecompressor *
soup_zstd_decompressor_new_with_dictionary (GBytes *dictionary)
{
	SoupZstdDecompressor *self;

	g_return_val_if_fail (dictionary != NULL, NULL);

	self = g_object_new (SOUP_TYPE_ZSTD_DECOMPRESSOR, NULL);
	self->dictionary = g_bytes_ref (dictionary);
	return self;
}

static GConverterResult
soup_zstd_decompressor_convert (GConverter      *converter,
                                const void      *inbuf,
                                gsize            inbuf_size,
                                void            *outbuf,
                                gsize            outbuf_size,
                                GConverterFlags  flags,
                                gsize           *bytes_read,
                                gsize           *bytes_written,
                                GError         **error)
{
	SoupZstdDecompressor *self = SOUP_ZSTD_DECOMPRESSOR (converter);
	ZSTD_inBuffer input;
	ZSTD_outBuffer output;
	size_t result;
	gsize available_in = inbuf_size;
	const guint8 *next_in = inbuf;

	g_return_val_if_fail (inbuf, G_CONVERTER_ERROR);

	if (self->last_error) {
		if (error)
			*error = g_steal_pointer (&self->last_error);
		g_clear_error (&self->last_error);
		return G_CONVERTER_ERROR;
	}

	/* NOTE: all error domains/codes must match GZlibDecompressor */

	if (self->dictionary && !self->header_consumed) {
		gsize remaining = DCZ_HEADER_SIZE - self->header_buf_filled;
		gsize to_consume = MIN (available_in, remaining);

		memcpy (self->header_buf + self->header_buf_filled, next_in, to_consume);
		self->header_buf_filled += to_consume;
		next_in += to_consume;
		available_in -= to_consume;

		if (self->header_buf_filled == DCZ_HEADER_SIZE) {
			if (memcmp (self->header_buf, DCZ_MAGIC, sizeof (DCZ_MAGIC)) != 0) {
				g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
				                     "SoupZstdDecompressorError: Invalid dcz magic header");
				return G_CONVERTER_ERROR;
			}

			gsize dict_size;
			const guchar *dict_data = g_bytes_get_data (self->dictionary, &dict_size);
			guint8 expected_hash[32];
			gsize hash_len = sizeof (expected_hash);
			GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
			g_checksum_update (checksum, dict_data, (gssize)dict_size);
			g_checksum_get_digest (checksum, expected_hash, &hash_len);
			g_checksum_free (checksum);
			if (memcmp (self->header_buf + sizeof (DCZ_MAGIC), expected_hash, 32) != 0) {
				g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
				                     "SoupZstdDecompressorError: Dictionary hash mismatch");
				return G_CONVERTER_ERROR;
			}

			self->header_consumed = TRUE;
		}

		if (available_in == 0) {
			*bytes_read = inbuf_size;
			*bytes_written = 0;
			return G_CONVERTER_CONVERTED;
		}
	}

	if (self->dstream == NULL) {
		self->dstream = ZSTD_createDStream ();
		if (self->dstream == NULL) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			                     "SoupZstdDecompressorError: Failed to initialize state");
			return G_CONVERTER_ERROR;
		}
		if (self->dictionary) {
			gsize dict_size;
			const guchar *dict_data = g_bytes_get_data (self->dictionary, &dict_size);
			size_t r = ZSTD_DCtx_loadDictionary (self->dstream, dict_data, dict_size);
			if (ZSTD_isError (r)) {
				g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
				             "SoupZstdDecompressorError: Failed to load dictionary: %s",
				             ZSTD_getErrorName (r));
				return G_CONVERTER_ERROR;
			}
		}
	}

	input.src = next_in;
	input.size = available_in;
	input.pos = 0;

	output.dst = outbuf;
	output.size = outbuf_size;
	output.pos = 0;

	result = ZSTD_decompressStream (self->dstream, &output, &input);

	*bytes_read = (inbuf_size - available_in) + input.pos;
	*bytes_written = output.pos;

	/* As per API docs: If any data was either produced or consumed, and then an error happens, then only
	 * the successful conversion is reported and the error is returned on the next call. */
	if (*bytes_read || *bytes_written) {
		if (ZSTD_isError (result)) {
			self->last_error = g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED,
			                               "SoupZstdDecompressorError: %s",
			                               ZSTD_getErrorName (result));
		}
		if (result == 0)
			return G_CONVERTER_FINISHED;
		return G_CONVERTER_CONVERTED;
	}

	if (ZSTD_isError (result)) {
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "SoupZstdDecompressorError: %s",
		             ZSTD_getErrorName (result));
		return G_CONVERTER_ERROR;
	}

	if (result == 0)
		return G_CONVERTER_FINISHED;

	g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
	                     "SoupZstdDecompressorError: More input required (corrupt input)");
	return G_CONVERTER_ERROR;
}

static void
soup_zstd_decompressor_reset (GConverter *converter)
{
	SoupZstdDecompressor *self = SOUP_ZSTD_DECOMPRESSOR (converter);

	if (self->dstream) {
		if (self->dictionary)
			g_clear_pointer (&self->dstream, ZSTD_freeDStream);
		else
			ZSTD_DCtx_reset (self->dstream, ZSTD_reset_session_only);
	}
	g_clear_error (&self->last_error);
	self->header_consumed = FALSE;
	self->header_buf_filled = 0;
}

static void
soup_zstd_decompressor_finalize (GObject *object)
{
	SoupZstdDecompressor *self = (SoupZstdDecompressor *)object;
	g_clear_pointer (&self->dstream, ZSTD_freeDStream);
	g_clear_error (&self->last_error);
	g_clear_pointer (&self->dictionary, g_bytes_unref);
	G_OBJECT_CLASS (soup_zstd_decompressor_parent_class)->finalize (object);
}

static void soup_zstd_decompressor_iface_init (GConverterIface *iface)
{
	iface->convert = soup_zstd_decompressor_convert;
	iface->reset = soup_zstd_decompressor_reset;
}

static void
soup_zstd_decompressor_class_init (SoupZstdDecompressorClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = soup_zstd_decompressor_finalize;
}

static void
soup_zstd_decompressor_init (SoupZstdDecompressor *self)
{
}
