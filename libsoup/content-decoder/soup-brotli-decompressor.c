/* soup-brotli-decompressor.c
 *
 * Copyright 2019 Igalia S.L.
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

#include <brotli/decode.h>
#include <brotli/shared_dictionary.h>
#include <gio/gio.h>
#include <string.h>

#include "soup-brotli-decompressor.h"

/* dcb framing: 4-byte magic (\xffDCB) + 32-byte SHA-256 hash of the dictionary */
static const guint8 DCB_MAGIC[] = { 0xff, 'D', 'C', 'B' };
#define DCB_HEADER_SIZE (sizeof (DCB_MAGIC) + 32)

struct _SoupBrotliDecompressor
{
	GObject parent_instance;
	BrotliDecoderState *state;
	GError *last_error;
	GBytes *dictionary;
	gboolean header_consumed;
	gsize header_buf_filled;
	guint8 header_buf[DCB_HEADER_SIZE];
};

static void soup_brotli_decompressor_iface_init (GConverterIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupBrotliDecompressor, soup_brotli_decompressor, G_TYPE_OBJECT,
                               G_IMPLEMENT_INTERFACE (G_TYPE_CONVERTER, soup_brotli_decompressor_iface_init))

SoupBrotliDecompressor *
soup_brotli_decompressor_new (void)
{
	return g_object_new (SOUP_TYPE_BROTLI_DECOMPRESSOR, NULL);
}

SoupBrotliDecompressor *
soup_brotli_decompressor_new_with_dictionary (GBytes *dictionary)
{
	SoupBrotliDecompressor *self;

	g_return_val_if_fail (dictionary != NULL, NULL);

	self = g_object_new (SOUP_TYPE_BROTLI_DECOMPRESSOR, NULL);
	self->dictionary = g_bytes_ref (dictionary);
	return self;
}

static GError *
soup_brotli_decompressor_create_error (SoupBrotliDecompressor  *self)
{
	BrotliDecoderErrorCode code;
	const char *error_string;

	g_assert (self->state != NULL);
	code = BrotliDecoderGetErrorCode (self->state);
	error_string = BrotliDecoderErrorString (code);
	return g_error_new (G_IO_ERROR, G_IO_ERROR_FAILED, "SoupBrotliDecompressorError: %s", error_string);
}

static void
soup_brotli_decompressor_set_error (SoupBrotliDecompressor  *self,
                                    GError                 **error)
{
	BrotliDecoderErrorCode code;
	const char *error_string;

	if (error == NULL)
		return;

	g_assert (self->state != NULL);
	code = BrotliDecoderGetErrorCode (self->state);
	error_string = BrotliDecoderErrorString (code);
	g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "SoupBrotliDecompressorError: %s", error_string);
}

static GConverterResult
soup_brotli_decompressor_convert (GConverter      *converter,
				  const void      *inbuf,
				  gsize            inbuf_size,
				  void            *outbuf,
				  gsize            outbuf_size,
				  GConverterFlags  flags,
				  gsize           *bytes_read,
				  gsize           *bytes_written,
				  GError         **error)
{
	SoupBrotliDecompressor *self = SOUP_BROTLI_DECOMPRESSOR (converter);
	BrotliDecoderResult result;
	gsize available_in = inbuf_size;
	const guint8 *next_in = inbuf;
	gsize available_out = outbuf_size;
	guchar *next_out = outbuf;

	g_return_val_if_fail (inbuf, G_CONVERTER_ERROR);

	if (self->last_error) {
		if (error)
			*error = g_steal_pointer (&self->last_error);
		g_clear_error (&self->last_error);
		return G_CONVERTER_ERROR;
	}

	/* NOTE: all error domains/codes must match GZlibDecompressor */

	if (self->dictionary && !self->header_consumed) {
		gsize remaining = DCB_HEADER_SIZE - self->header_buf_filled;
		gsize to_consume = MIN (available_in, remaining);

		memcpy (self->header_buf + self->header_buf_filled, next_in, to_consume);
		self->header_buf_filled += to_consume;
		next_in += to_consume;
		available_in -= to_consume;

		if (self->header_buf_filled == DCB_HEADER_SIZE) {
			if (memcmp (self->header_buf, DCB_MAGIC, sizeof (DCB_MAGIC)) != 0) {
				g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
				                     "SoupBrotliDecompressorError: Invalid dcb magic header");
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
			if (memcmp (self->header_buf + sizeof (DCB_MAGIC), expected_hash, 32) != 0) {
				g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
										"SoupBrotliDecompressorError: Dictionary hash mismatch");
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

	if (self->state == NULL) {
		self->state = BrotliDecoderCreateInstance (NULL, NULL, NULL);
		if (self->state == NULL) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "SoupBrotliDecompressorError: Failed to initialize state");
			return G_CONVERTER_ERROR;
		}
		if (self->dictionary) {
			gsize dict_size;
			const uint8_t *dict_data = g_bytes_get_data (self->dictionary, &dict_size);
			BrotliDecoderAttachDictionary (self->state, BROTLI_SHARED_DICTIONARY_RAW, dict_size, dict_data);
		}
	}

	result = BrotliDecoderDecompressStream (self->state, &available_in, &next_in, &available_out, &next_out, NULL);

	/* available_in is now set to *unread* input size */
	*bytes_read = inbuf_size - available_in;
	/* available_out is now set to *unwritten* output size */
	*bytes_written = outbuf_size - available_out;

	/* As per API docs: If any data was either produced or consumed, and then an error happens, then only
	 * the successful conversion is reported and the error is returned on the next call. */
	if (*bytes_read || *bytes_written) {
		switch (result) {
		case BROTLI_DECODER_RESULT_ERROR:
			self->last_error = soup_brotli_decompressor_create_error (self);
			break;
		case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
			self->last_error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT, "SoupBrotliDecompressorError: More input required (corrupt input)");
			break;
		case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
			/* Just continue with more output then */
			break;
		case BROTLI_DECODER_RESULT_SUCCESS:
			/* Just continue returning finished next time */
			break;
		}

		return G_CONVERTER_CONVERTED;
	}

	switch (result) {
	case BROTLI_DECODER_RESULT_SUCCESS:
		return G_CONVERTER_FINISHED;
	case BROTLI_DECODER_RESULT_ERROR:
		soup_brotli_decompressor_set_error (self, error);
		return G_CONVERTER_ERROR;
	case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT, "SoupBrotliDecompressorError: More input required (corrupt input)");
		return G_CONVERTER_ERROR;
	case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
		g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE, "SoupBrotliDecompressorError: Larger output buffer required");
		return G_CONVERTER_ERROR;
	}

	g_assert_not_reached ();
	return G_CONVERTER_ERROR;
}

static void
soup_brotli_decompressor_reset (GConverter *converter)
{
	SoupBrotliDecompressor *self = SOUP_BROTLI_DECOMPRESSOR (converter);

	if (self->state && BrotliDecoderIsUsed (self->state))
		g_clear_pointer (&self->state, BrotliDecoderDestroyInstance);
	g_clear_error (&self->last_error);
	self->header_consumed = FALSE;
	self->header_buf_filled = 0;
}

static void
soup_brotli_decompressor_finalize (GObject *object)
{
	SoupBrotliDecompressor *self = (SoupBrotliDecompressor *)object;
	g_clear_pointer (&self->state, BrotliDecoderDestroyInstance);
	g_clear_error (&self->last_error);
	g_clear_pointer (&self->dictionary, g_bytes_unref);
	G_OBJECT_CLASS (soup_brotli_decompressor_parent_class)->finalize (object);
}

static void soup_brotli_decompressor_iface_init (GConverterIface *iface)
{
	iface->convert = soup_brotli_decompressor_convert;
	iface->reset = soup_brotli_decompressor_reset;
}

static void
soup_brotli_decompressor_class_init (SoupBrotliDecompressorClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = soup_brotli_decompressor_finalize;
}

static void
soup_brotli_decompressor_init (SoupBrotliDecompressor *self)
{
}
