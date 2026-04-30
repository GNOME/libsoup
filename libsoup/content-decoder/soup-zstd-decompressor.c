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

#include "soup-zstd-decompressor.h"

struct _SoupZstdDecompressor
{
	GObject parent_instance;
	ZSTD_DStream *dstream;
	GError *last_error;
};

static void soup_zstd_decompressor_iface_init (GConverterIface *iface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupZstdDecompressor, soup_zstd_decompressor, G_TYPE_OBJECT,
                               G_IMPLEMENT_INTERFACE (G_TYPE_CONVERTER, soup_zstd_decompressor_iface_init))

SoupZstdDecompressor *
soup_zstd_decompressor_new (void)
{
	return g_object_new (SOUP_TYPE_ZSTD_DECOMPRESSOR, NULL);
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

	g_return_val_if_fail (inbuf, G_CONVERTER_ERROR);

	if (self->last_error) {
		if (error)
			*error = g_steal_pointer (&self->last_error);
		g_clear_error (&self->last_error);
		return G_CONVERTER_ERROR;
	}

	/* NOTE: all error domains/codes must match GZlibDecompressor */

	if (self->dstream == NULL) {
		self->dstream = ZSTD_createDStream ();
		if (self->dstream == NULL) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			                     "SoupZstdDecompressorError: Failed to initialize state");
			return G_CONVERTER_ERROR;
		}
	}

	input.src = inbuf;
	input.size = inbuf_size;
	input.pos = 0;

	output.dst = outbuf;
	output.size = outbuf_size;
	output.pos = 0;

	result = ZSTD_decompressStream (self->dstream, &output, &input);

	*bytes_read = input.pos;
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

	if (self->dstream)
		ZSTD_DCtx_reset (self->dstream, ZSTD_reset_session_only);
	g_clear_error (&self->last_error);
}

static void
soup_zstd_decompressor_finalize (GObject *object)
{
	SoupZstdDecompressor *self = (SoupZstdDecompressor *)object;
	g_clear_pointer (&self->dstream, ZSTD_freeDStream);
	g_clear_error (&self->last_error);
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
