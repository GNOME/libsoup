/* brotli-decompressor-test.c
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

#include "test-utils.h"
#include "libsoup/soup-brotli-decompressor.h"

static void
test_brotli (void)
{
        SoupBrotliDecompressor *dec = soup_brotli_decompressor_new ();
        char *compressed_filename = g_build_filename (g_test_get_dir (G_TEST_DIST), "brotli-data", "compressed.br", NULL);
        char *uncompressed_filename = g_build_filename (g_test_get_dir (G_TEST_DIST), "brotli-data", "uncompressed.txt", NULL);
        char *contents;
        gsize length;
        GByteArray *out_bytes = g_byte_array_new ();
        char *in_buf;
        GConverterResult result;

        g_assert_true (g_file_get_contents (compressed_filename, &contents, &length, NULL));
        in_buf = contents;

        do {
                GError *error = NULL;
                guint8 out_buf[16]; /* This is stupidly small just to simulate common usage of converting in chunks */
                gsize bytes_read, bytes_written;
                result = g_converter_convert (G_CONVERTER (dec), in_buf, length, out_buf, sizeof out_buf, 0,
                                              &bytes_read, &bytes_written, &error);

                g_assert_no_error (error);
                g_assert_cmpint (result, !=, G_CONVERTER_ERROR);

                g_byte_array_append (out_bytes, out_buf, bytes_written);
                in_buf += bytes_read;
                length -= bytes_read;

        } while (result == G_CONVERTER_CONVERTED);

        g_assert_cmpint (result, ==, G_CONVERTER_FINISHED);

        /* NUL terminate data so we can cmpstr below. */
        g_byte_array_append (out_bytes, (const guint8*)"\0", 1);

        g_free (contents);
        g_assert_true (g_file_get_contents (uncompressed_filename, &contents, &length, NULL));
        g_assert_cmpstr ((char*)out_bytes->data, ==, contents);

        g_byte_array_free (out_bytes, TRUE);
        g_object_unref (dec);
        g_free (compressed_filename);
        g_free (uncompressed_filename);
        g_free (contents);
}

static void
test_brotli_corrupt (void)
{
        SoupBrotliDecompressor *dec = soup_brotli_decompressor_new ();
        char *compressed_filename = g_build_filename (g_test_get_dir (G_TEST_DIST), "brotli-data", "corrupt.br", NULL);
        GError *error = NULL;
        char *contents;
        gsize length;
        char *in_buf;
        GConverterResult result;

        g_assert_true (g_file_get_contents (compressed_filename, &contents, &length, NULL));
        in_buf = contents;

        do {
                guint8 out_buf[4096];
                gsize bytes_read, bytes_written;
                result = g_converter_convert (G_CONVERTER (dec), in_buf, length, out_buf, sizeof out_buf, 0,
                                              &bytes_read, &bytes_written, &error);

                in_buf += bytes_read;
                length -= bytes_read;
        } while (result == G_CONVERTER_CONVERTED);

        g_assert_cmpint (result, ==, G_CONVERTER_ERROR);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);

        g_object_unref (dec);
        g_free (compressed_filename);
        g_free (contents);
        g_error_free (error);
}

static void
test_brotli_reset (void)
{
        SoupBrotliDecompressor *dec = soup_brotli_decompressor_new ();
        char *compressed_filename = g_build_filename (g_test_get_dir (G_TEST_DIST), "brotli-data", "compressed.br", NULL);
        char *contents;
        gsize length, in_len;
        char *in_buf;
        GConverterResult result;
        int iterations = 0;

        g_assert_true (g_file_get_contents (compressed_filename, &contents, &length, NULL));
        in_buf = contents;
        in_len = length;

        do {
                GError *error = NULL;
                guint8 out_buf[16];
                gsize bytes_read, bytes_written;
                result = g_converter_convert (G_CONVERTER (dec), in_buf, in_len, out_buf, sizeof out_buf, 0,
                                              &bytes_read, &bytes_written, &error);

                /* Just randomly reset in the middle and ensure everything keeps working */
                if (iterations == 6) {
                        g_converter_reset (G_CONVERTER (dec));
                        in_buf = contents;
                        in_len = length;
                }

                g_assert_no_error (error);
                g_assert_cmpint (result, !=, G_CONVERTER_ERROR);
                in_buf += bytes_read;
                in_len -= bytes_read;
                ++iterations;
        } while (result == G_CONVERTER_CONVERTED);

        g_assert_cmpint (result, ==, G_CONVERTER_FINISHED);

        g_object_unref (dec);
        g_free (compressed_filename);
        g_free (contents);
}

int
main (int argc, char **argv)
{

	int ret;

	test_init (argc, argv, NULL);

        g_test_add_func ("/brotli/basic", test_brotli);
        g_test_add_func ("/brotli/corrupt", test_brotli_corrupt);
        g_test_add_func ("/brotli/reset", test_brotli_reset);

	ret = g_test_run ();
	test_cleanup ();
	return ret;
}
