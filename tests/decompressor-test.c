/* decompressor-test.c
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

#include "test-utils.h"
#ifdef WITH_BROTLI
#include "soup-brotli-decompressor.h"
#endif
#ifdef WITH_ZSTD
#include "soup-zstd-decompressor.h"
#endif

typedef struct {
        GConverter *(*create) (void);
        const char *compressed_ext;
} DecompressorTestData;

static char *
get_compressed_filename (const DecompressorTestData *td, const char *basename)
{
        char *name = g_strconcat (basename, td->compressed_ext, NULL);
        char *path = g_build_filename (g_test_get_dir (G_TEST_DIST), "compressed-data", name, NULL);
        g_free (name);
        return path;
}

static void
test_basic (gconstpointer user_data)
{
        const DecompressorTestData *td = user_data;
        GConverter *dec = td->create ();
        char *compressed_filename = get_compressed_filename (td, "compressed");
        char *uncompressed_filename = g_build_filename (g_test_get_dir (G_TEST_DIST), "compressed-data",
                                                        "uncompressed.txt", NULL);
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
                result = g_converter_convert (dec, in_buf, length, out_buf, sizeof out_buf, 0,
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
test_corrupt (gconstpointer user_data)
{
        const DecompressorTestData *td = user_data;
        GConverter *dec = td->create ();
        char *compressed_filename = get_compressed_filename (td, "corrupt");
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
                result = g_converter_convert (dec, in_buf, length, out_buf, sizeof out_buf, 0,
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
test_reset (gconstpointer user_data)
{
        const DecompressorTestData *td = user_data;
        GConverter *dec = td->create ();
        char *contents;
        gsize length, in_len;
        char *in_buf;
        GConverterResult result;
        int iterations = 0;
        char *compressed_filename = get_compressed_filename (td, "compressed");

        g_assert_true (g_file_get_contents (compressed_filename, &contents, &length, NULL));
        in_buf = contents;
        in_len = length;

        do {
                GError *error = NULL;
                guint8 out_buf[16];
                gsize bytes_read, bytes_written;
                result = g_converter_convert (dec, in_buf, in_len, out_buf, sizeof out_buf, 0,
                                              &bytes_read, &bytes_written, &error);

                /* Just randomly reset in the middle and ensure everything keeps working */
                if (iterations == 6) {
                        g_converter_reset (dec);
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

static void
test_truncated (gconstpointer user_data)
{
        const DecompressorTestData *td = user_data;
        GConverter *dec = td->create ();
        char *compressed_filename = get_compressed_filename (td, "compressed");
        GError *error = NULL;
        char *contents;
        gsize length;
        gsize bytes_read, bytes_written;
        guint8 out_buf[4096];
        GConverterResult result;

        g_assert_true (g_file_get_contents (compressed_filename, &contents, &length, NULL));
        g_assert_cmpuint (length, >, 4);

        /* Feed all but the last 4 bytes so the frame is incomplete */
        result = g_converter_convert (dec, contents, length - 4, out_buf, sizeof out_buf, 0,
                                      &bytes_read, &bytes_written, &error);
        g_assert_no_error (error);
        g_assert_cmpint (result, ==, G_CONVERTER_CONVERTED);

        /* Call with no input — decompressor must report it needs more input */
        result = g_converter_convert (dec, contents, 0, out_buf, sizeof out_buf, 0,
                                      &bytes_read, &bytes_written, &error);
        g_assert_error (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT);
        g_assert_cmpint (result, ==, G_CONVERTER_ERROR);

        g_clear_error (&error);
        g_free (contents);
        g_free (compressed_filename);
        g_object_unref (dec);
}

static void
add_tests (const char *prefix, const DecompressorTestData *td)
{
        char path[64];

        g_snprintf (path, sizeof path, "/%s/basic", prefix);
        g_test_add_data_func (path, td, test_basic);

        g_snprintf (path, sizeof path, "/%s/corrupt", prefix);
        g_test_add_data_func (path, td, test_corrupt);

        g_snprintf (path, sizeof path, "/%s/reset", prefix);
        g_test_add_data_func (path, td, test_reset);

        g_snprintf (path, sizeof path, "/%s/truncated", prefix);
        g_test_add_data_func (path, td, test_truncated);
}

int
main (int argc, char **argv)
{
        int ret;

        test_init (argc, argv, NULL);

#ifdef WITH_BROTLI
        static const DecompressorTestData brotli_data = {
                .create = (GConverter * (*)(void)) soup_brotli_decompressor_new,
                .compressed_ext = ".br",
        };
        add_tests ("brotli", &brotli_data);
#endif

#ifdef WITH_ZSTD
        static const DecompressorTestData zstd_data = {
                .create = (GConverter * (*)(void)) soup_zstd_decompressor_new,
                .compressed_ext = ".zst",
        };
        add_tests ("zstd", &zstd_data);
#endif

        ret = g_test_run ();
        test_cleanup ();
        return ret;
}
