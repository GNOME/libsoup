/*
 * Copyright 2021 Igalia S.L.
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
#include "soup-body-input-stream-http2.h"

static void
do_large_data_test (void)
{
#define CHUNK_SIZE ((gsize)1024 * 1024 * 512) // 512 MiB
#define TEST_SIZE (CHUNK_SIZE * 4) // 2 GiB

        GInputStream *stream = soup_body_input_stream_http2_new ();
        SoupBodyInputStreamHttp2 *mem_stream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        gsize data_needed = TEST_SIZE;
        guint8 *memory_chunk = g_try_new (guint8, CHUNK_SIZE);
        guint8 *trash_buffer = g_try_new (guint8, CHUNK_SIZE);

	if (memory_chunk == NULL || trash_buffer == NULL) {
		g_test_skip ("large memory allocation failed");
		goto out;
	}

        /* We can add unlimited data and as long as its read the data will
         * be freed, so this should work fine even though its reading GB of data */

        while (data_needed > 0) {
                /* Copy chunk */
                soup_body_input_stream_http2_add_data (mem_stream, memory_chunk, CHUNK_SIZE);

                /* This should free the copy */
                gssize read = g_input_stream_read (stream, trash_buffer, CHUNK_SIZE, NULL, NULL);
                g_assert_cmpint (read, ==, CHUNK_SIZE);
                data_needed -= CHUNK_SIZE;
        }

        data_needed = TEST_SIZE;
        while (data_needed > 0) {
                soup_body_input_stream_http2_add_data (mem_stream, memory_chunk, CHUNK_SIZE);

                /* Skipping also frees the copy */
                gssize skipped = g_input_stream_skip (stream, CHUNK_SIZE, NULL, NULL);
                g_assert_cmpint (skipped, ==, CHUNK_SIZE);
                data_needed -= CHUNK_SIZE;
        }

out:
        g_free (trash_buffer);
        g_free (memory_chunk);
        g_object_unref (stream);
}

static void
do_multiple_chunk_test (void)
{
        GInputStream *stream = soup_body_input_stream_http2_new ();
        SoupBodyInputStreamHttp2 *mem_stream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        const char * const chunks[] = {
                "1234", "5678", "9012", "hell", "owor", "ld..",
        };

        for (guint i = 0; i < G_N_ELEMENTS (chunks); ++i)
                soup_body_input_stream_http2_add_data (mem_stream, (guint8*)chunks[i], 4);

        /* Do partial reads of chunks to ensure it always comes out as expected */
        for (guint i = 0; i < G_N_ELEMENTS (chunks); ++i) {
                char buffer[5] = { 0 };
                gssize read = g_input_stream_read (stream, buffer, 2, NULL, NULL);
                g_assert_cmpint (read, ==, 2);
                read = g_input_stream_read (stream, buffer + 2, 2, NULL, NULL);
                g_assert_cmpint (read, ==, 2);
                g_assert_cmpstr (buffer, ==, chunks[i]);
        }

        g_object_unref (stream);
}

static void
on_skip_ready (GInputStream *stream, GAsyncResult *res, GMainLoop *loop)
{
        GError *error = NULL;
        gssize skipped = g_input_stream_skip_finish (stream, res, &error);

        g_assert_no_error (error);
        g_assert_cmpint (skipped, ==, 2);

        g_main_loop_quit (loop);
}

static void
do_skip_async_test (void)
{
        GInputStream *stream = soup_body_input_stream_http2_new ();
        SoupBodyInputStreamHttp2 *bistream = SOUP_BODY_INPUT_STREAM_HTTP2 (stream);
        GMainLoop *loop = g_main_loop_new (NULL, FALSE);

        soup_body_input_stream_http2_add_data (bistream, (guchar*)"test", 5);

        g_input_stream_skip_async (stream, 2, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback)on_skip_ready, loop);

        g_main_loop_run (loop);
        g_object_unref (stream);
        g_main_loop_unref (loop);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/body_stream/large_data", do_large_data_test);
        g_test_add_func ("/body_stream/multiple_chunks", do_multiple_chunk_test);
        g_test_add_func ("/body_stream/skip_async", do_skip_async_test);

	ret = g_test_run ();

        test_cleanup ();

	return ret;
}
