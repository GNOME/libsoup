/*
 * Copyright 2025 Philip Withnall
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "fuzz.h"

int
LLVMFuzzerTestOneInput (const unsigned char *data, size_t size)
{
        SoupMessageHeaders *headers = NULL;
        char *method = NULL;
        char *path = NULL;
        SoupHTTPVersion ver;

        fuzz_set_logging_func ();

        headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);

        soup_headers_parse_request ((const char *) data, size, headers, &method, &path, &ver);

        soup_message_headers_unref (headers);
        g_free (method);
        g_free (path);

        return 0;
}
