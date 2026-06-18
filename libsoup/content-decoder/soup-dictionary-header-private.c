/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/* soup-dictionary-header-private.c
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
#include <config.h>
#endif

#include <gio/gio.h>
#include <string.h>

#include "soup-dictionary-header-private.h"

void
soup_dictionary_header_init (SoupDictionaryHeader *header)
{
	g_assert (header != NULL);
	header->consumed = FALSE;
	header->filled = 0;
}

gboolean
soup_dictionary_header_consume (SoupDictionaryHeader  *header,
				 const guint8          *magic,
				 gsize                  magic_size,
				 GBytes                *dictionary,
				 const guint8         **next_in,
				 gsize                 *available_in,
				 gsize                  header_size,
				 const char            *invalid_magic_error,
				 const char            *hash_mismatch_error,
				 GError               **error)
{
	g_return_val_if_fail (header != NULL, FALSE);
	g_return_val_if_fail (next_in != NULL, FALSE);
	g_return_val_if_fail (available_in != NULL, FALSE);
	g_return_val_if_fail (magic != NULL, FALSE);
	g_return_val_if_fail (magic_size > 0, FALSE);
	g_return_val_if_fail (dictionary != NULL, FALSE);

	gsize remaining;
	gsize to_consume;
	gsize dict_size;
	const guchar *dict_data;
	guint8 expected_hash[32];
	gsize hash_len = sizeof (expected_hash);
	GChecksum *checksum;

	g_assert (header_size <= sizeof (header->buffer));

	remaining = header_size - header->filled;
	to_consume = MIN (*available_in, remaining);

	memcpy (header->buffer + header->filled, *next_in, to_consume);
	header->filled += to_consume;
	*next_in += to_consume;
	*available_in -= to_consume;

	if (header->filled < header_size)
		return TRUE;

	if (memcmp (header->buffer, magic, magic_size) != 0) {
		if (error)
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, invalid_magic_error);
		return FALSE;
	}

	dict_data = g_bytes_get_data (dictionary, &dict_size);
	checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, dict_data, (gssize)dict_size);
	g_checksum_get_digest (checksum, expected_hash, &hash_len);
	g_checksum_free (checksum);

	if (memcmp (header->buffer + magic_size, expected_hash, hash_len) != 0) {
		if (error)
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, hash_mismatch_error);
		return FALSE;
	}

	header->consumed = TRUE;
	return TRUE;
}