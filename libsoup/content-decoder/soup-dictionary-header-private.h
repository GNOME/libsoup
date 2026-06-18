/* soup-dictionary-header-private.h
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

#pragma once

#include <glib.h>

G_BEGIN_DECLS

typedef struct {
	gboolean consumed;
	gsize filled;
	guint8 buffer[40];
} SoupDictionaryHeader;

void soup_dictionary_header_init (SoupDictionaryHeader *header);
gboolean soup_dictionary_header_consume (SoupDictionaryHeader  *header,
					 const guint8          *magic,
					 gsize                  magic_size,
					 GBytes                *dictionary,
					 const guint8         **next_in,
					 gsize                 *available_in,
					 gsize                  header_size,
					 const char            *invalid_magic_error,
					 const char            *hash_mismatch_error,
					 GError               **error);

G_END_DECLS