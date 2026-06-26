/* soup-brotli-decompressor.h
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

#pragma once

#include <glib-object.h>
#include "soup-version.h"

G_BEGIN_DECLS

#define SOUP_TYPE_BROTLI_DECOMPRESSOR (soup_brotli_decompressor_get_type())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupBrotliDecompressor, soup_brotli_decompressor, SOUP, BROTLI_DECOMPRESSOR, GObject)

SoupBrotliDecompressor *soup_brotli_decompressor_new (void);

G_END_DECLS
