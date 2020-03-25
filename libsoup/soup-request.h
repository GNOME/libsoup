/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009, 2010 Red Hat, Inc.
 * Copyright (C) 2010 Igalia, S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#pragma once

#include <gio/gio.h>

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_REQUEST (soup_request_get_type ())
SOUP_AVAILABLE_IN_2_34
G_DECLARE_DERIVABLE_TYPE (SoupRequest, soup_request, SOUP, REQUEST, GObject)

struct _SoupRequestClass {
	GObjectClass parent;

	const char **schemes;

	gboolean       (*check_uri)          (SoupRequest          *req_base,
					      SoupURI              *uri,
					      GError              **error);

	GInputStream * (*send)               (SoupRequest          *request,
					      GCancellable         *cancellable,
					      GError              **error);
	void           (*send_async)         (SoupRequest          *request,
					      GCancellable         *cancellable,
					      GAsyncReadyCallback   callback,
					      gpointer              user_data);
	GInputStream * (*send_finish)        (SoupRequest          *request,
					      GAsyncResult         *result,
					      GError              **error);

	goffset        (*get_content_length) (SoupRequest          *request);
	const char *   (*get_content_type)   (SoupRequest          *request);
};

#define SOUP_REQUEST_URI     "uri"
#define SOUP_REQUEST_SESSION "session"

SOUP_AVAILABLE_IN_2_34
GInputStream *soup_request_send               (SoupRequest          *request,
					       GCancellable         *cancellable,
					       GError              **error);
SOUP_AVAILABLE_IN_2_34
void          soup_request_send_async         (SoupRequest          *request,
					       GCancellable         *cancellable,
					       GAsyncReadyCallback   callback,
					       gpointer              user_data);
SOUP_AVAILABLE_IN_2_34
GInputStream *soup_request_send_finish        (SoupRequest          *request,
					       GAsyncResult         *result,
					       GError              **error);

SOUP_AVAILABLE_IN_2_34
SoupURI      *soup_request_get_uri            (SoupRequest          *request);
SOUP_AVAILABLE_IN_2_34
SoupSession  *soup_request_get_session        (SoupRequest          *request);

SOUP_AVAILABLE_IN_2_34
goffset       soup_request_get_content_length (SoupRequest          *request);
SOUP_AVAILABLE_IN_2_34
const char   *soup_request_get_content_type   (SoupRequest          *request);

G_END_DECLS
