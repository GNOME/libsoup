/*
 * Copyright 2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SOUP_AUTOCLEANUPS_H
#define SOUP_AUTOCLEANUPS_H

#include <libsoup/soup-types.h>

#if SOUP_VERSION_MAX_ALLOWED >= SOUP_VERSION_2_52
#ifdef G_DEFINE_AUTOPTR_CLEANUP_FUNC

G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAddress, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuth, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuthDomain, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookie, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookieJar, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupDate, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMessage, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequest, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequestHTTP, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupServer, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSession, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionAsync, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionFeature, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionSync, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSocket, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupURI, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupWebsocketConnection, g_object_unref)

#endif
#endif

#endif /* SOUP_AUTOCLEANUPS_H */
