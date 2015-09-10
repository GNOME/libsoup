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

#include <libsoup/soup-auth-domain-basic.h>
#include <libsoup/soup-auth-domain-digest.h>
#include <libsoup/soup-auth-manager.h>
#include <libsoup/soup-cache.h>
#include <libsoup/soup-content-decoder.h>
#include <libsoup/soup-content-sniffer.h>
#include <libsoup/soup-cookie.h>
#include <libsoup/soup-cookie-jar-db.h>
#include <libsoup/soup-cookie-jar-text.h>
#include <libsoup/soup-date.h>
#include <libsoup/soup-logger.h>
#include <libsoup/soup-multipart.h>
#include <libsoup/soup-multipart-input-stream.h>
#include <libsoup/soup-request-data.h>
#include <libsoup/soup-request-file.h>
#include <libsoup/soup-types.h>
#include <libsoup/soup-uri.h>
#include <libsoup/soup-xmlrpc.h>

#if SOUP_VERSION_MAX_ALLOWED >= SOUP_VERSION_2_52
#ifndef __GI_SCANNER__
#ifdef G_DEFINE_AUTOPTR_CLEANUP_FUNC

G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAddress, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuth, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuthDomain, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuthDomainBasic, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuthDomainDigest, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupAuthManager, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupBuffer, soup_buffer_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCache, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupContentDecoder, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupContentSniffer, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookie, soup_cookie_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookieJar, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookieJarDB, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupCookieJarText, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupDate, soup_date_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupLogger, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMessage, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMessageBody, soup_message_body_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMessageHeaders, soup_message_headers_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMultipart, soup_multipart_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupMultipartInputStream, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequest, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequestData, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequestFile, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupRequestHTTP, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupServer, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSession, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionAsync, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionFeature, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSessionSync, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupSocket, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupURI, soup_uri_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupWebsocketConnection, g_object_unref)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(SoupXMLRPCParams, soup_xmlrpc_params_free)

#endif
#endif
#endif

#endif /* SOUP_AUTOCLEANUPS_H */
