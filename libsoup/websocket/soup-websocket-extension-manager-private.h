/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-websocket-extension-manager-private.h
 *
 * Copyright (C) 2019 Igalia S.L.
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

#ifndef __SOUP_WEBSOCKET_EXTENSION_MANAGER_PRIVATE_H__
#define __SOUP_WEBSOCKET_EXTENSION_MANAGER_PRIVATE_H__ 1

#include "soup-websocket-extension-manager.h"

GPtrArray *soup_websocket_extension_manager_get_supported_extensions (SoupWebsocketExtensionManager *manager);

#endif /* __SOUP_WEBSOCKET_EXTENSION_MANAGER_PRIVATE_H__ */
