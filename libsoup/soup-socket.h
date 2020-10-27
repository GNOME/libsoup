/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SOCKET            (soup_socket_get_type ())
G_DECLARE_FINAL_TYPE (SoupSocket, soup_socket, SOUP, SOCKET, GObject)

typedef void (*SoupSocketCallback)            (SoupSocket         *sock,
					       guint               status,
					       gpointer            user_data);

SoupSocket    *soup_socket_new                (const char         *optname1,
					       ...) G_GNUC_NULL_TERMINATED;

void           soup_socket_connect_async      (SoupSocket         *sock,
					       GCancellable       *cancellable,
					       SoupSocketCallback  callback,
					       gpointer            user_data);
guint          soup_socket_connect_sync       (SoupSocket         *sock,
					       GCancellable       *cancellable);
gboolean       soup_socket_listen             (SoupSocket         *sock);

gboolean       soup_socket_start_ssl          (SoupSocket         *sock,
					       GCancellable       *cancellable);
gboolean       soup_socket_start_proxy_ssl    (SoupSocket         *sock,
					       GCancellable       *cancellable);
gboolean       soup_socket_is_ssl             (SoupSocket         *sock);

void           soup_socket_disconnect         (SoupSocket         *sock);
gboolean       soup_socket_is_connected       (SoupSocket         *sock);

GInetSocketAddress   *soup_socket_get_local_address  (SoupSocket         *sock);
GInetSocketAddress   *soup_socket_get_remote_address (SoupSocket         *sock);

typedef enum {
	SOUP_SOCKET_OK,
	SOUP_SOCKET_WOULD_BLOCK,
	SOUP_SOCKET_EOF,
	SOUP_SOCKET_ERROR
} SoupSocketIOStatus;

SoupSocketIOStatus  soup_socket_read       (SoupSocket         *sock,
					    gpointer            buffer,
					    gsize               len,
					    gsize              *nread,
					    GCancellable       *cancellable,
					    GError            **error);
SoupSocketIOStatus  soup_socket_read_until (SoupSocket         *sock,
					    gpointer            buffer,
					    gsize               len,
					    gconstpointer       boundary,
					    gsize               boundary_len,
					    gsize              *nread,
					    gboolean           *got_boundary,
					    GCancellable       *cancellable,
					    GError            **error);

SoupSocketIOStatus  soup_socket_write      (SoupSocket         *sock,
					    gconstpointer       buffer,
					    gsize               len,
					    gsize              *nwrote,
					    GCancellable       *cancellable,
					    GError            **error);

G_END_DECLS
