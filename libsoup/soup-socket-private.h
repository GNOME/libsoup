/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011-2014 Red Hat, Inc.
 */

#ifndef SOUP_SOCKET_PRIVATE_H
#define SOUP_SOCKET_PRIVATE_H 1

#include "soup-socket.h"

#define SOUP_SOCKET_CLEAN_DISPOSE    "clean-dispose"
#define SOUP_SOCKET_PROXY_RESOLVER   "proxy-resolver"

gboolean   soup_socket_connect_sync_internal   (SoupSocket           *sock,
						GCancellable         *cancellable,
						GError              **error);
void       soup_socket_connect_async_internal  (SoupSocket           *sock,
						GCancellable         *cancellable,
						GAsyncReadyCallback   callback,
						gpointer              user_data);
gboolean   soup_socket_connect_finish_internal (SoupSocket           *sock,
						GAsyncResult         *result,
						GError              **error);

gboolean   soup_socket_handshake_sync          (SoupSocket           *sock,
						const char           *host,
						GCancellable         *cancellable,
						GError              **error);
void       soup_socket_handshake_async         (SoupSocket           *sock,
						const char           *host,
						GCancellable         *cancellable,
						GAsyncReadyCallback   callback,
						gpointer              user_data);
gboolean   soup_socket_handshake_finish        (SoupSocket           *sock,
						GAsyncResult         *result,
						GError              **error);

GSocket   *soup_socket_get_gsocket             (SoupSocket           *sock);
GIOStream *soup_socket_get_connection          (SoupSocket           *sock);
GIOStream *soup_socket_get_iostream            (SoupSocket           *sock);

SoupURI   *soup_socket_get_http_proxy_uri      (SoupSocket           *sock);

#endif /* SOUP_SOCKET_PRIVATE_H */
