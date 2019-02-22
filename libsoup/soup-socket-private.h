/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011-2014 Red Hat, Inc.
 */

#ifndef __SOUP_SOCKET_PRIVATE_H__
#define __SOUP_SOCKET_PRIVATE_H__ 1

#include "soup-socket.h"

#define SOUP_SOCKET_SOCKET_PROPERTIES "socket-properties"
#define SOUP_SOCKET_FD                "fd"
#define SOUP_SOCKET_GSOCKET           "gsocket"
#define SOUP_SOCKET_IOSTREAM          "iostream"
#define SOUP_SOCKET_IPV6_ONLY         "ipv6-only"

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
GSocket   *soup_socket_steal_gsocket           (SoupSocket           *sock);
GIOStream *soup_socket_get_connection          (SoupSocket           *sock);
GIOStream *soup_socket_get_iostream            (SoupSocket           *sock);

SoupURI   *soup_socket_get_http_proxy_uri      (SoupSocket           *sock);

gboolean   soup_socket_listen_full             (SoupSocket           *sock,
                                                GError              **error);



typedef struct {
	GMainContext *async_context;
	gboolean use_thread_context;

	GProxyResolver *proxy_resolver;
	SoupAddress *local_addr;

	GTlsDatabase *tlsdb;
	GTlsInteraction *tls_interaction;
	gboolean ssl_strict;

	guint io_timeout;
	guint idle_timeout;

	/*< private >*/
	guint ref_count;
} SoupSocketProperties;

GType soup_socket_properties_get_type (void);
#define SOUP_TYPE_SOCKET_PROPERTIES (soup_socket_properties_get_type ())

SoupSocketProperties *soup_socket_properties_new   (GMainContext    *async_context,
						    gboolean         use_thread_context,
						    GProxyResolver  *proxy_resolver,
						    SoupAddress     *local_addr,
						    GTlsDatabase    *tlsdb,
						    GTlsInteraction *tls_interaction,
						    gboolean         ssl_strict,
						    guint            io_timeout,
						    guint            idle_timeout);

SoupSocketProperties *soup_socket_properties_ref   (SoupSocketProperties *props);
void                  soup_socket_properties_unref (SoupSocketProperties *props);

void soup_socket_properties_push_async_context (SoupSocketProperties *props);
void soup_socket_properties_pop_async_context  (SoupSocketProperties *props);

#endif /* __SOUP_SOCKET_PRIVATE_H__ */
