/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SOCKET            (soup_socket_get_type ())
G_DECLARE_FINAL_TYPE (SoupSocket, soup_socket, SOUP, SOCKET, GObject)

SoupSocket    *soup_socket_new                (const char         *optname1,
					       ...) G_GNUC_NULL_TERMINATED;

gboolean       soup_socket_listen             (SoupSocket         *sock,
					       GError            **error);

gboolean       soup_socket_is_ssl             (SoupSocket         *sock);

void           soup_socket_disconnect         (SoupSocket         *sock);
gboolean       soup_socket_is_connected       (SoupSocket         *sock);
GIOStream     *soup_socket_get_connection     (SoupSocket         *sock);
GSocket       *soup_socket_get_gsocket        (SoupSocket         *sock);
GSocket       *soup_socket_steal_gsocket      (SoupSocket         *sock);
GIOStream     *soup_socket_get_iostream       (SoupSocket         *sock);

GInetSocketAddress   *soup_socket_get_local_address  (SoupSocket         *sock);
GInetSocketAddress   *soup_socket_get_remote_address (SoupSocket         *sock);

GTlsCertificate      *soup_socket_get_tls_certificate        (SoupSocket *sock);
GTlsCertificateFlags  soup_socket_get_tls_certificate_errors (SoupSocket *sock);

G_END_DECLS
