/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-server-message-io.h"
#include <gio/gio.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER_CONNECTION (soup_server_connection_get_type ())
G_DECLARE_FINAL_TYPE (SoupServerConnection, soup_server_connection, SOUP, SERVER_CONNECTION, GObject)

SoupServerConnection *soup_server_connection_new                             (GSocket               *socket,
                                                                              GTlsCertificate       *tls_certificate,
                                                                              GTlsDatabase          *tls_database,
                                                                              GTlsAuthenticationMode tls_auth_mode);
SoupServerConnection *soup_server_connection_new_for_connection              (GIOStream             *connection,
                                                                              GSocketAddress        *local_addr,
                                                                              GSocketAddress        *remote_addr);
void                  soup_server_connection_set_advertise_http2             (SoupServerConnection *conn,
                                                                              gboolean              advertise_http2);
void                  soup_server_connection_accepted                        (SoupServerConnection  *conn);
SoupServerMessageIO  *soup_server_connection_get_io_data                     (SoupServerConnection  *conn);
gboolean              soup_server_connection_is_ssl                          (SoupServerConnection  *conn);
void                  soup_server_connection_disconnect                      (SoupServerConnection  *conn);
gboolean              soup_server_connection_is_connected                    (SoupServerConnection  *conn);
GSocket              *soup_server_connection_get_socket                      (SoupServerConnection  *conn);
GIOStream            *soup_server_connection_steal                           (SoupServerConnection  *conn);
GIOStream            *soup_server_connection_get_iostream                    (SoupServerConnection  *conn);
GSocketAddress       *soup_server_connection_get_local_address               (SoupServerConnection  *conn);
GSocketAddress       *soup_server_connection_get_remote_address              (SoupServerConnection  *conn);
GTlsCertificate      *soup_server_connection_get_tls_peer_certificate        (SoupServerConnection  *conn);
GTlsCertificateFlags  soup_server_connection_get_tls_peer_certificate_errors (SoupServerConnection  *conn);

G_END_DECLS
