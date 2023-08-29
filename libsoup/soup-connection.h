/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_CONNECTION_H__
#define __SOUP_CONNECTION_H__ 1

#include "soup-types-private.h"
#include "soup-message-private.h"
#include "soup-misc.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONNECTION (soup_connection_get_type ())
G_DECLARE_FINAL_TYPE (SoupConnection, soup_connection, SOUP, CONNECTION, GObject)

typedef enum {
	SOUP_CONNECTION_NEW,
	SOUP_CONNECTION_CONNECTING,
	SOUP_CONNECTION_IDLE,
	SOUP_CONNECTION_IN_USE,
	SOUP_CONNECTION_DISCONNECTED
} SoupConnectionState;

void            soup_connection_connect_async    (SoupConnection       *conn,
						  int                   io_priority,
						  GCancellable         *cancellable,
						  GAsyncReadyCallback   callback,
						  gpointer              user_data);
gboolean        soup_connection_connect_finish   (SoupConnection       *conn,
						  GAsyncResult         *result,
						  GError              **error);
gboolean        soup_connection_connect          (SoupConnection       *conn,
						  GCancellable         *cancellable,
						  GError              **error);
void            soup_connection_tunnel_handshake_async  (SoupConnection     *conn,
							 int                 io_priority,
							 GCancellable       *cancellable,
							 GAsyncReadyCallback callback,
							 gpointer            user_data);
gboolean        soup_connection_tunnel_handshake_finish (SoupConnection *conn,
							 GAsyncResult   *result,
							 GError        **error);
gboolean        soup_connection_tunnel_handshake        (SoupConnection *conn,
							 GCancellable   *cancellable,
							 GError        **error);
void            soup_connection_disconnect     (SoupConnection   *conn);

GSocket        *soup_connection_get_socket     (SoupConnection   *conn);
GIOStream      *soup_connection_get_iostream   (SoupConnection   *conn);
GIOStream      *soup_connection_steal_iostream (SoupConnection   *conn);
GUri           *soup_connection_get_remote_uri (SoupConnection   *conn);
GUri           *soup_connection_get_proxy_uri  (SoupConnection   *conn);
gboolean        soup_connection_is_via_proxy   (SoupConnection   *conn);
gboolean        soup_connection_is_tunnelled   (SoupConnection   *conn);

SoupConnectionState soup_connection_get_state  (SoupConnection   *conn);
void            soup_connection_set_in_use     (SoupConnection   *conn,
                                                gboolean          in_use);
gboolean        soup_connection_is_idle_open   (SoupConnection   *conn);

SoupClientMessageIO *soup_connection_setup_message_io    (SoupConnection *conn,
                                                          SoupMessage    *msg);

GTlsCertificate     *soup_connection_get_tls_certificate                       (SoupConnection  *conn);
GTlsCertificateFlags soup_connection_get_tls_certificate_errors                (SoupConnection  *conn);
GTlsProtocolVersion  soup_connection_get_tls_protocol_version                  (SoupConnection  *conn);
char                *soup_connection_get_tls_ciphersuite_name                  (SoupConnection  *conn);
void                 soup_connection_request_tls_certificate                   (SoupConnection  *conn,
                                                                                GTlsConnection  *connection,
                                                                                GTask           *task);
void                 soup_connection_complete_tls_certificate_request          (SoupConnection  *conn,
                                                                                GTlsCertificate *certificate,
                                                                                GTask           *task);
void                 soup_connection_set_tls_client_certificate                (SoupConnection  *conn,
                                                                                GTlsCertificate *certificate);
void                 soup_connection_request_tls_certificate_password          (SoupConnection  *conn,
                                                                                GTlsPassword    *password,
                                                                                GTask           *task);
void                 soup_connection_complete_tls_certificate_password_request (SoupConnection  *conn,
                                                                                GTask           *task);

guint64              soup_connection_get_id                     (SoupConnection *conn);
GSocketAddress      *soup_connection_get_remote_address         (SoupConnection *conn);
SoupHTTPVersion      soup_connection_get_negotiated_protocol    (SoupConnection *conn);
gboolean             soup_connection_is_reusable                (SoupConnection *conn);
GThread             *soup_connection_get_owner                  (SoupConnection *conn);

void soup_connection_set_http2_initial_window_size        (SoupConnection *conn,
                                                           int             window_size);
int  soup_connection_get_http2_initial_window_size        (SoupConnection *conn);
void soup_connection_set_http2_initial_stream_window_size (SoupConnection *conn,
                                                           int             window_size);
int  soup_connection_get_http2_initial_stream_window_size (SoupConnection *conn);

G_END_DECLS

#endif /* __SOUP_CONNECTION_H__ */
