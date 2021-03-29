/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_CONNECTION_H__
#define __SOUP_CONNECTION_H__ 1

#include "soup-types.h"
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
	SOUP_CONNECTION_REMOTE_DISCONNECTED,
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
gboolean        soup_connection_get_tls_info   (SoupConnection   *conn,
						GTlsCertificate **certificate,
						GTlsCertificateFlags *errors);

SoupConnectionState soup_connection_get_state  (SoupConnection   *conn);
void                soup_connection_set_state  (SoupConnection   *conn,
						SoupConnectionState state);

void            soup_connection_set_reusable   (SoupConnection   *conn,
                                                gboolean          reusable);

gboolean        soup_connection_get_ever_used  (SoupConnection   *conn);

void            soup_connection_send_request   (SoupConnection           *conn,
						SoupMessageQueueItem     *item,
						SoupMessageIOCompletionFn completion_cb,
						gpointer                  user_data);

GTlsCertificate     *soup_connection_get_tls_certificate        (SoupConnection *conn);
GTlsCertificateFlags soup_connection_get_tls_certificate_errors (SoupConnection *conn);

guint64              soup_connection_get_id                     (SoupConnection *conn);

G_END_DECLS

#endif /* __SOUP_CONNECTION_H__ */
