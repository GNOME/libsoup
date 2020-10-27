/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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
G_DECLARE_DERIVABLE_TYPE (SoupConnection, soup_connection, SOUP, CONNECTION, GObject)

struct _SoupConnectionClass {
	GObjectClass parent_class;

	/* signals */
	void (*disconnected)    (SoupConnection *);
};

typedef enum {
	SOUP_CONNECTION_NEW,
	SOUP_CONNECTION_CONNECTING,
	SOUP_CONNECTION_IDLE,
	SOUP_CONNECTION_IN_USE,
	SOUP_CONNECTION_REMOTE_DISCONNECTED,
	SOUP_CONNECTION_DISCONNECTED
} SoupConnectionState;

void            soup_connection_connect_async    (SoupConnection       *conn,
						  GCancellable         *cancellable,
						  GAsyncReadyCallback   callback,
						  gpointer              user_data);
gboolean        soup_connection_connect_finish   (SoupConnection       *conn,
						  GAsyncResult         *result,
						  GError              **error);
gboolean        soup_connection_connect_sync     (SoupConnection       *conn,
						  GCancellable         *cancellable,
						  GError              **error);
gboolean        soup_connection_start_ssl_sync   (SoupConnection       *conn,
						  GCancellable         *cancellable,
						  GError              **error);
void            soup_connection_start_ssl_async  (SoupConnection       *conn,
						  GCancellable         *cancellable,
						  GAsyncReadyCallback   callback,
						  gpointer              user_data);
gboolean        soup_connection_start_ssl_finish (SoupConnection       *conn,
						  GAsyncResult         *result,
						  GError              **error);

void            soup_connection_disconnect     (SoupConnection   *conn);

SoupSocket     *soup_connection_get_socket     (SoupConnection   *conn);
SoupURI        *soup_connection_get_remote_uri (SoupConnection   *conn);
SoupURI        *soup_connection_get_proxy_uri  (SoupConnection   *conn);
gboolean        soup_connection_is_via_proxy   (SoupConnection   *conn);
gboolean        soup_connection_is_tunnelled   (SoupConnection   *conn);

SoupConnectionState soup_connection_get_state  (SoupConnection   *conn);
void                soup_connection_set_state  (SoupConnection   *conn,
						SoupConnectionState state);

gboolean        soup_connection_get_ever_used  (SoupConnection   *conn);

void            soup_connection_send_request   (SoupConnection           *conn,
						SoupMessageQueueItem     *item,
						SoupMessageIOCompletionFn completion_cb,
						gpointer                  user_data);

G_END_DECLS

#endif /* __SOUP_CONNECTION_H__ */
