/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2011 Igalia, S.L.
 * Copyright 2011 Red Hat, Inc.
 */

#ifndef SOUP_MISC_PRIVATE_H
#define SOUP_MISC_PRIVATE_H 1

#include "soup-socket.h"
#include "soup-message-headers.h"

char *soup_uri_decoded_copy (const char *str, int length, int *decoded_length);
char *soup_uri_to_string_internal (SoupURI *uri, gboolean just_path_and_query,
				   gboolean force_port);
gboolean soup_uri_is_http (SoupURI *uri, char **aliases);
gboolean soup_uri_is_https (SoupURI *uri, char **aliases);

gboolean soup_socket_connect_sync_internal   (SoupSocket          *sock,
					      GCancellable        *cancellable,
					      GError             **error);
void     soup_socket_connect_async_internal  (SoupSocket          *sock,
					      GCancellable        *cancellable,
					      GAsyncReadyCallback  callback,
					      gpointer             user_data);
gboolean soup_socket_connect_finish_internal (SoupSocket          *sock,
					      GAsyncResult        *result,
					      GError             **error);

gboolean soup_socket_handshake_sync   (SoupSocket           *sock,
				       const char           *host,
				       GCancellable         *cancellable,
				       GError              **error);
void     soup_socket_handshake_async  (SoupSocket           *sock,
				       const char           *host,
				       GCancellable         *cancellable,
				       GAsyncReadyCallback   callback,
				       gpointer              user_data);
gboolean soup_socket_handshake_finish (SoupSocket           *sock,
				       GAsyncResult         *result,
				       GError              **error);

GSocket   *soup_socket_get_gsocket    (SoupSocket *sock);
GIOStream *soup_socket_get_connection (SoupSocket *sock);
GIOStream *soup_socket_get_iostream   (SoupSocket *sock);

#define SOUP_SOCKET_CLEAN_DISPOSE "clean-dispose"
#define SOUP_SOCKET_PROXY_RESOLVER "proxy-resolver"
SoupURI *soup_socket_get_http_proxy_uri (SoupSocket *sock);

/* At some point it might be possible to mark additional methods
 * safe or idempotent...
 */
#define SOUP_METHOD_IS_SAFE(method) (method == SOUP_METHOD_GET || \
				     method == SOUP_METHOD_HEAD || \
				     method == SOUP_METHOD_OPTIONS || \
				     method == SOUP_METHOD_PROPFIND)

#define SOUP_METHOD_IS_IDEMPOTENT(method) (method == SOUP_METHOD_GET || \
					   method == SOUP_METHOD_HEAD || \
					   method == SOUP_METHOD_OPTIONS || \
					   method == SOUP_METHOD_PROPFIND || \
					   method == SOUP_METHOD_PUT || \
					   method == SOUP_METHOD_DELETE)

GSource *soup_add_completion_reffed (GMainContext *async_context,
				     GSourceFunc   function,
				     gpointer      data);

guint soup_message_headers_get_ranges_internal (SoupMessageHeaders  *hdrs,
						goffset              total_length,
						gboolean             check_satisfiable,
						SoupRange          **ranges,
						int                 *length);

#endif /* SOUP_MISC_PRIVATE_H */
