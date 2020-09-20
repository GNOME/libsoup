/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-uri.h"
#include "soup-websocket-connection.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER (soup_server_get_type ())
SOUP_AVAILABLE_IN_2_4
G_DECLARE_DERIVABLE_TYPE (SoupServer, soup_server, SOUP, SERVER, GObject)

typedef struct _SoupClientContext SoupClientContext;
SOUP_AVAILABLE_IN_2_4
GType soup_client_context_get_type (void);
#define SOUP_TYPE_CLIENT_CONTEXT (soup_client_context_get_type ())

typedef enum {
	SOUP_SERVER_LISTEN_HTTPS     = (1 << 0),
	SOUP_SERVER_LISTEN_IPV4_ONLY = (1 << 1),
	SOUP_SERVER_LISTEN_IPV6_ONLY = (1 << 2)
} SoupServerListenOptions;

struct _SoupServerClass {
	GObjectClass parent_class;

	/* signals */
	void (*request_started)  (SoupServer *server, SoupMessage *msg,
				  SoupClientContext *client);
	void (*request_read)     (SoupServer *server, SoupMessage *msg,
				  SoupClientContext *client);
	void (*request_finished) (SoupServer *server, SoupMessage *msg,
				  SoupClientContext *client);
	void (*request_aborted)  (SoupServer *server, SoupMessage *msg,
				  SoupClientContext *client);

	gpointer padding[6];
};

#define SOUP_SERVER_TLS_CERTIFICATE "tls-certificate"
#define SOUP_SERVER_RAW_PATHS       "raw-paths"
#define SOUP_SERVER_SERVER_HEADER   "server-header"
#define SOUP_SERVER_HTTP_ALIASES    "http-aliases"
#define SOUP_SERVER_HTTPS_ALIASES   "https-aliases"

SOUP_AVAILABLE_IN_2_4
SoupServer     *soup_server_new                (const char               *optname1,
					        ...) G_GNUC_NULL_TERMINATED;

SOUP_AVAILABLE_IN_2_48
gboolean        soup_server_set_ssl_cert_file  (SoupServer               *server,
					        const char               *ssl_cert_file,
					        const char               *ssl_key_file,
					        GError                  **error);
SOUP_AVAILABLE_IN_2_4
gboolean        soup_server_is_https           (SoupServer               *server);

SOUP_AVAILABLE_IN_2_48
gboolean        soup_server_listen             (SoupServer               *server,
					        GSocketAddress           *address,
					        SoupServerListenOptions   options,
					        GError                  **error);
SOUP_AVAILABLE_IN_2_48
gboolean        soup_server_listen_all         (SoupServer               *server,
					        guint                     port,
					        SoupServerListenOptions   options,
					        GError                  **error);
SOUP_AVAILABLE_IN_2_48
gboolean        soup_server_listen_local       (SoupServer               *server,
					        guint                     port,
					        SoupServerListenOptions   options,
					        GError                  **error);
SOUP_AVAILABLE_IN_2_48
gboolean        soup_server_listen_socket      (SoupServer               *server,
					        GSocket                  *socket,
					        SoupServerListenOptions   options,
					        GError                  **error);
SOUP_AVAILABLE_IN_2_48
GSList         *soup_server_get_uris           (SoupServer               *server);
SOUP_AVAILABLE_IN_2_48
GSList         *soup_server_get_listeners      (SoupServer               *server);

SOUP_AVAILABLE_IN_2_4
void            soup_server_disconnect         (SoupServer               *server);

SOUP_AVAILABLE_IN_2_50
gboolean        soup_server_accept_iostream    (SoupServer               *server,
						GIOStream                *stream,
						GSocketAddress           *local_addr,
						GSocketAddress           *remote_addr,
						GError                  **error);

/* Handlers and auth */

typedef void  (*SoupServerCallback)            (SoupServer         *server,
						SoupMessage        *msg,
						const char         *path,
						GHashTable         *query,
						SoupClientContext  *client,
						gpointer            user_data);

SOUP_AVAILABLE_IN_2_4
void            soup_server_add_handler        (SoupServer         *server,
					        const char         *path,
					        SoupServerCallback  callback,
					        gpointer            user_data,
					        GDestroyNotify      destroy);
SOUP_AVAILABLE_IN_2_50
void            soup_server_add_early_handler  (SoupServer         *server,
						const char         *path,
						SoupServerCallback  callback,
						gpointer            user_data,
						GDestroyNotify      destroy);

#define SOUP_SERVER_ADD_WEBSOCKET_EXTENSION    "add-websocket-extension"
#define SOUP_SERVER_REMOVE_WEBSOCKET_EXTENSION "remove-websocket-extension"

typedef void (*SoupServerWebsocketCallback) (SoupServer              *server,
					     SoupWebsocketConnection *connection,
					     const char              *path,
					     SoupClientContext       *client,
					     gpointer                 user_data);
SOUP_AVAILABLE_IN_2_50
void            soup_server_add_websocket_handler (SoupServer                   *server,
						   const char                   *path,
						   const char                   *origin,
						   char                        **protocols,
						   SoupServerWebsocketCallback   callback,
						   gpointer                      user_data,
						   GDestroyNotify                destroy);
SOUP_AVAILABLE_IN_2_68
void            soup_server_add_websocket_extension    (SoupServer *server,
							GType       extension_type);
SOUP_AVAILABLE_IN_2_68
void            soup_server_remove_websocket_extension (SoupServer *server,
							GType       extension_type);

SOUP_AVAILABLE_IN_2_4
void            soup_server_remove_handler     (SoupServer         *server,
					        const char         *path);

SOUP_AVAILABLE_IN_2_4
void            soup_server_add_auth_domain    (SoupServer         *server,
					        SoupAuthDomain     *auth_domain);
SOUP_AVAILABLE_IN_2_4
void            soup_server_remove_auth_domain (SoupServer         *server,
					        SoupAuthDomain     *auth_domain);

/* I/O */
SOUP_AVAILABLE_IN_2_4
void            soup_server_pause_message   (SoupServer  *server,
					     SoupMessage *msg);
SOUP_AVAILABLE_IN_2_4
void            soup_server_unpause_message (SoupServer  *server,
					     SoupMessage *msg);

/* Client context */

SOUP_AVAILABLE_IN_2_48
GSocket        *soup_client_context_get_socket        (SoupClientContext *client);
SOUP_AVAILABLE_IN_2_48
GSocketAddress *soup_client_context_get_local_address  (SoupClientContext *client);
SOUP_AVAILABLE_IN_2_48
GSocketAddress *soup_client_context_get_remote_address (SoupClientContext *client);
SOUP_AVAILABLE_IN_2_4
const char     *soup_client_context_get_host           (SoupClientContext *client);
SOUP_AVAILABLE_IN_2_4
SoupAuthDomain *soup_client_context_get_auth_domain    (SoupClientContext *client);
SOUP_AVAILABLE_IN_2_4
const char     *soup_client_context_get_auth_user      (SoupClientContext *client);

SOUP_AVAILABLE_IN_2_50
GIOStream      *soup_client_context_steal_connection   (SoupClientContext *client);

G_END_DECLS
