/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SOCKET_H
#define SOUP_SOCKET_H 1

#include <glib-object.h>
#include <libsoup/soup-address.h>

#define SOUP_TYPE_SOCKET            (soup_socket_get_type ())
#define SOUP_SOCKET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOCKET, SoupSocket))
#define SOUP_SOCKET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOCKET, SoupSocketClass))
#define SOUP_IS_SOCKET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOCKET))
#define SOUP_IS_SOCKET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SOCKET))
#define SOUP_SOCKET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOCKET, SoupSocketClass))

typedef struct SoupSocketPrivate SoupSocketPrivate;

typedef struct {
	GObject parent;

	SoupSocketPrivate *priv;
} SoupSocket;

typedef struct {
	GObjectClass parent_class;

} SoupSocketClass;

GType soup_socket_get_type (void);


typedef gpointer SoupSocketConnectId;

typedef enum {
	SOUP_SOCKET_CONNECT_ERROR_NONE,
	SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE,
	SOUP_SOCKET_CONNECT_ERROR_NETWORK
} SoupSocketConnectStatus;

typedef void (*SoupSocketConnectFn) (SoupSocket              *socket, 
				     SoupSocketConnectStatus  status, 
				     gpointer                 data);

SoupSocketConnectId  soup_socket_connect        (const char         *hostname,
						 guint               port, 
						 SoupSocketConnectFn func, 
						 gpointer            data);

void                 soup_socket_connect_cancel (SoupSocketConnectId id);

SoupSocket          *soup_socket_connect_sync   (const char         *hostname, 
						 guint               port);


typedef gpointer SoupSocketNewId;

typedef enum {
	SOUP_SOCKET_NEW_STATUS_OK,
	SOUP_SOCKET_NEW_STATUS_ERROR
} SoupSocketNewStatus;

typedef void (*SoupSocketNewFn) (SoupSocket*         socket, 
				 SoupSocketNewStatus status, 
				 gpointer            data);

SoupSocketNewId     soup_socket_new             (SoupAddress        *addr, 
						 guint               port,
						 SoupSocketNewFn     func,
						 gpointer            data);

void                soup_socket_new_cancel      (SoupSocketNewId     id);

SoupSocket         *soup_socket_new_sync        (SoupAddress        *addr,
						 guint               port);


GIOChannel         *soup_socket_get_iochannel   (SoupSocket*         socket);

SoupAddress        *soup_socket_get_address     (const SoupSocket*   socket);

guint               soup_socket_get_port        (const SoupSocket*   socket);


#define SOUP_SERVER_ANY_PORT 0

SoupSocket         *soup_socket_server_new        (SoupAddress        *local_addr,
						   guint               local_port);

SoupSocket         *soup_socket_server_accept     (SoupSocket         *socket);

SoupSocket         *soup_socket_server_try_accept (SoupSocket         *socket);

#endif /* SOUP_SOCKET_H */
