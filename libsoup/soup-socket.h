/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: ronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      David Helder  (dhelder@umich.edu)
 *      Alex Graveley (alex@helixcode.com)
 * 
 * Original code compliments of David Helder's GNET Networking Library.
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_SOCKET_H
#define SOUP_SOCKET_H 1

#include <glib.h>
#include <libsoup/soup-address.h>

typedef struct _SoupSocket SoupSocket;

typedef gpointer SoupSocketConnectId;

typedef enum {
	SOUP_SOCKET_CONNECT_ERROR_NONE,
	SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE,
	SOUP_SOCKET_CONNECT_ERROR_NETWORK
} SoupSocketConnectStatus;

typedef void (*SoupSocketConnectFn) (SoupSocket              *socket, 
				     SoupSocketConnectStatus  status, 
				     gpointer                 data);

SoupSocketConnectId  soup_socket_connect        (const gchar*        hostname,
						 const gint          port, 
						 SoupSocketConnectFn func, 
						 gpointer            data);

void                 soup_socket_connect_cancel (SoupSocketConnectId id);

SoupSocket          *soup_socket_connect_sync   (const gchar        *hostname, 
						 const gint          port);


typedef gpointer SoupSocketNewId;

typedef enum {
	SOUP_SOCKET_NEW_STATUS_OK,
	SOUP_SOCKET_NEW_STATUS_ERROR
} SoupSocketNewStatus;

typedef void (*SoupSocketNewFn) (SoupSocket*         socket, 
				 SoupSocketNewStatus status, 
				 gpointer            data);

SoupSocketNewId     soup_socket_new             (SoupAddress        *addr, 
						 SoupSocketNewFn     func,
						 gpointer            data);

void                soup_socket_new_cancel      (SoupSocketNewId     id);

SoupSocket         *soup_socket_new_sync        (SoupAddress        *addr);


void                soup_socket_ref             (SoupSocket*         s);

void                soup_socket_unref           (SoupSocket*         s);

GIOChannel         *soup_socket_get_iochannel   (SoupSocket*         socket);

SoupAddress        *soup_socket_get_address     (const SoupSocket*   socket);

gint                soup_socket_get_port        (const SoupSocket*   socket);


#define SOUP_SERVER_ANY_PORT 0

SoupSocket         *soup_socket_server_new        (const gint          port);

SoupSocket         *soup_socket_server_accept     (SoupSocket         *socket);

SoupSocket         *soup_socket_server_try_accept (SoupSocket         *socket);

#endif /* SOUP_SOCKET_H */
