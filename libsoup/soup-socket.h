/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: ronous Callback-based SOAP Request Queue.
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

typedef struct _SoupAddress SoupAddress;

typedef gpointer SoupAddressNewId;

typedef enum {
	SOUP_ADDRESS_STATUS_OK,
	SOUP_ADDRESS_STATUS_ERROR
} SoupAddressStatus;

typedef void (*SoupAddressNewFn) (SoupAddress       *inetaddr, 
				  SoupAddressStatus  status, 
				  gpointer           user_data);

SoupAddressNewId     soup_address_new                (const gchar*       name, 
						      const gint         port, 
						      SoupAddressNewFn   func, 
						      gpointer           data);

void                 soup_address_new_cancel         (SoupAddressNewId   id);

SoupAddress         *soup_address_new_sync           (const gchar *name, 
						      const gint port);

void                 soup_address_ref                (SoupAddress*       ia);

void                 soup_address_unref              (SoupAddress*       ia);


typedef gpointer SoupAddressGetNameId;

typedef void (*SoupAddressGetNameFn) (SoupAddress       *inetaddr, 
				      SoupAddressStatus  status, 
				      const gchar       *name,
				      gpointer           user_data);

SoupAddressGetNameId soup_address_get_name           (SoupAddress*         ia, 
						      SoupAddressGetNameFn func,
						      gpointer             data);

void                 soup_address_get_name_cancel    (SoupAddressGetNameId id);

gchar*               soup_address_get_canonical_name (SoupAddress*         ia);

gint                 soup_address_get_port           (const SoupAddress*   ia);

void                 soup_address_set_port           (const SoupAddress*   ia, 
						      guint                port);

guint                soup_address_hash               (const gpointer       p);

gint                 soup_address_equal              (const gpointer       p1, 
						      const gpointer       p2);

gint                 soup_address_noport_equal       (const gpointer       p1, 
						      const gpointer       p2);

gchar*               soup_address_gethostname        (void);

SoupAddress*         soup_address_gethostaddr        (void);


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

#endif /* SOUP_SOCKET_H */
