/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SOCKET_H
#define SOUP_SOCKET_H 1

#include <glib-object.h>
#include <libsoup/soup-address.h>
#include <libsoup/soup-error.h>

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

	/* signals */
	void (*connect_result) (SoupSocket *, SoupKnownErrorCode);

	void (*new_connection) (SoupSocket *, SoupSocket *);
} SoupSocketClass;

GType soup_socket_get_type (void);

SoupSocket    *soup_socket_new                (void);

void           soup_socket_connect            (SoupSocket         *sock,
					       SoupAddress        *rem_addr);
gboolean       soup_socket_listen             (SoupSocket         *sock,
					       SoupAddress        *local_addr);
void           soup_socket_start_ssl          (SoupSocket         *sock);


typedef void (*SoupSocketCallback)            (SoupSocket         *sock,
					       SoupKnownErrorCode  status,
					       gpointer            user_data);
typedef void (*SoupSocketListenerCallback)    (SoupSocket         *listener,
					       SoupSocket         *sock,
					       gpointer            user_data);

SoupSocket    *soup_socket_client_new         (const char         *hostname,
					       guint               port,
					       gboolean            ssl,
					       SoupSocketCallback  callback,
					       gpointer            user_data);
SoupSocket    *soup_socket_server_new         (SoupAddress        *local_addr,
					       gboolean            ssl,
					       SoupSocketListenerCallback,
					       gpointer            user_data);


GIOChannel    *soup_socket_get_iochannel      (SoupSocket         *sock);

SoupAddress   *soup_socket_get_local_address  (SoupSocket         *sock);
SoupAddress   *soup_socket_get_remote_address (SoupSocket         *sock);

#endif /* SOUP_SOCKET_H */
