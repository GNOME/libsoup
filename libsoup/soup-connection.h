/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_CONNECTION_H
#define SOUP_CONNECTION_H 1

#include <time.h>

#include <libsoup/soup-types.h>

#define SOUP_TYPE_CONNECTION            (soup_connection_get_type ())
#define SOUP_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_CONNECTION, SoupConnection))
#define SOUP_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_CONNECTION, SoupConnectionClass))
#define SOUP_IS_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_CONNECTION))
#define SOUP_IS_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_CONNECTION))
#define SOUP_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_CONNECTION, SoupConnectionClass))

typedef struct SoupConnectionPrivate SoupConnectionPrivate;

struct SoupConnection {
	GObject parent;

	SoupConnectionPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void (*connect_result) (SoupConnection *, SoupKnownErrorCode);
	void (*disconnected) (SoupConnection *);
} SoupConnectionClass;

GType soup_connection_get_type (void);


typedef void  (*SoupConnectionCallback)        (SoupConnection     *sock,
						SoupKnownErrorCode  status,
						gpointer            data);

SoupConnection *soup_connection_new            (const SoupUri      *uri,
						SoupConnectionCallback,
						gpointer            data);
SoupConnection *soup_connection_new_proxy      (const SoupUri      *proxy_uri,
						SoupConnectionCallback,
						gpointer            data);
SoupConnection *soup_connection_new_tunnel     (const SoupUri      *proxy_uri,
						const SoupUri      *dest_uri,
						SoupConnectionCallback,
						gpointer            data);

gboolean        soup_connection_is_proxy       (SoupConnection *conn);

void            soup_connection_disconnect     (SoupConnection *conn);
gboolean        soup_connection_is_connected   (SoupConnection *conn);

SoupSocket     *soup_connection_get_socket     (SoupConnection *conn);

gboolean        soup_connection_is_new         (SoupConnection *conn);
gboolean        soup_connection_is_in_use      (SoupConnection *conn);
time_t          soup_connection_last_used      (SoupConnection *conn);

void            soup_connection_send_request   (SoupConnection *conn,
						SoupMessage    *req);

#endif /* SOUP_CONNECTION_H */
