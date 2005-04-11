/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SOCKET_H
#define SOUP_SOCKET_H 1

#include <libsoup/soup-types.h>

#define SOUP_TYPE_SOCKET            (soup_socket_get_type ())
#define SOUP_SOCKET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOCKET, SoupSocket))
#define SOUP_SOCKET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOCKET, SoupSocketClass))
#define SOUP_IS_SOCKET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOCKET))
#define SOUP_IS_SOCKET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SOCKET))
#define SOUP_SOCKET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOCKET, SoupSocketClass))

typedef struct SoupSocketPrivate SoupSocketPrivate;

struct SoupSocket {
	GObject parent;

	SoupSocketPrivate *priv;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void (*connect_result) (SoupSocket *, guint);
	void (*readable)       (SoupSocket *);
	void (*writable)       (SoupSocket *);
	void (*disconnected)   (SoupSocket *);

	void (*new_connection) (SoupSocket *, SoupSocket *);
} SoupSocketClass;

#define SOUP_SOCKET_FLAG_NONBLOCKING "non-blocking"
#define SOUP_SOCKET_FLAG_NODELAY     "nodelay"
#define SOUP_SOCKET_FLAG_REUSEADDR   "reuseaddr"
#define SOUP_SOCKET_IS_SERVER        "is-server"
#define SOUP_SOCKET_SSL_CREDENTIALS  "ssl-creds"

GType soup_socket_get_type (void);

SoupSocket    *soup_socket_new                (const char         *optname1,
					       ...);

guint          soup_socket_connect            (SoupSocket         *sock,
					       SoupAddress        *remote_addr);
gboolean       soup_socket_listen             (SoupSocket         *sock,
					       SoupAddress        *local_addr);
gboolean       soup_socket_start_ssl          (SoupSocket         *sock);
gboolean       soup_socket_start_proxy_ssl    (SoupSocket         *sock,
					       const char         *ssl_host);

void           soup_socket_disconnect         (SoupSocket         *sock);
gboolean       soup_socket_is_connected       (SoupSocket         *sock);

typedef void (*SoupSocketCallback)            (SoupSocket         *sock,
					       guint               status,
					       gpointer            user_data);
typedef void (*SoupSocketListenerCallback)    (SoupSocket         *listener,
					       SoupSocket         *sock,
					       gpointer            user_data);

SoupSocket    *soup_socket_client_new_async   (const char         *hostname,
					       guint               port,
					       gpointer            ssl_creds,
					       SoupSocketCallback  callback,
					       gpointer            user_data);
SoupSocket    *soup_socket_client_new_sync    (const char         *hostname,
					       guint               port,
					       gpointer            ssl_creds,
					       guint              *status_ret);
SoupSocket    *soup_socket_server_new         (SoupAddress        *local_addr,
					       gpointer            ssl_creds,
					       SoupSocketListenerCallback callback,
					       gpointer            user_data);

SoupAddress   *soup_socket_get_local_address  (SoupSocket         *sock);
SoupAddress   *soup_socket_get_remote_address (SoupSocket         *sock);


typedef enum {
	SOUP_SOCKET_OK,
	SOUP_SOCKET_WOULD_BLOCK,
	SOUP_SOCKET_EOF,
	SOUP_SOCKET_ERROR
} SoupSocketIOStatus;

SoupSocketIOStatus  soup_socket_read       (SoupSocket         *sock,
					    gpointer            buffer,
					    gsize               len,
					    gsize              *nread);
SoupSocketIOStatus  soup_socket_read_until (SoupSocket         *sock,
					    gpointer            buffer,
					    gsize               len,
					    gconstpointer       boundary,
					    gsize               boundary_len,
					    gsize              *nread,
					    gboolean           *got_boundary);

SoupSocketIOStatus  soup_socket_write      (SoupSocket         *sock,
					    gconstpointer       buffer,
					    gsize               len,
					    gsize              *nwrote);


#endif /* SOUP_SOCKET_H */
