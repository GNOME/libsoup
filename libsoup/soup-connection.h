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
	void (*connect_result) (SoupConnection *, guint);
	void (*disconnected)   (SoupConnection *);

	void (*authenticate)   (SoupConnection *, SoupMessage *,
				const char *auth_type, const char *auth_realm,
				char **username, char **password);
	void (*reauthenticate) (SoupConnection *, SoupMessage *,
				const char *auth_type, const char *auth_realm,
				char **username, char **password);

	/* methods */
	void (*send_request) (SoupConnection *, SoupMessage *);
} SoupConnectionClass;

GType soup_connection_get_type (void);


#define SOUP_CONNECTION_ORIGIN_URI      "origin-uri"
#define SOUP_CONNECTION_PROXY_URI       "proxy-uri"
#define SOUP_CONNECTION_SSL_CREDENTIALS "ssl-creds"

SoupConnection *soup_connection_new            (const char       *propname1,
						...);

typedef void  (*SoupConnectionCallback)        (SoupConnection   *sock,
						guint             status,
						gpointer          data);

void            soup_connection_connect_async  (SoupConnection   *conn,
						SoupConnectionCallback callback,
						gpointer          user_data);
guint           soup_connection_connect_sync   (SoupConnection   *conn);

void            soup_connection_disconnect     (SoupConnection   *conn);

gboolean        soup_connection_is_in_use      (SoupConnection   *conn);
time_t          soup_connection_last_used      (SoupConnection   *conn);

void            soup_connection_send_request   (SoupConnection   *conn,
						SoupMessage      *req);

/* protected */
void            soup_connection_authenticate   (SoupConnection   *conn,
						SoupMessage      *msg,
						const char       *auth_type,
						const char       *auth_realm,
						char            **username,
						char            **password);
void            soup_connection_reauthenticate (SoupConnection   *conn,
						SoupMessage      *msg,
						const char       *auth_type,
						const char       *auth_realm,
						char            **username,
						char            **password);


#endif /* SOUP_CONNECTION_H */
