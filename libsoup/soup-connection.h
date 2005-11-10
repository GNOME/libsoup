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

struct SoupConnection {
	GObject parent;

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


/**
 * SoupConnectionCallback:
 * @conn: the #SoupConnection
 * @status: an HTTP status code indicating success or failure
 * @data: the data passed to soup_connection_connect_async()
 *
 * The callback function passed to soup_connection_connect_async().
 **/
typedef void  (*SoupConnectionCallback)        (SoupConnection   *conn,
						guint             status,
						gpointer          data);


#define SOUP_CONNECTION_ORIGIN_URI      "origin-uri"
#define SOUP_CONNECTION_PROXY_URI       "proxy-uri"
#define SOUP_CONNECTION_SSL_CREDENTIALS "ssl-creds"
#define SOUP_CONNECTION_MESSAGE_FILTER  "message-filter"
#define SOUP_CONNECTION_ASYNC_CONTEXT   "async-context"

SoupConnection *soup_connection_new            (const char       *propname1,
						...) G_GNUC_NULL_TERMINATED;

void            soup_connection_connect_async  (SoupConnection   *conn,
						SoupConnectionCallback callback,
						gpointer          user_data);
guint           soup_connection_connect_sync   (SoupConnection   *conn);

void            soup_connection_disconnect     (SoupConnection   *conn);

gboolean        soup_connection_is_in_use      (SoupConnection   *conn);
time_t          soup_connection_last_used      (SoupConnection   *conn);

void            soup_connection_send_request   (SoupConnection   *conn,
						SoupMessage      *req);

void            soup_connection_reserve        (SoupConnection   *conn);
void            soup_connection_release        (SoupConnection   *conn);

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
