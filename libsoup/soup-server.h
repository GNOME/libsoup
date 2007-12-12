/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SERVER_H
#define SOUP_SERVER_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-method.h>
#include <libsoup/soup-uri.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER            (soup_server_get_type ())
#define SOUP_SERVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SERVER, SoupServer))
#define SOUP_SERVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SERVER, SoupServerClass))
#define SOUP_IS_SERVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SERVER))
#define SOUP_IS_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SERVER))
#define SOUP_SERVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SERVER, SoupServerClass))

struct SoupServer {
	GObject parent;

};

typedef struct {
	GObjectClass parent_class;

} SoupServerClass;

GType soup_server_get_type (void);


typedef struct SoupServerHandler SoupServerHandler;

typedef struct {
	SoupMessage       *msg;
	char              *path;
	SoupServerAuth    *auth;
	SoupServer        *server;
	SoupServerHandler *handler;
	SoupSocket        *sock;
} SoupServerContext;

typedef void (*SoupServerCallbackFn) (SoupServerContext    *context,
				      SoupMessage          *msg, 
				      gpointer              user_data);

typedef void (*SoupServerUnregisterFn) (SoupServer        *server,
					SoupServerHandler *handler,
					gpointer           user_data);

struct SoupServerHandler {
	char                   *path;

	SoupServerAuthContext  *auth_ctx;

	SoupServerCallbackFn    callback;
	SoupServerUnregisterFn  unregister;
	gpointer                user_data;
};

#define SOUP_SERVER_PORT          "port"
#define SOUP_SERVER_INTERFACE     "interface"
#define SOUP_SERVER_SSL_CERT_FILE "ssl-cert-file"
#define SOUP_SERVER_SSL_KEY_FILE  "ssl-key-file"
#define SOUP_SERVER_ASYNC_CONTEXT "async-context"

SoupServer        *soup_server_new            (const char            *optname1,
					       ...) G_GNUC_NULL_TERMINATED;

SoupProtocol       soup_server_get_protocol   (SoupServer            *serv);
guint              soup_server_get_port       (SoupServer            *serv);

SoupSocket        *soup_server_get_listener   (SoupServer            *serv);

void               soup_server_run            (SoupServer            *serv);
void               soup_server_run_async      (SoupServer            *serv);
void               soup_server_quit           (SoupServer            *serv);

GMainContext      *soup_server_get_async_context (SoupServer         *serv);

/* Handlers */

void               soup_server_add_handler    (SoupServer            *serv,
					       const char            *path,
					       SoupServerAuthContext *auth_ctx,
					       SoupServerCallbackFn   callback,
					       SoupServerUnregisterFn unreg,
					       gpointer               data);
void               soup_server_remove_handler (SoupServer            *serv,
					       const char            *path);
SoupServerHandler *soup_server_get_handler    (SoupServer            *serv,
					       const char            *path);
GSList            *soup_server_list_handlers  (SoupServer            *serv);

void               soup_server_pause_message   (SoupServer           *server,
						SoupMessage          *msg);
void               soup_server_unpause_message (SoupServer           *server,
						SoupMessage          *msg);

/* Functions for accessing information about the specific connection */

SoupAddress *soup_server_context_get_client_address (SoupServerContext *ctx);
const char  *soup_server_context_get_client_host    (SoupServerContext *ctx);

G_END_DECLS

#endif /* SOUP_SERVER_H */
