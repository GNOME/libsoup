/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_SERVER_H
#define SOUP_SERVER_H 1

#include <glib.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-method.h>
#include <libsoup/soup-misc.h>
#include <libsoup/soup-uri.h>
#include <libsoup/soup-server-auth.h>

typedef struct _SoupServer SoupServer;
typedef struct _SoupServerHandler SoupServerHandler;

typedef struct {
	SoupMessage       *msg;
	gchar             *path;
	SoupMethodId       method_id;
	SoupServerAuth    *auth;
	SoupServer        *server;
	SoupServerHandler *handler;
} SoupServerContext;

typedef void (*SoupServerCallbackFn) (SoupServerContext    *context,
				      SoupMessage          *msg, 
				      gpointer              user_data);

typedef void (*SoupServerUnregisterFn) (SoupServer        *server,
					SoupServerHandler *handler,
					gpointer           user_data);

struct _SoupServerHandler {
	const gchar            *path;

	SoupServerAuthContext  *auth_ctx;

	SoupServerCallbackFn    callback;
	SoupServerUnregisterFn  unregister;
	gpointer                user_data;
};

SoupServer        *soup_server_new           (SoupProtocol           proto,
					      guint                  port);

SoupServer        *soup_server_cgi           (void);

void               soup_server_ref           (SoupServer            *serv);

void               soup_server_unref         (SoupServer            *serv);

SoupProtocol       soup_server_get_protocol  (SoupServer            *serv);

gint               soup_server_get_port      (SoupServer            *serv);

void               soup_server_run           (SoupServer            *serv);

void               soup_server_run_async     (SoupServer            *serv);

void               soup_server_quit          (SoupServer            *serv);

void               soup_server_register      (SoupServer            *serv,
					      const gchar           *path,
					      SoupServerAuthContext *auth_ctx,
					      SoupServerCallbackFn   callback,
					      SoupServerUnregisterFn unregister,
					      gpointer               user_data);

void               soup_server_unregister    (SoupServer            *serv,
					      const gchar           *path);

SoupServerHandler *soup_server_get_handler   (SoupServer            *serv,
					      const gchar           *path);

GSList            *soup_server_list_handlers (SoupServer            *serv);

/* 
 * Apache/soup-httpd module initializtion
 * Implement soup_server_init() in your shared library. 
 */
extern void soup_server_init (SoupServer *server);

typedef struct _SoupServerMessage SoupServerMessage;

SoupServerMessage *soup_server_message_new        (SoupMessage       *src_msg);

void               soup_server_message_start      (SoupServerMessage *servmsg);

void               soup_server_message_add_data   (SoupServerMessage *servmsg,
						   SoupOwnership      owner,
						   gchar             *body,
						   gulong             length);

void               soup_server_message_finish     (SoupServerMessage *servmsg);

SoupMessage       *soup_server_message_get_source (SoupServerMessage *servmsg);

#endif /* SOUP_SERVER_H */
