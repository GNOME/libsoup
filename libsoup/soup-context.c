/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <gnet/gnet.h>

#include "soup-context.h"
#include "soup-private.h"
#include "soup-uri.h"

GHashTable *servers;

static SoupContext *
soup_context_new (SoupServer *server, SoupUri *uri) 
{
	SoupContext *ctx = g_new0 (SoupContext, 1);
	ctx->priv = g_new0 (SoupContextPrivate, 1);
	ctx->priv->server = server;
	ctx->priv->keep_alive = TRUE;
	ctx->priv->chunk_size = DEFAULT_CHUNK_SIZE;
	ctx->uri = uri;
	ctx->custom_headers = NULL;
	return ctx;
}

SoupContext *
soup_context_get (gchar *uri) 
{
	SoupServer *serv;
	SoupContext *ret = NULL;
	SoupUri *suri = soup_uri_new (uri);

	if (!servers)
		servers = g_hash_table_new (g_str_hash, g_str_equal);
	else
		serv = g_hash_table_lookup (servers, suri->host);

	if (serv) {
		if (serv->contexts) 
			ret = g_hash_table_lookup (serv->contexts, suri->path);
	        else
			serv->contexts = g_hash_table_new (g_str_hash, 
							   g_str_equal);
	} else {
		serv = g_new0 (SoupServer, 1);
		serv->host = g_strdup (suri->host);
		g_hash_table_insert (servers, suri->host, serv);
	}

	if (ret) return ret;

	ret = soup_context_new (serv, suri);

	g_hash_table_insert (serv->contexts, suri->path, ret);

	return ret;
}

void
soup_context_free (SoupContext *ctx)
{
}

struct SoupContextConnectFunctor {
	SoupContext           *ctx;
	SoupConnectCallbackFn  cb;
	gpointer               user_data;
};

static void 
soup_context_connect_cb (GTcpSocket                   *socket, 
			 GInetAddr*                    addr,
			 GTcpSocketConnectAsyncStatus  status,
			 gpointer                      user_data)
{
	struct SoupContextConnectFunctor *data = user_data;
	SoupContext                      *ctx = data->ctx;
	SoupConnectCallbackFn             cb = data->cb;
	gpointer                          cb_data = data->user_data;
	SoupConnection                   *new_conn;

	g_free (data);

	gnet_inetaddr_unref(addr);

	switch (status) {
	case GTCP_SOCKET_CONNECT_ASYNC_STATUS_OK:
		new_conn = g_new0 (SoupConnection, 1);
		new_conn->port = ctx->uri->port;
		new_conn->in_use = TRUE;
		new_conn->socket = socket;

		ctx->priv->server->connections = 
			g_slist_prepend (ctx->priv->server->connections, 
					 new_conn);

		(*cb) (ctx, SOUP_CONNECT_ERROR_NONE, socket, cb_data); 
		break;
	case GTCP_SOCKET_CONNECT_ASYNC_STATUS_INETADDR_ERROR:
		(*cb) (ctx, SOUP_CONNECT_ERROR_ADDR_RESOLVE, NULL, cb_data); 
		break;
	case GTCP_SOCKET_CONNECT_ASYNC_STATUS_TCP_ERROR:
		(*cb) (ctx, SOUP_CONNECT_ERROR_NETWORK, NULL, cb_data); 
		break;
	}
}

void
soup_context_get_connection (SoupContext           *ctx,
			     SoupConnectCallbackFn  cb,
			     gpointer               user_data)
{
	GSList *conns;

	if (!ctx->priv->keep_alive)
		goto FORCE_NEW_CONNECTION;
	
	conns = ctx->priv->server->connections;

	while (conns) {
		SoupConnection *conn = conns->data;

		if (!conn->in_use && conn->port == ctx->uri->port) {
			conn->in_use = TRUE;
			(*cb) (ctx, 
			       SOUP_CONNECT_ERROR_NONE, 
			       conn->socket, 
			       user_data);
			return;
		}

		conns = conns->next;
	}

 FORCE_NEW_CONNECTION:
	{
		struct SoupContextConnectFunctor *data;
		data = g_new0 (struct SoupContextConnectFunctor, 1);
		data->ctx = ctx;
		data->cb = cb;
		data->user_data = user_data;
		gnet_tcp_socket_connect_async (ctx->uri->host, 
					       ctx->uri->port,
					       soup_context_connect_cb,
					       user_data);
		return;
	}
}

void 
soup_context_return_connection (SoupContext       *ctx,
				GTcpSocket        *socket)
{
	SoupServer *server = ctx->priv->server;
	GSList *conns = server->connections;

	while (conns) {
		SoupConnection *conn = conns->data;

		if (conn->socket == socket) {
			if (ctx->priv->keep_alive) {
				conn->in_use = FALSE;
			} else {
				server->connections = 
					g_slist_remove (server->connections, 
							socket);
				gnet_tcp_socket_unref (socket);
				connection_count--;
			}

			return;
		}

		conns = conns->next;
	}
}
