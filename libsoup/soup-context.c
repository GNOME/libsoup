/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <glib.h>
#include <gnet/gnet.h>

#include "soup-context.h"
#include "soup-private.h"
#include "soup-misc.h"
#include "soup-uri.h"

GHashTable *soup_servers;  /* KEY: hostname, VALUE: SoupServer */

static gint connection_count = 0;

static guint most_recently_used_id = 0;

static SoupContext *
soup_context_new (SoupServer *server, SoupUri *uri) 
{
	SoupContext *ctx = g_new0 (SoupContext, 1);
	ctx->server = server;
	ctx->keep_alive = TRUE;
	ctx->uri = uri;
	return ctx;
}

SoupContext *
soup_context_get (gchar *uri) 
{
	SoupServer *serv = NULL;
	SoupContext *ret = NULL;
	SoupUri *suri = soup_uri_new (uri);

	if (!soup_servers)
		soup_servers = g_hash_table_new (soup_str_case_hash, 
						 soup_str_case_equal);
	else
		serv = g_hash_table_lookup (soup_servers, suri->host);

	if (!serv) {
		serv = g_new0 (SoupServer, 1);
		serv->host = g_strdup (suri->host);
		g_hash_table_insert (soup_servers, suri->host, serv);
	}

	if (!serv->contexts)
		serv->contexts = g_hash_table_new (g_str_hash, g_str_equal);
	else
		ret = g_hash_table_lookup (serv->contexts, suri->path);

	if (!ret) {
		ret = soup_context_new (serv, suri);
		g_hash_table_insert (serv->contexts, suri->path, ret);
	}

	soup_context_ref (ret);

	return ret;
}

void
soup_context_ref (SoupContext *ctx)
{
	ctx->refcnt++;
}

void
soup_context_unref (SoupContext *ctx)
{
	if (ctx->refcnt-- == 0) {
		SoupServer *serv = ctx->server;

		g_hash_table_remove (serv->contexts, ctx->uri->path);

		if (g_hash_table_size (serv->contexts) == 0) {
			GSList *conns = serv->connections;

			g_hash_table_remove (soup_servers, serv->host);
			
			while (conns) {
				SoupConnection *conn = conns->data;
				gnet_tcp_socket_unref (conn->socket);
				g_free (conn);
				connection_count--;

				conns = conns->next;
			}

			g_free (serv->host);
			g_slist_free (serv->connections);
			g_hash_table_destroy (serv->contexts);
			g_free (serv);
		}
			
		soup_uri_free (ctx->uri);
		g_free (ctx);
	}
}

struct SoupConnectData {
	SoupContext           *ctx;
	SoupConnectCallbackFn  cb;
	gpointer               user_data;

	guint                  timeout_tag;
	gpointer               gnet_connect_tag;
};

static void 
soup_context_connect_cb (GTcpSocket                   *socket, 
			 GInetAddr*                    addr,
			 GTcpSocketConnectAsyncStatus  status,
			 gpointer                      user_data)
{
	struct SoupConnectData *data = user_data;
	SoupContext            *ctx = data->ctx;
	SoupConnectCallbackFn   cb = data->cb;
	gpointer                cb_data = data->user_data;
	SoupConnection         *new_conn;

	g_free (data);

	gnet_inetaddr_unref(addr);

	switch (status) {
	case GTCP_SOCKET_CONNECT_ASYNC_STATUS_OK:
		new_conn = g_new0 (SoupConnection, 1);
		new_conn->port = ctx->uri->port;
		new_conn->in_use = TRUE;
		new_conn->socket = socket;

		connection_count++;

		ctx->server->connections = 
			g_slist_prepend (ctx->server->connections, 
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

static SoupConnection *
soup_try_existing_connections (SoupContext *ctx)
{
	GSList *conns = ctx->server->connections;

	if (!ctx->keep_alive)
		return NULL;

	while (conns) {
		SoupConnection *conn = conns->data;

		if (!conn->in_use && conn->port == ctx->uri->port)
			return conn;

		conns = conns->next;
	}

	return NULL;
}

struct SoupConnDesc {
	SoupServer     *serv;
	SoupConnection *conn;
};

static void
soup_prune_foreach (gchar *hostname, 
		    SoupServer *serv, 
		    struct SoupConnDesc *last)
{
	GSList *conns = serv->connections;

	while (conns) {
		SoupConnection *conn = conns->data;
		if (!conn->in_use)
			if (last->conn == NULL || 
			    last->conn->last_used_id > conn->last_used_id) {
				last->conn = conn;
				last->serv = serv;
			}
		
		conns = conns->next;
	}
}

static gboolean
soup_prune_least_used_connection (void)
{
	struct SoupConnDesc last;
	last.serv = NULL;
	last.conn = NULL;

	g_hash_table_foreach (soup_servers, (GHFunc) soup_prune_foreach, &last);

	if (last.conn) {
		last.serv->connections = 
			g_slist_remove (last.serv->connections, last.conn);
		gnet_tcp_socket_unref (last.conn->socket);
		g_free (last.conn);

		connection_count--;

		return TRUE;
	}

	return FALSE;
}

static gboolean 
soup_prune_timeout (struct SoupConnectData *data)
{
	if (connection_count >= soup_get_connection_limit() &&
	    !soup_try_existing_connections (data->ctx) &&
	    !soup_prune_least_used_connection ())
		return TRUE;
	
	soup_context_get_connection (data->ctx, data->cb, data->user_data);
	g_free (data);

	return FALSE;
}

SoupConnectId
soup_context_get_connection (SoupContext           *ctx,
			     SoupConnectCallbackFn  cb,
			     gpointer               user_data)
{
	SoupConnection *conn;
	struct SoupConnectData *data;

	if ((conn = soup_try_existing_connections (ctx))) {
		conn->in_use = TRUE;
		
		(*cb) (ctx, 
		       SOUP_CONNECT_ERROR_NONE, 
		       conn->socket, 
		       user_data);
		
		return NULL;
	}

	data = g_new0 (struct SoupConnectData, 1);
	data->ctx = ctx;
	data->cb = cb;
	data->user_data = user_data;

	if (connection_count >= soup_get_connection_limit() && 
	    !soup_prune_least_used_connection ()) {
		data->timeout_tag = 
			g_timeout_add (500, 
				       (GSourceFunc) soup_prune_timeout,
				       data);
	} else {
		data->gnet_connect_tag =
			gnet_tcp_socket_connect_async (ctx->uri->host, 
						       ctx->uri->port,
						       soup_context_connect_cb,
						       data);
	}
		
	return data;
}

void 
soup_context_release_connection (SoupContext       *ctx,
				 GTcpSocket        *socket)
{
	SoupServer *server = ctx->server;
	GSList *conns = server->connections;

	while (conns) {
		SoupConnection *conn = conns->data;

		if (conn->socket == socket) {
			if (ctx->keep_alive) {
				conn->last_used_id = ++most_recently_used_id;
				conn->in_use = FALSE;
			} else {
				server->connections = 
					g_slist_remove (server->connections, 
							conn);
				gnet_tcp_socket_unref (socket);
				g_free (conn);
				connection_count--;
			}

			return;
		}

		conns = conns->next;
	}
}

void 
soup_context_cancel_connect (SoupConnectId tag) 
{
	struct SoupConnectData *data = tag;

	if (!tag) return;

	if (data->timeout_tag)
		g_source_remove (data->timeout_tag);
	else if (data->gnet_connect_tag)
		gnet_tcp_socket_connect_async_cancel (data->gnet_connect_tag);

	g_free (data);
}

gchar *
soup_context_get_uri (SoupContext *ctx)
{
	return soup_uri_to_string (ctx->uri, TRUE);
}
