/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <config.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include <gnet/gnet.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "soup-context.h"
#include "soup-private.h"
#include "soup-misc.h"
#include "soup-ssl.h"

GHashTable *soup_servers;  /* KEY: hostname, VALUE: SoupServer */

static gint connection_count = 0;

static guint most_recently_used_id = 0;

static SoupContext *
soup_context_new (SoupServer *server, SoupUri *uri) 
{
	SoupContext *ctx = g_new0 (SoupContext, 1);
	ctx->server = server;
	ctx->uri = uri;
	ctx->refcnt = 0;

	if (g_strcasecmp (uri->protocol, "http") == 0) 
		ctx->protocol = SOUP_PROTOCOL_HTTP;
	else if (g_strcasecmp (uri->protocol, "https") == 0) 
		ctx->protocol = SOUP_PROTOCOL_SHTTP;
	else if (g_strcasecmp (uri->protocol, "mailto") == 0) 
		ctx->protocol = SOUP_PROTOCOL_SMTP;
	else if (g_strcasecmp (uri->protocol, "socks4") == 0) 
		ctx->protocol = SOUP_PROTOCOL_SOCKS4;
	else if (g_strcasecmp (uri->protocol, "socks5") == 0) 
		ctx->protocol = SOUP_PROTOCOL_SOCKS5;

	return ctx;
}

SoupContext *
soup_context_get (gchar *uri) 
{
	SoupServer *serv = NULL;
	SoupContext *ret = NULL;
	SoupUri *suri = soup_uri_new (uri);

	if (!suri->protocol) {
		soup_uri_free (suri);
		return NULL;
	}

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
	g_return_if_fail (ctx != NULL);

	ctx->refcnt++;
}

void
soup_context_unref (SoupContext *ctx)
{
	g_return_if_fail (ctx != NULL);

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
			 GInetAddr                    *addr,
			 GTcpSocketConnectAsyncStatus  status,
			 gpointer                      user_data)
{
	struct SoupConnectData *data = user_data;
	SoupContext            *ctx = data->ctx;
	SoupConnectCallbackFn   cb = data->cb;
	gpointer                cb_data = data->user_data;
	SoupConnection         *new_conn;

	g_free (data);

	if (addr) gnet_inetaddr_unref(addr);

	switch (status) {
	case GTCP_SOCKET_CONNECT_ASYNC_STATUS_OK:
		new_conn = g_new0 (SoupConnection, 1);
		new_conn->server = ctx->server;
		new_conn->context = ctx;
		new_conn->socket = socket;
		new_conn->port = ctx->uri->port;
		new_conn->keep_alive = TRUE;
		new_conn->in_use = TRUE;
		new_conn->last_used_id = 0;

		connection_count++;

		ctx->server->connections = 
			g_slist_prepend (ctx->server->connections, 
					 new_conn);

		(*cb) (ctx, SOUP_CONNECT_ERROR_NONE, new_conn, cb_data); 
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

	while (conns) {
		SoupConnection *conn = conns->data;

		if (!conn->in_use && 
		    conn->port == ctx->uri->port && 
		    conn->keep_alive)
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
	guint conn_limit = soup_get_connection_limit();

	if (conn_limit &&
	    connection_count >= conn_limit &&
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
	guint conn_limit = soup_get_connection_limit();

	g_return_val_if_fail (ctx != NULL, NULL);

	if ((conn = soup_try_existing_connections (ctx))) {
		conn->in_use = TRUE;
		(*cb) (ctx, SOUP_CONNECT_ERROR_NONE, conn, user_data);
		return NULL;
	}

	data = g_new0 (struct SoupConnectData, 1);
	data->ctx = ctx;
	data->cb = cb;
	data->user_data = user_data;

	if (conn_limit && 
	    connection_count >= conn_limit && 
	    !soup_prune_least_used_connection ()) {
		data->timeout_tag = 
			g_timeout_add (500, 
				       (GSourceFunc) soup_prune_timeout,
				       data);
	} else {
		static gint sync_name_lookup = -1;

		if (sync_name_lookup == -1) {
			if (getenv ("SOUP_NO_ASYNC_CONNECT")) {
				sync_name_lookup = TRUE;
				g_warning ("Using synchronous connect method");
			} else 
				sync_name_lookup = FALSE;
		}
		
		if (sync_name_lookup == FALSE)
			data->gnet_connect_tag =
				gnet_tcp_socket_connect_async (
				        ctx->uri->host, 
					ctx->uri->port,
					soup_context_connect_cb,
					data);
		else {
			/* Syncronous Version -- Use for debugging */
			soup_context_connect_cb (
			        gnet_tcp_socket_connect (ctx->uri->host, 
							 ctx->uri->port),
				NULL, 
				GTCP_SOCKET_CONNECT_ASYNC_STATUS_OK,
				data);
			return NULL;
		}
	}

	return data;
}

void 
soup_context_cancel_connect (SoupConnectId tag) 
{
	struct SoupConnectData *data = tag;

	g_return_if_fail (data != NULL);

	if (data->timeout_tag)
		g_source_remove (data->timeout_tag);
	else if (data->gnet_connect_tag)
		gnet_tcp_socket_connect_async_cancel (data->gnet_connect_tag);

	g_free (data);
}

SoupUri *
soup_context_get_uri (SoupContext *ctx)
{
	g_return_val_if_fail (ctx != NULL, NULL);
	return ctx->uri;
}

SoupProtocol
soup_context_get_protocol (SoupContext *ctx)
{
	g_return_val_if_fail (ctx != NULL, 0);
	return ctx->protocol;
}

void
soup_connection_release (SoupConnection *conn)
{
	g_return_if_fail (conn != NULL);

	if (conn->keep_alive) {
		conn->last_used_id = ++most_recently_used_id;
		conn->in_use = FALSE;
	} else {
		conn->server->connections = 
			g_slist_remove (conn->server->connections, conn);
		gnet_tcp_socket_unref (conn->socket);
		g_free (conn);
		connection_count--;
	}
}

static void 
soup_connection_setup_socket (GIOChannel *channel)
{
#ifdef TCP_NODELAY
	int yes = 1, flags = 0, fd = g_io_channel_unix_get_fd (channel);

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

	flags = fcntl(fd, F_GETFL, 0);
	fcntl (fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

GIOChannel *
soup_connection_get_iochannel (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, NULL);

	if (!conn->channel) {
		conn->channel = gnet_tcp_socket_get_iochannel (conn->socket);

		if (conn->context->protocol == SOUP_PROTOCOL_SHTTP)
			conn->channel = soup_get_ssl_iochannel (conn->channel);

		soup_connection_setup_socket (conn->channel);
	} else
		g_io_channel_ref (conn->channel);

	return conn->channel;
}

void 
soup_connection_set_keep_alive (SoupConnection *conn, gboolean keep_alive)
{
	g_return_if_fail (conn != NULL);
	conn->keep_alive = keep_alive;
}

gboolean 
soup_connection_is_keep_alive (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->keep_alive;
}

SoupContext *
soup_connection_get_context (SoupConnection *conn) 
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->context;
}

gboolean 
soup_connection_is_new (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->last_used_id == 0;
}
