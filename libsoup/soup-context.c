/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-context.c: Asyncronous Callback-based SOAP Request Queue.
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
#include "soup-socket.h"
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

/**
 * soup_context_get:
 * @uri: the stringified URI.
 *
 * Returns a pointer to the %SoupContext representing @uri. If a context
 * already exists for the URI, it is returned with an added reference.
 * Otherwise, a new context is created with a reference count of one.
 *
 * Return value: a %SoupContext representing @uri.  
 */
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

/**
 * soup_context_ref:
 * @ctx: a %SoupContext.
 *
 * Adds a reference to @ctx.
 */
void
soup_context_ref (SoupContext *ctx)
{
	g_return_if_fail (ctx != NULL);

	ctx->refcnt++;
}

/**
 * soup_context_unref:
 * @ctx: a %SoupContext.
 *
 * Decrement the reference count on @ctx. If the reference count reaches
 * zero, the %SoupContext is freed. If this is the last context for a
 * given server address, any open connections are closed.
 */
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
				soup_socket_unref (conn->socket);
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
	gpointer               connect_tag;
};

static void 
soup_context_connect_cb (SoupSocket              *socket, 
			 SoupAddress             *addr,
			 SoupSocketConnectStatus  status,
			 gpointer                 user_data)
{
	struct SoupConnectData *data = user_data;
	SoupContext            *ctx = data->ctx;
	SoupConnectCallbackFn   cb = data->cb;
	gpointer                cb_data = data->user_data;
	SoupConnection         *new_conn;

	g_free (data);

	if (addr) soup_address_unref(addr);

	switch (status) {
	case SOUP_SOCKET_CONNECT_ERROR_NONE:
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
	case SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE:
		(*cb) (ctx, SOUP_CONNECT_ERROR_ADDR_RESOLVE, NULL, cb_data); 
		break;
	case SOUP_SOCKET_CONNECT_ERROR_NETWORK:
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
		soup_socket_unref (last.conn->socket);
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

/**
 * soup_context_get_connection:
 * @ctx: a %SoupContext.
 * @cb: a %SoupConnectCallbackFn to be called when a valid connection is
 * available.
 * @user_data: the user_data passed to @cb.
 *
 * Initiates the process of establishing a network connection to the
 * server referenced in @ctx. If an existing connection is available and
 * not in use, @cb is called immediately, and a %SoupConnectId of 0 is
 * returned. Otherwise, a new connection is established. If the current
 * connection count exceeds that set in @soup_set_connection_limit, the
 * new connection is not created until an existing connection is closed.
 *
 * Once a network connection is successfully established, or an existing
 * connection becomes available for use, @cb is called, passing the
 * %SoupConnection representing it.
 *
 * Return value: a %SoupConnectId which can be used to cancel a connection
 * attempt using %soup_context_cancel_connect.
 */
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
	    !soup_prune_least_used_connection ())
		data->timeout_tag = 
			g_timeout_add (500, 
				       (GSourceFunc) soup_prune_timeout,
				       data);
	else data->connect_tag =
		     soup_socket_connect (ctx->uri->host, 
					  ctx->uri->port,
					  soup_context_connect_cb,
					  data);

	return data;
}

/**
 * soup_context_cancel_connect:
 * @tag: a %SoupConnextId representing a connection in progress.
 *
 * Cancels the connection attempt represented by @tag. The
 * %SoupConnectCallbackFn passed in %soup_context_get_connection is not
 * called.
 */
void 
soup_context_cancel_connect (SoupConnectId tag) 
{
	struct SoupConnectData *data = tag;

	g_return_if_fail (data != NULL);

	if (data->timeout_tag)
		g_source_remove (data->timeout_tag);
	else if (data->connect_tag)
		soup_socket_connect_cancel (data->connect_tag);

	g_free (data);
}

/**
 * soup_context_get_uri:
 * @ctx: a %SoupContext.
 * 
 * Returns a pointer to the %SoupUri represented by @ctx.
 *
 * Return value: the %SoupUri for @ctx.
 */
SoupUri *
soup_context_get_uri (SoupContext *ctx)
{
	g_return_val_if_fail (ctx != NULL, NULL);
	return ctx->uri;
}

/**
 * soup_context_get_protocol:
 * @ctx: a %SoupContext.
 * 
 * Returns the %SoupProtocol used for connections created for %ctx.
 *
 * Return value: the %SoupProtocol used for connections to %ctx.
 */
SoupProtocol
soup_context_get_protocol (SoupContext *ctx)
{
	g_return_val_if_fail (ctx != NULL, 0);
	return ctx->protocol;
}

/**
 * soup_connection_release:
 * @conn: a %SoupConnection currently in use.
 * 
 * Mark the connection represented by @conn as being unused. If the
 * keep-alive flag is not set on the connection, the connection is closed
 * and its resources freed, otherwise the connection is returned to the
 * unused connection pool for the server. 
 */
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
		soup_socket_unref (conn->socket);
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

/**
 * soup_connection_get_iochannel:
 * @conn: a %SoupConnection.
 * 
 * Returns a GIOChannel used for IO operations on the network connection
 * represented by @conn.
 *
 * Return value: a pointer to the GIOChannel used for IO on %conn. 
 */
GIOChannel *
soup_connection_get_iochannel (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, NULL);

	if (!conn->channel) {
		conn->channel = soup_socket_get_iochannel (conn->socket);

		soup_connection_setup_socket (conn->channel);

		if (conn->context->protocol == SOUP_PROTOCOL_SHTTP)
			conn->channel = soup_ssl_get_iochannel (conn->channel);
	} else
		g_io_channel_ref (conn->channel);

	return conn->channel;
}

/**
 * soup_connection_set_keepalive:
 * @conn: a %SoupConnection.
 * @keep_alive: boolean keep-alive value.
 * 
 * Sets the keep-alive flag on the %SoupConnection pointed to by %conn.
 */
void 
soup_connection_set_keep_alive (SoupConnection *conn, gboolean keep_alive)
{
	g_return_if_fail (conn != NULL);
	conn->keep_alive = keep_alive;
}

/**
 * soup_connection_set_keepalive:
 * @conn: a %SoupConnection.
 *
 * Returns the keep-alive flag for the %SoupConnection pointed to by
 * %conn. If this flag is TRUE, the connection will be returned to the pool
 * of unused connections when next %soup_connection_release is called,
 * otherwise the connection will be closed and resources freed.
 *
 * Return value: the keep-alive flag for @conn.
 */
gboolean 
soup_connection_is_keep_alive (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->keep_alive;
}

/**
 * soup_connection_get_context:
 * @conn: a %SoupConnection.
 * 
 * Returns the %SoupContext from which @conn was created.
 *
 * Return value: the %SoupContext associated with @conn.
 */
SoupContext *
soup_connection_get_context (SoupConnection *conn) 
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->context;
}

/**
 * soup_connection_is_new:
 * @conn: a %SoupConnection.
 * 
 * Returns TRUE if this is the first use of @conn
 * (I.E. %soup_connection_release has not yet been called on it).
 *
 * Return value: boolean representing whether this is the first time a
 * connection has been used.
 */
gboolean 
soup_connection_is_new (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->last_used_id == 0;
}
