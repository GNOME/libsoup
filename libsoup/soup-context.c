/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-context.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include <fcntl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "soup-auth.h"
#include "soup-auth-ntlm.h"
#include "soup-context.h"
#include "soup-private.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"

GHashTable *soup_hosts;  /* KEY: hostname, VALUE: SoupHost */

static gint connection_count = 0;

static guint most_recently_used_id = 0;

/**
 * soup_context_get:
 * @uri: the stringified URI.
 *
 * Returns a pointer to the #SoupContext representing @uri. If a
 * context already exists for the URI, it is returned with an added
 * reference. Otherwise, a new context is created with a reference
 * count of one.
 *
 * Return value: a #SoupContext representing @uri.
 */
SoupContext *
soup_context_get (const gchar *uri)
{
	SoupUri *suri;
	SoupContext *con;

	g_return_val_if_fail (uri != NULL, NULL);

	suri = soup_uri_new (uri);
	if (!suri) return NULL;

	con = soup_context_from_uri (suri);
	soup_uri_free (suri);

	return con;
}

/**
 * soup_context_uri_hash:
 * @key: a #SoupUri
 *
 * Return value: Hash value of the user, passwd, path, and query
 * fields in @key.
 **/
static guint
soup_context_uri_hash (gconstpointer key)
{
	const SoupUri *uri = key;
	guint ret;

	ret = uri->protocol;
	if (uri->path)
		ret += g_str_hash (uri->path);
	if (uri->query)
		ret += g_str_hash (uri->query);
	if (uri->user)
		ret += g_str_hash (uri->user);
	if (uri->passwd)
		ret += g_str_hash (uri->passwd);

	return ret;
}

static inline gboolean
parts_equal (const char *one, const char *two)
{
	if (!one && !two)
		return TRUE;
	if (!one || !two)
		return FALSE;
	return !strcmp (one, two);
}

/**
 * soup_context_uri_equal:
 * @v1: a #SoupUri
 * @v2: a #SoupUri
 *
 * Return value: %TRUE if @v1 and @v2 match in user, passwd, path, and
 * query. Otherwise, %FALSE.
 **/
static gboolean
soup_context_uri_equal (gconstpointer v1, gconstpointer v2)
{
	const SoupUri *one = v1;
	const SoupUri *two = v2;

	if (one->protocol != two->protocol)
		return FALSE;
	if (!parts_equal (one->path, two->path))
		return FALSE;
	if (!parts_equal (one->user, two->user))
		return FALSE;
	if (!parts_equal (one->passwd, two->passwd))
		return FALSE;
	if (!parts_equal (one->query, two->query))
		return FALSE;

	return TRUE;
}

/**
 * soup_context_from_uri:
 * @suri: a #SoupUri.
 *
 * Returns a pointer to the #SoupContext representing @suri. If a
 * context already exists for the URI, it is returned with an added
 * reference. Otherwise, a new context is created with a reference
 * count of one.
 *
 * Return value: a #SoupContext representing @uri.
 */
SoupContext *
soup_context_from_uri (SoupUri *suri)
{
	SoupHost *serv = NULL;
	SoupContext *ret = NULL;

	g_return_val_if_fail (suri != NULL, NULL);
	g_return_val_if_fail (suri->protocol != 0, NULL);

	if (!soup_hosts)
		soup_hosts = g_hash_table_new (soup_str_case_hash,
					       soup_str_case_equal);
	else
		serv = g_hash_table_lookup (soup_hosts, suri->host);

	if (!serv) {
		serv = g_new0 (SoupHost, 1);
		serv->host = g_strdup (suri->host);
		g_hash_table_insert (soup_hosts, serv->host, serv);
	}

	if (!serv->contexts)
		serv->contexts = g_hash_table_new (soup_context_uri_hash,
						   soup_context_uri_equal);
	else
		ret = g_hash_table_lookup (serv->contexts, suri);

	if (!ret) {
		ret = g_new0 (SoupContext, 1);
		ret->server = serv;
		ret->uri = soup_uri_copy (suri);
		ret->refcnt = 0;

		g_hash_table_insert (serv->contexts, ret->uri, ret);
	}

	soup_context_ref (ret);

	return ret;
}

/**
 * soup_context_ref:
 * @ctx: a #SoupContext.
 *
 * Adds a reference to @ctx.
 */
void
soup_context_ref (SoupContext *ctx)
{
	g_return_if_fail (ctx != NULL);

	ctx->refcnt++;
}

static void
free_path (gpointer path, gpointer realm, gpointer unused)
{
	g_free (path);
	g_free (realm);
}

static void
free_auth (gpointer realm, gpointer auth, gpointer unused)
{
	g_free (realm);
	g_object_unref (auth);
}

/**
 * soup_context_unref:
 * @ctx: a #SoupContext.
 *
 * Decrement the reference count on @ctx. If the reference count
 * reaches zero, the #SoupContext is freed. If this is the last
 * context for a given server address, any open connections are
 * closed.
 */
void
soup_context_unref (SoupContext *ctx)
{
	g_return_if_fail (ctx != NULL);

	--ctx->refcnt;

	if (ctx->refcnt == 0) {
		SoupHost *serv = ctx->server;

		g_hash_table_remove (serv->contexts, ctx->uri);

		if (g_hash_table_size (serv->contexts) == 0) {
			/*
			 * Remove this host from the active hosts hash
			 */
			g_hash_table_remove (soup_hosts, serv->host);

			/* 
			 * Free all cached SoupAuths
			 */
			if (serv->auth_realms) {
				g_hash_table_foreach (serv->auth_realms,
						      free_path, NULL);
				g_hash_table_destroy (serv->auth_realms);
			}
			if (serv->auths) {
				g_hash_table_foreach (serv->auths,
						      free_auth, NULL);
				g_hash_table_destroy (serv->auths);
			}

			g_hash_table_destroy (serv->contexts);
			g_free (serv->host);
			g_free (serv);
		}

		soup_uri_free (ctx->uri);
		g_free (ctx);
	}
}

static void
connection_free (SoupConnection *conn)
{
	g_return_if_fail (conn != NULL);

	conn->server->connections =
		g_slist_remove (conn->server->connections, conn);

	if (conn->auth)
		g_object_unref (conn->auth);

	g_io_channel_unref (conn->channel);
	soup_context_unref (conn->context);
	g_object_unref (conn->socket);
	if (conn->death_tag)
		g_source_remove (conn->death_tag);
	g_free (conn);

	connection_count--;
}

static gboolean 
connection_death (GIOChannel*     iochannel,
		  GIOCondition    condition,
		  SoupConnection *conn)
{
	connection_free (conn);
	return FALSE;
}

static void
soup_connection_set_in_use (SoupConnection *conn, gboolean in_use)
{
	if (in_use == conn->in_use)
		return;

	conn->in_use = in_use;
	if (!conn->in_use) {
		GIOChannel *chan;

		chan = soup_connection_get_iochannel (conn);
		conn->death_tag = 
			g_io_add_watch (chan,
					G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) connection_death,
					conn);
		g_io_channel_unref (chan);
	} else {
		g_source_remove (conn->death_tag);
		conn->death_tag = 0;
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
prune_connection_foreach (gchar               *hostname,
			  SoupHost            *serv,
			  SoupConnection     **last)
{
	GSList *conns = serv->connections;

	while (conns) {
		SoupConnection *conn = conns->data;

		if (!conn->in_use) {
			if (*last == NULL ||
			    (*last)->last_used_id > conn->last_used_id)
				*last = conn;
		}

		conns = conns->next;
	}
}

static gboolean
prune_least_used_connection (void)
{
	SoupConnection *last = NULL;

	g_hash_table_foreach (soup_hosts, 
			      (GHFunc) prune_connection_foreach, 
			      &last);
	if (last) {
		connection_free (last);
		return TRUE;
	}

	return FALSE;
}

static gboolean retry_connect_timeout_cb (struct SoupConnectData *data);

static void
soup_context_connect_cb (SoupSocket              *socket,
			 SoupSocketConnectStatus  status,
			 gpointer                 user_data)
{
	struct SoupConnectData *data = user_data;
	SoupContext            *ctx = data->ctx;
	SoupConnection         *new_conn;

	switch (status) {
	case SOUP_SOCKET_CONNECT_ERROR_NONE:
		new_conn = g_new0 (SoupConnection, 1);
		new_conn->server = ctx->server;
		new_conn->socket = socket;
		new_conn->port = ctx->uri->port;
		new_conn->keep_alive = TRUE;
		new_conn->in_use = TRUE;
		new_conn->new = TRUE;
		new_conn->last_used_id = 0;

		new_conn->context = ctx;
		soup_context_ref (ctx);

		ctx->server->connections =
			g_slist_prepend (ctx->server->connections, new_conn);

		(*data->cb) (ctx, 
			     SOUP_CONNECT_ERROR_NONE, 
			     new_conn, 
			     data->user_data);
		break;
	case SOUP_SOCKET_CONNECT_ERROR_ADDR_RESOLVE:
		connection_count--;

		(*data->cb) (ctx, 
			     SOUP_CONNECT_ERROR_ADDR_RESOLVE, 
			     NULL, 
			     data->user_data);
		break;
	case SOUP_SOCKET_CONNECT_ERROR_NETWORK:
		connection_count--;

		/*
		 * Check if another connection exists to this server
		 * before reporting error. 
		 */
		if (ctx->server->connections) {
			data->timeout_tag =
				g_timeout_add (
					150,
					(GSourceFunc) retry_connect_timeout_cb,
					data);
			return;
		}

		(*data->cb) (ctx, 
			     SOUP_CONNECT_ERROR_NETWORK, 
			     NULL, 
			     data->user_data);
		break;
	}

	soup_context_unref (ctx);
	g_free (data);
}

static gboolean
try_existing_connections (SoupContext           *ctx,
			  SoupConnectCallbackFn  cb,
			  gpointer               user_data)
{
	GSList *conns = ctx->server->connections;
	
	while (conns) {
		SoupConnection *conn = conns->data;

		if (conn->in_use == FALSE &&
		    conn->keep_alive == TRUE &&
		    conn->port == (guint) ctx->uri->port) {
			/* Set connection to in use */
			soup_connection_set_in_use (conn, TRUE);

			/* Reset connection context */
			soup_context_ref (ctx);
			soup_context_unref (conn->context);
			conn->context = ctx;

			/* Issue success callback */
			(*cb) (ctx, SOUP_CONNECT_ERROR_NONE, conn, user_data);
			return TRUE;
		}

		conns = conns->next;
	}

	return FALSE;
}

static gboolean
try_create_connection (struct SoupConnectData **dataptr)
{
	struct SoupConnectData *data = *dataptr;
	gint conn_limit = soup_get_connection_limit ();
	gpointer connect_tag;

	/* 
	 * Check if we are allowed to create a new connection, otherwise wait
	 * for next timeout.  
	 */
	if (conn_limit &&
	    connection_count >= conn_limit &&
	    !prune_least_used_connection ()) {
		data->connect_tag = 0;
		return FALSE;
	}

	connection_count++;

	data->timeout_tag = 0;
	connect_tag = soup_socket_connect (data->ctx->uri->host,
					   data->ctx->uri->port,
					   soup_context_connect_cb,
					   data);
	/* 
	 * NOTE: soup_socket_connect can fail immediately and call our
	 * callback which will delete the state.  
	 */
	if (connect_tag)
		data->connect_tag = connect_tag;
	else
		*dataptr = NULL;

	return TRUE;
}

static gboolean
retry_connect_timeout_cb (struct SoupConnectData *data)
{
	if (try_existing_connections (data->ctx, 
				      data->cb, 
				      data->user_data)) {
		soup_context_unref (data->ctx);
		g_free (data);
		return FALSE;
	}

	return try_create_connection (&data) == FALSE;
}

/**
 * soup_context_get_connection:
 * @ctx: a #SoupContext.
 * @cb: a #SoupConnectCallbackFn to be called when a valid connection is
 * available.
 * @user_data: the user_data passed to @cb.
 *
 * Initiates the process of establishing a network connection to the
 * server referenced in @ctx. If an existing connection is available
 * and not in use, @cb is called immediately, and a #SoupConnectId of
 * 0 is returned. Otherwise, a new connection is established. If the
 * current connection count exceeds that set in
 * soup_set_connection_limit(), the new connection is not created
 * until an existing connection is closed.
 *
 * Once a network connection is successfully established, or an
 * existing connection becomes available for use, @cb is called,
 * passing the #SoupConnection representing it.
 *
 * Return value: a #SoupConnectId which can be used to cancel a
 * connection attempt using soup_context_cancel_connect().
 */
SoupConnectId
soup_context_get_connection (SoupContext           *ctx,
			     SoupConnectCallbackFn  cb,
			     gpointer               user_data)
{
	struct SoupConnectData *data;

	g_return_val_if_fail (ctx != NULL, NULL);

	/* Look for an existing unused connection */
	if (try_existing_connections (ctx, cb, user_data))
		return NULL;

	data = g_new0 (struct SoupConnectData, 1);
	data->cb = cb;
	data->user_data = user_data;

	data->ctx = ctx;
	soup_context_ref (ctx);

	if (!try_create_connection (&data))
		data->timeout_tag =
			g_timeout_add (150,
				       (GSourceFunc) retry_connect_timeout_cb,
				       data);

	return data;
}

/**
 * soup_context_cancel_connect:
 * @tag: a #SoupConnectId representing a connection in progress.
 *
 * Cancels the connection attempt represented by @tag. The
 * #SoupConnectCallbackFn passed in soup_context_get_connection() is
 * not called.
 */
void
soup_context_cancel_connect (SoupConnectId tag)
{
	struct SoupConnectData *data = tag;

	g_return_if_fail (data != NULL);

	if (data->timeout_tag)
		g_source_remove (data->timeout_tag);
	else if (data->connect_tag) {
		connection_count--;
		soup_socket_connect_cancel (data->connect_tag);
	}

	g_free (data);
}

/**
 * soup_context_get_uri:
 * @ctx: a #SoupContext.
 *
 * Returns a pointer to the #SoupUri represented by @ctx.
 *
 * Return value: the #SoupUri for @ctx.
 */
const SoupUri *
soup_context_get_uri (SoupContext *ctx)
{
	g_return_val_if_fail (ctx != NULL, NULL);
	return ctx->uri;
}

/**
 * soup_connection_release:
 * @conn: a #SoupConnection currently in use.
 *
 * Mark the connection represented by @conn as being unused. If the
 * keep-alive flag is not set on the connection, the connection is
 * closed and its resources freed, otherwise the connection is
 * returned to the unused connection pool for the server.
 */
void
soup_connection_release (SoupConnection *conn)
{
	g_return_if_fail (conn != NULL);

	if (conn->keep_alive) {
		conn->last_used_id = ++most_recently_used_id;
		soup_connection_set_in_use (conn, FALSE);
	} else
		connection_free (conn);
}

static void
soup_connection_setup_socket (GIOChannel *channel)
{
	int yes = 1, flags = 0, fd = g_io_channel_unix_get_fd (channel);

	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

	flags = fcntl(fd, F_GETFL, 0);
	fcntl (fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * soup_connection_get_iochannel:
 * @conn: a #SoupConnection.
 *
 * Returns a #GIOChannel used for IO operations on the network
 * connection represented by @conn.
 *
 * Return value: a pointer to the #GIOChannel used for IO on @conn.
 */
GIOChannel *
soup_connection_get_iochannel (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, NULL);

	if (!conn->channel) {
		conn->channel = soup_socket_get_iochannel (conn->socket);

		soup_connection_setup_socket (conn->channel);

		if (conn->context->uri->protocol == SOUP_PROTOCOL_HTTPS) {
			GIOChannel *ssl_chan;

			ssl_chan = soup_ssl_get_iochannel (conn->channel);
			g_io_channel_unref (conn->channel);
			conn->channel = ssl_chan;
		}
	}

	g_io_channel_ref (conn->channel);

	return conn->channel;
}

/**
 * soup_connection_set_keep_alive:
 * @conn: a #SoupConnection.
 * @keep_alive: boolean keep-alive value.
 *
 * Sets the keep-alive flag on the #SoupConnection pointed to by
 * @conn.
 */
void
soup_connection_set_keep_alive (SoupConnection *conn, gboolean keep_alive)
{
	g_return_if_fail (conn != NULL);
	conn->keep_alive = keep_alive;
}

/**
 * soup_connection_is_keep_alive:
 * @conn: a #SoupConnection.
 *
 * Returns the keep-alive flag for the #SoupConnection pointed to by
 * @conn. If this flag is TRUE, the connection will be returned to the
 * pool of unused connections when next soup_connection_release() is
 * called, otherwise the connection will be closed and resources
 * freed.
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
 * @conn: a #SoupConnection.
 *
 * Returns the #SoupContext from which @conn was created, with an
 * added ref.
 *
 * Return value: the #SoupContext associated with @conn. Unref when
 * finished.
 */
SoupContext *
soup_connection_get_context (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	
	soup_context_ref (conn->context);
	return conn->context;
}

/**
 * soup_connection_set_used:
 * @conn: a #SoupConnection.
 *
 * Clears the "new" flag on @conn.
 */
void
soup_connection_set_used (SoupConnection *conn)
{
	g_return_if_fail (conn != NULL);

	conn->new = FALSE;
}

/**
 * soup_connection_is_new:
 * @conn: a #SoupConnection.
 *
 * Returns %TRUE if this is the first use of @conn (ie. no response
 * has been read from it yet)
 *
 * Return value: boolean representing whether this is the first time a
 * connection has been used.
 */
gboolean
soup_connection_is_new (SoupConnection *conn)
{
	g_return_val_if_fail (conn != NULL, FALSE);
	return conn->new;
}


static void
get_idle_conns_for_host (gpointer key, gpointer value, gpointer data)
{
	SoupHost *host = value;
	SoupConnection *conn;
	GSList *c, **idle_conns = data;

	for (c = host->connections; c; c = c->next) {
		conn = c->data;
		if (!conn->in_use)
			*idle_conns = g_slist_prepend (*idle_conns, conn);
	}
}

/**
 * soup_connection_purge_idle:
 *
 * Closes all idle open connections.
 **/
void
soup_connection_purge_idle (void)
{
	GSList *idle_conns, *i;

	if (!soup_hosts)
		return;

	idle_conns = NULL;
	g_hash_table_foreach (soup_hosts, get_idle_conns_for_host, &idle_conns);

	for (i = idle_conns; i; i = i->next)
		connection_free (i->data);
	g_slist_free (idle_conns);
}


/* Authentication */

SoupAuth *
soup_context_lookup_auth (SoupContext *ctx, SoupMessage *msg)
{
	char *path, *dir;
	const char *realm;

	g_return_val_if_fail (ctx != NULL, NULL);

	if (ctx->server->use_ntlm && msg && msg->connection) {
		if (!msg->connection->auth)
			msg->connection->auth = soup_auth_ntlm_new ();
		return msg->connection->auth;
	}

	if (!ctx->server->auth_realms)
		return NULL;

	path = g_strdup (ctx->uri->path);
	dir = path;
        do {
                realm = g_hash_table_lookup (ctx->server->auth_realms, path);
                if (realm)
			break;

                dir = strrchr (path, '/');
                if (dir)
			*dir = '\0';
        } while (dir);

	g_free (path);
	if (realm)
		return g_hash_table_lookup (ctx->server->auths, realm);
	else
		return NULL;
}

static gboolean
update_auth_internal (SoupContext *ctx, SoupConnection *conn,
		      const GSList *headers, gboolean prior_auth_failed)
{
	SoupHost *server = ctx->server;
	SoupAuth *new_auth, *prior_auth, *old_auth;
	gpointer old_path, old_realm;
	const char *path;
	char *realm;
	GSList *pspace, *p;

	if (server->use_ntlm && conn && conn->auth) {
		if (soup_auth_is_authenticated (conn->auth)) {
			/* This is a "permission denied", not a
			 * "password incorrect". There's nothing more
			 * we can do.
			 */
			return FALSE;
		}

		/* Free the intermediate auth */
		g_object_unref (conn->auth);
		conn->auth = NULL;
	}

	/* Try to construct a new auth from the headers; if we can't,
	 * there's no way we'll be able to authenticate.
	 */
	new_auth = soup_auth_new_from_header_list (headers, ctx->uri->authmech);
	if (!new_auth)
		return FALSE;

	/* See if this auth is the same auth we used last time */
	prior_auth = soup_context_lookup_auth (ctx, NULL);
	if (prior_auth &&
	    G_OBJECT_TYPE (prior_auth) == G_OBJECT_TYPE (new_auth) &&
	    !strcmp (soup_auth_get_realm (prior_auth),
		     soup_auth_get_realm (new_auth))) {
		g_object_unref (new_auth);
		if (prior_auth_failed) {
			/* The server didn't like the username/password
			 * we provided before.
			 */
			soup_context_invalidate_auth (ctx, prior_auth);
			return FALSE;
		} else {
			/* The user is trying to preauthenticate using
			 * information we already have, so there's nothing
			 * that needs to be done.
			 */
			return TRUE;
		}
	}

	if (SOUP_IS_AUTH_NTLM (new_auth)) {
		server->use_ntlm = TRUE;
		if (conn) {
			conn->auth = new_auth;
			return soup_context_authenticate_auth (ctx, new_auth);
		} else {
			g_object_unref (new_auth);
			return FALSE;
		}
	}

	if (!server->auth_realms) {
		server->auth_realms = g_hash_table_new (g_str_hash, g_str_equal);
		server->auths = g_hash_table_new (g_str_hash, g_str_equal);
	}

	/* Record where this auth realm is used */
	realm = g_strdup_printf ("%s:%s",
				 soup_auth_get_scheme_name (new_auth),
				 soup_auth_get_realm (new_auth));
	pspace = soup_auth_get_protection_space (new_auth, ctx->uri);
	for (p = pspace; p; p = p->next) {
		path = p->data;
		if (g_hash_table_lookup_extended (server->auth_realms, path,
						  &old_path, &old_realm)) {
			g_hash_table_remove (server->auth_realms, old_path);
			g_free (old_path);
			g_free (old_realm);
		}

		g_hash_table_insert (server->auth_realms,
				     g_strdup (path), g_strdup (realm));
	}
	soup_auth_free_protection_space (new_auth, pspace);

	/* Now, make sure the auth is recorded. (If there's a
	 * pre-existing auth, we keep that rather than the new one,
	 * since the old one might already be authenticated.)
	 */
	old_auth = g_hash_table_lookup (server->auths, realm);
	if (old_auth) {
		g_free (realm);
		g_object_unref (new_auth);
		new_auth = old_auth;
	} else 
		g_hash_table_insert (server->auths, realm, new_auth);

	/* Try to authenticate if needed. */
	if (!soup_auth_is_authenticated (new_auth))
		return soup_context_authenticate_auth (ctx, new_auth);

	return TRUE;
}

gboolean
soup_context_update_auth (SoupContext *ctx, SoupMessage *msg)
{
	const GSList *headers;

	g_return_val_if_fail (ctx != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	if (msg->errorcode == SOUP_ERROR_PROXY_UNAUTHORIZED) {
		headers = soup_message_get_header_list (msg->response_headers,
							"Proxy-Authenticate");
	} else {
		headers = soup_message_get_header_list (msg->response_headers,
							"WWW-Authenticate");
	}

	return update_auth_internal (ctx, msg->connection, headers, TRUE);
}

void
soup_context_preauthenticate (SoupContext *ctx, const char *header)
{
	GSList *headers;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (header != NULL);

	headers = g_slist_append (NULL, (char *)header);
	update_auth_internal (ctx, NULL, headers, FALSE);
	g_slist_free (headers);
}

gboolean
soup_context_authenticate_auth (SoupContext *ctx, SoupAuth *auth)
{
	const SoupUri *uri = ctx->uri;

	if (!uri->user && soup_auth_fn) {
		(*soup_auth_fn) (soup_auth_get_scheme_name (auth),
				 (SoupUri *) uri,
				 soup_auth_get_realm (auth), 
				 soup_auth_fn_user_data);
	}

	if (!uri->user)
		return FALSE;

	soup_auth_authenticate (auth, uri->user, uri->passwd);
	return TRUE;
}

void
soup_context_invalidate_auth (SoupContext *ctx, SoupAuth *auth)
{
	char *realm;
	gpointer key, value;

	g_return_if_fail (ctx != NULL);
	g_return_if_fail (auth != NULL);

	/* Try to just clean up the auth without removing it. */
	if (soup_auth_invalidate (auth))
		return;

	/* Nope, need to remove it completely */
	realm = g_strdup_printf ("%s:%s",
				 soup_auth_get_scheme_name (auth),
				 soup_auth_get_realm (auth));

	if (g_hash_table_lookup_extended (ctx->server->auths, realm,
					  &key, &value) &&
	    auth == (SoupAuth *)value) {
		g_hash_table_remove (ctx->server->auths, realm);
		g_free (key);
		g_object_unref (auth);
	}
	g_free (realm);
}
