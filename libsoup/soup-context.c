/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-context.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
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
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-private.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"

GHashTable *soup_hosts;  /* KEY: hostname, VALUE: SoupHost */
static int connection_count = 0;

struct SoupContextPrivate {
	SoupUri      *uri;
	SoupHost     *server;
};

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

static void
init (GObject *object)
{
	SoupContext *ctx = SOUP_CONTEXT (object);

	ctx->priv = g_new0 (SoupContextPrivate, 1);
}

static void
free_path (gpointer path, gpointer realm, gpointer unused)
{
	g_free (path);
	g_free (realm);
}

static void
free_auth (gpointer key, gpointer auth, gpointer free_key)
{
	if (free_key)
		g_free (key);
	g_object_unref (auth);
}

static void
finalize (GObject *object)
{
	SoupContext *ctx = SOUP_CONTEXT (object);
	SoupHost *serv = ctx->priv->server;

	if (serv && ctx->priv->uri) {
		g_hash_table_remove (serv->contexts, ctx->priv->uri);
		if (g_hash_table_size (serv->contexts) == 0) {
			/* Remove this host from the active hosts hash */
			g_hash_table_remove (soup_hosts, serv->host);

			/* Free all cached SoupAuths */
			if (serv->auth_realms) {
				g_hash_table_foreach (serv->auth_realms,
						      free_path, NULL);
				g_hash_table_destroy (serv->auth_realms);
			}
			if (serv->auths) {
				g_hash_table_foreach (serv->auths,
						      free_auth,
						      GINT_TO_POINTER (TRUE));
				g_hash_table_destroy (serv->auths);
			}
			if (serv->ntlm_auths) {
				g_hash_table_foreach (serv->ntlm_auths,
						      free_auth,
						      GINT_TO_POINTER (FALSE));
				g_hash_table_destroy (serv->ntlm_auths);
			}

			g_hash_table_destroy (serv->contexts);
			g_free (serv->host);
			g_free (serv);
		}
	}

	if (ctx->priv->uri)
		soup_uri_free (ctx->priv->uri);

	g_free (ctx->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_context, SoupContext, class_init, init, PARENT_TYPE)


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
soup_context_get (const char *uri)
{
	SoupUri *suri;
	SoupContext *ctx;

	g_return_val_if_fail (uri != NULL, NULL);

	suri = soup_uri_new (uri);
	if (!suri)
		return NULL;

	ctx = soup_context_from_uri (suri);
	soup_uri_free (suri);

	return ctx;
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
soup_context_from_uri (const SoupUri *suri)
{
	SoupHost *serv = NULL;
	SoupContext *ctx = NULL;

	g_return_val_if_fail (suri != NULL, NULL);
	g_return_val_if_fail (suri->protocol != 0, NULL);

	if (!soup_hosts) {
		soup_hosts = g_hash_table_new (soup_str_case_hash,
					       soup_str_case_equal);
	} else
		serv = g_hash_table_lookup (soup_hosts, suri->host);

	if (!serv) {
		serv = g_new0 (SoupHost, 1);
		serv->host = g_strdup (suri->host);
		g_hash_table_insert (soup_hosts, serv->host, serv);
	}

	if (!serv->contexts) {
		serv->contexts = g_hash_table_new (soup_context_uri_hash,
						   soup_context_uri_equal);
	} else
		ctx = g_hash_table_lookup (serv->contexts, suri);

	if (!ctx) {
		ctx = g_object_new (SOUP_TYPE_CONTEXT, NULL);
		ctx->priv->server = serv;
		ctx->priv->uri = soup_uri_copy (suri);

		g_hash_table_insert (serv->contexts, ctx->priv->uri, ctx);
	}

	return g_object_ref (ctx);
}

static void
connection_disconnected (SoupConnection *conn, gpointer user_data)
{
	SoupHost *server = user_data;
	SoupAuth *auth;

	if (server->ntlm_auths) {
		auth = g_hash_table_lookup (server->ntlm_auths, conn);
		if (auth) {
			g_hash_table_remove (server->ntlm_auths, conn);
			g_object_unref (auth);
		}
	}

	server->connections = g_slist_remove (server->connections, conn);
	connection_count--;
}

struct SoupConnectData {
	SoupContext           *ctx;
	SoupConnectCallbackFn  cb;
	gpointer               user_data;

	guint                  timeout_tag;
	SoupConnection        *conn;
};

static void
prune_connection_foreach (gpointer key, gpointer value, gpointer data)
{
	SoupHost *serv = value;
	SoupConnection **last = data;
	GSList *conns;

	for (conns = serv->connections; conns; conns = conns->next) {
		SoupConnection *conn = conns->data;

		if (soup_connection_is_in_use (conn))
			continue;

		if (*last == NULL ||
		    soup_connection_last_used (*last) >
		    soup_connection_last_used (conn))
			*last = conn;
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
		soup_connection_disconnect (last);
		g_object_unref (last);
		return TRUE;
	}

	return FALSE;
}

static gboolean retry_connect_timeout_cb (struct SoupConnectData *data);

static void
soup_context_connect_cb (SoupConnection     *conn,
			 SoupKnownErrorCode  status,
			 gpointer            user_data)
{
	struct SoupConnectData *data = user_data;
	SoupContext            *ctx = data->ctx;

	switch (status) {
	case SOUP_ERROR_OK:
		g_signal_connect (conn, "disconnected",
				  G_CALLBACK (connection_disconnected),
				  ctx->priv->server);

		/* FIXME */
		g_object_set_data (G_OBJECT (conn), "SoupContext-port",
				   GUINT_TO_POINTER (ctx->priv->uri->port));

		ctx->priv->server->connections =
			g_slist_prepend (ctx->priv->server->connections, conn);

		break;

	case SOUP_ERROR_CANT_RESOLVE:
		connection_count--;
		g_object_unref (conn);
		break;

	default:
		connection_count--;
		g_object_unref (conn);

		/*
		 * Check if another connection exists to this server
		 * before reporting error. 
		 */
		if (ctx->priv->server->connections) {
			data->timeout_tag =
				g_timeout_add (
					150,
					(GSourceFunc) retry_connect_timeout_cb,
					data);
			return;
		}

		break;
	}

	(*data->cb) (ctx, status, conn, data->user_data);
	g_object_unref (ctx);
	g_free (data);
}

static gboolean
try_existing_connections (SoupContext           *ctx,
			  SoupConnectCallbackFn  cb,
			  gpointer               user_data)
{
	GSList *conns = ctx->priv->server->connections;
	
	while (conns) {
		SoupConnection *conn = conns->data;
		guint port = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (conn), "SoupContext-port"));

		if (!soup_connection_is_in_use (conn) &&
		    port == ctx->priv->uri->port) {
			/* Issue success callback */
			(*cb) (ctx, SOUP_ERROR_OK, conn, user_data);
			return TRUE;
		}

		conns = conns->next;
	}

	return FALSE;
}

static gboolean
try_create_connection (struct SoupConnectData *data)
{
	int conn_limit = soup_get_connection_limit ();
	SoupContext *proxy = soup_get_proxy ();
	SoupUri *uri = data->ctx->priv->uri;

	/* 
	 * Check if we are allowed to create a new connection, otherwise wait
	 * for next timeout.  
	 */
	if (conn_limit &&
	    connection_count >= conn_limit &&
	    !prune_least_used_connection ()) {
		data->conn = NULL;
		return FALSE;
	}

	connection_count++;

	data->timeout_tag = 0;

	if (proxy) {
		if (uri->protocol == SOUP_PROTOCOL_HTTPS) {
			data->conn = soup_connection_new_tunnel (
				proxy->priv->uri, uri,
				soup_context_connect_cb, data);
		} else {
			data->conn = soup_connection_new_proxy (
				proxy->priv->uri,
				soup_context_connect_cb, data);
		}
	} else
		data->conn = soup_connection_new (uri, soup_context_connect_cb, data);

	return TRUE;
}

static gboolean
retry_connect_timeout_cb (struct SoupConnectData *data)
{
	if (try_existing_connections (data->ctx, 
				      data->cb, 
				      data->user_data)) {
		g_object_unref (data->ctx);
		g_free (data);
		return FALSE;
	}

	return try_create_connection (data) == FALSE;
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

	g_return_val_if_fail (SOUP_IS_CONTEXT (ctx), NULL);

	/* Look for an existing unused connection */
	if (try_existing_connections (ctx, cb, user_data))
		return NULL;

	data = g_new0 (struct SoupConnectData, 1);
	data->cb = cb;
	data->user_data = user_data;

	data->ctx = g_object_ref (ctx);

	if (!try_create_connection (data)) {
		data->timeout_tag =
			g_timeout_add (150,
				       (GSourceFunc) retry_connect_timeout_cb,
				       data);
	}
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
	else if (data->conn) {
		connection_count--;
		g_object_unref (data->conn);
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
	g_return_val_if_fail (SOUP_IS_CONTEXT (ctx), NULL);
	return ctx->priv->uri;
}

static void
get_idle_conns_for_host (gpointer key, gpointer value, gpointer data)
{
	SoupHost *host = value;
	SoupConnection *conn;
	GSList *c, **idle_conns = data;

	for (c = host->connections; c; c = c->next) {
		conn = c->data;
		if (!soup_connection_is_in_use (conn))
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

	for (i = idle_conns; i; i = i->next) {
		soup_connection_disconnect (i->data);
		g_object_unref (i->data);
	}
	g_slist_free (idle_conns);
}


/* Authentication */

SoupAuth *
soup_context_lookup_auth (SoupContext *ctx, SoupMessage *msg)
{
	char *path, *dir;
	const char *realm;

	g_return_val_if_fail (SOUP_IS_CONTEXT (ctx), NULL);

	if (ctx->priv->server->ntlm_auths && msg) {
		SoupConnection *conn = soup_message_get_connection (msg);

		if (conn) {
			GHashTable *ntlm_auths = ctx->priv->server->ntlm_auths;
			SoupAuth *auth;

			auth = g_hash_table_lookup (ntlm_auths, conn);
			if (!auth) {
				auth = soup_auth_ntlm_new ();
				g_hash_table_insert (ntlm_auths, conn, auth);
			}
			return auth;
		}
	}

	if (!ctx->priv->server->auth_realms)
		return NULL;

	path = g_strdup (ctx->priv->uri->path);
	dir = path;
        do {
                realm = g_hash_table_lookup (ctx->priv->server->auth_realms, path);
                if (realm)
			break;

                dir = strrchr (path, '/');
                if (dir)
			*dir = '\0';
        } while (dir);

	g_free (path);
	if (realm)
		return g_hash_table_lookup (ctx->priv->server->auths, realm);
	else
		return NULL;
}

static gboolean
update_auth_internal (SoupContext *ctx, SoupConnection *conn,
		      const GSList *headers, gboolean prior_auth_failed)
{
	SoupHost *server = ctx->priv->server;
	SoupAuth *new_auth, *prior_auth, *old_auth;
	gpointer old_path, old_realm;
	const char *path;
	char *realm;
	GSList *pspace, *p;

	if (server->ntlm_auths && conn) {
		prior_auth = g_hash_table_lookup (server->ntlm_auths, conn);
		if (prior_auth) {
			if (soup_auth_is_authenticated (prior_auth)) {
				/* This is a "permission denied", not
				 * a "password incorrect". There's
				 * nothing more we can do.
				 */
				return FALSE;
			}

			/* Free the intermediate auth */
			g_hash_table_remove (server->ntlm_auths, conn);
			g_object_unref (prior_auth);
		}
	}

	/* Try to construct a new auth from the headers; if we can't,
	 * there's no way we'll be able to authenticate.
	 */
	new_auth = soup_auth_new_from_header_list (headers, ctx->priv->uri->authmech);
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
		if (!server->ntlm_auths)
			server->ntlm_auths = g_hash_table_new (NULL, NULL);
		if (conn) {
			g_hash_table_insert (server->ntlm_auths, conn, new_auth);
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
	pspace = soup_auth_get_protection_space (new_auth, ctx->priv->uri);
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

	g_return_val_if_fail (SOUP_IS_CONTEXT (ctx), FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);

	if (msg->errorcode == SOUP_ERROR_PROXY_UNAUTHORIZED) {
		headers = soup_message_get_header_list (msg->response_headers,
							"Proxy-Authenticate");
	} else {
		headers = soup_message_get_header_list (msg->response_headers,
							"WWW-Authenticate");
	}

	return update_auth_internal (ctx, soup_message_get_connection (msg),
				     headers, TRUE);
}

void
soup_context_preauthenticate (SoupContext *ctx, const char *header)
{
	GSList *headers;

	g_return_if_fail (SOUP_IS_CONTEXT (ctx));
	g_return_if_fail (header != NULL);

	headers = g_slist_append (NULL, (char *)header);
	update_auth_internal (ctx, NULL, headers, FALSE);
	g_slist_free (headers);
}

gboolean
soup_context_authenticate_auth (SoupContext *ctx, SoupAuth *auth)
{
	const SoupUri *uri = ctx->priv->uri;

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

	g_return_if_fail (SOUP_IS_CONTEXT (ctx));
	g_return_if_fail (auth != NULL);

	/* Try to just clean up the auth without removing it. */
	if (soup_auth_invalidate (auth))
		return;

	/* Nope, need to remove it completely */
	realm = g_strdup_printf ("%s:%s",
				 soup_auth_get_scheme_name (auth),
				 soup_auth_get_realm (auth));

	if (g_hash_table_lookup_extended (ctx->priv->server->auths, realm,
					  &key, &value) &&
	    auth == (SoupAuth *)value) {
		g_hash_table_remove (ctx->priv->server->auths, realm);
		g_free (key);
		g_object_unref (auth);
	}
	g_free (realm);
}
