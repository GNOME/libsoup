/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "soup-session.h"
#include "soup-connection.h"
#include "soup-connection-ntlm.h"
#include "soup-marshal.h"
#include "soup-message-queue.h"
#include "soup-private.h"

typedef struct {
	SoupUri    *root_uri;
	guint       error;

	GSList     *connections;      /* CONTAINS: SoupConnection */
	guint       num_conns;

	GHashTable *auth_realms;      /* path -> scheme:realm */
	GHashTable *auths;            /* scheme:realm -> SoupAuth */
} SoupSessionHost;

struct SoupSessionPrivate {
	SoupUri *proxy_uri;
	guint max_conns, max_conns_per_host;
	gboolean use_ntlm;

	SoupMessageQueue *queue;

	GHashTable *hosts; /* SoupUri -> SoupSessionHost */
	GHashTable *conns; /* SoupConnection -> SoupSessionHost */
	guint num_conns;

	SoupSessionHost *proxy_host;
};

static guint    host_uri_hash  (gconstpointer key);
static gboolean host_uri_equal (gconstpointer v1, gconstpointer v2);

static gboolean run_queue (SoupSession *session, gboolean try_pruning);

#define SOUP_SESSION_MAX_CONNS_DEFAULT 10
#define SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT 4

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	AUTHENTICATE,
	REAUTHENTICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
  PROP_0,

  PROP_PROXY_URI,
  PROP_MAX_CONNS,
  PROP_MAX_CONNS_PER_HOST,
  PROP_USE_NTLM,

  LAST_PROP
};

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
init (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);

	session->priv = g_new0 (SoupSessionPrivate, 1);
	session->priv->queue = soup_message_queue_new ();
	session->priv->hosts = g_hash_table_new (host_uri_hash,
						 host_uri_equal);
	session->priv->conns = g_hash_table_new (NULL, NULL);

	session->priv->max_conns = SOUP_SESSION_MAX_CONNS_DEFAULT;
	session->priv->max_conns_per_host = SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT;
}

static void
finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupMessageQueueIter iter;
	SoupMessage *msg;

	for (msg = soup_message_queue_first (session->priv->queue, &iter); msg;
	     msg = soup_message_queue_next (session->priv->queue, &iter)) {
		soup_message_queue_remove (session->priv->queue, &iter);
		soup_message_cancel (msg);
	}
	soup_message_queue_destroy (session->priv->queue);

	g_free (session->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */
	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSessionClass, authenticate),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT_STRING_STRING_POINTER_POINTER,
			      G_TYPE_NONE, 5,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_STRING,
			      G_TYPE_POINTER,
			      G_TYPE_POINTER);
	signals[REAUTHENTICATE] =
		g_signal_new ("reauthenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSessionClass, reauthenticate),
			      NULL, NULL,
			      soup_marshal_NONE__OBJECT_STRING_STRING_POINTER_POINTER,
			      G_TYPE_NONE, 5,
			      SOUP_TYPE_MESSAGE,
			      G_TYPE_STRING,
			      G_TYPE_STRING,
			      G_TYPE_POINTER,
			      G_TYPE_POINTER);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_PROXY_URI,
		g_param_spec_pointer (SOUP_SESSION_PROXY_URI,
				      "Proxy URI",
				      "The HTTP Proxy to use for this session",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS,
		g_param_spec_int (SOUP_SESSION_MAX_CONNS,
				  "Max Connection Count",
				  "The maximum number of connections that the session can open at once",
				  1,
				  G_MAXINT,
				  10,
				  G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS_PER_HOST,
		g_param_spec_int (SOUP_SESSION_MAX_CONNS_PER_HOST,
				  "Max Per-Host Connection Count",
				  "The maximum number of connections that the session can open at once to a given host",
				  1,
				  G_MAXINT,
				  4,
				  G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_USE_NTLM,
		g_param_spec_boolean (SOUP_SESSION_USE_NTLM,
				      "Use NTLM",
				      "Whether or not to use NTLM authentication",
				      FALSE,
				      G_PARAM_READWRITE));
}

SOUP_MAKE_TYPE (soup_session, SoupSession, class_init, init, PARENT_TYPE)

SoupSession *
soup_session_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION, NULL);
}

SoupSession *
soup_session_new_with_options (const char *optname1, ...)
{
	SoupSession *session;
	va_list ap;

	va_start (ap, optname1);
	session = (SoupSession *)g_object_new_valist (SOUP_TYPE_SESSION, optname1, ap);
	va_end (ap);

	return session;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	gpointer pval;

	switch (prop_id) {
	case PROP_PROXY_URI:
		pval = g_value_get_pointer (value);
		session->priv->proxy_uri = pval ? soup_uri_copy (pval) : NULL;
		break;
	case PROP_MAX_CONNS:
		session->priv->max_conns = g_value_get_int (value);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		session->priv->max_conns_per_host = g_value_get_int (value);
		break;
	case PROP_USE_NTLM:
		session->priv->use_ntlm = g_value_get_boolean (value);
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);

	switch (prop_id) {
	case PROP_PROXY_URI:
		g_value_set_pointer (value, session->priv->proxy_uri ?
				     soup_uri_copy (session->priv->proxy_uri) :
				     NULL);
		break;
	case PROP_MAX_CONNS:
		g_value_set_int (value, session->priv->max_conns);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		g_value_set_int (value, session->priv->max_conns_per_host);
		break;
	case PROP_USE_NTLM:
		g_value_set_boolean (value, session->priv->use_ntlm);
		break;
	default:
		break;
	}
}


/* Hosts */
static guint
host_uri_hash (gconstpointer key)
{
	const SoupUri *uri = key;

	return (uri->protocol << 16) + uri->port + g_str_hash (uri->host);
}

static gboolean
host_uri_equal (gconstpointer v1, gconstpointer v2)
{
	const SoupUri *one = v1;
	const SoupUri *two = v2;

	if (one->protocol != two->protocol)
		return FALSE;
	if (one->port != two->port)
		return FALSE;

	return strcmp (one->host, two->host) == 0;
}

static SoupSessionHost *
get_host_for_message (SoupSession *session, SoupMessage *msg)
{
	SoupSessionHost *host;
	const SoupUri *source = soup_message_get_uri (msg);

	host = g_hash_table_lookup (session->priv->hosts, source);
	if (host)
		return host;

	host = g_new0 (SoupSessionHost, 1);
	host->root_uri = soup_uri_copy_root (source);

	g_hash_table_insert (session->priv->hosts, host->root_uri, host);
	return host;
}


/* Authentication */

static SoupAuth *
lookup_auth (SoupSession *session, SoupMessage *msg, gboolean proxy)
{
	SoupSessionHost *host;
	char *path, *dir;
	const char *realm, *const_path;

	if (proxy) {
		host = session->priv->proxy_host;
		const_path = "/";
	} else {
		host = get_host_for_message (session, msg);
		const_path = soup_message_get_uri (msg)->path;
	}
	g_return_val_if_fail (host != NULL, NULL);

	if (!host->auth_realms)
		return NULL;

	path = g_strdup (const_path);
	dir = path;
        do {
                realm = g_hash_table_lookup (host->auth_realms, path);
                if (realm)
			break;

                dir = strrchr (path, '/');
                if (dir)
			*dir = '\0';
        } while (dir);

	g_free (path);
	if (realm)
		return g_hash_table_lookup (host->auths, realm);
	else
		return NULL;
}

static void
invalidate_auth (SoupSessionHost *host, SoupAuth *auth)
{
	char *realm;
	gpointer key, value;

	realm = g_strdup_printf ("%s:%s",
				 soup_auth_get_scheme_name (auth),
				 soup_auth_get_realm (auth));

	if (g_hash_table_lookup_extended (host->auths, realm, &key, &value) &&
	    auth == (SoupAuth *)value) {
		g_hash_table_remove (host->auths, realm);
		g_free (key);
		g_object_unref (auth);
	}
	g_free (realm);
}

static gboolean
authenticate_auth (SoupSession *session, SoupAuth *auth,
		   SoupMessage *msg, gboolean prior_auth_failed)
{
	const SoupUri *uri = soup_message_get_uri (msg);
	char *username = NULL, *password = NULL;

	if (uri->passwd && !prior_auth_failed) {
		soup_auth_authenticate (auth, uri->user, uri->passwd);
		return TRUE;
	}

	g_signal_emit (session, signals[prior_auth_failed ? REAUTHENTICATE : AUTHENTICATE], 0,
		       msg, soup_auth_get_scheme_name (auth),
		       soup_auth_get_realm (auth),
		       &username, &password);
	if (username || password)
		soup_auth_authenticate (auth, username, password);
	if (username)
		g_free (username);
	if (password) {
		memset (password, 0, strlen (password));
		g_free (password);
	}

	return soup_auth_is_authenticated (auth);
}

static gboolean
update_auth_internal (SoupSession *session, SoupMessage *msg,
		      const GSList *headers, gboolean proxy,
		      gboolean got_unauthorized)
{
	SoupSessionHost *host;
	SoupAuth *new_auth, *prior_auth, *old_auth;
	gpointer old_path, old_realm;
	const SoupUri *msg_uri;
	const char *path;
	char *realm;
	GSList *pspace, *p;
	gboolean prior_auth_failed = FALSE;

	host = get_host_for_message (session, msg);
	g_return_val_if_fail (host != NULL, FALSE);

	/* Try to construct a new auth from the headers; if we can't,
	 * there's no way we'll be able to authenticate.
	 */
	msg_uri = soup_message_get_uri (msg);
	new_auth = soup_auth_new_from_header_list (headers);
	if (!new_auth)
		return FALSE;

	/* See if this auth is the same auth we used last time */
	prior_auth = lookup_auth (session, msg, proxy);
	if (prior_auth &&
	    G_OBJECT_TYPE (prior_auth) == G_OBJECT_TYPE (new_auth) &&
	    !strcmp (soup_auth_get_realm (prior_auth),
		     soup_auth_get_realm (new_auth))) {
		if (!got_unauthorized) {
			/* The user is just trying to preauthenticate
			 * using information we already have, so
			 * there's nothing more that needs to be done.
			 */
			g_object_unref (new_auth);
			return TRUE;
		}

		/* The server didn't like the username/password we
		 * provided before. Invalidate it and note this fact.
		 */
		invalidate_auth (host, prior_auth);
		prior_auth_failed = TRUE;
	}

	if (!host->auth_realms) {
		host->auth_realms = g_hash_table_new (g_str_hash, g_str_equal);
		host->auths = g_hash_table_new (g_str_hash, g_str_equal);
	}

	/* Record where this auth realm is used */
	realm = g_strdup_printf ("%s:%s",
				 soup_auth_get_scheme_name (new_auth),
				 soup_auth_get_realm (new_auth));
	pspace = soup_auth_get_protection_space (new_auth, msg_uri);
	for (p = pspace; p; p = p->next) {
		path = p->data;
		if (g_hash_table_lookup_extended (host->auth_realms, path,
						  &old_path, &old_realm)) {
			g_hash_table_remove (host->auth_realms, old_path);
			g_free (old_path);
			g_free (old_realm);
		}

		g_hash_table_insert (host->auth_realms,
				     g_strdup (path), g_strdup (realm));
	}
	soup_auth_free_protection_space (new_auth, pspace);

	/* Now, make sure the auth is recorded. (If there's a
	 * pre-existing auth, we keep that rather than the new one,
	 * since the old one might already be authenticated.)
	 */
	old_auth = g_hash_table_lookup (host->auths, realm);
	if (old_auth) {
		g_free (realm);
		g_object_unref (new_auth);
		new_auth = old_auth;
	} else 
		g_hash_table_insert (host->auths, realm, new_auth);

	/* If we need to authenticate, try to do it. */
	if (!soup_auth_is_authenticated (new_auth)) {
		return authenticate_auth (session, new_auth,
					  msg, prior_auth_failed);
	}

	/* Otherwise we're good. */
	return TRUE;
}

static void
connection_authenticate (SoupConnection *conn, SoupMessage *msg,
			 const char *auth_type, const char *auth_realm,
			 char **username, char **password, gpointer session)
{
	g_signal_emit (session, signals[AUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}

static void
connection_reauthenticate (SoupConnection *conn, SoupMessage *msg,
			   const char *auth_type, const char *auth_realm,
			   char **username, char **password,
			   gpointer user_data)
{
	g_signal_emit (conn, signals[REAUTHENTICATE], 0,
		       msg, auth_type, auth_realm, username, password);
}


static void
authorize_handler (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	const GSList *headers;
	gboolean proxy;

	if (msg->status_code == SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED) {
		headers = soup_message_get_header_list (msg->response_headers,
							"Proxy-Authenticate");
		proxy = TRUE;
	} else {
		headers = soup_message_get_header_list (msg->response_headers,
							"WWW-Authenticate");
		proxy = FALSE;
	}
	if (!headers)
		return;

	if (update_auth_internal (session, msg, headers, proxy, TRUE))
		soup_session_requeue_message (session, msg);
}

static void
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	const char *new_loc;
	SoupUri *new_uri;

	new_loc = soup_message_get_header (msg->response_headers, "Location");
	if (!new_loc)
		return;
	new_uri = soup_uri_new (new_loc);
	if (!new_uri)
		goto INVALID_REDIRECT;

	soup_message_set_uri (msg, new_uri);
	soup_uri_free (new_uri);

	soup_session_requeue_message (session, msg);
	return;

 INVALID_REDIRECT:
	soup_message_set_status_full (msg,
				      SOUP_STATUS_MALFORMED,
				      "Invalid Redirect URL");
}

static void
request_finished (SoupMessage *req, gpointer user_data)
{
	req->status = SOUP_MESSAGE_STATUS_FINISHED;
}

static void
final_finished (SoupMessage *req, gpointer user_data)
{
	SoupSession *session = user_data;

	if (!SOUP_MESSAGE_IS_STARTING (req)) {
		soup_message_queue_remove_message (session->priv->queue, req);

		g_signal_handlers_disconnect_by_func (req, request_finished, session);
		g_signal_handlers_disconnect_by_func (req, final_finished, session);
		g_object_unref (req);

		run_queue (session, FALSE);
	}
}

static void
add_auth (SoupSession *session, SoupMessage *msg, gboolean proxy)
{
	const char *header = proxy ? "Proxy-Authorization" : "Authorization";
	SoupAuth *auth;
	char *token;

	soup_message_remove_header (msg->request_headers, header);

	auth = lookup_auth (session, msg, proxy);
	if (!auth)
		return;
	if (!soup_auth_is_authenticated (auth) &&
	    !authenticate_auth (session, auth, msg, FALSE))
		return;

	token = soup_auth_get_authorization (auth, msg);
	if (token) {
		soup_message_add_header (msg->request_headers, header, token);
		g_free (token);
	}
}

static void
send_request (SoupSession *session, SoupMessage *req, SoupConnection *conn)
{
	req->status = SOUP_MESSAGE_STATUS_RUNNING;

	add_auth (session, req, FALSE);
	if (session->priv->proxy_uri)
		add_auth (session, req, TRUE);
	soup_connection_send_request (conn, req);
}

static void
find_oldest_connection (gpointer key, gpointer host, gpointer data)
{
	SoupConnection *conn = key, **oldest = data;

	if (!oldest || (soup_connection_last_used (conn) <
			soup_connection_last_used (*oldest)))
		*oldest = conn;
}

static gboolean
try_prune_connection (SoupSession *session)
{
	SoupConnection *oldest = NULL;

	g_hash_table_foreach (session->priv->conns, find_oldest_connection,
			      &oldest);
	if (oldest) {
		soup_connection_disconnect (oldest);
		g_object_unref (oldest);
		return TRUE;
	} else
		return FALSE;
}

static void connection_closed (SoupConnection *conn, SoupSession *session);

static void
cleanup_connection (SoupSession *session, SoupConnection *conn)
{
	SoupSessionHost *host =
		g_hash_table_lookup (session->priv->conns, conn);

	g_return_if_fail (host != NULL);

	g_hash_table_remove (session->priv->conns, conn);
	g_signal_handlers_disconnect_by_func (conn, connection_closed, session);
	session->priv->num_conns--;

	host->connections = g_slist_remove (host->connections, conn);
	host->num_conns--;
}

static void
connection_closed (SoupConnection *conn, SoupSession *session)
{
	cleanup_connection (session, conn);

	/* Run the queue in case anyone was waiting for a connection
	 * to be closed.
	 */
	run_queue (session, FALSE);
}

static void
got_connection (SoupConnection *conn, guint status, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionHost *host = g_hash_table_lookup (session->priv->conns, conn);

	g_return_if_fail (host != NULL);

	if (status == SOUP_STATUS_OK) {
		host->connections = g_slist_prepend (host->connections, conn);
		run_queue (session, FALSE);
		return;
	}

	/* We failed */
	cleanup_connection (session, conn);
	g_object_unref (conn);

	if (host->connections) {
		/* Something went wrong this time, but we have at
		 * least one open connection to this host. So just
		 * leave the message in the queue so it can use that
		 * connection once it's free.
		 */
		return;
	}

	/* Flush any queued messages for this host */
	host->error = status;
	run_queue (session, FALSE);

	if (status != SOUP_STATUS_CANT_RESOLVE &&
	    status != SOUP_STATUS_CANT_RESOLVE_PROXY) {
		/* If the error was "can't resolve", then it's not likely
		 * to improve. But if it was something else, it may have
		 * been transient, so we clear the error so the user can
		 * try again later.
		 */
		host->error = 0;
	}
}

static gboolean
run_queue (SoupSession *session, gboolean try_pruning)
{
	SoupMessageQueueIter iter;
	SoupMessage *msg;
	SoupConnection *conn;
	SoupSessionHost *host;
	gboolean skipped_any = FALSE, started_any = FALSE;
	GSList *conns;

	/* FIXME: prefer CONNECTING messages */

 try_again:
	for (msg = soup_message_queue_first (session->priv->queue, &iter); msg; msg = soup_message_queue_next (session->priv->queue, &iter)) {

		if (!SOUP_MESSAGE_IS_STARTING (msg))
			continue;

		host = get_host_for_message (session, msg);

		/* If the hostname is known to be bad, fail right away */
		if (host->error) {
			soup_message_set_status (msg, host->error);
			soup_message_finished (msg);
		}

		/* If there is an idle connection, use it */
		for (conns = host->connections; conns; conns = conns->next) {
			if (!soup_connection_is_in_use (conns->data))
				break;
		}
		if (conns) {
			send_request (session, msg, conns->data);
			started_any = TRUE;
			continue;
		}

		if (msg->status == SOUP_MESSAGE_STATUS_CONNECTING) {
			/* We already started a connection for this
			 * message, so don't start another one.
			 */
			continue;
		}

		/* If we have the max number of per-host connections
		 * or total connections open, we'll have to wait.
		 */
		if (host->num_conns >= session->priv->max_conns_per_host)
			continue;
		else if (session->priv->num_conns >= session->priv->max_conns) {
			/* In this case, closing an idle connection
			 * somewhere else would let us open one here.
			 */
			skipped_any = TRUE;
			continue;
		}

		/* Otherwise, open a new connection */
		conn = g_object_new (
			(session->priv->use_ntlm ?
			 SOUP_TYPE_CONNECTION_NTLM : SOUP_TYPE_CONNECTION),
			SOUP_CONNECTION_DEST_URI, host->root_uri,
			SOUP_CONNECTION_PROXY_URI, session->priv->proxy_uri,
			NULL);
		g_signal_connect (conn, "authenticate",
				  G_CALLBACK (connection_authenticate),
				  session);
		g_signal_connect (conn, "reauthenticate",
				  G_CALLBACK (connection_reauthenticate),
				  session);

		soup_connection_connect_async (conn, got_connection, session);
		g_signal_connect (conn, "disconnected",
				  G_CALLBACK (connection_closed), session);
		g_hash_table_insert (session->priv->conns, conn, host);
		session->priv->num_conns++;

		/* Increment the host's connection count, but don't add
		 * this connection to the list yet, since it's not ready.
		 */
		host->num_conns++;

		/* Mark the request as connecting, so we don't try to
		 * open another new connection for it next time around.
		 */
		msg->status = SOUP_MESSAGE_STATUS_CONNECTING;

		started_any = TRUE;
	}

	if (try_pruning && skipped_any && !started_any) {
		/* We didn't manage to start any message, but there is
		 * at least one message in the queue that could be
		 * sent if we pruned an idle connection from some
		 * other server.
		 */
		if (try_prune_connection (session)) {
			try_pruning = FALSE;
			goto try_again;
		}
	}

	return started_any;
}

static void
queue_message (SoupSession *session, SoupMessage *req, gboolean requeue)
{
	req->status = SOUP_MESSAGE_STATUS_QUEUED;
	if (!requeue)
		soup_message_queue_append (session->priv->queue, req);

	run_queue (session, TRUE);
}

/**
 * soup_session_queue_message:
 * @session: a #SoupSession
 * @req: the message to queue
 * @callback: a #SoupMessageCallbackFn which will be called after the
 * message completes or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message @req for sending. All messages are processed
 * while the glib main loop runs. If @req has been processed before,
 * any resources related to the time it was last sent are freed.
 *
 * Upon message completion, the callback specified in @callback will
 * be invoked. If after returning from this callback the message has
 * not been requeued, @req will be unreffed.
 */
void
soup_session_queue_message (SoupSession *session, SoupMessage *req,
			    SoupMessageCallbackFn callback, gpointer user_data)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	g_signal_connect (req, "finished",
			  G_CALLBACK (request_finished), session);
	if (callback) {
		g_signal_connect (req, "finished",
				  G_CALLBACK (callback), user_data);
	}
	g_signal_connect_after (req, "finished",
				G_CALLBACK (final_finished), session);

	soup_message_add_status_code_handler  (req, SOUP_STATUS_UNAUTHORIZED,
					       SOUP_HANDLER_POST_BODY,
					       authorize_handler, session);
	soup_message_add_status_code_handler  (req,
					       SOUP_STATUS_PROXY_UNAUTHORIZED,
					       SOUP_HANDLER_POST_BODY,
					       authorize_handler, session);

	if (!(soup_message_get_flags (req) & SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_status_class_handler (
			req, SOUP_STATUS_CLASS_REDIRECT,
			SOUP_HANDLER_POST_BODY,
			redirect_handler, session);
	}

	queue_message (session, req, FALSE);
}

/**
 * soup_session_requeue_message:
 * @session: a #SoupSession
 * @req: the message to requeue
 *
 * This causes @req to be placed back on the queue to be attempted
 * again.
 **/
void
soup_session_requeue_message (SoupSession *session, SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	queue_message (session, req, TRUE);
}


/**
 * soup_session_send_message:
 * @session: a #SoupSession
 * @req: the message to send
 * 
 * Synchronously send @req. This call will not return until the
 * transfer is finished successfully or there is an unrecoverable
 * error.
 *
 * @req is not freed upon return.
 *
 * Return value: the HTTP status code of the response
 */
guint
soup_session_send_message (SoupSession *session, SoupMessage *req)
{
	g_return_val_if_fail (SOUP_IS_SESSION (session), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (SOUP_IS_MESSAGE (req), SOUP_STATUS_MALFORMED);

	/* Balance out the unref that final_finished will do */
	g_object_ref (req);

	soup_session_queue_message (session, req, NULL, NULL);

	while (1) {
		g_main_iteration (TRUE);

		if (req->status == SOUP_MESSAGE_STATUS_FINISHED ||
		    SOUP_STATUS_IS_TRANSPORT (req->status_code))
			break;
	}

	return req->status_code;
}
