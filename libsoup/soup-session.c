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

#include "soup-auth.h"
#include "soup-connection.h"
#include "soup-connection-ntlm.h"
#include "soup-marshal.h"
#include "soup-message-filter.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-session.h"
#include "soup-session-private.h"
#include "soup-ssl.h"
#include "soup-uri.h"

typedef struct {
	SoupUri    *root_uri;

	GSList     *connections;      /* CONTAINS: SoupConnection */
	guint       num_conns;

	GHashTable *auth_realms;      /* path -> scheme:realm */
	GHashTable *auths;            /* scheme:realm -> SoupAuth */
} SoupSessionHost;

typedef struct {
	SoupUri *proxy_uri;
	guint max_conns, max_conns_per_host;
	gboolean use_ntlm;

	char *ssl_ca_file;
	SoupSSLCredentials *ssl_creds;

	SoupMessageQueue *queue;

	GSList *filters;

	GHashTable *hosts; /* SoupUri -> SoupSessionHost */
	GHashTable *conns; /* SoupConnection -> SoupSessionHost */
	guint num_conns;

	SoupSessionHost *proxy_host;

	/* Must hold the host_lock before potentially creating a
	 * new SoupSessionHost, or adding/removing a connection.
	 * Must not emit signals or destroy objects while holding it.
	 */
	GMutex *host_lock;

	GMainContext *async_context;

	/* Holds the timeout value for the connection, when
	   no response is received.
	*/
	guint timeout;
} SoupSessionPrivate;
#define SOUP_SESSION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_SESSION, SoupSessionPrivate))

static guint    host_uri_hash  (gconstpointer key);
static gboolean host_uri_equal (gconstpointer v1, gconstpointer v2);
static void     free_host      (SoupSessionHost *host);

static void setup_message   (SoupMessageFilter *filter, SoupMessage *msg);

static void queue_message   (SoupSession *session, SoupMessage *msg,
			     SoupMessageCallbackFn callback,
			     gpointer user_data);
static void requeue_message (SoupSession *session, SoupMessage *msg);
static void cancel_message  (SoupSession *session, SoupMessage *msg);

#define SOUP_SESSION_MAX_CONNS_DEFAULT 10
#define SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT 4

static void filter_iface_init (SoupMessageFilterClass *filter_class);

G_DEFINE_TYPE_EXTENDED (SoupSession, soup_session, G_TYPE_OBJECT, 0,
			G_IMPLEMENT_INTERFACE (SOUP_TYPE_MESSAGE_FILTER,
					       filter_iface_init))

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
	PROP_SSL_CA_FILE,
	PROP_ASYNC_CONTEXT,
	PROP_TIMEOUT,

	LAST_PROP
};

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_session_init (SoupSession *session)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	priv->queue = soup_message_queue_new ();

	priv->host_lock = g_mutex_new ();
	priv->hosts = g_hash_table_new (host_uri_hash, host_uri_equal);
	priv->conns = g_hash_table_new (NULL, NULL);

	priv->max_conns = SOUP_SESSION_MAX_CONNS_DEFAULT;
	priv->max_conns_per_host = SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT;

	priv->timeout = 0;
}

static gboolean
foreach_free_host (gpointer key, gpointer host, gpointer data)
{
	free_host (host);
	return TRUE;
}

static void
cleanup_hosts (SoupSessionPrivate *priv)
{
	GHashTable *old_hosts;

	g_mutex_lock (priv->host_lock);
	old_hosts = priv->hosts;
	priv->hosts = g_hash_table_new (host_uri_hash, host_uri_equal);
	g_mutex_unlock (priv->host_lock);

	g_hash_table_foreach_remove (old_hosts, foreach_free_host, NULL);
	g_hash_table_destroy (old_hosts);
}

static void
dispose (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	GSList *f;

	soup_session_abort (session);
	cleanup_hosts (priv);

	if (priv->filters) {
		for (f = priv->filters; f; f = f->next)
			g_object_unref (f->data);
		g_slist_free (priv->filters);
		priv->filters = NULL;
	}

	G_OBJECT_CLASS (soup_session_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	soup_message_queue_destroy (priv->queue);

	g_mutex_free (priv->host_lock);
	g_hash_table_destroy (priv->hosts);
	g_hash_table_destroy (priv->conns);

	if (priv->proxy_uri)
		soup_uri_free (priv->proxy_uri);
	if (priv->proxy_host)
		free_host (priv->proxy_host);

	if (priv->ssl_creds)
		soup_ssl_free_client_credentials (priv->ssl_creds);

	if (priv->async_context)
		g_main_context_unref (priv->async_context);

	G_OBJECT_CLASS (soup_session_parent_class)->finalize (object);
}

static void
soup_session_class_init (SoupSessionClass *session_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (session_class);

	g_type_class_add_private (session_class, sizeof (SoupSessionPrivate));

	/* virtual method definition */
	session_class->queue_message = queue_message;
	session_class->requeue_message = requeue_message;
	session_class->cancel_message = cancel_message;

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */

	/**
	 * SoupSession::authenticate:
	 * @session: the session
	 * @msg: the #SoupMessage being sent
	 * @auth_type: the authentication type
	 * @auth_realm: the realm being authenticated to
	 * @username: the signal handler should set this to point to
	 * the provided username
	 * @password: the signal handler should set this to point to
	 * the provided password
	 *
	 * Emitted when the session requires authentication. The
	 * credentials may come from the user, or from cached
	 * information. If no credentials are available, leave
	 * @username and @password unchanged.
	 *
	 * If the provided credentials fail, the #reauthenticate
	 * signal will be emitted.
	 **/
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

	/**
	 * SoupSession::reauthenticate:
	 * @session: the session
	 * @msg: the #SoupMessage being sent
	 * @auth_type: the authentication type
	 * @auth_realm: the realm being authenticated to
	 * @username: the signal handler should set this to point to
	 * the provided username
	 * @password: the signal handler should set this to point to
	 * the provided password
	 *
	 * Emitted when the credentials provided by the application to
	 * the #authenticate signal have failed. This gives the
	 * application a second chance to provide authentication
	 * credentials. If the new credentials also fail, #SoupSession
	 * will emit #reauthenticate again, and will continue doing so
	 * until the provided credentials work, or a #reauthenticate
	 * signal emission "fails" (because the handler left @username
	 * and @password unchanged). At that point, the 401 or 407
	 * error status will be returned to the caller.
	 *
	 * If your application only uses cached passwords, it should
	 * only connect to #authenticate, and not #reauthenticate.
	 *
	 * If your application always prompts the user for a password,
	 * and never uses cached information, then you can connect the
	 * same handler to #authenticate and #reauthenticate.
	 *
	 * To get standard web-browser behavior, return either cached
	 * information or a user-provided password (whichever is
	 * available) from the #authenticate handler, but return only
	 * user-provided information from the #reauthenticate handler.
	 **/
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
				      G_PARAM_READWRITE));
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
	g_object_class_install_property (
		object_class, PROP_SSL_CA_FILE,
		g_param_spec_string (SOUP_SESSION_SSL_CA_FILE,
				     "SSL CA file",
				     "File containing SSL CA certificates",
				     NULL,
				     G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_SESSION_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "The GMainContext to dispatch async I/O in",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_TIMEOUT,
		g_param_spec_uint (SOUP_SESSION_TIMEOUT,
				   "Timeout value",
				   "Value in seconds to timeout a blocking I/O",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE));
}

static void
filter_iface_init (SoupMessageFilterClass *filter_class)
{
	/* interface implementation */
	filter_class->setup_message = setup_message;
}


static gboolean
safe_uri_equal (const SoupUri *a, const SoupUri *b)
{
	if (!a && !b)
		return TRUE;

	if ((a && !b) || (b && !a))
		return FALSE;

	return soup_uri_equal (a, b);
}

static gboolean
safe_str_equal (const char *a, const char *b)
{
	if (!a && !b)
		return TRUE;

	if ((a && !b) || (b && !a))
		return FALSE;

	return strcmp (a, b) == 0;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	gpointer pval;
	gboolean need_abort = FALSE;
	gboolean ca_file_changed = FALSE;
	const char *new_ca_file;

	switch (prop_id) {
	case PROP_PROXY_URI:
		pval = g_value_get_pointer (value);

		if (!safe_uri_equal (priv->proxy_uri, pval))
			need_abort = TRUE;

		if (priv->proxy_uri)
			soup_uri_free (priv->proxy_uri);

		priv->proxy_uri = pval ? soup_uri_copy (pval) : NULL;

		if (need_abort) {
			soup_session_abort (session);
			cleanup_hosts (priv);
		}

		break;
	case PROP_MAX_CONNS:
		priv->max_conns = g_value_get_int (value);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		priv->max_conns_per_host = g_value_get_int (value);
		break;
	case PROP_USE_NTLM:
		priv->use_ntlm = g_value_get_boolean (value);
		break;
	case PROP_SSL_CA_FILE:
		new_ca_file = g_value_get_string (value);

		if (!safe_str_equal (priv->ssl_ca_file, new_ca_file))
			ca_file_changed = TRUE;

		g_free (priv->ssl_ca_file);
		priv->ssl_ca_file = g_strdup (new_ca_file);

		if (ca_file_changed) {
			if (priv->ssl_creds) {
				soup_ssl_free_client_credentials (priv->ssl_creds);
				priv->ssl_creds = NULL;
			}

			cleanup_hosts (priv);
		}

		break;
	case PROP_ASYNC_CONTEXT:
		priv->async_context = g_value_get_pointer (value);
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
		break;
	case PROP_TIMEOUT:
		priv->timeout = g_value_get_uint (value);
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
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	switch (prop_id) {
	case PROP_PROXY_URI:
		g_value_set_pointer (value, priv->proxy_uri ?
				     soup_uri_copy (priv->proxy_uri) :
				     NULL);
		break;
	case PROP_MAX_CONNS:
		g_value_set_int (value, priv->max_conns);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		g_value_set_int (value, priv->max_conns_per_host);
		break;
	case PROP_USE_NTLM:
		g_value_set_boolean (value, priv->use_ntlm);
		break;
	case PROP_SSL_CA_FILE:
		g_value_set_string (value, priv->ssl_ca_file);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, priv->timeout);
		break;
	default:
		break;
	}
}


/**
 * soup_session_add_filter:
 * @session: a #SoupSession
 * @filter: an object implementing the #SoupMessageFilter interface
 *
 * Adds @filter to @session's list of message filters to be applied to
 * all messages.
 **/
void
soup_session_add_filter (SoupSession *session, SoupMessageFilter *filter)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE_FILTER (filter));
	priv = SOUP_SESSION_GET_PRIVATE (session);

	g_object_ref (filter);
	priv->filters = g_slist_prepend (priv->filters, filter);
}

/**
 * soup_session_remove_filter:
 * @session: a #SoupSession
 * @filter: an object implementing the #SoupMessageFilter interface
 *
 * Removes @filter from @session's list of message filters
 **/
void
soup_session_remove_filter (SoupSession *session, SoupMessageFilter *filter)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE_FILTER (filter));
	priv = SOUP_SESSION_GET_PRIVATE (session);

	priv->filters = g_slist_remove (priv->filters, filter);
	g_object_unref (filter);
}

/**
 * soup_session_get_async_context:
 * @session: a #SoupSession
 *
 * Gets @session's async_context. This does not add a ref to the
 * context, so you will need to ref it yourself if you want it to
 * outlive its session.
 *
 * Return value: @session's #GMainContext, which may be %NULL
 **/
GMainContext *
soup_session_get_async_context (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	priv = SOUP_SESSION_GET_PRIVATE (session);

	return priv->async_context;
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
soup_session_host_new (SoupSession *session, const SoupUri *source_uri)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupSessionHost *host;

	host = g_new0 (SoupSessionHost, 1);
	host->root_uri = soup_uri_copy_root (source_uri);

	if (host->root_uri->protocol == SOUP_PROTOCOL_HTTPS &&
	    !priv->ssl_creds) {
		priv->ssl_creds =
			soup_ssl_get_client_credentials (priv->ssl_ca_file);
	}

	return host;
}

/* Note: get_host_for_message doesn't lock the host_lock. The caller
 * must do it itself if there's a chance the host doesn't already
 * exist.
 */
static SoupSessionHost *
get_host_for_message (SoupSession *session, SoupMessage *msg)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupSessionHost *host;
	const SoupUri *source = soup_message_get_uri (msg);

	host = g_hash_table_lookup (priv->hosts, source);
	if (host)
		return host;

	host = soup_session_host_new (session, source);
	g_hash_table_insert (priv->hosts, host->root_uri, host);

	return host;
}

/* Note: get_proxy_host doesn't lock the host_lock. The caller must do
 * it itself if there's a chance the host doesn't already exist.
 */
static SoupSessionHost *
get_proxy_host (SoupSession *session)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	if (priv->proxy_host || !priv->proxy_uri)
		return priv->proxy_host;

	priv->proxy_host =
		soup_session_host_new (session, priv->proxy_uri);
	return priv->proxy_host;
}

static void
free_realm (gpointer path, gpointer scheme_realm, gpointer data)
{
	g_free (path);
	g_free (scheme_realm);
}

static void
free_auth (gpointer scheme_realm, gpointer auth, gpointer data)
{
	g_free (scheme_realm);
	g_object_unref (auth);
}

static void
free_host (SoupSessionHost *host)
{
	while (host->connections) {
		SoupConnection *conn = host->connections->data;

		host->connections = g_slist_remove (host->connections, conn);
		soup_connection_disconnect (conn);
	}

	if (host->auth_realms) {
		g_hash_table_foreach (host->auth_realms, free_realm, NULL);
		g_hash_table_destroy (host->auth_realms);
	}
	if (host->auths) {
		g_hash_table_foreach (host->auths, free_auth, NULL);
		g_hash_table_destroy (host->auths);
	}

	soup_uri_free (host->root_uri);
	g_free (host);
}	

/* Authentication */

static SoupAuth *
lookup_auth (SoupSession *session, SoupMessage *msg, gboolean proxy)
{
	SoupSessionHost *host;
	char *path, *dir;
	const char *realm, *const_path;

	if (proxy) {
		host = get_proxy_host (session);
		const_path = "/";
	} else {
		host = get_host_for_message (session, msg);
		const_path = soup_message_get_uri (msg)->path;

		if (!const_path)
			const_path = "/";
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
                if (dir) {
			if (dir[1])
				dir[1] = '\0';
			else
				*dir = '\0';
		}
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
	char *info;
	gpointer key, value;

	info = soup_auth_get_info (auth);
	if (g_hash_table_lookup_extended (host->auths, info, &key, &value) &&
	    auth == (SoupAuth *)value) {
		g_hash_table_remove (host->auths, info);
		g_free (key);
		g_object_unref (auth);
	}
	g_free (info);
}

static gboolean
authenticate_auth (SoupSession *session, SoupAuth *auth,
		   SoupMessage *msg, gboolean prior_auth_failed,
		   gboolean proxy)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	const SoupUri *uri;
	char *username = NULL, *password = NULL;

	if (proxy)
		uri = priv->proxy_uri;
	else
		uri = soup_message_get_uri (msg);

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
update_auth_internal (SoupSession *session, SoupMessage *msg, gboolean proxy)
{
	SoupSessionHost *host;
	SoupAuth *new_auth, *prior_auth, *old_auth;
	gpointer old_path, old_auth_info;
	const char *path;
	char *auth_info;
	GSList *pspace, *p;
	gboolean prior_auth_failed = FALSE;

	if (proxy)
		host = get_proxy_host (session);
	else
		host = get_host_for_message (session, msg);

	g_return_val_if_fail (host != NULL, FALSE);

	/* Try to construct a new auth from the headers; if we can't,
	 * there's no way we'll be able to authenticate.
	 */
	new_auth = soup_auth_new_from_headers (
		msg->response_headers,
		proxy ? "Proxy-Authenticate" : "WWW-Authenticate");
	if (!new_auth)
		return FALSE;

	auth_info = soup_auth_get_info (new_auth);

	/* See if this auth is the same auth we used last time */
	prior_auth = proxy ? soup_message_get_proxy_auth (msg) : soup_message_get_auth (msg);
	if (prior_auth) {
		char *old_auth_info = soup_auth_get_info (prior_auth);

		if (!strcmp (old_auth_info, auth_info)) {
			/* The server didn't like the username/password we
			 * provided before. Invalidate it and note this fact.
			 */
			invalidate_auth (host, prior_auth);
			prior_auth_failed = TRUE;
		}
		g_free (old_auth_info);
	}

	if (!host->auth_realms) {
		host->auth_realms = g_hash_table_new (g_str_hash, g_str_equal);
		host->auths = g_hash_table_new (g_str_hash, g_str_equal);
	}

	/* Record where this auth realm is used. RFC 2617 is somewhat
	 * unclear about the scope of protection spaces with regard to
	 * proxies. The only mention of it is as an aside in section
	 * 3.2.1, where it is defining the fields of a Digest
	 * challenge and says that the protection space is always the
	 * entire proxy. Is this the case for all authentication
	 * schemes or just Digest? Who knows, but we're assuming all.
	 */
	if (proxy)
		pspace = g_slist_prepend (NULL, g_strdup (""));
	else
		pspace = soup_auth_get_protection_space (new_auth, soup_message_get_uri (msg));

	for (p = pspace; p; p = p->next) {
		path = p->data;
		if (g_hash_table_lookup_extended (host->auth_realms, path,
						  &old_path, &old_auth_info)) {
			g_hash_table_remove (host->auth_realms, old_path);
			g_free (old_path);
			g_free (old_auth_info);
		}

		g_hash_table_insert (host->auth_realms,
				     g_strdup (path), g_strdup (auth_info));
	}
	soup_auth_free_protection_space (new_auth, pspace);

	/* Now, make sure the auth is recorded. (If there's a
	 * pre-existing auth, we keep that rather than the new one,
	 * since the old one might already be authenticated.)
	 */
	old_auth = g_hash_table_lookup (host->auths, auth_info);
	if (old_auth) {
		g_free (auth_info);
		g_object_unref (new_auth);
		new_auth = old_auth;
	} else 
		g_hash_table_insert (host->auths, auth_info, new_auth);

	/* If we need to authenticate, try to do it. */
	if (!soup_auth_is_authenticated (new_auth)) {
		return authenticate_auth (session, new_auth,
					  msg, prior_auth_failed, proxy);
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
	gboolean proxy;

	proxy = (msg->status_code == SOUP_STATUS_PROXY_AUTHENTICATION_REQUIRED);
	if (update_auth_internal (session, msg, proxy))
		soup_session_requeue_message (session, msg);
}

static void
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	const char *new_loc;
	SoupUri *new_uri;

	new_loc = soup_message_headers_find (msg->response_headers, "Location");
	if (!new_loc)
		return;

	/* Location is supposed to be an absolute URI, but some sites
	 * are lame, so we use soup_uri_new_with_base().
	 */
	new_uri = soup_uri_new_with_base (soup_message_get_uri (msg), new_loc);
	if (!new_uri) {
		soup_message_set_status_full (msg,
					      SOUP_STATUS_MALFORMED,
					      "Invalid Redirect URL");
		return;
	}

	soup_message_set_uri (msg, new_uri);
	soup_uri_free (new_uri);

	soup_session_requeue_message (session, msg);
}

static void
add_auth (SoupSession *session, SoupMessage *msg, gboolean proxy)
{
	SoupAuth *auth;

	auth = lookup_auth (session, msg, proxy);
	if (auth && !soup_auth_is_authenticated (auth)) {
		if (!authenticate_auth (session, auth, msg, FALSE, proxy))
			auth = NULL;
	}

	if (proxy)
		soup_message_set_proxy_auth (msg, auth);
	else
		soup_message_set_auth (msg, auth);
}

static void
setup_message (SoupMessageFilter *filter, SoupMessage *msg)
{
	SoupSession *session = SOUP_SESSION (filter);
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	GSList *f;

	for (f = priv->filters; f; f = f->next) {
		filter = f->data;
		soup_message_filter_setup_message (filter, msg);
	}

	add_auth (session, msg, FALSE);
	soup_message_add_status_code_handler (
		msg, SOUP_STATUS_UNAUTHORIZED,
		SOUP_HANDLER_POST_BODY,
		authorize_handler, session);

	if (priv->proxy_uri) {
		add_auth (session, msg, TRUE);
		soup_message_add_status_code_handler  (
			msg, SOUP_STATUS_PROXY_UNAUTHORIZED,
			SOUP_HANDLER_POST_BODY,
			authorize_handler, session);
	}
}

static void
find_oldest_connection (gpointer key, gpointer host, gpointer data)
{
	SoupConnection *conn = key, **oldest = data;

	/* Don't prune a connection that is currently in use, or
	 * hasn't been used yet.
	 */
	if (soup_connection_is_in_use (conn) ||
	    soup_connection_last_used (conn) == 0)
		return;

	if (!*oldest || (soup_connection_last_used (conn) <
			 soup_connection_last_used (*oldest)))
		*oldest = conn;
}

/**
 * soup_session_try_prune_connection:
 * @session: a #SoupSession
 *
 * Finds the least-recently-used idle connection in @session and closes
 * it.
 *
 * Return value: %TRUE if a connection was closed, %FALSE if there are
 * no idle connections.
 **/
gboolean
soup_session_try_prune_connection (SoupSession *session)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupConnection *oldest = NULL;

	g_mutex_lock (priv->host_lock);
	g_hash_table_foreach (priv->conns, find_oldest_connection,
			      &oldest);
	if (oldest) {
		/* Ref the connection before unlocking the mutex in
		 * case someone else tries to prune it too.
		 */
		g_object_ref (oldest);
		g_mutex_unlock (priv->host_lock);
		soup_connection_disconnect (oldest);
		g_object_unref (oldest);
		return TRUE;
	} else {
		g_mutex_unlock (priv->host_lock);
		return FALSE;
	}
}

static void
connection_disconnected (SoupConnection *conn, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupSessionHost *host;

	g_mutex_lock (priv->host_lock);

	host = g_hash_table_lookup (priv->conns, conn);
	if (host) {
		g_hash_table_remove (priv->conns, conn);
		host->connections = g_slist_remove (host->connections, conn);
		host->num_conns--;
	}

	g_signal_handlers_disconnect_by_func (conn, connection_disconnected, session);
	priv->num_conns--;

	g_mutex_unlock (priv->host_lock);
	g_object_unref (conn);
}

static void
connect_result (SoupConnection *conn, guint status, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupSessionHost *host;
	SoupMessageQueueIter iter;
	SoupMessage *msg;

	g_mutex_lock (priv->host_lock);

	host = g_hash_table_lookup (priv->conns, conn);
	if (!host) {
		g_mutex_unlock (priv->host_lock);
		return;
	}

	if (status == SOUP_STATUS_OK) {
		soup_connection_reserve (conn);
		host->connections = g_slist_prepend (host->connections, conn);
		g_mutex_unlock (priv->host_lock);
		return;
	}

	/* The connection failed. */
	g_mutex_unlock (priv->host_lock);
	connection_disconnected (conn, session);

	if (host->connections) {
		/* Something went wrong this time, but we have at
		 * least one open connection to this host. So just
		 * leave the message in the queue so it can use that
		 * connection once it's free.
		 */
		return;
	}

	/* There are two possibilities: either status is
	 * SOUP_STATUS_TRY_AGAIN, in which case the session implementation
	 * will create a new connection (and all we need to do here
	 * is downgrade the message from CONNECTING to QUEUED); or
	 * status is something else, probably CANT_CONNECT or
	 * CANT_RESOLVE or the like, in which case we need to cancel
	 * any messages waiting for this host, since they're out
	 * of luck.
	 */
	for (msg = soup_message_queue_first (priv->queue, &iter); msg; msg = soup_message_queue_next (priv->queue, &iter)) {
		if (get_host_for_message (session, msg) == host) {
			if (status == SOUP_STATUS_TRY_AGAIN) {
				if (msg->status == SOUP_MESSAGE_STATUS_CONNECTING)
					msg->status = SOUP_MESSAGE_STATUS_QUEUED;
			} else {
				soup_message_set_status (msg, status);
				soup_session_cancel_message (session, msg);
			}
		}
	}
}

/**
 * soup_session_get_connection:
 * @session: a #SoupSession
 * @msg: a #SoupMessage
 * @try_pruning: on return, whether or not to try pruning a connection
 * @is_new: on return, %TRUE if the returned connection is new and not
 * yet connected
 * 
 * Tries to find or create a connection for @msg; this is an internal
 * method for #SoupSession subclasses.
 *
 * If there is an idle connection to the relevant host available, then
 * that connection will be returned (with *@is_new set to %FALSE). The
 * connection will be marked "reserved", so the caller must call
 * soup_connection_release() if it ends up not using the connection
 * right away.
 *
 * If there is no idle connection available, but it is possible to
 * create a new connection, then one will be created and returned,
 * with *@is_new set to %TRUE. The caller MUST then call
 * soup_connection_connect_sync() or soup_connection_connect_async()
 * to connect it. If the connection attempt succeeds, the connection
 * will be marked "reserved" and added to @session's connection pool
 * once it connects. If the connection attempt fails, the connection
 * will be unreffed.
 *
 * If no connection is available and a new connection cannot be made,
 * soup_session_get_connection() will return %NULL. If @session has
 * the maximum number of open connections open, but does not have the
 * maximum number of per-host connections open to the relevant host,
 * then *@try_pruning will be set to %TRUE. In this case, the caller
 * can call soup_session_try_prune_connection() to close an idle
 * connection, and then try soup_session_get_connection() again. (If
 * calling soup_session_try_prune_connection() wouldn't help, then
 * *@try_pruning is left untouched; it is NOT set to %FALSE.)
 *
 * Return value: a #SoupConnection, or %NULL
 **/
SoupConnection *
soup_session_get_connection (SoupSession *session, SoupMessage *msg,
			     gboolean *try_pruning, gboolean *is_new)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);
	SoupConnection *conn;
	SoupSessionHost *host;
	GSList *conns;

	g_mutex_lock (priv->host_lock);

	host = get_host_for_message (session, msg);
	for (conns = host->connections; conns; conns = conns->next) {
		if (!soup_connection_is_in_use (conns->data)) {
			soup_connection_reserve (conns->data);
			g_mutex_unlock (priv->host_lock);
			*is_new = FALSE;
			return conns->data;
		}
	}

	if (msg->status == SOUP_MESSAGE_STATUS_CONNECTING) {
		/* We already started a connection for this
		 * message, so don't start another one.
		 */
		g_mutex_unlock (priv->host_lock);
		return NULL;
	}

	if (host->num_conns >= priv->max_conns_per_host) {
		g_mutex_unlock (priv->host_lock);
		return NULL;
	}

	if (priv->num_conns >= priv->max_conns) {
		*try_pruning = TRUE;
		g_mutex_unlock (priv->host_lock);
		return NULL;
	}

	/* Make sure priv->proxy_host gets set now while
	 * we have the host_lock.
	 */
	if (priv->proxy_uri)
		get_proxy_host (session);

	conn = g_object_new (
		(priv->use_ntlm ?
		 SOUP_TYPE_CONNECTION_NTLM : SOUP_TYPE_CONNECTION),
		SOUP_CONNECTION_ORIGIN_URI, host->root_uri,
		SOUP_CONNECTION_PROXY_URI, priv->proxy_uri,
		SOUP_CONNECTION_SSL_CREDENTIALS, priv->ssl_creds,
		SOUP_CONNECTION_MESSAGE_FILTER, session,
		SOUP_CONNECTION_ASYNC_CONTEXT, priv->async_context,
		SOUP_CONNECTION_TIMEOUT, priv->timeout,
		NULL);
	g_signal_connect (conn, "connect_result",
			  G_CALLBACK (connect_result),
			  session);
	g_signal_connect (conn, "disconnected",
			  G_CALLBACK (connection_disconnected),
			  session);
	g_signal_connect (conn, "authenticate",
			  G_CALLBACK (connection_authenticate),
			  session);
	g_signal_connect (conn, "reauthenticate",
			  G_CALLBACK (connection_reauthenticate),
			  session);

	g_hash_table_insert (priv->conns, conn, host);

	/* We increment the connection counts so it counts against the
	 * totals, but we don't add it to the host's connection list
	 * yet, since it's not ready for use.
	 */
	priv->num_conns++;
	host->num_conns++;

	/* Mark the request as connecting, so we don't try to open
	 * another new connection for it while waiting for this one.
	 */
	msg->status = SOUP_MESSAGE_STATUS_CONNECTING;

	g_mutex_unlock (priv->host_lock);
	*is_new = TRUE;
	return conn;
}

SoupMessageQueue *
soup_session_get_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	return priv->queue;
}

static void
message_finished (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	if (!SOUP_MESSAGE_IS_STARTING (msg)) {
		soup_message_queue_remove_message (priv->queue, msg);
		g_signal_handlers_disconnect_by_func (msg, message_finished, session);
	}
}

static void
queue_message (SoupSession *session, SoupMessage *msg,
	       SoupMessageCallbackFn callback, gpointer user_data)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	g_signal_connect_after (msg, "finished",
				G_CALLBACK (message_finished), session);

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_status_class_handler (
			msg, SOUP_STATUS_CLASS_REDIRECT,
			SOUP_HANDLER_POST_BODY,
			redirect_handler, session);
	}

	msg->status = SOUP_MESSAGE_STATUS_QUEUED;
	soup_message_queue_append (priv->queue, msg);
}

/**
 * soup_session_queue_message:
 * @session: a #SoupSession
 * @msg: the message to queue
 * @callback: a #SoupMessageCallbackFn which will be called after the
 * message completes or when an unrecoverable error occurs.
 * @user_data: a pointer passed to @callback.
 * 
 * Queues the message @msg for sending. All messages are processed
 * while the glib main loop runs. If @msg has been processed before,
 * any resources related to the time it was last sent are freed.
 *
 * Upon message completion, the callback specified in @callback will
 * be invoked (in the thread associated with @session's async
 * context). If after returning from this callback the message has not
 * been requeued, @msg will be unreffed.
 */
void
soup_session_queue_message (SoupSession *session, SoupMessage *msg,
			    SoupMessageCallbackFn callback, gpointer user_data)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_SESSION_GET_CLASS (session)->queue_message (session, msg,
							 callback, user_data);
}

static void
requeue_message (SoupSession *session, SoupMessage *msg)
{
	msg->status = SOUP_MESSAGE_STATUS_QUEUED;
}

/**
 * soup_session_requeue_message:
 * @session: a #SoupSession
 * @msg: the message to requeue
 *
 * This causes @msg to be placed back on the queue to be attempted
 * again.
 **/
void
soup_session_requeue_message (SoupSession *session, SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_SESSION_GET_CLASS (session)->requeue_message (session, msg);
}


/**
 * soup_session_send_message:
 * @session: a #SoupSession
 * @msg: the message to send
 * 
 * Synchronously send @msg. This call will not return until the
 * transfer is finished successfully or there is an unrecoverable
 * error.
 *
 * @msg is not freed upon return.
 *
 * Return value: the HTTP status code of the response
 */
guint
soup_session_send_message (SoupSession *session, SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_SESSION (session), SOUP_STATUS_MALFORMED);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_STATUS_MALFORMED);

	return SOUP_SESSION_GET_CLASS (session)->send_message (session, msg);
}


static void
cancel_message (SoupSession *session, SoupMessage *msg)
{
	SoupSessionPrivate *priv = SOUP_SESSION_GET_PRIVATE (session);

	soup_message_queue_remove_message (priv->queue, msg);
	soup_message_finished (msg);
}

/**
 * soup_session_cancel_message:
 * @session: a #SoupSession
 * @msg: the message to cancel
 *
 * Causes @session to immediately finish processing @msg. You should
 * set a status code on @msg with soup_message_set_status() before
 * calling this function.
 **/
void
soup_session_cancel_message (SoupSession *session, SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_SESSION_GET_CLASS (session)->cancel_message (session, msg);
}

static void
gather_conns (gpointer key, gpointer host, gpointer data)
{
	SoupConnection *conn = key;
	GSList **conns = data;

	*conns = g_slist_prepend (*conns, conn);
}

/**
 * soup_session_abort:
 * @session: the session
 *
 * Cancels all pending requests in @session.
 **/
void
soup_session_abort (SoupSession *session)
{
	SoupSessionPrivate *priv;
	SoupMessageQueueIter iter;
	SoupMessage *msg;
	GSList *conns, *c;

	g_return_if_fail (SOUP_IS_SESSION (session));
	priv = SOUP_SESSION_GET_PRIVATE (session);

	for (msg = soup_message_queue_first (priv->queue, &iter);
	     msg;
	     msg = soup_message_queue_next (priv->queue, &iter)) {
		soup_message_set_status (msg, SOUP_STATUS_CANCELLED);
		soup_session_cancel_message (session, msg);
	}

	/* Close all connections */
	g_mutex_lock (priv->host_lock);
	conns = NULL;
	g_hash_table_foreach (priv->conns, gather_conns, &conns);

	for (c = conns; c; c = c->next)
		g_object_ref (c->data);
	g_mutex_unlock (priv->host_lock);
	for (c = conns; c; c = c->next) {
		soup_connection_disconnect (c->data);
		g_object_unref (c->data);
	}

	g_slist_free (conns);
}
