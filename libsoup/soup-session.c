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
#include "soup-session.h"
#include "soup-connection.h"
#include "soup-connection-ntlm.h"
#include "soup-marshal.h"
#include "soup-message-filter.h"
#include "soup-message-queue.h"
#include "soup-ssl.h"
#include "soup-uri.h"

typedef struct {
	SoupUri    *root_uri;

	GSList     *connections;      /* CONTAINS: SoupConnection */
	guint       num_conns;

	GHashTable *auth_realms;      /* path -> scheme:realm */
	GHashTable *auths;            /* scheme:realm -> SoupAuth */
} SoupSessionHost;

struct SoupSessionPrivate {
	SoupUri *proxy_uri;
	guint max_conns, max_conns_per_host;
	gboolean use_ntlm;

	char *ssl_ca_file;
	gpointer ssl_creds;

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
};

static guint    host_uri_hash  (gconstpointer key);
static gboolean host_uri_equal (gconstpointer v1, gconstpointer v2);
static void     free_host      (SoupSessionHost *host, SoupSession *session);

static void setup_message   (SoupMessageFilter *filter, SoupMessage *msg);

static void queue_message   (SoupSession *session, SoupMessage *msg,
			     SoupMessageCallbackFn callback,
			     gpointer user_data);
static void requeue_message (SoupSession *session, SoupMessage *msg);
static void cancel_message  (SoupSession *session, SoupMessage *msg);

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
  PROP_SSL_CA_FILE,

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
	session->priv->host_lock = g_mutex_new ();
	session->queue = soup_message_queue_new ();
	session->priv->hosts = g_hash_table_new (host_uri_hash,
						 host_uri_equal);
	session->priv->conns = g_hash_table_new (NULL, NULL);

	session->priv->max_conns = SOUP_SESSION_MAX_CONNS_DEFAULT;
	session->priv->max_conns_per_host = SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT;
}

static gboolean
foreach_free_host (gpointer key, gpointer host, gpointer session)
{
	free_host (host, session);
	return TRUE;
}

static void
cleanup_hosts (SoupSession *session)
{
	g_hash_table_foreach_remove (session->priv->hosts,
				     foreach_free_host, session);
}

static void
dispose (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	GSList *f;

	soup_session_abort (session);
	cleanup_hosts (session);

	if (session->priv->filters) {
		for (f = session->priv->filters; f; f = f->next)
			g_object_unref (f->data);
		g_slist_free (session->priv->filters);
		session->priv->filters = NULL;
	}

	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);

	g_mutex_free (session->priv->host_lock);
	soup_message_queue_destroy (session->queue);
	g_hash_table_destroy (session->priv->hosts);
	g_hash_table_destroy (session->priv->conns);
	g_free (session->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	SoupSessionClass *session_class = SOUP_SESSION_CLASS (object_class);

	parent_class = g_type_class_ref (PARENT_TYPE);

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
}

static void
filter_iface_init (SoupMessageFilterClass *filter_class)
{
	/* interface implementation */
	filter_class->setup_message = setup_message;
}

SOUP_MAKE_TYPE_WITH_IFACE (soup_session, SoupSession, class_init, init, PARENT_TYPE, filter_iface_init, SOUP_TYPE_MESSAGE_FILTER)

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
	gpointer pval;
	gboolean need_abort = FALSE;
	gboolean ca_file_changed = FALSE;
	const char *new_ca_file;

	switch (prop_id) {
	case PROP_PROXY_URI:
		pval = g_value_get_pointer (value);

		if (!safe_uri_equal (session->priv->proxy_uri, pval))
			need_abort = TRUE;

		if (session->priv->proxy_uri)
			soup_uri_free (session->priv->proxy_uri);

		session->priv->proxy_uri = pval ? soup_uri_copy (pval) : NULL;

		if (need_abort) {
			soup_session_abort (session);
			cleanup_hosts (session);
		}

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
	case PROP_SSL_CA_FILE:
		new_ca_file = g_value_get_string (value);

		if (!safe_str_equal (session->priv->ssl_ca_file, new_ca_file))
			ca_file_changed = TRUE;

		g_free (session->priv->ssl_ca_file);
		session->priv->ssl_ca_file = g_strdup (new_ca_file);

		if (ca_file_changed) {
			if (session->priv->ssl_creds) {
				soup_ssl_free_client_credentials (session->priv->ssl_creds);
				session->priv->ssl_creds = NULL;
			}

			cleanup_hosts (session);
		}

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
	case PROP_SSL_CA_FILE:
		g_value_set_string (value, session->priv->ssl_ca_file);
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
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE_FILTER (filter));

	g_object_ref (filter);
	session->priv->filters = g_slist_prepend (session->priv->filters,
						  filter);
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
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE_FILTER (filter));

	session->priv->filters = g_slist_remove (session->priv->filters,
						 filter);
	g_object_unref (filter);
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
	SoupSessionHost *host;

	host = g_new0 (SoupSessionHost, 1);
	host->root_uri = soup_uri_copy_root (source_uri);

	if (host->root_uri->protocol == SOUP_PROTOCOL_HTTPS &&
	    !session->priv->ssl_creds) {
		session->priv->ssl_creds =
			soup_ssl_get_client_credentials (session->priv->ssl_ca_file);
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
	SoupSessionHost *host;
	const SoupUri *source = soup_message_get_uri (msg);

	host = g_hash_table_lookup (session->priv->hosts, source);
	if (host)
		return host;

	host = soup_session_host_new (session, source);
	g_hash_table_insert (session->priv->hosts, host->root_uri, host);

	return host;
}

/* Note: get_proxy_host doesn't lock the host_lock. The caller must do
 * it itself if there's a chance the host doesn't already exist.
 */
static SoupSessionHost *
get_proxy_host (SoupSession *session)
{
	if (session->priv->proxy_host || !session->priv->proxy_uri)
		return session->priv->proxy_host;

	session->priv->proxy_host =
		soup_session_host_new (session, session->priv->proxy_uri);
	return session->priv->proxy_host;
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
free_host (SoupSessionHost *host, SoupSession *session)
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
		   SoupMessage *msg, gboolean prior_auth_failed,
		   gboolean proxy)
{
	const SoupUri *uri;
	char *username = NULL, *password = NULL;

	if (proxy)
		uri = session->priv->proxy_uri;
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

	if (proxy)
		host = get_proxy_host (session);
	else
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

	/* 
	 * RFC 2617 is somewhat unclear about the scope of protection
	 * spaces with regard to proxies.  The only mention of it is
	 * as an aside in section 3.2.1, where it is defining the fields
	 * of a Digest challenge and says that the protection space is
	 * always the entire proxy.  Is this the case for all authentication
	 * schemes or just Digest?  Who knows, but we're assuming all.
	 */
	if (proxy)
		pspace = g_slist_prepend (NULL, g_strdup (""));
	else
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
	const char *header = proxy ? "Proxy-Authorization" : "Authorization";
	SoupAuth *auth;
	char *token;

	auth = lookup_auth (session, msg, proxy);
	if (!auth)
		return;
	if (!soup_auth_is_authenticated (auth) &&
	    !authenticate_auth (session, auth, msg, FALSE, proxy))
		return;

	token = soup_auth_get_authorization (auth, msg);
	if (token) {
		soup_message_remove_header (msg->request_headers, header);
		soup_message_add_header (msg->request_headers, header, token);
		g_free (token);
	}
}

static void
setup_message (SoupMessageFilter *filter, SoupMessage *msg)
{
	SoupSession *session = SOUP_SESSION (filter);
	GSList *f;

	for (f = session->priv->filters; f; f = f->next) {
		filter = f->data;
		soup_message_filter_setup_message (filter, msg);
	}

	add_auth (session, msg, FALSE);
	soup_message_add_status_code_handler (
		msg, SOUP_STATUS_UNAUTHORIZED,
		SOUP_HANDLER_POST_BODY,
		authorize_handler, session);

	if (session->priv->proxy_uri) {
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
	SoupConnection *oldest = NULL;

	g_mutex_lock (session->priv->host_lock);
	g_hash_table_foreach (session->priv->conns, find_oldest_connection,
			      &oldest);
	if (oldest) {
		/* Ref the connection before unlocking the mutex in
		 * case someone else tries to prune it too.
		 */
		g_object_ref (oldest);
		g_mutex_unlock (session->priv->host_lock);
		soup_connection_disconnect (oldest);
		g_object_unref (oldest);
		return TRUE;
	} else {
		g_mutex_unlock (session->priv->host_lock);
		return FALSE;
	}
}

static void
connection_disconnected (SoupConnection *conn, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionHost *host;

	g_mutex_lock (session->priv->host_lock);

	host = g_hash_table_lookup (session->priv->conns, conn);
	if (host) {
		g_hash_table_remove (session->priv->conns, conn);
		host->connections = g_slist_remove (host->connections, conn);
		host->num_conns--;
	}

	g_signal_handlers_disconnect_by_func (conn, connection_disconnected, session);
	session->priv->num_conns--;

	g_mutex_unlock (session->priv->host_lock);
	g_object_unref (conn);
}

static void
connect_result (SoupConnection *conn, guint status, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionHost *host;
	SoupMessageQueueIter iter;
	SoupMessage *msg;

	g_mutex_lock (session->priv->host_lock);

	host = g_hash_table_lookup (session->priv->conns, conn);
	if (!host) {
		g_mutex_unlock (session->priv->host_lock);
		return;
	}

	if (status == SOUP_STATUS_OK) {
		host->connections = g_slist_prepend (host->connections, conn);
		g_mutex_unlock (session->priv->host_lock);
		return;
	}

	/* The connection failed. */
	g_mutex_unlock (session->priv->host_lock);
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
	for (msg = soup_message_queue_first (session->queue, &iter); msg; msg = soup_message_queue_next (session->queue, &iter)) {
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
 * Tries to find or create a connection for @msg. If there is an idle
 * connection to the relevant host available, then it will be returned
 * (with *@is_new set to %FALSE). Otherwise, if it is possible to
 * create a new connection, one will be created and returned, with
 * *@is_new set to %TRUE.
 *
 * If no connection can be made, it will return %NULL. If @session has
 * the maximum number of open connections open, but does not have the
 * maximum number of per-host connections open to the relevant host, then
 * *@try_pruning will be set to %TRUE. In this case, the caller can
 * call soup_session_try_prune_connection() to close an idle connection,
 * and then try soup_session_get_connection() again. (If calling
 * soup_session_try_prune_connection() wouldn't help, then *@try_pruning
 * is left untouched; it is NOT set to %FALSE.)
 *
 * Return value: a #SoupConnection, or %NULL
 **/
SoupConnection *
soup_session_get_connection (SoupSession *session, SoupMessage *msg,
			     gboolean *try_pruning, gboolean *is_new)
{
	SoupConnection *conn;
	SoupSessionHost *host;
	GSList *conns;

	g_mutex_lock (session->priv->host_lock);

	host = get_host_for_message (session, msg);
	for (conns = host->connections; conns; conns = conns->next) {
		if (!soup_connection_is_in_use (conns->data)) {
			soup_connection_reserve (conns->data);
			g_mutex_unlock (session->priv->host_lock);
			*is_new = FALSE;
			return conns->data;
		}
	}

	if (msg->status == SOUP_MESSAGE_STATUS_CONNECTING) {
		/* We already started a connection for this
		 * message, so don't start another one.
		 */
		g_mutex_unlock (session->priv->host_lock);
		return NULL;
	}

	if (host->num_conns >= session->priv->max_conns_per_host) {
		g_mutex_unlock (session->priv->host_lock);
		return NULL;
	}

	if (session->priv->num_conns >= session->priv->max_conns) {
		*try_pruning = TRUE;
		g_mutex_unlock (session->priv->host_lock);
		return NULL;
	}

	/* Make sure session->priv->proxy_host gets set now while
	 * we have the host_lock.
	 */
	if (session->priv->proxy_uri)
		get_proxy_host (session);

	conn = g_object_new (
		(session->priv->use_ntlm ?
		 SOUP_TYPE_CONNECTION_NTLM : SOUP_TYPE_CONNECTION),
		SOUP_CONNECTION_ORIGIN_URI, host->root_uri,
		SOUP_CONNECTION_PROXY_URI, session->priv->proxy_uri,
		SOUP_CONNECTION_SSL_CREDENTIALS, session->priv->ssl_creds,
		SOUP_CONNECTION_MESSAGE_FILTER, session,
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

	g_hash_table_insert (session->priv->conns, conn, host);

	/* We increment the connection counts so it counts against the
	 * totals, but we don't add it to the host's connection list
	 * yet, since it's not ready for use.
	 */
	session->priv->num_conns++;
	host->num_conns++;

	/* Mark the request as connecting, so we don't try to open
	 * another new connection for it while waiting for this one.
	 */
	msg->status = SOUP_MESSAGE_STATUS_CONNECTING;

	g_mutex_unlock (session->priv->host_lock);
	*is_new = TRUE;
	return conn;
}

static void
message_finished (SoupMessage *msg, gpointer user_data)
{
	SoupSession *session = user_data;

	if (!SOUP_MESSAGE_IS_STARTING (msg)) {
		soup_message_queue_remove_message (session->queue, msg);
		g_signal_handlers_disconnect_by_func (msg, message_finished, session);
	}
}

static void
queue_message (SoupSession *session, SoupMessage *msg,
	       SoupMessageCallbackFn callback, gpointer user_data)
{
	g_signal_connect_after (msg, "finished",
				G_CALLBACK (message_finished), session);

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_status_class_handler (
			msg, SOUP_STATUS_CLASS_REDIRECT,
			SOUP_HANDLER_POST_BODY,
			redirect_handler, session);
	}

	msg->status = SOUP_MESSAGE_STATUS_QUEUED;
	soup_message_queue_append (session->queue, msg);
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
 * be invoked. If after returning from this callback the message has
 * not been requeued, @msg will be unreffed.
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
	soup_message_queue_remove_message (session->queue, msg);
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

/**
 * soup_session_abort:
 * @session: the session
 *
 * Cancels all pending requests in @session.
 **/
void
soup_session_abort (SoupSession *session)
{
	SoupMessageQueueIter iter;
	SoupMessage *msg;

	g_return_if_fail (SOUP_IS_SESSION (session));

	for (msg = soup_message_queue_first (session->queue, &iter); msg; msg = soup_message_queue_next (session->queue, &iter)) {
		soup_message_set_status (msg, SOUP_STATUS_CANCELLED);
		soup_session_cancel_message (session, msg);
	}
}
