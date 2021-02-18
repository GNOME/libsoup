/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-session.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n-lib.h>

#include "soup-session.h"
#include "soup.h"
#include "auth/soup-auth-manager.h"
#include "auth/soup-auth-ntlm.h"
#include "cache/soup-cache-private.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-message-queue.h"
#include "soup-session-private.h"
#include "soup-session-feature-private.h"
#include "soup-socket-properties.h"
#include "soup-uri-utils-private.h"
#include "websocket/soup-websocket.h"
#include "websocket/soup-websocket-connection.h"
#include "websocket/soup-websocket-extension-manager-private.h"

#define HOST_KEEP_ALIVE 5 * 60 * 1000 /* 5 min in msecs */

/**
 * SECTION:soup-session
 * @short_description: Soup session state object
 *
 * #SoupSession is the object that controls client-side HTTP. A
 * #SoupSession encapsulates all of the state that libsoup is keeping
 * on behalf of your program; cached HTTP connections, authentication
 * information, etc. It also keeps track of various global options
 * and features that you are using.
 *
 * Most applications will only need a single #SoupSession; the primary
 * reason you might need multiple sessions is if you need to have
 * multiple independent authentication contexts. (Eg, you are
 * connecting to a server and authenticating as two different users at
 * different times; the easiest way to ensure that each #SoupMessage
 * is sent with the authentication information you intended is to use
 * one session for the first user, and a second session for the other
 * user.)
 *
 * Additional #SoupSession functionality is provided by
 * #SoupSessionFeature objects, which can be added to a session with
 * soup_session_add_feature() or soup_session_add_feature_by_type()
 * For example, #SoupLogger provides support for
 * logging HTTP traffic, #SoupContentDecoder provides support for
 * compressed response handling, and #SoupContentSniffer provides
 * support for HTML5-style response body content sniffing.
 * Additionally, subtypes of #SoupAuth can be added
 * as features, to add support for additional authentication types.
 *
 * All #SoupSessions are created with a #SoupAuthManager, and support
 * for %SOUP_TYPE_AUTH_BASIC and %SOUP_TYPE_AUTH_DIGEST. Additionally,
 * sessions using the plain #SoupSession class (rather than one of its deprecated
 * subtypes) have a #SoupContentDecoder by default.
 **/

/**
 * SoupSession:
 *
 * Class managing options and state for #SoupMessage<!-- -->s.
 */

typedef struct {
	GUri            *uri;
	GNetworkAddress *addr;

	GSList      *connections;      /* CONTAINS: SoupConnection */
	guint        num_conns;

	guint        num_messages;

	GSource     *keep_alive_src;
	SoupSession *session;
} SoupSessionHost;
static guint soup_host_uri_hash (gconstpointer key);
static gboolean soup_host_uri_equal (gconstpointer v1, gconstpointer v2);

struct _SoupSession {
	GObject parent;
};

typedef struct {
	gboolean disposed;

	GTlsDatabase *tlsdb;
	GTlsInteraction *tls_interaction;
	gboolean tlsdb_use_default;

	guint io_timeout, idle_timeout;
	GInetSocketAddress *local_addr;

	GProxyResolver *proxy_resolver;
	gboolean proxy_use_default;

	SoupSocketProperties *socket_props;

	SoupMessageQueue *queue;

	char *user_agent;
	char *accept_language;
	gboolean accept_language_auto;

	GSList *features;
	GHashTable *features_cache;

	GHashTable *http_hosts, *https_hosts; /* char* -> SoupSessionHost */
	GHashTable *conns; /* SoupConnection -> SoupSessionHost */
	guint num_conns;
	guint max_conns, max_conns_per_host;

	/* Must hold the conn_lock before potentially creating a new
	 * SoupSessionHost, adding/removing a connection,
	 * disconnecting a connection, moving a connection from
	 * IDLE to IN_USE, or when updating socket properties.
	 * Must not emit signals or destroy objects while holding it.
	 * The conn_cond is signaled when it may be possible for
	 * a previously-blocked message to continue.
	 */
	GMutex conn_lock;
	GCond conn_cond;

	GMainContext *async_context;
} SoupSessionPrivate;

static void free_host (SoupSessionHost *host);
static void connection_state_changed (GObject *object, GParamSpec *param,
				      gpointer user_data);
static void connection_disconnected (SoupConnection *conn, gpointer user_data);
static void drop_connection (SoupSession *session, SoupSessionHost *host,
			     SoupConnection *conn);

static void async_run_queue (SoupSession *session);

static void async_send_request_running (SoupSession *session, SoupMessageQueueItem *item);

static void soup_session_kick_queue (SoupSession *session);

static void
soup_session_process_queue_item (SoupSession          *session,
				 SoupMessageQueueItem *item,
				 gboolean             *should_cleanup,
				 gboolean              loop);

#define SOUP_SESSION_MAX_CONNS_DEFAULT 10
#define SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT 2

#define SOUP_SESSION_MAX_RESEND_COUNT 20

#define SOUP_SESSION_USER_AGENT_BASE "libsoup/" PACKAGE_VERSION

G_DEFINE_TYPE_WITH_PRIVATE (SoupSession, soup_session, G_TYPE_OBJECT)

enum {
	REQUEST_QUEUED,
	REQUEST_UNQUEUED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_PROXY_RESOLVER,
	PROP_MAX_CONNS,
	PROP_MAX_CONNS_PER_HOST,
	PROP_TLS_DATABASE,
	PROP_ASYNC_CONTEXT,
	PROP_TIMEOUT,
	PROP_USER_AGENT,
	PROP_ACCEPT_LANGUAGE,
	PROP_ACCEPT_LANGUAGE_AUTO,
	PROP_IDLE_TIMEOUT,
	PROP_LOCAL_ADDRESS,
	PROP_TLS_INTERACTION,

	LAST_PROP
};

/**
 * SOUP_SESSION_ERROR:
 *
 * A #GError domain for #SoupSession<!-- -->-related errors. Used with
 * #SoupSessionError.
 */
/**
 * SoupSessionError:
 * @SOUP_SESSION_ERROR_BAD_URI: the URI could not be parsed
 * @SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME: the URI scheme is not
 *   supported by this #SoupSession
 * @SOUP_SESSION_ERROR_PARSING: the server's response could not
 *   be parsed
 * @SOUP_SESSION_ERROR_ENCODING: the server's response was in an
 *   unsupported format
 * @SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS: the message has been redirected
 *   too many times
 * @SOUP_SESSION_ERROR_TOO_MANY_RESTARTS: the message has been restarted
 *   too many times
 * @SOUP_SESSION_ERROR_REDIRECT_NO_LOCATION: failed to redirect message because
 *   Location header was missing or empty in response
 * @SOUP_SESSION_ERROR_REDIRECT_BAD_URI: failed to redirect message because
 *   Location header contains an invalid URI
 *
 * A #SoupSession error.
 */
G_DEFINE_QUARK (soup-session-error-quark, soup_session_error)

static void
soup_session_init (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupAuthManager *auth_manager;

	priv->queue = soup_message_queue_new (session);
        priv->async_context = g_main_context_ref_thread_default ();
        priv->io_timeout = priv->idle_timeout = 60;

	g_mutex_init (&priv->conn_lock);
	g_cond_init (&priv->conn_cond);
	priv->http_hosts = g_hash_table_new_full (soup_host_uri_hash,
						  soup_host_uri_equal,
						  NULL, (GDestroyNotify)free_host);
	priv->https_hosts = g_hash_table_new_full (soup_host_uri_hash,
						   soup_host_uri_equal,
						   NULL, (GDestroyNotify)free_host);
	priv->conns = g_hash_table_new (NULL, NULL);

	priv->max_conns = SOUP_SESSION_MAX_CONNS_DEFAULT;
	priv->max_conns_per_host = SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT;

	priv->features_cache = g_hash_table_new (NULL, NULL);

	auth_manager = g_object_new (SOUP_TYPE_AUTH_MANAGER, NULL);
	soup_session_feature_add_feature (SOUP_SESSION_FEATURE (auth_manager),
					  SOUP_TYPE_AUTH_BASIC);
	soup_session_feature_add_feature (SOUP_SESSION_FEATURE (auth_manager),
					  SOUP_TYPE_AUTH_DIGEST);
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (auth_manager));
	g_object_unref (auth_manager);

        soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_DECODER);

        /* If the user overrides the proxy or tlsdb during construction,
                * we don't want to needlessly resolve the extension point. So
                * we just set flags saying to do it later.
                */
        priv->proxy_use_default = TRUE;
        priv->tlsdb_use_default = TRUE;
}

static void
soup_session_dispose (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	priv->disposed = TRUE;
	soup_session_abort (session);
	g_warn_if_fail (g_hash_table_size (priv->conns) == 0);

	while (priv->features)
		soup_session_remove_feature (session, priv->features->data);

	G_OBJECT_CLASS (soup_session_parent_class)->dispose (object);
}

static void
soup_session_finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	soup_message_queue_destroy (priv->queue);

	g_mutex_clear (&priv->conn_lock);
	g_cond_clear (&priv->conn_cond);
	g_hash_table_destroy (priv->http_hosts);
	g_hash_table_destroy (priv->https_hosts);
	g_hash_table_destroy (priv->conns);

	g_free (priv->user_agent);
	g_free (priv->accept_language);

	g_clear_object (&priv->tlsdb);
	g_clear_object (&priv->tls_interaction);

	g_clear_pointer (&priv->async_context, g_main_context_unref);
	g_clear_object (&priv->local_addr);

	g_hash_table_destroy (priv->features_cache);

	g_clear_object (&priv->proxy_resolver);

	g_clear_pointer (&priv->socket_props, soup_socket_properties_unref);

	G_OBJECT_CLASS (soup_session_parent_class)->finalize (object);
}

/* requires conn_lock */
static void
ensure_socket_props (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (priv->socket_props)
		return;

	priv->socket_props = soup_socket_properties_new (priv->local_addr,
							 priv->tls_interaction,
							 priv->io_timeout,
							 priv->idle_timeout);
	if (!priv->proxy_use_default)
		soup_socket_properties_set_proxy_resolver (priv->socket_props, priv->proxy_resolver);
	if (!priv->tlsdb_use_default)
		soup_socket_properties_set_tls_database (priv->socket_props, priv->tlsdb);
}

static void
set_tlsdb (SoupSession  *session,
	   GTlsDatabase *tlsdb)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	priv->tlsdb_use_default = FALSE;
	if (tlsdb == priv->tlsdb)
		return;

	g_clear_object (&priv->tlsdb);
	priv->tlsdb = tlsdb ? g_object_ref (tlsdb) : NULL;
	g_object_notify (G_OBJECT (session), "tls-database");
}

static GTlsDatabase *
get_tlsdb (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (priv->tlsdb_use_default && !priv->tlsdb)
		priv->tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());

	return priv->tlsdb;
}

static void
set_proxy_resolver (SoupSession    *session,
		    GProxyResolver *g_resolver)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	priv->proxy_use_default = FALSE;
	if (priv->proxy_resolver == g_resolver)
		return;

	g_clear_object (&priv->proxy_resolver);
	priv->proxy_resolver = g_resolver ? g_object_ref (g_resolver) : NULL;
	g_object_notify (G_OBJECT (session), "proxy-resolver");
}

static GProxyResolver *
get_proxy_resolver (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (!priv->proxy_use_default)
		return priv->proxy_resolver;

	return g_proxy_resolver_get_default ();
}

static void
soup_session_set_property (GObject *object, guint prop_id,
			   const GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	const char *user_agent;
	gboolean socket_props_changed = FALSE;

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = g_value_dup_object (value);
		socket_props_changed = TRUE;
		break;
	case PROP_PROXY_RESOLVER:
		set_proxy_resolver (session, g_value_get_object (value));
		socket_props_changed = TRUE;
		break;
	case PROP_MAX_CONNS:
		priv->max_conns = g_value_get_int (value);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		priv->max_conns_per_host = g_value_get_int (value);
		break;
	case PROP_TLS_DATABASE:
		set_tlsdb (session, g_value_get_object (value));
		socket_props_changed = TRUE;
		break;
	case PROP_TLS_INTERACTION:
		g_clear_object(&priv->tls_interaction);
		priv->tls_interaction = g_value_dup_object (value);
		socket_props_changed = TRUE;
		break;
	case PROP_TIMEOUT:
		priv->io_timeout = g_value_get_uint (value);
		socket_props_changed = TRUE;
		break;
	case PROP_USER_AGENT:
		g_free (priv->user_agent);
		user_agent = g_value_get_string (value);
		if (!user_agent)
			priv->user_agent = NULL;
		else if (!*user_agent) {
			priv->user_agent =
				g_strdup (SOUP_SESSION_USER_AGENT_BASE);
		} else if (g_str_has_suffix (user_agent, " ")) {
			priv->user_agent =
				g_strdup_printf ("%s%s", user_agent,
						 SOUP_SESSION_USER_AGENT_BASE);
		} else
			priv->user_agent = g_strdup (user_agent);
		break;
	case PROP_ACCEPT_LANGUAGE:
		g_free (priv->accept_language);
		priv->accept_language = g_strdup (g_value_get_string (value));
		priv->accept_language_auto = FALSE;
		break;
	case PROP_ACCEPT_LANGUAGE_AUTO:
		priv->accept_language_auto = g_value_get_boolean (value);
		if (priv->accept_language) {
			g_free (priv->accept_language);
			priv->accept_language = NULL;
		}

		/* Get languages from system if needed */
		if (priv->accept_language_auto)
			priv->accept_language = soup_get_accept_languages_from_system ();
		break;
	case PROP_IDLE_TIMEOUT:
		priv->idle_timeout = g_value_get_uint (value);
		socket_props_changed = TRUE;
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}

	g_mutex_lock (&priv->conn_lock);
	if (priv->socket_props && socket_props_changed) {
		soup_socket_properties_unref (priv->socket_props);
		priv->socket_props = NULL;
		ensure_socket_props (session);
	}
	g_mutex_unlock (&priv->conn_lock);
}

static void
soup_session_get_property (GObject *object, guint prop_id,
			   GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, priv->local_addr);
		break;
	case PROP_PROXY_RESOLVER:
		g_value_set_object (value, get_proxy_resolver (session));
		break;
	case PROP_MAX_CONNS:
		g_value_set_int (value, priv->max_conns);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		g_value_set_int (value, priv->max_conns_per_host);
		break;
	case PROP_TLS_DATABASE:
		g_value_set_object (value, get_tlsdb (session));
		break;
	case PROP_TLS_INTERACTION:
		g_value_set_object (value, priv->tls_interaction);
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, priv->io_timeout);
		break;
	case PROP_USER_AGENT:
		g_value_set_string (value, priv->user_agent);
		break;
	case PROP_ACCEPT_LANGUAGE:
		g_value_set_string (value, priv->accept_language);
		break;
	case PROP_ACCEPT_LANGUAGE_AUTO:
		g_value_set_boolean (value, priv->accept_language_auto);
		break;
	case PROP_IDLE_TIMEOUT:
		g_value_set_uint (value, priv->idle_timeout);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * soup_session_new:
 *
 * Creates a #SoupSession with the default options.
 *
 * Returns: the new session.
 *
 */
SoupSession *
soup_session_new (void)
{
	return g_object_new (SOUP_TYPE_SESSION, NULL);
}

/**
 * soup_session_new_with_options:
 * @optname1: name of first property to set
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates a #SoupSession with the specified options.
 *
 * Returns: the new session.
 *
 */
SoupSession *
soup_session_new_with_options (const char *optname1,
			       ...)
{
	SoupSession *session;
	va_list ap;

	va_start (ap, optname1);
	session = (SoupSession *)g_object_new_valist (SOUP_TYPE_SESSION,
						      optname1, ap);
	va_end (ap);

	return session;
}

/* Hosts */

/* Note that we can't use soup_uri_host_hash() and soup_uri_host_equal()
 * because we want to ignore the protocol; http://example.com and
 * webcal://example.com are the same host.
 */
static guint
soup_host_uri_hash (gconstpointer key)
{
	GUri *uri = (GUri*)key;

	g_return_val_if_fail (uri != NULL && g_uri_get_host (uri) != NULL, 0);

	return g_uri_get_port (uri) + soup_str_case_hash (g_uri_get_host (uri));
}

static gboolean
soup_host_uri_equal (gconstpointer v1, gconstpointer v2)
{
	GUri *one = (GUri*)v1;
	GUri *two = (GUri*)v2;

	g_return_val_if_fail (one != NULL && two != NULL, one == two);

        const char *one_host = g_uri_get_host (one);
        const char *two_host = g_uri_get_host (two);
	g_return_val_if_fail (one_host != NULL && two_host != NULL, one_host == two_host);

	if (g_uri_get_port (one) != g_uri_get_port (two))
		return FALSE;

	return g_ascii_strcasecmp (one_host, two_host) == 0;
}

static SoupSessionHost *
soup_session_host_new (SoupSession *session, GUri *uri)
{
	SoupSessionHost *host;
        const char *scheme = g_uri_get_scheme (uri);

	host = g_slice_new0 (SoupSessionHost);
	if (g_strcmp0 (scheme, "http") &&
	    g_strcmp0 (scheme, "https")) {
		host->uri = soup_uri_copy (uri,
					   SOUP_URI_SCHEME, soup_uri_is_https (uri) ?
					   "https" : "http",
					   SOUP_URI_NONE);
	} else
                host->uri = g_uri_ref (uri);

	host->addr = g_object_new (G_TYPE_NETWORK_ADDRESS,
				   "hostname", g_uri_get_host (host->uri),
				   "port", g_uri_get_port (host->uri),
				   "scheme", g_uri_get_scheme (host->uri),
				   NULL);
	host->keep_alive_src = NULL;
	host->session = session;

	return host;
}

/* Requires conn_lock to be locked */
static SoupSessionHost *
get_host_for_uri (SoupSession *session, GUri *uri)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;
	gboolean https;
	GUri *uri_tmp = NULL;

	https = soup_uri_is_https (uri);
	if (https)
		host = g_hash_table_lookup (priv->https_hosts, uri);
	else
		host = g_hash_table_lookup (priv->http_hosts, uri);
	if (host)
		return host;

	if (!soup_uri_is_http (uri) && !soup_uri_is_https (uri)) {
		uri = uri_tmp = soup_uri_copy (uri,
					       SOUP_URI_SCHEME, https ? "https" : "http",
					       SOUP_URI_NONE);
	}
	host = soup_session_host_new (session, uri);
	if (uri_tmp)
		g_uri_unref (uri_tmp);

	if (https)
		g_hash_table_insert (priv->https_hosts, host->uri, host);
	else
		g_hash_table_insert (priv->http_hosts, host->uri, host);

	return host;
}

/* Requires conn_lock to be locked */
static SoupSessionHost *
get_host_for_message (SoupSession *session, SoupMessage *msg)
{
	return get_host_for_uri (session, soup_message_get_uri (msg));
}

static void
free_host (SoupSessionHost *host)
{
	g_warn_if_fail (host->connections == NULL);

	if (host->keep_alive_src) {
		g_source_destroy (host->keep_alive_src);
		g_source_unref (host->keep_alive_src);
	}

	g_uri_unref (host->uri);
	g_object_unref (host->addr);
	g_slice_free (SoupSessionHost, host);
}

#define SOUP_SESSION_WOULD_REDIRECT_AS_GET(session, msg) \
	(soup_message_get_status (msg) == SOUP_STATUS_SEE_OTHER || \
	 (soup_message_get_status (msg) == SOUP_STATUS_FOUND && \
	  !SOUP_METHOD_IS_SAFE (soup_message_get_method (msg))) || \
	 (soup_message_get_status (msg) == SOUP_STATUS_MOVED_PERMANENTLY && \
	  soup_message_get_method (msg) == SOUP_METHOD_POST))

#define SOUP_SESSION_WOULD_REDIRECT_AS_SAFE(session, msg) \
	((soup_message_get_status (msg) == SOUP_STATUS_MOVED_PERMANENTLY || \
	  soup_message_get_status (msg) == SOUP_STATUS_PERMANENT_REDIRECT || \
	  soup_message_get_status (msg) == SOUP_STATUS_TEMPORARY_REDIRECT || \
	  soup_message_get_status (msg) == SOUP_STATUS_FOUND) && \
	 SOUP_METHOD_IS_SAFE (soup_message_get_method (msg)))

static GUri *
redirection_uri (SoupSession *session,
		 SoupMessage *msg,
		 GError     **error)
{
	const char *new_loc;
	GUri *new_uri;

	new_loc = soup_message_headers_get_one (soup_message_get_response_headers (msg),
						"Location");
	if (!new_loc || !*new_loc) {
		g_set_error_literal (error,
				     SOUP_SESSION_ERROR,
				     SOUP_SESSION_ERROR_REDIRECT_NO_LOCATION,
				     _("Location header is missing or empty in response headers"));
		return NULL;
	}

        new_uri = g_uri_parse_relative (soup_message_get_uri (msg), new_loc, SOUP_HTTP_URI_FLAGS, NULL);
	if (!new_uri)
                return NULL;

	if (!g_uri_get_host (new_uri) || !*g_uri_get_host (new_uri) ||
	    (!soup_uri_is_http (new_uri) && !soup_uri_is_https (new_uri))) {
		g_uri_unref (new_uri);
		g_set_error (error,
			     SOUP_SESSION_ERROR,
			     SOUP_SESSION_ERROR_REDIRECT_BAD_URI,
			     _("Invalid URI “%s” in Location response header"),
			     new_loc);
		return NULL;
	}

	return new_uri;
}

static gboolean
soup_session_requeue_item (SoupSession          *session,
			   SoupMessageQueueItem *item,
			   GError              **error)
{
	gboolean retval;

	if (item->resend_count >= SOUP_SESSION_MAX_RESEND_COUNT) {
		if (SOUP_STATUS_IS_REDIRECTION (soup_message_get_status (item->msg))) {
			g_set_error_literal (error,
					     SOUP_SESSION_ERROR,
					     SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS,
					     _("Too many redirects"));
		} else {
			g_set_error_literal (error,
					     SOUP_SESSION_ERROR,
					     SOUP_SESSION_ERROR_TOO_MANY_RESTARTS,
					     _("Message was restarted too many times"));
		}
		retval = FALSE;
	} else {
		item->resend_count++;
		item->state = SOUP_MESSAGE_RESTARTING;
		retval = TRUE;
	}

	return retval;
}

/**
 * soup_session_redirect_message:
 * @session: the session
 * @msg: a #SoupMessage that has received a 3xx response
 * @error: return location for a #GError, or %NULL
 *
 * Updates @msg's URI according to its status code and "Location"
 * header, and requeues it on @session. Use this when you have set
 * %SOUP_MESSAGE_NO_REDIRECT on a message, but have decided to allow a
 * particular redirection to occur, or if you want to allow a
 * redirection that #SoupSession will not perform automatically (eg,
 * redirecting a non-safe method such as DELETE).
 *
 * If @msg's status code indicates that it should be retried as a GET
 * request, then @msg will be modified accordingly.
 *
 * If @msg has already been redirected too many times, this will
 * cause it to fail with %SOUP_STATUS_TOO_MANY_REDIRECTS.
 *
 * Returns: %TRUE if a redirection was applied, %FALSE if not
 * (eg, because there was no Location header, or it could not be
 * parsed).
 *
 */
static gboolean
soup_session_redirect_message (SoupSession *session,
			       SoupMessage *msg,
			       GError     **error)
{
	SoupSessionPrivate *priv;
	GUri *new_uri;
	char *host;
	SoupMessageQueueItem *item;
	gboolean retval;

	g_return_val_if_fail (SOUP_IS_SESSION (session), FALSE);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);
	g_return_val_if_fail (!error || *error == NULL, FALSE);

	new_uri = redirection_uri (session, msg, error);
	if (!new_uri)
		return FALSE;

	if (SOUP_SESSION_WOULD_REDIRECT_AS_GET (session, msg)) {
		if (soup_message_get_method (msg) != SOUP_METHOD_HEAD) {
			g_object_set (msg,
				      "method", SOUP_METHOD_GET,
				      NULL);
		}
		soup_message_set_request_body (msg, NULL, NULL, 0);
		soup_message_headers_set_encoding (soup_message_get_request_headers (msg),
						   SOUP_ENCODING_NONE);
	}

	host = soup_uri_get_host_for_headers (new_uri);
	if (soup_uri_uses_default_port (new_uri))
		soup_message_headers_replace (soup_message_get_request_headers (msg), "Host", host);
	else {
		char *value;

		value = g_strdup_printf ("%s:%d", host, g_uri_get_port (new_uri));
		soup_message_headers_replace (soup_message_get_request_headers (msg), "Host", value);
		g_free (value);
	}
	g_free (host);

	soup_message_set_uri (msg, new_uri);
	g_uri_unref (new_uri);

	priv = soup_session_get_instance_private (session);
	item = soup_message_queue_lookup (priv->queue, msg);
	retval = soup_session_requeue_item (session, item, error);
	soup_message_queue_item_unref (item);

	return retval;
}

static void
redirect_handler (SoupMessage *msg,
		  gpointer     user_data)
{
	SoupMessageQueueItem *item = user_data;
	SoupSession *session = item->session;

	if (!SOUP_SESSION_WOULD_REDIRECT_AS_GET (session, msg) &&
	    !SOUP_SESSION_WOULD_REDIRECT_AS_SAFE (session, msg))
		return;

	soup_session_redirect_message (session, msg, &item->error);
}

static void
soup_session_set_item_connection (SoupSession          *session,
				  SoupMessageQueueItem *item,
				  SoupConnection       *conn)
{
	g_clear_object (&item->conn);
	item->conn = conn ? g_object_ref (conn) : NULL;
	soup_message_set_connection (item->msg, conn);
}

static void
message_restarted (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

	if (item->conn &&
	    (!soup_message_is_keepalive (msg) ||
	     SOUP_STATUS_IS_REDIRECTION (soup_message_get_status (msg)))) {
		if (soup_connection_get_state (item->conn) == SOUP_CONNECTION_IN_USE)
			soup_connection_set_state (item->conn, SOUP_CONNECTION_IDLE);
		soup_session_set_item_connection (item->session, item, NULL);
	}

	soup_message_cleanup_response (msg);
}

static SoupMessageQueueItem *
soup_session_append_queue_item (SoupSession        *session,
				SoupMessage        *msg,
				gboolean            async,
				GCancellable       *cancellable,
				SoupSessionCallback callback,
				gpointer            user_data)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	SoupSessionHost *host;
	GSList *f;

	soup_message_cleanup_response (msg);

	item = soup_message_queue_append (priv->queue, msg, cancellable, callback, user_data);
	item->async = async;

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_message (session, item->msg);
	host->num_messages++;
	g_mutex_unlock (&priv->conn_lock);

	if (!soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_header_handler (
			msg, "got_body", "Location",
			G_CALLBACK (redirect_handler), item);
	}
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (message_restarted), item);

	for (f = priv->features; f; f = g_slist_next (f)) {
		SoupSessionFeature *feature = SOUP_SESSION_FEATURE (f->data);

		g_object_ref (feature);
		soup_session_feature_request_queued (feature, msg);
	}
	g_signal_emit (session, signals[REQUEST_QUEUED], 0, msg);

	soup_message_queue_item_ref (item);
	return item;
}

static void
soup_session_send_queue_item (SoupSession *session,
			      SoupMessageQueueItem *item,
			      SoupMessageIOCompletionFn completion_cb)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageHeaders *request_headers;
	const char *method;

	request_headers = soup_message_get_request_headers (item->msg);
	if (priv->user_agent)
		soup_message_headers_replace (request_headers, "User-Agent", priv->user_agent);

	if (priv->accept_language && !soup_message_headers_get_list (request_headers, "Accept-Language"))
		soup_message_headers_append (request_headers, "Accept-Language", priv->accept_language);

	/* Force keep alive connections for HTTP 1.0. Performance will
	 * improve when issuing multiple requests to the same host in
	 * a short period of time, as we wouldn't need to establish
	 * new connections. Keep alive is implicit for HTTP 1.1.
	 */
	if (!soup_message_headers_header_contains (request_headers, "Connection", "Keep-Alive") &&
	    !soup_message_headers_header_contains (request_headers, "Connection", "close") &&
	    !soup_message_headers_header_contains (request_headers, "Connection", "Upgrade")) {
		soup_message_headers_append (request_headers, "Connection", "Keep-Alive");
	}

        if (!soup_message_headers_get_one (request_headers, "Host")) {
                GUri *uri = soup_message_get_uri (item->msg);
                char *host;

                host = soup_uri_get_host_for_headers (uri);
                if (soup_uri_uses_default_port (uri))
                        soup_message_headers_append (request_headers, "Host", host);
                else {
                        char *value;

                        value = g_strdup_printf ("%s:%d", host, g_uri_get_port (uri));
                        soup_message_headers_append (request_headers, "Host", value);
                        g_free (value);
                }
                g_free (host);
        }

	/* A user agent SHOULD send a Content-Length in a request message when
	 * no Transfer-Encoding is sent and the request method defines a meaning
	 * for an enclosed payload body. For example, a Content-Length header
	 * field is normally sent in a POST request even when the value is 0
	 * (indicating an empty payload body).
	 */
	method = soup_message_get_method (item->msg);
	if ((method == SOUP_METHOD_POST || method == SOUP_METHOD_PUT) &&
	    soup_message_get_request_body_stream (item->msg) == NULL) {
		soup_message_headers_set_content_length (request_headers, 0);
	}

	soup_message_starting (item->msg);
	if (item->state == SOUP_MESSAGE_RUNNING)
		soup_connection_send_request (item->conn, item, completion_cb, item);
}

static gboolean
soup_session_cleanup_connections (SoupSession *session,
				  gboolean     cleanup_idle)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GSList *conns = NULL, *c;
	GHashTableIter iter;
	gpointer conn, host;
	SoupConnectionState state;

	g_mutex_lock (&priv->conn_lock);
	g_hash_table_iter_init (&iter, priv->conns);
	while (g_hash_table_iter_next (&iter, &conn, &host)) {
		state = soup_connection_get_state (conn);
		if (state == SOUP_CONNECTION_REMOTE_DISCONNECTED ||
		    (cleanup_idle && state == SOUP_CONNECTION_IDLE)) {
			conns = g_slist_prepend (conns, g_object_ref (conn));
			g_hash_table_iter_remove (&iter);
			drop_connection (session, host, conn);
		}
	}
	g_mutex_unlock (&priv->conn_lock);

	if (!conns)
		return FALSE;

	for (c = conns; c; c = c->next) {
		conn = c->data;
		soup_connection_disconnect (conn);
		g_object_unref (conn);
	}
	g_slist_free (conns);

	return TRUE;
}

static gboolean
free_unused_host (gpointer user_data)
{
	SoupSessionHost *host = (SoupSessionHost *) user_data;
	SoupSessionPrivate *priv = soup_session_get_instance_private (host->session);
	GUri *uri = host->uri;

	g_mutex_lock (&priv->conn_lock);

	/* In a multithreaded session, a connection might have been
	 * added while we were waiting for conn_lock.
	 */
	if (host->connections) {
		g_mutex_unlock (&priv->conn_lock);
		return FALSE;
	}

	/* This will free the host in addition to removing it from the
	 * hash table
	 */
	if (soup_uri_is_https (uri))
		g_hash_table_remove (priv->https_hosts, uri);
	else
		g_hash_table_remove (priv->http_hosts, uri);
	g_mutex_unlock (&priv->conn_lock);

	return FALSE;
}

static void
drop_connection (SoupSession *session, SoupSessionHost *host, SoupConnection *conn)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	/* Note: caller must hold conn_lock, and must remove @conn
	 * from priv->conns itself.
	 */

	if (host) {
		host->connections = g_slist_remove (host->connections, conn);
		host->num_conns--;

		/* Free the SoupHost (and its GNetworkAddress) if there
		 * has not been any new connection to the host during
		 * the last HOST_KEEP_ALIVE msecs.
		 */
		if (host->num_conns == 0) {
			g_assert (host->keep_alive_src == NULL);
			host->keep_alive_src = soup_add_timeout (priv->async_context,
								 HOST_KEEP_ALIVE,
								 free_unused_host,
								 host);
		}
	}

	g_signal_handlers_disconnect_by_func (conn, connection_disconnected, session);
	g_signal_handlers_disconnect_by_func (conn, connection_state_changed, session);
	priv->num_conns--;

	g_object_unref (conn);
}

static void
connection_disconnected (SoupConnection *conn, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;

	g_mutex_lock (&priv->conn_lock);

	host = g_hash_table_lookup (priv->conns, conn);
	if (host)
		g_hash_table_remove (priv->conns, conn);
	drop_connection (session, host, conn);

	g_mutex_unlock (&priv->conn_lock);

	soup_session_kick_queue (session);
}

static void
connection_state_changed (GObject *object, GParamSpec *param, gpointer user_data)
{
	SoupSession *session = user_data;
	SoupConnection *conn = SOUP_CONNECTION (object);

	if (soup_connection_get_state (conn) == SOUP_CONNECTION_IDLE)
		soup_session_kick_queue (session);
}

static void
soup_session_unqueue_item (SoupSession          *session,
			   SoupMessageQueueItem *item)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;
	GSList *f;

	if (item->conn) {
		if (soup_message_get_method (item->msg) != SOUP_METHOD_CONNECT ||
		    !SOUP_STATUS_IS_SUCCESSFUL (soup_message_get_status (item->msg)))
			soup_connection_set_state (item->conn, SOUP_CONNECTION_IDLE);
		soup_session_set_item_connection (session, item, NULL);
	}

	if (item->state != SOUP_MESSAGE_FINISHED) {
		g_warning ("finished an item with state %d", item->state);
		return;
	}

	soup_message_queue_remove (priv->queue, item);

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_message (session, item->msg);
	host->num_messages--;
	g_cond_broadcast (&priv->conn_cond);
	g_mutex_unlock (&priv->conn_lock);

	/* g_signal_handlers_disconnect_by_func doesn't work if you
	 * have a metamarshal, meaning it doesn't work with
	 * soup_message_add_header_handler()
	 */
	g_signal_handlers_disconnect_matched (item->msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, item);

	for (f = priv->features; f; f = g_slist_next (f)) {
		SoupSessionFeature *feature = SOUP_SESSION_FEATURE (f->data);

		soup_session_feature_request_unqueued (feature, item->msg);
		g_object_unref (feature);
	}
	g_signal_emit (session, signals[REQUEST_UNQUEUED], 0, item->msg);
	soup_message_queue_item_unref (item);
}

static void
message_completed (SoupMessage *msg, SoupMessageIOCompletion completion, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

	if (item->async)
		soup_session_kick_queue (item->session);

	if (completion == SOUP_MESSAGE_IO_STOLEN) {
		item->state = SOUP_MESSAGE_FINISHED;
		soup_session_unqueue_item (item->session, item);
		return;
	}

	if (item->state != SOUP_MESSAGE_RESTARTING) {
		item->state = SOUP_MESSAGE_FINISHING;

		if (!item->async)
			soup_session_process_queue_item (item->session, item, NULL, TRUE);
	}
}

static void
tunnel_complete (SoupMessageQueueItem *tunnel_item,
		 guint status, GError *error)
{
	SoupMessageQueueItem *item = tunnel_item->related;
	SoupSession *session = tunnel_item->session;

	soup_message_finished (tunnel_item->msg);
	soup_message_queue_item_unref (tunnel_item);

	if (soup_message_get_status (item->msg))
		item->state = SOUP_MESSAGE_FINISHING;
	else if (item->state == SOUP_MESSAGE_TUNNELING)
		item->state = SOUP_MESSAGE_READY;

	item->error = error;
	if (!SOUP_STATUS_IS_SUCCESSFUL (status) || item->error) {
		soup_connection_disconnect (item->conn);
		soup_session_set_item_connection (session, item, NULL);
		if (!error && soup_message_get_status (item->msg) == SOUP_STATUS_NONE)
			soup_message_set_status (item->msg, status, NULL);
	}

	if (item->async)
		soup_session_kick_queue (session);
	soup_message_queue_item_unref (item);
}

static void
tunnel_handshake_complete (SoupConnection       *conn,
			   GAsyncResult         *result,
			   SoupMessageQueueItem *tunnel_item)
{
	GError *error = NULL;

	soup_connection_tunnel_handshake_finish (conn, result, &error);
	tunnel_complete (tunnel_item, SOUP_STATUS_OK, error);
}

static void
tunnel_message_completed (SoupMessage *msg, SoupMessageIOCompletion completion,
			  gpointer user_data)
{
	SoupMessageQueueItem *tunnel_item = user_data;
	SoupMessageQueueItem *item = tunnel_item->related;
	SoupSession *session = tunnel_item->session;
	guint status;

	if (tunnel_item->state == SOUP_MESSAGE_RESTARTING) {
		soup_message_restarted (msg);
		if (tunnel_item->conn) {
			tunnel_item->state = SOUP_MESSAGE_RUNNING;
			soup_session_send_queue_item (session, tunnel_item,
						      (SoupMessageIOCompletionFn)tunnel_message_completed);
			soup_message_io_run (msg, !tunnel_item->async);
			return;
		}

		item->state = SOUP_MESSAGE_RESTARTING;
	}

	tunnel_item->state = SOUP_MESSAGE_FINISHED;
	soup_session_unqueue_item (session, tunnel_item);

	status = soup_message_get_status (tunnel_item->msg);
	if (!SOUP_STATUS_IS_SUCCESSFUL (status) || item->state == SOUP_MESSAGE_RESTARTING) {
		tunnel_complete (tunnel_item, status, NULL);
		return;
	}

	if (tunnel_item->async) {
		soup_connection_tunnel_handshake_async (item->conn,
							item->io_priority,
							item->cancellable,
							(GAsyncReadyCallback)tunnel_handshake_complete,
							tunnel_item);
	} else {
		GError *error = NULL;

		soup_connection_tunnel_handshake (item->conn, item->cancellable, &error);
		tunnel_complete (tunnel_item, SOUP_STATUS_OK, error);
	}
}

static void
tunnel_connect (SoupMessageQueueItem *item)
{
	SoupSession *session = item->session;
	SoupMessageQueueItem *tunnel_item;
	GUri *uri;
	SoupMessage *msg;

	item->state = SOUP_MESSAGE_TUNNELING;

	uri = soup_connection_get_remote_uri (item->conn);
	msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT, uri);
	soup_message_add_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	tunnel_item = soup_session_append_queue_item (session, msg,
						      item->async,
						      item->cancellable,
						      NULL, NULL);
	tunnel_item->io_priority = item->io_priority;
	tunnel_item->related = item;
	soup_message_queue_item_ref (item);
	soup_session_set_item_connection (session, tunnel_item, item->conn);
	tunnel_item->state = SOUP_MESSAGE_RUNNING;

	soup_session_send_queue_item (session, tunnel_item,
				      (SoupMessageIOCompletionFn)tunnel_message_completed);
	soup_message_io_run (msg, !item->async);
	g_object_unref (msg);
}

static void
connect_complete (SoupMessageQueueItem *item, SoupConnection *conn, GError *error)
{
	SoupSession *session = item->session;

	if (!error) {
		item->state = SOUP_MESSAGE_CONNECTED;
		return;
	}

	item->error = error;
	soup_connection_disconnect (conn);
	if (item->state == SOUP_MESSAGE_CONNECTING) {
		soup_session_set_item_connection (session, item, NULL);
		item->state = SOUP_MESSAGE_READY;
	}
}

static void
connect_async_complete (GObject      *object,
			GAsyncResult *result,
			gpointer      user_data)
{
	SoupConnection *conn = SOUP_CONNECTION (object);
	SoupMessageQueueItem *item = user_data;
	GError *error = NULL;

	soup_connection_connect_finish (conn, result, &error);
	connect_complete (item, conn, error);

	if (item->state == SOUP_MESSAGE_CONNECTED ||
	    item->state == SOUP_MESSAGE_READY)
		async_run_queue (item->session);
	else
		soup_session_kick_queue (item->session);

	soup_message_queue_item_unref (item);
}

/* requires conn_lock */
static SoupConnection *
get_connection_for_host (SoupSession *session,
			 SoupMessageQueueItem *item,
			 SoupSessionHost *host,
			 gboolean need_new_connection,
			 gboolean *try_cleanup)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupConnection *conn;
	GSList *conns;
	guint num_pending = 0;

	if (priv->disposed)
		return NULL;

	if (item->conn) {
		g_return_val_if_fail (soup_connection_get_state (item->conn) != SOUP_CONNECTION_DISCONNECTED, FALSE);
		return item->conn;
	}

	for (conns = host->connections; conns; conns = conns->next) {
		conn = conns->data;

		if (!need_new_connection && soup_connection_get_state (conn) == SOUP_CONNECTION_IDLE) {
			soup_connection_set_state (conn, SOUP_CONNECTION_IN_USE);
			return conn;
		} else if (soup_connection_get_state (conn) == SOUP_CONNECTION_CONNECTING)
			num_pending++;
	}

	/* Limit the number of pending connections; num_messages / 2
	 * is somewhat arbitrary...
	 */
	if (num_pending > host->num_messages / 2)
		return NULL;

	if (host->num_conns >= priv->max_conns_per_host) {
		if (need_new_connection)
			*try_cleanup = TRUE;
		return NULL;
	}

	if (priv->num_conns >= priv->max_conns) {
		*try_cleanup = TRUE;
		return NULL;
	}

	ensure_socket_props (session);
	conn = g_object_new (SOUP_TYPE_CONNECTION,
			     "remote-uri", host->uri,
			     "ssl", soup_uri_is_https (host->uri),
			     "socket-properties", priv->socket_props,
			     NULL);

	g_signal_connect (conn, "disconnected",
			  G_CALLBACK (connection_disconnected),
			  session);
	g_signal_connect (conn, "notify::state",
			  G_CALLBACK (connection_state_changed),
			  session);

	g_hash_table_insert (priv->conns, conn, host);

	priv->num_conns++;
	host->num_conns++;
	host->connections = g_slist_prepend (host->connections, conn);

	if (host->keep_alive_src) {
		g_source_destroy (host->keep_alive_src);
		g_source_unref (host->keep_alive_src);
		host->keep_alive_src = NULL;
	}

	return conn;
}

static gboolean
get_connection (SoupMessageQueueItem *item, gboolean *should_cleanup)
{
	SoupSession *session = item->session;
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;
	SoupConnection *conn = NULL;
	gboolean my_should_cleanup = FALSE;
	gboolean need_new_connection;

	soup_session_cleanup_connections (session, FALSE);

	need_new_connection =
		(soup_message_query_flags (item->msg, SOUP_MESSAGE_NEW_CONNECTION)) ||
		(!soup_message_query_flags (item->msg, SOUP_MESSAGE_IDEMPOTENT) &&
		 !SOUP_METHOD_IS_IDEMPOTENT (soup_message_get_method (item->msg)));

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_message (session, item->msg);
	while (TRUE) {
		conn = get_connection_for_host (session, item, host,
						need_new_connection,
						&my_should_cleanup);
		if (conn || item->async)
			break;

		if (my_should_cleanup) {
			g_mutex_unlock (&priv->conn_lock);
			soup_session_cleanup_connections (session, TRUE);
			g_mutex_lock (&priv->conn_lock);

			my_should_cleanup = FALSE;
			continue;
		}

		g_cond_wait (&priv->conn_cond, &priv->conn_lock);
	}
	g_mutex_unlock (&priv->conn_lock);

	if (!conn) {
		if (should_cleanup)
			*should_cleanup = my_should_cleanup;
		return FALSE;
	}

	soup_session_set_item_connection (session, item, conn);

	if (soup_connection_get_state (item->conn) != SOUP_CONNECTION_NEW) {
		item->state = SOUP_MESSAGE_READY;
		return TRUE;
	}

	item->state = SOUP_MESSAGE_CONNECTING;

	if (item->async) {
		soup_message_queue_item_ref (item);
		soup_connection_connect_async (item->conn,
					       item->io_priority,
					       item->cancellable,
					       connect_async_complete, item);
		return FALSE;
	} else {
		GError *error = NULL;

		soup_connection_connect (item->conn, item->cancellable, &error);
		connect_complete (item, conn, error);

		return TRUE;
	}
}

static void
soup_session_process_queue_item (SoupSession          *session,
				 SoupMessageQueueItem *item,
				 gboolean             *should_cleanup,
				 gboolean              loop)
{
	g_assert (item->session == session);

	do {
		if (item->paused)
			return;

		switch (item->state) {
		case SOUP_MESSAGE_STARTING:
			if (!get_connection (item, should_cleanup))
				return;
			break;

		case SOUP_MESSAGE_CONNECTED:
			if (soup_connection_is_tunnelled (item->conn))
				tunnel_connect (item);
			else
				item->state = SOUP_MESSAGE_READY;
			break;

		case SOUP_MESSAGE_READY:
			if (item->connect_only) {
				item->state = SOUP_MESSAGE_FINISHING;
				break;
			}

			if (item->error || soup_message_get_status (item->msg)) {
				item->state = SOUP_MESSAGE_FINISHING;
				break;
			}

			item->state = SOUP_MESSAGE_RUNNING;

			soup_session_send_queue_item (session, item,
						      (SoupMessageIOCompletionFn)message_completed);

			if (item->async)
				async_send_request_running (session, item);
			return;

		case SOUP_MESSAGE_RUNNING:
			if (item->async)
				return;

			item->state = SOUP_MESSAGE_FINISHING;
			break;

		case SOUP_MESSAGE_CACHED:
		case SOUP_MESSAGE_TUNNELING:
			/* Will be handled elsewhere */
			return;

		case SOUP_MESSAGE_RESTARTING:
			item->state = SOUP_MESSAGE_STARTING;
			soup_message_restarted (item->msg);
			break;

		case SOUP_MESSAGE_FINISHING:
			item->state = SOUP_MESSAGE_FINISHED;
			soup_message_finished (item->msg);
			soup_message_queue_item_ref (item);
			soup_session_unqueue_item (session, item);
			if (item->async && item->callback)
				item->callback (session, item->msg, item->callback_data);
			soup_message_queue_item_unref (item);
			return;

		default:
			/* Nothing to do with this message in any
			 * other state.
			 */
			g_warn_if_fail (item->async);
			return;
		}
	} while (loop && item->state != SOUP_MESSAGE_FINISHED);
}

static void
async_run_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	SoupMessage *msg;
	gboolean try_cleanup = TRUE, should_cleanup = FALSE;

	g_object_ref (session);
	soup_session_cleanup_connections (session, FALSE);

 try_again:
	for (item = soup_message_queue_first (priv->queue);
	     item;
	     item = soup_message_queue_next (priv->queue, item)) {
		msg = item->msg;

		/* CONNECT messages are handled specially */
		if (soup_message_get_method (msg) == SOUP_METHOD_CONNECT)
			continue;

		if (!item->async ||
                    item->async_context != g_main_context_get_thread_default ())
			continue;

		item->async_pending = FALSE;
		soup_session_process_queue_item (session, item, &should_cleanup, TRUE);
	}

	if (try_cleanup && should_cleanup) {
		/* There is at least one message in the queue that
		 * could be sent if we cleanupd an idle connection from
		 * some other server.
		 */
		if (soup_session_cleanup_connections (session, TRUE)) {
			try_cleanup = should_cleanup = FALSE;
			goto try_again;
		}
	}

	g_object_unref (session);
}

static gboolean
idle_run_queue (gpointer user_data)
{
	GWeakRef *wref = user_data;
	SoupSession *session;

	session = g_weak_ref_get (wref);
	if (!session)
		return FALSE;

	async_run_queue (session);
	g_object_unref (session);
	return FALSE;
}

static void
idle_run_queue_dnotify (gpointer user_data)
{
	GWeakRef *wref = user_data;

	g_weak_ref_clear (wref);
	g_slice_free (GWeakRef, wref);
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
soup_session_requeue_message (SoupSession *session,
			      SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;

	item = soup_message_queue_lookup (priv->queue, msg);
	soup_session_requeue_item (session, item, &item->error);
	soup_message_queue_item_unref (item);
}

/**
 * soup_session_pause_message:
 * @session: a #SoupSession
 * @msg: a #SoupMessage currently running on @session
 *
 * Pauses HTTP I/O on @msg. Call soup_session_unpause_message() to
 * resume I/O.
 **/
void
soup_session_pause_message (SoupSession *session,
			    SoupMessage *msg)
{
	SoupSessionPrivate *priv;
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_session_get_instance_private (session);
	item = soup_message_queue_lookup (priv->queue, msg);
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->async);

	item->paused = TRUE;
	if (item->state == SOUP_MESSAGE_RUNNING)
		soup_message_io_pause (msg);
	soup_message_queue_item_unref (item);
}

static void
soup_session_kick_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	GHashTable *async_pending;
	gboolean have_sync_items = FALSE;

	if (priv->disposed)
		return;

	async_pending = g_hash_table_new (NULL, NULL);
	for (item = soup_message_queue_first (priv->queue);
	     item;
	     item = soup_message_queue_next (priv->queue, item)) {
		if (item->async) {
			GMainContext *context = item->async_context;

			if (!g_hash_table_contains (async_pending, context)) {
				if (!item->async_pending) {
					GWeakRef *wref = g_slice_new (GWeakRef);
					GSource *source;

					g_weak_ref_init (wref, session);
					source = soup_add_completion_reffed (context, idle_run_queue, wref, idle_run_queue_dnotify);
					g_source_unref (source);
				}
				g_hash_table_add (async_pending, context);
			}
			item->async_pending = TRUE;
		} else
			have_sync_items = TRUE;
	}
	g_hash_table_unref (async_pending);

	if (have_sync_items) {
		g_mutex_lock (&priv->conn_lock);
		g_cond_broadcast (&priv->conn_cond);
		g_mutex_unlock (&priv->conn_lock);
	}
}

/**
 * soup_session_unpause_message:
 * @session: a #SoupSession
 * @msg: a #SoupMessage currently running on @session
 *
 * Resumes HTTP I/O on @msg. Use this to resume after calling
 * soup_session_pause_message().
 *
 * If @msg is being sent via blocking I/O, this will resume reading or
 * writing immediately. If @msg is using non-blocking I/O, then
 * reading or writing won't resume until you return to the main loop.
 **/
void
soup_session_unpause_message (SoupSession *session,
			      SoupMessage *msg)
{
	SoupSessionPrivate *priv;
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_session_get_instance_private (session);
	item = soup_message_queue_lookup (priv->queue, msg);
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->async);

	item->paused = FALSE;
	if (item->state == SOUP_MESSAGE_RUNNING)
		soup_message_io_unpause (msg);
	soup_message_queue_item_unref (item);

	soup_session_kick_queue (session);
}

void
soup_session_cancel_message (SoupSession *session,
			     SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;

	item = soup_message_queue_lookup (priv->queue, msg);
        /* If the message is already ending, don't do anything */
	if (!item)
                return;

	g_cancellable_cancel (item->cancellable);
	soup_message_queue_item_unref (item);
}

/**
 * soup_session_abort:
 * @session: the session
 *
 * Cancels all pending requests in @session and closes all idle
 * persistent connections.
 *
 */
void
soup_session_abort (SoupSession *session)
{
	SoupSessionPrivate *priv;
	GSList *conns, *c;
	GHashTableIter iter;
	gpointer conn, host;
        SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	priv = soup_session_get_instance_private (session);

	/* Cancel everything */
	for (item = soup_message_queue_first (priv->queue);
	     item;
	     item = soup_message_queue_next (priv->queue, item)) {
		g_cancellable_cancel (item->cancellable);
	}

	/* Close all idle connections */
	g_mutex_lock (&priv->conn_lock);
	conns = NULL;
	g_hash_table_iter_init (&iter, priv->conns);
	while (g_hash_table_iter_next (&iter, &conn, &host)) {
		SoupConnectionState state;

		state = soup_connection_get_state (conn);
		if (state == SOUP_CONNECTION_IDLE ||
		    state == SOUP_CONNECTION_REMOTE_DISCONNECTED) {
			conns = g_slist_prepend (conns, g_object_ref (conn));
			g_hash_table_iter_remove (&iter);
			drop_connection (session, host, conn);
		}
	}
	g_mutex_unlock (&priv->conn_lock);

	for (c = conns; c; c = c->next) {
		soup_connection_disconnect (c->data);
		g_object_unref (c->data);
	}

	g_slist_free (conns);
}

/**
 * soup_session_add_feature:
 * @session: a #SoupSession
 * @feature: an object that implements #SoupSessionFeature
 *
 * Adds @feature's functionality to @session.
 *
 * See the main #SoupSession documentation for information on what
 * features are present in sessions by default.
 *
 **/
void
soup_session_add_feature (SoupSession *session, SoupSessionFeature *feature)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_SESSION_FEATURE (feature));

	priv = soup_session_get_instance_private (session);
	priv->features = g_slist_prepend (priv->features, g_object_ref (feature));
	g_hash_table_remove_all (priv->features_cache);
	soup_session_feature_attach (feature, session);
}

/**
 * soup_session_add_feature_by_type:
 * @session: a #SoupSession
 * @feature_type: a #GType
 *
 * If @feature_type is the type of a class that implements
 * #SoupSessionFeature, this creates a new feature of that type and
 * adds it to @session as with soup_session_add_feature(). You can use
 * this when you don't need to customize the new feature in any way.
 *
 * If @feature_type is not a #SoupSessionFeature type, this gives each
 * existing feature on @session the chance to accept @feature_type as
 * a "subfeature". This can be used to add new #SoupAuth types, for instance.
 *
 * See the main #SoupSession documentation for information on what
 * features are present in sessions by default.
 *
 **/
void
soup_session_add_feature_by_type (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);

	if (g_type_is_a (feature_type, SOUP_TYPE_SESSION_FEATURE)) {
		SoupSessionFeature *feature;

		feature = g_object_new (feature_type, NULL);
		soup_session_add_feature (session, feature);
		g_object_unref (feature);
	} else {
		GSList *f;

		for (f = priv->features; f; f = f->next) {
			if (soup_session_feature_add_feature (f->data, feature_type))
				return;
		}
		g_warning ("No feature manager for feature of type '%s'", g_type_name (feature_type));
	}
}

/**
 * soup_session_remove_feature:
 * @session: a #SoupSession
 * @feature: a feature that has previously been added to @session
 *
 * Removes @feature's functionality from @session.
 *
 **/
void
soup_session_remove_feature (SoupSession *session, SoupSessionFeature *feature)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (g_slist_find (priv->features, feature)) {
		priv->features = g_slist_remove (priv->features, feature);
		g_hash_table_remove_all (priv->features_cache);
		soup_session_feature_detach (feature, session);
		g_object_unref (feature);
	}
}

/**
 * soup_session_remove_feature_by_type:
 * @session: a #SoupSession
 * @feature_type: a #GType
 *
 * Removes all features of type @feature_type (or any subclass of
 * @feature_type) from @session. You can also remove standard features
 * from the session at construct time by using the
 * SoupSession:remove-feature-by-type property.
 *
 **/
void
soup_session_remove_feature_by_type (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;
	GSList *f;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);

	if (g_type_is_a (feature_type, SOUP_TYPE_SESSION_FEATURE)) {
	restart:
		for (f = priv->features; f; f = f->next) {
			if (G_TYPE_CHECK_INSTANCE_TYPE (f->data, feature_type)) {
				soup_session_remove_feature (session, f->data);
				goto restart;
			}
		}
	} else {
		for (f = priv->features; f; f = f->next) {
			if (soup_session_feature_remove_feature (f->data, feature_type))
				return;
		}
		g_warning ("No feature manager for feature of type '%s'", g_type_name (feature_type));
	}
}

/**
 * soup_session_has_feature:
 * @session: a #SoupSession
 * @feature_type: the #GType of the class of features to check for
 *
 * Tests if @session has at a feature of type @feature_type (which can
 * be the type of either a #SoupSessionFeature, or else a subtype of
 * some class managed by another feature, such as #SoupAuth).
 *
 * Returns: %TRUE or %FALSE
 *
 **/
gboolean
soup_session_has_feature (SoupSession *session,
			  GType        feature_type)
{
	SoupSessionPrivate *priv;
	GSList *f;

	g_return_val_if_fail (SOUP_IS_SESSION (session), FALSE);

	priv = soup_session_get_instance_private (session);

	if (g_type_is_a (feature_type, SOUP_TYPE_SESSION_FEATURE)) {
		for (f = priv->features; f; f = f->next) {
			if (G_TYPE_CHECK_INSTANCE_TYPE (f->data, feature_type))
				return TRUE;
		}
	} else {
		for (f = priv->features; f; f = f->next) {
			if (soup_session_feature_has_feature (f->data, feature_type))
				return TRUE;
		}
	}

	return FALSE;
}

/**
 * soup_session_get_features:
 * @session: a #SoupSession
 * @feature_type: the #GType of the class of features to get
 *
 * Generates a list of @session's features of type @feature_type. (If
 * you want to see all features, you can pass %SOUP_TYPE_SESSION_FEATURE
 * for @feature_type.)
 *
 * Returns: (transfer container) (element-type Soup.SessionFeature):
 * a list of features. You must free the list, but not its contents
 *
 **/
GSList *
soup_session_get_features (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;
	GSList *f, *ret;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	for (f = priv->features, ret = NULL; f; f = f->next) {
		if (G_TYPE_CHECK_INSTANCE_TYPE (f->data, feature_type))
			ret = g_slist_prepend (ret, f->data);
	}
	return g_slist_reverse (ret);
}

/**
 * soup_session_get_feature:
 * @session: a #SoupSession
 * @feature_type: the #GType of the feature to get
 *
 * Gets the first feature in @session of type @feature_type. For
 * features where there may be more than one feature of a given type,
 * use soup_session_get_features().
 *
 * Returns: (nullable) (transfer none): a #SoupSessionFeature, or
 * %NULL. The feature is owned by @session.
 *
 **/
SoupSessionFeature *
soup_session_get_feature (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;
	SoupSessionFeature *feature;
	GSList *f;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);

	feature = g_hash_table_lookup (priv->features_cache,
				       GSIZE_TO_POINTER (feature_type));
	if (feature)
		return feature;

	for (f = priv->features; f; f = f->next) {
		feature = f->data;
		if (G_TYPE_CHECK_INSTANCE_TYPE (feature, feature_type)) {
			g_hash_table_insert (priv->features_cache,
					     GSIZE_TO_POINTER (feature_type),
					     feature);
			return feature;
		}
	}
	return NULL;
}

/**
 * soup_session_get_feature_for_message:
 * @session: a #SoupSession
 * @feature_type: the #GType of the feature to get
 * @msg: a #SoupMessage
 *
 * Gets the first feature in @session of type @feature_type, provided
 * that it is not disabled for @msg. As with
 * soup_session_get_feature(), this should only be used for features
 * where @feature_type is only expected to match a single feature. In
 * particular, if there are two matching features, and the first is
 * disabled on @msg, and the second is not, then this will return
 * %NULL, not the second feature.
 *
 * Returns: (nullable) (transfer none): a #SoupSessionFeature, or %NULL. The
 * feature is owned by @session.
 *
 **/
SoupSessionFeature *
soup_session_get_feature_for_message (SoupSession *session, GType feature_type,
				      SoupMessage *msg)
{
	SoupSessionFeature *feature;

	feature = soup_session_get_feature (session, feature_type);
	if (feature && soup_message_disables_feature (msg, feature))
		return NULL;
	return feature;
}

static void
soup_session_class_init (SoupSessionClass *session_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (session_class);

	/* virtual method override */
	object_class->dispose = soup_session_dispose;
	object_class->finalize = soup_session_finalize;
	object_class->set_property = soup_session_set_property;
	object_class->get_property = soup_session_get_property;

	/* signals */

	/**
	 * SoupSession::request-queued:
	 * @session: the session
	 * @msg: the request that was queued
	 *
	 * Emitted when a request is queued on @session.
	 *
	 * When sending a request, first #SoupSession::request_queued
	 * is emitted, indicating that the session has become aware of
	 * the request.
	 *
	 * After a connection is available to send the request various
	 * #SoupMessage signals are emitted as the message is
	 * processed. If the message is requeued, it will emit
	 * #SoupMessage::restarted, which will then be followed by other
	 * #SoupMessage signals when the message is re-sent.
	 *
	 * Eventually, the message will emit #SoupMessage::finished.
	 * Normally, this signals the completion of message
	 * processing. However, it is possible that the application
	 * will requeue the message from the "finished" handler.
	 * In that case the process will loop back.
	 *
	 * Eventually, a message will reach "finished" and not be
	 * requeued. At that point, the session will emit
	 * #SoupSession::request_unqueued to indicate that it is done
	 * with the message.
	 *
	 * To sum up: #SoupSession::request_queued and
	 * #SoupSession::request_unqueued are guaranteed to be emitted
	 * exactly once, but #SoupMessage::finished (and all of the
	 * other #SoupMessage signals) may be invoked multiple times
	 * for a given message.
	 *
	 **/
	signals[REQUEST_QUEUED] =
		g_signal_new ("request-queued",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0, /* FIXME? */
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_MESSAGE);

	/**
	 * SoupSession::request-unqueued:
	 * @session: the session
	 * @msg: the request that was unqueued
	 *
	 * Emitted when a request is removed from @session's queue,
	 * indicating that @session is done with it. See
	 * #SoupSession::request_queued for a detailed description of the
	 * message lifecycle within a session.
	 *
	 **/
	signals[REQUEST_UNQUEUED] =
		g_signal_new ("request-unqueued",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0, /* FIXME? */
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_MESSAGE);

	/* properties */
	/**
	 * SoupSession:proxy-resolver:
	 *
	 * A #GProxyResolver to use with this session.
	 *
	 * If no proxy resolver is set, then the default proxy resolver
	 * will be used. See g_proxy_resolver_get_default().
	 * You can set it to %NULL if you don't want to use proxies, or
	 * set it to your own #GProxyResolver if you want to control
	 * what proxies get used.
	 *
	 */
	g_object_class_install_property (
		object_class, PROP_PROXY_RESOLVER,
		g_param_spec_object ("proxy-resolver",
				     "Proxy Resolver",
				     "The GProxyResolver to use for this session",
				     G_TYPE_PROXY_RESOLVER,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS,
		g_param_spec_int ("max-conns",
				  "Max Connection Count",
				  "The maximum number of connections that the session can open at once",
				  1,
				  G_MAXINT,
				  SOUP_SESSION_MAX_CONNS_DEFAULT,
				  G_PARAM_READWRITE |
				  G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS_PER_HOST,
		g_param_spec_int ("max-conns-per-host",
				  "Max Per-Host Connection Count",
				  "The maximum number of connections that the session can open at once to a given host",
				  1,
				  G_MAXINT,
				  SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT,
				  G_PARAM_READWRITE |
				  G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:idle-timeout:
	 *
	 * Connection lifetime (in seconds) when idle. Any connection
	 * left idle longer than this will be closed.
	 *
	 * Although you can change this property at any time, it will
	 * only affect newly-created connections, not currently-open
	 * ones. You can call soup_session_abort() after setting this
	 * if you want to ensure that all future connections will have
	 * this timeout value.
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_IDLE_TIMEOUT,
		g_param_spec_uint ("idle-timeout",
				   "Idle Timeout",
				   "Connection lifetime when idle",
				   0, G_MAXUINT, 60,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:tls-database:
	 *
	 * Sets the #GTlsDatabase to use for validating SSL/TLS
	 * certificates.
	 *
	 * If no certificate database is set, then the default database will be
	 * used. See g_tls_backend_get_default_database().
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_TLS_DATABASE,
		g_param_spec_object ("tls-database",
				     "TLS Database",
				     "TLS database to use",
				     G_TYPE_TLS_DATABASE,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:timeout:
	 *
	 * The timeout (in seconds) for socket I/O operations
	 * (including connecting to a server, and waiting for a reply
	 * to an HTTP request).
	 *
	 * Although you can change this property at any time, it will
	 * only affect newly-created connections, not currently-open
	 * ones. You can call soup_session_abort() after setting this
	 * if you want to ensure that all future connections will have
	 * this timeout value.
	 *
	 * Not to be confused with #SoupSession:idle-timeout (which is
	 * the length of time that idle persistent connections will be
	 * kept open).
	 */
	g_object_class_install_property (
		object_class, PROP_TIMEOUT,
		g_param_spec_uint ("timeout",
				   "Timeout value",
				   "Value in seconds to timeout a blocking I/O",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:user-agent:
	 *
	 * If non-%NULL, the value to use for the "User-Agent" header
	 * on #SoupMessage<!-- -->s sent from this session.
	 *
	 * RFC 2616 says: "The User-Agent request-header field
	 * contains information about the user agent originating the
	 * request. This is for statistical purposes, the tracing of
	 * protocol violations, and automated recognition of user
	 * agents for the sake of tailoring responses to avoid
	 * particular user agent limitations. User agents SHOULD
	 * include this field with requests."
	 *
	 * The User-Agent header contains a list of one or more
	 * product tokens, separated by whitespace, with the most
	 * significant product token coming first. The tokens must be
	 * brief, ASCII, and mostly alphanumeric (although "-", "_",
	 * and "." are also allowed), and may optionally include a "/"
	 * followed by a version string. You may also put comments,
	 * enclosed in parentheses, between or after the tokens.
	 *
	 * If you set a #SoupSession:user_agent property that has trailing
	 * whitespace, #SoupSession will append its own product token
	 * (eg, "<literal>libsoup/2.3.2</literal>") to the end of the
	 * header for you.
	 **/
	g_object_class_install_property (
		object_class, PROP_USER_AGENT,
		g_param_spec_string ("user-agent",
				     "User-Agent string",
				     "User-Agent string",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:accept-language:
	 *
	 * If non-%NULL, the value to use for the "Accept-Language" header
	 * on #SoupMessage<!-- -->s sent from this session.
	 *
	 * Setting this will disable
	 * #SoupSession:accept-language-auto.
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_ACCEPT_LANGUAGE,
		g_param_spec_string ("accept-language",
				     "Accept-Language string",
				     "Accept-Language string",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:accept-language-auto:
	 *
	 * If %TRUE, #SoupSession will automatically set the string
	 * for the "Accept-Language" header on every #SoupMessage
	 * sent, based on the return value of g_get_language_names().
	 *
	 * Setting this will override any previous value of
	 * #SoupSession:accept-language.
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_ACCEPT_LANGUAGE_AUTO,
		g_param_spec_boolean ("accept-language-auto",
				      "Accept-Language automatic mode",
				      "Accept-Language automatic mode",
				      FALSE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:local-address:
	 *
	 * Sets the #GInetSocketAddress to use for the client side of
	 * the connection.
	 *
	 * Use this property if you want for instance to bind the
	 * local socket to a specific IP address.
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_LOCAL_ADDRESS,
		g_param_spec_object ("local-address",
				     "Local address",
				     "Address of local end of socket",
				     G_TYPE_INET_SOCKET_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:tls-interaction:
	 *
	 * A #GTlsInteraction object that will be passed on to any
	 * #GTlsConnections created by the session. (This can be used to
	 * provide client-side certificates, for example.)
	 *
	 **/
	g_object_class_install_property (
		object_class, PROP_TLS_INTERACTION,
		g_param_spec_object ("tls-interaction",
				     "TLS Interaction",
				     "TLS interaction to use",
				     G_TYPE_TLS_INTERACTION,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
}


static gboolean
expected_to_be_requeued (SoupSession *session, SoupMessage *msg)
{
	if (soup_message_get_status (msg) == SOUP_STATUS_UNAUTHORIZED ||
	    soup_message_get_status (msg) == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		SoupSessionFeature *feature =
			soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER);
		return !feature || !soup_message_disables_feature (msg, feature);
	}

	if (!soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT)) {
		return SOUP_SESSION_WOULD_REDIRECT_AS_GET (session, msg) ||
			SOUP_SESSION_WOULD_REDIRECT_AS_SAFE (session, msg);
	}

	return FALSE;
}

/* send_request_async */

static void
async_send_request_return_result (SoupMessageQueueItem *item,
				  gpointer stream, GError *error)
{
	GTask *task;

	g_return_if_fail (item->task != NULL);

	g_signal_handlers_disconnect_matched (item->msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, item);

	task = item->task;
	item->task = NULL;

	if (error)
		g_task_return_error (task, error);
	else if (item->error) {
		if (stream)
			g_object_unref (stream);
		g_task_return_error (task, g_error_copy (item->error));
	} else
		g_task_return_pointer (task, stream, g_object_unref);
	g_object_unref (task);
}

static void
async_send_request_restarted (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

	/* We won't be needing this, then. */
	if (item->task)
		g_object_set_data (G_OBJECT (item->task), "SoupSession:ostream", NULL);
	item->io_started = FALSE;
}

static void
async_send_request_finished (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;
	GMemoryOutputStream *mostream;
	GInputStream *istream = NULL;
	GError *error = NULL;

	if (!item->task) {
		/* Something else already took care of it. */
		return;
	}

	mostream = g_object_get_data (G_OBJECT (item->task), "SoupSession:ostream");
	if (mostream) {
		gpointer data;
		gssize size;

		/* We thought it would be requeued, but it wasn't, so
		 * return the original body.
		 */
		size = g_memory_output_stream_get_data_size (mostream);
		data = size ? g_memory_output_stream_steal_data (mostream) : g_strdup ("");
		istream = g_memory_input_stream_new_from_data (data, size, g_free);
	} else if (item->io_started) {
		/* The message finished before becoming readable. This
		 * will happen, eg, if it's cancelled from got-headers.
		 * Do nothing; the op will complete via read_ready_cb()
		 * after we return;
		 */
		return;
	} else {
		/* The message finished before even being started;
		 * probably a tunnel connect failure.
		 */
		istream = g_memory_input_stream_new ();
	}

	async_send_request_return_result (item, istream, error);
}

static void
send_async_spliced (GObject *source, GAsyncResult *result, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;
	GInputStream *istream = g_object_get_data (source, "istream");
	GError *error = NULL;

	/* It should be safe to call the sync close() method here since
	 * the message body has already been written.
	 */
	g_input_stream_close (istream, NULL, NULL);
	g_object_unref (istream);

	/* If the message was cancelled, it will be completed via other means */
	if (g_cancellable_is_cancelled (item->cancellable) ||
	    !item->task) {
		soup_message_queue_item_unref (item);
		return;
	}

	if (g_output_stream_splice_finish (G_OUTPUT_STREAM (source),
					   result, &error) == -1) {
		async_send_request_return_result (item, NULL, error);
		soup_message_queue_item_unref (item);
		return;
	}

	/* Otherwise either restarted or finished will eventually be called. */
	soup_session_kick_queue (item->session);
	soup_message_queue_item_unref (item);
}

static void
send_async_maybe_complete (SoupMessageQueueItem *item,
			   GInputStream         *stream)
{
	if (expected_to_be_requeued (item->session, item->msg)) {
		GOutputStream *ostream;

		/* Gather the current message body... */
		ostream = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);
		g_object_set_data_full (G_OBJECT (item->task), "SoupSession:ostream",
					ostream, g_object_unref);

		g_object_set_data (G_OBJECT (ostream), "istream", stream);

		/* Give the splice op its own ref on item */
		soup_message_queue_item_ref (item);
		/* We don't use CLOSE_SOURCE because we need to control when the
		 * side effects of closing the SoupClientInputStream happen.
		 */
		g_output_stream_splice_async (ostream, stream,
					      G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
					      item->io_priority,
					      item->cancellable,
					      send_async_spliced, item);
		return;
	}

	async_send_request_return_result (item, stream, NULL);
}

static void
run_until_read_done (SoupMessage          *msg,
		     GAsyncResult         *result,
		     SoupMessageQueueItem *item)
{
	GInputStream *stream = NULL;
	GError *error = NULL;

	soup_message_io_run_until_read_finish (msg, result, &error);
	if (error && !item->io_started) {
		/* Message was restarted, we'll try again. */
		g_error_free (error);
		return;
	}

	if (!error)
		stream = soup_message_io_get_response_istream (msg, &error);

	if (stream) {
		send_async_maybe_complete (item, stream);
	        return;
	}

	if (item->state != SOUP_MESSAGE_FINISHED) {
		if (soup_message_io_in_progress (msg))
			soup_message_io_finished (msg);
		item->paused = FALSE;
		item->state = SOUP_MESSAGE_FINISHING;
		soup_session_process_queue_item (item->session, item, NULL, FALSE);
	}
	async_send_request_return_result (item, NULL, error);
}

static void
async_send_request_running (SoupSession *session, SoupMessageQueueItem *item)
{
	if (item->task) {
		item->io_started = TRUE;
		soup_message_io_run_until_read_async (item->msg,
						      item->io_priority,
						      item->cancellable,
						      (GAsyncReadyCallback)run_until_read_done,
						      item);
		return;
	}

	soup_message_io_run (item->msg, FALSE);
}

static void
cache_stream_finished (GInputStream         *stream,
		       SoupMessageQueueItem *item)
{
	g_signal_handlers_disconnect_matched (stream, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, item);
	item->state = SOUP_MESSAGE_FINISHING;
	soup_session_kick_queue (item->session);
	soup_message_queue_item_unref (item);
}

static void
async_return_from_cache (SoupMessageQueueItem *item,
			 GInputStream         *stream)
{
	const char *content_type;
	GHashTable *params = NULL;

	soup_message_got_headers (item->msg);

	content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (item->msg), &params);
	if (content_type) {
		soup_message_content_sniffed (item->msg, content_type, params);
		g_hash_table_unref (params);
	}

	soup_message_queue_item_ref (item);
	g_signal_connect (stream, "eof", G_CALLBACK (cache_stream_finished), item);
	g_signal_connect (stream, "closed", G_CALLBACK (cache_stream_finished), item);

	async_send_request_return_result (item, g_object_ref (stream), NULL);
}

typedef struct {
	SoupCache *cache;
	SoupMessage *conditional_msg;
	SoupMessageQueueItem *item;
} AsyncCacheConditionalData;

static void
async_cache_conditional_data_free (AsyncCacheConditionalData *data)
{
	g_object_unref (data->conditional_msg);
	g_object_unref (data->cache);
	soup_message_queue_item_unref (data->item);
	g_slice_free (AsyncCacheConditionalData, data);
}

static void
cancel_cache_response (SoupMessageQueueItem *item)
{
	item->paused = FALSE;
	item->state = SOUP_MESSAGE_FINISHING;
	soup_session_kick_queue (item->session);
}

static void
conditional_get_ready_cb (SoupSession               *session,
			  GAsyncResult              *result,
			  AsyncCacheConditionalData *data)
{
	GInputStream *stream;
	GError *error = NULL;

	stream = soup_session_send_finish (session, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		soup_cache_cancel_conditional_request (data->cache, data->conditional_msg);
		cancel_cache_response (data->item);
		async_cache_conditional_data_free (data);
		return;
	}
	g_object_unref (stream);

	soup_cache_update_from_conditional_request (data->cache, data->conditional_msg);

	if (soup_message_get_status (data->conditional_msg) == SOUP_STATUS_NOT_MODIFIED) {
		stream = soup_cache_send_response (data->cache, data->item->msg);
		if (stream) {
			async_return_from_cache (data->item, stream);
			g_object_unref (stream);
			async_cache_conditional_data_free (data);
			return;
		}
	}

	/* The resource was modified or the server returned a 200
	 * OK. Either way we reload it. FIXME.
	 */
	data->item->state = SOUP_MESSAGE_STARTING;
	soup_session_kick_queue (session);
	async_cache_conditional_data_free (data);
}

static gboolean
idle_return_from_cache_cb (gpointer data)
{
	GTask *task = data;
	SoupMessageQueueItem *item = g_task_get_task_data (task);
	GInputStream *istream;

	if (item->state == SOUP_MESSAGE_FINISHED) {
		/* The original request was cancelled so it has been
		 * already handled by the cancellation code path.
		 */
		return FALSE;
	} else if (g_cancellable_is_cancelled (item->cancellable)) {
		/* Cancel original msg after g_cancellable_cancel(). */
		cancel_cache_response (item);
		return FALSE;
	}

	istream = g_object_get_data (G_OBJECT (task), "SoupSession:istream");
	async_return_from_cache (item, istream);

	return FALSE;
}


static gboolean
async_respond_from_cache (SoupSession          *session,
			  SoupMessageQueueItem *item)
{
	SoupCache *cache;
	SoupCacheResponse response;

	cache = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);
	if (!cache)
		return FALSE;

	response = soup_cache_has_response (cache, item->msg);
	if (response == SOUP_CACHE_RESPONSE_FRESH) {
		GInputStream *stream;
		GSource *source;

		stream = soup_cache_send_response (cache, item->msg);
		if (!stream) {
			/* Cached file was deleted? */
			return FALSE;
		}
		g_object_set_data_full (G_OBJECT (item->task), "SoupSession:istream",
					stream, g_object_unref);

		source = g_timeout_source_new (0);
		g_task_attach_source (item->task, source,
				      (GSourceFunc) idle_return_from_cache_cb);
		g_source_unref (source);
		return TRUE;
	} else if (response == SOUP_CACHE_RESPONSE_NEEDS_VALIDATION) {
		SoupMessage *conditional_msg;
		AsyncCacheConditionalData *data;

		conditional_msg = soup_cache_generate_conditional_request (cache, item->msg);
		if (!conditional_msg)
			return FALSE;

		/* Detect any quick cancellation before the cache is able to return data. */
		data = g_slice_new0 (AsyncCacheConditionalData);
		data->cache = g_object_ref (cache);
		data->conditional_msg = conditional_msg;
		data->item = item;
		soup_message_queue_item_ref (item);
		soup_message_disable_feature (conditional_msg, SOUP_TYPE_CACHE);
		soup_session_send_async (session, conditional_msg,
					 item->io_priority,
					 item->cancellable,
					 (GAsyncReadyCallback)conditional_get_ready_cb,
					 data);

		return TRUE;
	} else
		return FALSE;
}

/**
 * soup_session_send_async:
 * @session: a #SoupSession
 * @msg: a #SoupMessage
 * @io_priority: the I/O priority of the request
 * @cancellable: a #GCancellable
 * @callback: the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously sends @msg and waits for the beginning of a
 * response. When @callback is called, then either @msg has been sent,
 * and its response headers received, or else an error has occurred.
 * Call soup_session_send_finish() to get a #GInputStream for reading
 * the response body.
 *
 * See soup_session_send() for more details on the general semantics.
 *
 */
void
soup_session_send_async (SoupSession         *session,
			 SoupMessage         *msg,
			 int                  io_priority,
			 GCancellable        *cancellable,
			 GAsyncReadyCallback  callback,
			 gpointer             user_data)
{
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));

	item = soup_session_append_queue_item (session, msg, TRUE,
					       cancellable, NULL, NULL);
	item->io_priority = io_priority;
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (async_send_request_restarted), item);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (async_send_request_finished), item);

	item->task = g_task_new (session, item->cancellable, callback, user_data);
	g_task_set_priority (item->task, io_priority);
	g_task_set_task_data (item->task, item, (GDestroyNotify) soup_message_queue_item_unref);
	if (async_respond_from_cache (session, item))
		item->state = SOUP_MESSAGE_CACHED;
	else
		soup_session_kick_queue (session);
}

/**
 * soup_session_send_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the response to a soup_session_send_async() call and (if
 * successful), returns a #GInputStream that can be used to read the
 * response body.
 *
 * Returns: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
 *
 */
GInputStream *
soup_session_send_finish (SoupSession   *session,
			  GAsyncResult  *result,
			  GError       **error)
{
	GTask *task;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	g_return_val_if_fail (g_task_is_valid (result, session), NULL);

	task = G_TASK (result);
	if (g_task_had_error (task)) {
		SoupMessageQueueItem *item = g_task_get_task_data (task);

		if (soup_message_io_in_progress (item->msg))
			soup_message_io_finished (item->msg);
		else if (item->state != SOUP_MESSAGE_FINISHED)
			item->state = SOUP_MESSAGE_FINISHING;

		if (item->state != SOUP_MESSAGE_FINISHED)
			soup_session_process_queue_item (session, item, NULL, FALSE);
	}

	return g_task_propagate_pointer (task, error);
}

/**
 * soup_session_send:
 * @session: a #SoupSession
 * @msg: a #SoupMessage
 * @cancellable: a #GCancellable
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously sends @msg and waits for the beginning of a response.
 * On success, a #GInputStream will be returned which you can use to
 * read the response body. ("Success" here means only that an HTTP
 * response was received and understood; it does not necessarily mean
 * that a 2xx class status code was received.)
 *
 * If non-%NULL, @cancellable can be used to cancel the request;
 * soup_session_send() will return a %G_IO_ERROR_CANCELLED error. Note
 * that with requests that have side effects (eg,
 * <literal>POST</literal>, <literal>PUT</literal>,
 * <literal>DELETE</literal>) it is possible that you might cancel the
 * request after the server acts on it, but before it returns a
 * response, leaving the remote resource in an unknown state.
 *
 * If @msg is requeued due to a redirect or authentication, the
 * initial (3xx/401/407) response body will be suppressed, and
 * soup_session_send() will only return once a final response has been
 * received.
 *
 * Returns: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
 *
 */
GInputStream *
soup_session_send (SoupSession   *session,
		   SoupMessage   *msg,
		   GCancellable  *cancellable,
		   GError       **error)
{
	SoupMessageQueueItem *item;
	GInputStream *stream = NULL;
	GOutputStream *ostream;
	GMemoryOutputStream *mostream;
	gssize size;
	GError *my_error = NULL;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	item = soup_session_append_queue_item (session, msg, FALSE,
					       cancellable, NULL, NULL);

	while (!stream) {
		/* Get a connection, etc */
		soup_session_process_queue_item (session, item, NULL, TRUE);
		if (item->state != SOUP_MESSAGE_RUNNING)
			break;

		/* Send request, read headers */
		if (!soup_message_io_run_until_read (msg, item->cancellable, &my_error)) {
			if (item->state == SOUP_MESSAGE_RESTARTING) {
				/* Message was restarted, we'll try again. */
				g_clear_error (&my_error);
				continue;
			}
			break;
		}

		stream = soup_message_io_get_response_istream (msg, &my_error);
		if (!stream)
			break;

		if (!expected_to_be_requeued (session, msg))
			break;

		/* Gather the current message body... */
		ostream = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);
		if (g_output_stream_splice (ostream, stream,
					    G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
					    G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
					    item->cancellable, &my_error) == -1) {
			g_object_unref (stream);
			g_object_unref (ostream);
			stream = NULL;
			break;
		}
		g_object_unref (stream);
		stream = NULL;

		/* If the message was requeued, loop */
		if (item->state == SOUP_MESSAGE_RESTARTING) {
			g_object_unref (ostream);
			continue;
		}

		/* Not requeued, so return the original body */
		mostream = G_MEMORY_OUTPUT_STREAM (ostream);
		size = g_memory_output_stream_get_data_size (mostream);
		stream = g_memory_input_stream_new ();
		if (size) {
			g_memory_input_stream_add_data (G_MEMORY_INPUT_STREAM (stream),
							g_memory_output_stream_steal_data (mostream),
							size, g_free);
		}
		g_object_unref (ostream);
	}

	if (my_error)
		g_propagate_error (error, my_error);
	else if (item->error) {
		g_clear_object (&stream);
		if (error)
			*error = g_error_copy (item->error);
	} else if (!stream)
		stream = g_memory_input_stream_new ();

	if (!stream) {
		if (soup_message_io_in_progress (msg))
			soup_message_io_finished (msg);
		else if (item->state != SOUP_MESSAGE_FINISHED)
			item->state = SOUP_MESSAGE_FINISHING;
		item->paused = FALSE;
		if (item->state != SOUP_MESSAGE_FINISHED)
			soup_session_process_queue_item (session, item, NULL, TRUE);
	}

	soup_message_queue_item_unref (item);
	return stream;
}

typedef struct {
        goffset content_length;
        char *content_type;
} SessionGetAsyncData;

static void
session_get_async_data_free (SessionGetAsyncData *data)
{
        g_free (data->content_type);
        g_slice_free (SessionGetAsyncData, data);
}

static void
session_get_async_data_set_content_type (SessionGetAsyncData *data,
                                         const char          *content_type,
                                         GHashTable          *params)
{
        GString *type;

        type = g_string_new (content_type);
        if (params) {
                GHashTableIter iter;
                gpointer key, value;

                g_hash_table_iter_init (&iter, params);
                while (g_hash_table_iter_next (&iter, &key, &value)) {
                        g_string_append (type, "; ");
                        soup_header_g_string_append_param (type, key, value);
                }
        }

        g_free (data->content_type);
        data->content_type = g_string_free (type, FALSE);
}

static void
http_input_stream_ready_cb (SoupSession  *session,
                            GAsyncResult *result,
                            GTask        *task)
{
        GInputStream *stream;
        GError *error = NULL;

        stream = soup_session_send_finish (session, result, &error);
        if (stream)
                g_task_return_pointer (task, stream, g_object_unref);
        else
                g_task_return_error (task, error);
        g_object_unref (task);
}

static void
get_http_content_sniffed (SoupMessage         *msg,
                          const char          *content_type,
                          GHashTable          *params,
                          SessionGetAsyncData *data)
{
        session_get_async_data_set_content_type (data, content_type, params);
}

static void
get_http_got_headers (SoupMessage         *msg,
                      SessionGetAsyncData *data)
{
        goffset content_length;
        const char *content_type;
        GHashTable *params = NULL;

        content_length = soup_message_headers_get_content_length (soup_message_get_response_headers (msg));
        data->content_length = content_length != 0 ? content_length : -1;
        content_type = soup_message_headers_get_content_type (soup_message_get_response_headers (msg), &params);
        session_get_async_data_set_content_type (data, content_type, params);
        g_clear_pointer (&params, g_hash_table_destroy);
}

/**
 * soup_session_read_uri_async:
 * @session: a #SoupSession
 * @uri: a URI, in string form
 * @io_priority: the I/O priority of the request
 * @cancellable: a #GCancellable
 * @callback: the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously retrieve @uri.
 *
 * If the given @uri is not HTTP it will fail with %SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME
 * error.
 *
 * When the operation is finished, @callback will be called. You can then
 * call soup_session_read_uri_finish() to get the result of the operation.
 */
void
soup_session_read_uri_async (SoupSession        *session,
                             const char         *uri,
                             int                 io_priority,
                             GCancellable       *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer            user_data)
{
        GTask *task;
        GUri *soup_uri;
        SoupMessage *msg;
        GError *error = NULL;
        SessionGetAsyncData *data;

        g_return_if_fail (SOUP_IS_SESSION (session));
        g_return_if_fail (uri != NULL);

        task = g_task_new (session, cancellable, callback, user_data);
        g_task_set_priority (task, io_priority);

        soup_uri = g_uri_parse (uri, SOUP_HTTP_URI_FLAGS, &error);
        if (!soup_uri) {
                g_task_return_new_error (task,
                                         SOUP_SESSION_ERROR,
                                         SOUP_SESSION_ERROR_BAD_URI,
                                         _("Could not parse URI “%s”: %s"),
                                         uri,
                                         error->message);
                g_error_free (error);
                g_object_unref (task);
                return;
        }

        if (!soup_uri_is_http (soup_uri) && !soup_uri_is_https (soup_uri)) {
                g_task_return_new_error (task,
                                         SOUP_SESSION_ERROR,
                                         SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME,
                                         _("Unsupported URI scheme “%s”"),
                                         g_uri_get_scheme (soup_uri));
                g_object_unref (task);
                g_uri_unref (soup_uri);
                return;
        }

        if (!SOUP_URI_IS_VALID (soup_uri)) {
                g_task_return_new_error (task,
                                         SOUP_SESSION_ERROR,
                                         SOUP_SESSION_ERROR_BAD_URI,
                                         _("Invalid “%s” URI: %s"),
                                         g_uri_get_scheme (soup_uri),
                                         uri);
                g_object_unref (task);
                g_uri_unref (soup_uri);
                return;
        }

        data = g_slice_new0 (SessionGetAsyncData);
        g_task_set_task_data (task, data, (GDestroyNotify)session_get_async_data_free);

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, soup_uri);
        g_signal_connect (msg, "content-sniffed",
                          G_CALLBACK (get_http_content_sniffed), data);
        g_signal_connect (msg, "got-headers",
                          G_CALLBACK (get_http_got_headers), data);
        soup_session_send_async (session, msg,
                                 g_task_get_priority (task),
                                 g_task_get_cancellable (task),
                                 (GAsyncReadyCallback)http_input_stream_ready_cb,
                                 task);
        g_object_unref (msg);
        g_uri_unref (soup_uri);
}

/**
 * soup_session_read_uri_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @content_length: (out) (nullable): location to store content length, or %NULL
 * @content_type: (out) (nullable) (transfer full): location to store content type, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Finish an asynchronous operation started by soup_session_read_uri_async().
 * If the content length is unknown -1 is returned in @content_length.
 *
 * Returns: (transfer full): a #GInputStream to read the contents from,
 *    or %NULL in case of error.
 */
GInputStream *
soup_session_read_uri_finish (SoupSession  *session,
                              GAsyncResult *result,
                              goffset      *content_length,
                              char        **content_type,
                              GError      **error)
{
        GTask *task;

        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (g_task_is_valid (result, session), NULL);

        task = G_TASK (result);

        if (!g_task_had_error (task) && (content_length || content_type)) {
                SessionGetAsyncData *data;

                data = g_task_get_task_data (task);
                if (content_length)
                        *content_length = data->content_length;
                if (content_type)
                        *content_type = g_steal_pointer (&data->content_type);
        }

        return g_task_propagate_pointer (task, error);
}

/**
 * soup_session_read_uri:
 * @session: a #SoupSession
 * @uri: a URI, in string form
 * @cancellable: a #GCancellable
 * @content_length: (out) (nullable): location to store content length, or %NULL
 * @content_type: (out) (nullable) (transfer full): location to store content type, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously retrieve @uri and return a #GInputStream to read the contents.
 * If the content length is unknown -1 is returned in @content_length.
 *
 * If the given @uri is not HTTP it will fail with %SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME
 * error.
 *
 * Returns: (transfer full): a #GInputStream to read the contents from,
 *    or %NULL in case of error.
 */
GInputStream *
soup_session_read_uri (SoupSession  *session,
                       const char   *uri,
                       GCancellable *cancellable,
                       goffset      *content_length,
                       char        **content_type,
                       GError      **error)
{
        GUri *soup_uri;
        SoupMessage *msg;
        GInputStream *stream;
        GError *internal_error = NULL;
        SessionGetAsyncData data = { 0, NULL };

        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (uri != NULL, NULL);

        soup_uri = g_uri_parse (uri, SOUP_HTTP_URI_FLAGS, &internal_error);
        if (!soup_uri) {
                g_set_error (error,
                             SOUP_SESSION_ERROR,
                             SOUP_SESSION_ERROR_BAD_URI,
                             _("Could not parse URI “%s”: %s"),
                             uri,
                             internal_error->message);
                g_error_free (internal_error);

                return NULL;
        }

        if (!soup_uri_is_http (soup_uri) && !soup_uri_is_https (soup_uri)) {
                g_set_error (error,
                             SOUP_SESSION_ERROR,
                             SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME,
                             _("Unsupported URI scheme “%s”"),
                             g_uri_get_scheme (soup_uri));
                g_uri_unref (soup_uri);

                return NULL;
        }

        if (!SOUP_URI_IS_VALID (soup_uri)) {
                g_set_error (error,
                             SOUP_SESSION_ERROR,
                             SOUP_SESSION_ERROR_BAD_URI,
                             _("Invalid “%s” URI: %s"),
                             g_uri_get_scheme (soup_uri),
                             uri);
                g_uri_unref (soup_uri);

                return NULL;
        }

        msg = soup_message_new_from_uri (SOUP_METHOD_GET, soup_uri);
        g_signal_connect (msg, "content-sniffed",
                          G_CALLBACK (get_http_content_sniffed), &data);
        g_signal_connect (msg, "got-headers",
                          G_CALLBACK (get_http_got_headers), &data);
        stream = soup_session_send (session, msg, cancellable, error);
        if (stream) {
                if (content_length)
                        *content_length = data.content_length;
                if (content_type) {
                        *content_type = data.content_type;
                        data.content_type = NULL;
                }
        }

        g_free (data.content_type);
        g_uri_unref (soup_uri);

        return stream;
}

static void
session_load_uri_async_splice_ready_cb (GOutputStream *ostream,
                                        GAsyncResult  *result,
                                        GTask         *task)
{
        GError *error = NULL;

        if (g_output_stream_splice_finish (ostream, result, &error) != -1) {
                g_task_return_pointer (task,
                                       g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream)),
                                       (GDestroyNotify)g_bytes_unref);
        } else {
                g_task_return_error (task, error);
        }
        g_object_unref (task);
}

static void
session_read_uri_async_ready_cb (SoupSession  *session,
                                 GAsyncResult *result,
                                 GTask        *task)
{
        GInputStream *stream;
        goffset content_length = 0;
        char *content_type = NULL;
        GOutputStream *ostream;
        GError *error = NULL;

        stream = soup_session_read_uri_finish (session, result, &content_length, &content_type, &error);
        if (!stream) {
                g_task_return_error (task, error);
                g_object_unref (task);

                return;
        }

        g_task_set_task_data (task, content_type, g_free);

        if (content_length == 0) {
                g_task_return_pointer (task,
                                       g_bytes_new_static (NULL, 0),
                                       (GDestroyNotify)g_bytes_unref);
                g_object_unref (task);
                g_object_unref (stream);

                return;
        }

        ostream = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);
        g_output_stream_splice_async (ostream,
                                      stream,
                                      G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                      G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                      g_task_get_priority (task),
                                      g_task_get_cancellable (task),
                                      (GAsyncReadyCallback)session_load_uri_async_splice_ready_cb,
                                      task);
        g_object_unref (ostream);
        g_object_unref (stream);
}

/**
 * soup_session_load_uri_bytes_async:
 * @session: a #SoupSession
 * @uri: a URI, in string form
 * @io_priority: the I/O priority of the request
 * @cancellable: a #GCancellable
 * @callback: the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously retrieve @uri to be returned as a #GBytes. This function
 * is like soup_session_read_uri_async() but the contents are read and returned
 * as a #GBytes. It should only be used when the resource to be retireved
 * is not too long and can be stored in memory.
 *
 * If the given @uri is not HTTP it will fail with %SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME
 * error.
 *
 * When the operation is finished, @callback will be called. You can then
 * call soup_session_load_uri_bytes_finish() to get the result of the operation.
 */
void
soup_session_load_uri_bytes_async (SoupSession        *session,
                                   const char         *uri,
                                   int                 io_priority,
                                   GCancellable       *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer            user_data)
{
        GTask *task;

        g_return_if_fail (SOUP_IS_SESSION (session));
        g_return_if_fail (uri != NULL);

        task = g_task_new (session, cancellable, callback, user_data);
        g_task_set_priority (task, io_priority);
        soup_session_read_uri_async (session, uri, io_priority, cancellable,
                                     (GAsyncReadyCallback)session_read_uri_async_ready_cb,
                                     task);
}

/**
 * soup_session_load_uri_bytes_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @content_type: (out) (nullable) (transfer full): location to store content type, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Finish an asynchronous operation started by soup_session_load_uri_bytes_async().
 *
 * Returns: (transfer full): a #GBytes with the contents, or %NULL in case of error.
 */
GBytes *
soup_session_load_uri_bytes_finish (SoupSession  *session,
                                    GAsyncResult *result,
                                    char        **content_type,
                                    GError      **error)
{
        GTask *task;

        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (g_task_is_valid (result, session), NULL);

        task = G_TASK (result);

        if (!g_task_had_error (task) && content_type)
                *content_type = g_strdup (g_task_get_task_data (task));

        return g_task_propagate_pointer (task, error);
}

/**
 * soup_session_load_uri_bytes:
 * @session: a #SoupSession
 * @uri: a URI, in string form
 * @cancellable: a #GCancellable
 * @content_type: (out) (nullable) (transfer full): location to store content type, or %NULL
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously retrieve @uri to be returned as a #GBytes. This function
 * is like soup_session_read_uri() but the contents are read and returned
 * as a #GBytes. It should only be used when the resource to be retireved
 * is not too long and can be stored in memory.
 *
 * If the given @uri is not HTTP it will fail with %SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME
 * error.
 *
 * Returns: (transfer full): a #GBytes with the contents, or %NULL in case of error.
 */
GBytes *
soup_session_load_uri_bytes (SoupSession  *session,
                             const char   *uri,
                             GCancellable *cancellable,
                             char        **content_type,
                             GError      **error)
{
        GInputStream *stream;
        GOutputStream *ostream;
        goffset content_length;
        GBytes *bytes = NULL;

        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (uri != NULL, NULL);

        stream = soup_session_read_uri (session, uri, cancellable, &content_length, content_type, error);
        if (!stream)
                return NULL;

        if (content_length == 0) {
                g_object_unref (stream);

                return g_bytes_new_static (NULL, 0);
        }

        ostream = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);
        if (g_output_stream_splice (ostream,
                                    stream,
                                    G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                    G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                    cancellable, error) != -1) {
                bytes = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream));
        }
        g_object_unref (ostream);
        g_object_unref (stream);

        return bytes;
}

static GIOStream *
steal_connection (SoupSession          *session,
                  SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);
        SoupConnection *conn;
        SoupSessionHost *host;
        GIOStream *stream;

        conn = g_object_ref (item->conn);
        soup_session_set_item_connection (session, item, NULL);

        g_mutex_lock (&priv->conn_lock);
        host = get_host_for_message (session, item->msg);
        g_hash_table_remove (priv->conns, conn);
        drop_connection (session, host, conn);
        g_mutex_unlock (&priv->conn_lock);

	stream = soup_connection_steal_iostream (conn);
	if (!item->connect_only)
		soup_message_io_stolen (item->msg);
	g_object_unref (conn);

	return stream;
}

/**
 * soup_session_steal_connection:
 * @session: a #SoupSession
 * @msg: the message whose connection is to be stolen
 *
 * "Steals" the HTTP connection associated with @msg from @session.
 * This happens immediately, regardless of the current state of the
 * connection, and @msg's callback will not be called. You can steal
 * the connection from a #SoupMessage signal handler if you need to
 * wait for part or all of the response to be received first.
 *
 * Calling this function may cause @msg to be freed if you are not
 * holding any other reference to it.
 *
 * Returns: (transfer full): the #GIOStream formerly associated
 *   with @msg (or %NULL if @msg was no longer associated with a
 *   connection). No guarantees are made about what kind of #GIOStream
 *   is returned.
 *
 */
static GIOStream *
soup_session_steal_connection (SoupSession *session,
			       SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	GIOStream *stream = NULL;

	item = soup_message_queue_lookup (priv->queue, msg);
	if (!item)
		return NULL;

	if (item->conn && soup_connection_get_state (item->conn) == SOUP_CONNECTION_IN_USE)
		stream = steal_connection (session, item);

	soup_message_queue_item_unref (item);

	return stream;
}

static GPtrArray *
soup_session_get_supported_websocket_extensions_for_message (SoupSession *session,
							     SoupMessage *msg)
{
        SoupSessionFeature *extension_manager;

        extension_manager = soup_session_get_feature_for_message (session, SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER, msg);
        if (!extension_manager)
                return NULL;

        return soup_websocket_extension_manager_get_supported_extensions (SOUP_WEBSOCKET_EXTENSION_MANAGER (extension_manager));
}

static void websocket_connect_async_stop (SoupMessage *msg, gpointer user_data);

static void
websocket_connect_async_complete (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupMessageQueueItem *item = g_task_get_task_data (task);

	/* Disconnect websocket_connect_async_stop() handler. */
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, task);

	if (item->error) {
		g_task_return_error (task, g_error_copy (item->error));
	} else {
		g_task_return_new_error (task,
					 SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
					 "%s", _("The server did not accept the WebSocket handshake."));
	}

	g_object_unref (task);
}

static void
websocket_connect_async_stop (SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupMessageQueueItem *item = g_task_get_task_data (task);
	GIOStream *stream;
	SoupWebsocketConnection *client;
	SoupSession *session = g_task_get_source_object (task);
	GPtrArray *supported_extensions;
	GList *accepted_extensions = NULL;
	GError *error = NULL;

	/* Disconnect websocket_connect_async_stop() handler. */
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, task);
	/* Ensure websocket_connect_async_complete is not called either. */
	item->callback = NULL;

	supported_extensions = soup_session_get_supported_websocket_extensions_for_message (session, msg);
	if (soup_websocket_client_verify_handshake (item->msg, supported_extensions, &accepted_extensions, &error)) {
		stream = soup_session_steal_connection (item->session, item->msg);
		client = soup_websocket_connection_new (stream,
							soup_message_get_uri (item->msg),
							SOUP_WEBSOCKET_CONNECTION_CLIENT,
							soup_message_headers_get_one (soup_message_get_request_headers (msg), "Origin"),
							soup_message_headers_get_one (soup_message_get_response_headers (msg), "Sec-WebSocket-Protocol"),
							accepted_extensions);
		g_object_unref (stream);
		g_task_return_pointer (task, client, g_object_unref);
		g_object_unref (task);

		return;
	}

	soup_message_io_finished (item->msg);
	g_task_return_error (task, error);
	g_object_unref (task);
}

/**
 * soup_session_websocket_connect_async:
 * @session: a #SoupSession
 * @msg: #SoupMessage indicating the WebSocket server to connect to
 * @origin: (allow-none): origin of the connection
 * @protocols: (allow-none) (array zero-terminated=1): a
 *   %NULL-terminated array of protocols supported
 * @io_priority: the I/O priority of the request
 * @cancellable: a #GCancellable
 * @callback: the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously creates a #SoupWebsocketConnection to communicate
 * with a remote server.
 *
 * All necessary WebSocket-related headers will be added to @msg, and
 * it will then be sent and asynchronously processed normally
 * (including handling of redirection and HTTP authentication).
 *
 * If the server returns "101 Switching Protocols", then @msg's status
 * code and response headers will be updated, and then the WebSocket
 * handshake will be completed. On success,
 * soup_session_websocket_connect_finish() will return a new
 * #SoupWebsocketConnection. On failure it will return a #GError.
 *
 * If the server returns a status other than "101 Switching
 * Protocols", then @msg will contain the complete response headers
 * and body from the server's response, and
 * soup_session_websocket_connect_finish() will return
 * %SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET.
 *
 */
void
soup_session_websocket_connect_async (SoupSession          *session,
				      SoupMessage          *msg,
				      const char           *origin,
				      char                **protocols,
				      int                   io_priority,
				      GCancellable         *cancellable,
				      GAsyncReadyCallback   callback,
				      gpointer              user_data)
{
	SoupMessageQueueItem *item;
	GTask *task;
	GPtrArray *supported_extensions;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	supported_extensions = soup_session_get_supported_websocket_extensions_for_message (session, msg);
	soup_websocket_client_prepare_handshake (msg, origin, protocols, supported_extensions);

	/* When the client is to _Establish a WebSocket Connection_ given a set
	 * of (/host/, /port/, /resource name/, and /secure/ flag), along with a
	 * list of /protocols/ and /extensions/ to be used, and an /origin/ in
	 * the case of web browsers, it MUST open a connection, send an opening
	 * handshake, and read the server's handshake in response.
	 */
	soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);

	task = g_task_new (session, cancellable, callback, user_data);
	item = soup_session_append_queue_item (session, msg, TRUE, cancellable,
					       websocket_connect_async_complete, task);
	item->io_priority = io_priority;
	g_task_set_task_data (task, item, (GDestroyNotify) soup_message_queue_item_unref);

	soup_message_add_status_code_handler (msg, "got-informational",
					      SOUP_STATUS_SWITCHING_PROTOCOLS,
					      G_CALLBACK (websocket_connect_async_stop), task);
	soup_session_kick_queue (session);
}

/**
 * soup_session_websocket_connect_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the #SoupWebsocketConnection response to a
 * soup_session_websocket_connect_async() call and (if successful),
 * returns a #SoupWebsocketConnection that can be used to communicate
 * with the server.
 *
 * Returns: (transfer full): a new #SoupWebsocketConnection, or
 *   %NULL on error.
 *
 */
SoupWebsocketConnection *
soup_session_websocket_connect_finish (SoupSession      *session,
				       GAsyncResult     *result,
				       GError          **error)
{
	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	g_return_val_if_fail (g_task_is_valid (result, session), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

SoupMessage *
soup_session_get_original_message_for_authentication (SoupSession *session,
						      SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	SoupMessage *original_msg;

	item = soup_message_queue_lookup (priv->queue, msg);
	if (!item)
                return msg;

	if (soup_message_get_method (msg) != SOUP_METHOD_CONNECT) {
		soup_message_queue_item_unref (item);
		return msg;
	}

	original_msg = item->related ? item->related->msg : msg;
	soup_message_queue_item_unref (item);
	return original_msg;
}
