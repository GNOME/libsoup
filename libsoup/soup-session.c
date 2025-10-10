/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
#include "soup-connection-manager.h"
#include "soup-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-misc.h"
#include "soup-message-queue-item.h"
#include "soup-session-private.h"
#include "soup-session-feature-private.h"
#include "soup-socket-properties.h"
#include "soup-uri-utils-private.h"
#include "websocket/soup-websocket.h"
#include "websocket/soup-websocket-connection.h"
#include "websocket/soup-websocket-extension-manager-private.h"

/**
 * SoupSession:
 *
 * Soup session state object.
 *
 * [class@Session] is the object that controls client-side HTTP. A
 * [class@Session] encapsulates all of the state that libsoup is keeping
 * on behalf of your program; cached HTTP connections, authentication
 * information, etc. It also keeps track of various global options
 * and features that you are using.
 *
 * Most applications will only need a single [class@Session]; the primary
 * reason you might need multiple sessions is if you need to have
 * multiple independent authentication contexts. (Eg, you are
 * connecting to a server and authenticating as two different users at
 * different times; the easiest way to ensure that each [class@Message]
 * is sent with the authentication information you intended is to use
 * one session for the first user, and a second session for the other
 * user.)
 *
 * Additional [class@Session] functionality is provided by
 * [iface@SessionFeature] objects, which can be added to a session with
 * [method@Session.add_feature] or [method@Session.add_feature_by_type]
 * For example, [class@Logger] provides support for
 * logging HTTP traffic, [class@ContentDecoder] provides support for
 * compressed response handling, and [class@ContentSniffer] provides
 * support for HTML5-style response body content sniffing.
 * Additionally, subtypes of [class@Auth] can be added
 * as features, to add support for additional authentication types.
 *
 * All `SoupSession`s are created with a [class@AuthManager], and support
 * for %SOUP_TYPE_AUTH_BASIC and %SOUP_TYPE_AUTH_DIGEST. Additionally,
 * sessions using the plain [class@Session] class (rather than one of its deprecated
 * subtypes) have a [class@ContentDecoder] by default.
 *
 * Note that all async methods will invoke their callbacks on the thread-default
 * context at the time of the function call.
 **/

typedef struct {
	GTlsDatabase *tlsdb;
	GTlsInteraction *tls_interaction;
	gboolean tlsdb_use_default;

	guint io_timeout, idle_timeout;
	GInetSocketAddress *local_addr;

	GProxyResolver *proxy_resolver;
	gboolean proxy_use_default;

	SoupSocketProperties *socket_props;

        GMainContext *context;
        GMutex queue_mutex;
	GQueue *queue;
        GMutex queue_sources_mutex;
	GHashTable *queue_sources;
        gint num_async_items;
        guint in_async_run_queue;
        gboolean needs_queue_sort;

	char *user_agent;
	char *accept_language;
	gboolean accept_language_auto;

	GSList *features;

        SoupConnectionManager *conn_manager;
} SoupSessionPrivate;

static void async_run_queue (SoupSession *session);

static void async_send_request_running (SoupSession *session, SoupMessageQueueItem *item);

static void soup_session_process_queue_item (SoupSession          *session,
                                             SoupMessageQueueItem *item,
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
	PROP_TIMEOUT,
	PROP_USER_AGENT,
	PROP_ACCEPT_LANGUAGE,
	PROP_ACCEPT_LANGUAGE_AUTO,
	PROP_REMOTE_CONNECTABLE,
	PROP_IDLE_TIMEOUT,
	PROP_LOCAL_ADDRESS,
	PROP_TLS_INTERACTION,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

/**
 * SoupSessionError:
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
 * @SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE: the message is already in the
 *   session queue. Messages can only be reused after unqueued.
 *
 * A [class@Session] error.
 */
G_DEFINE_QUARK (soup-session-error-quark, soup_session_error)

typedef struct {
	GSource source;
        GWeakRef session;
        guint num_items;
} SoupMessageQueueSource;

static gboolean
queue_dispatch (GSource    *source,
		GSourceFunc callback,
		gpointer    user_data)
{
        SoupMessageQueueSource *queue_source = (SoupMessageQueueSource *)source;
        SoupSession *session = g_weak_ref_get (&queue_source->session);

        if (!session)
                return G_SOURCE_REMOVE;

	g_source_set_ready_time (source, -1);
	async_run_queue (session);
        g_object_unref (session);

	return G_SOURCE_CONTINUE;
}

static void
queue_finalize (GSource *source)
{
        SoupMessageQueueSource *queue_source = (SoupMessageQueueSource *)source;

        g_weak_ref_clear (&queue_source->session);
}

static GSourceFuncs queue_source_funcs = {
	NULL, //queue_prepare,
	NULL, //queue_check,
	queue_dispatch,
        queue_finalize,
	NULL, NULL
};

static void
soup_session_add_queue_source (SoupSession  *session,
                               GMainContext *context)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);
        SoupMessageQueueSource *queue_source;

        if (!priv->queue_sources)
                priv->queue_sources = g_hash_table_new_full (NULL, NULL, NULL, (GDestroyNotify)g_source_unref);

        queue_source = g_hash_table_lookup (priv->queue_sources, context);
        if (!queue_source) {
                GSource *source;

                source = g_source_new (&queue_source_funcs, sizeof (SoupMessageQueueSource));
                queue_source = (SoupMessageQueueSource *)source;
                g_weak_ref_init (&queue_source->session, session);
                queue_source->num_items = 0;
                g_source_set_name (source, "SoupMessageQueue");
                g_source_set_can_recurse (source, TRUE);
                g_source_attach (source, context);
                g_hash_table_insert (priv->queue_sources, context, source);
        }

        queue_source->num_items++;
}

static void
soup_session_add_queue_source_for_item (SoupSession          *session,
                                        SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);

        if (!item->async)
                return;

        g_mutex_lock (&priv->queue_sources_mutex);
        soup_session_add_queue_source (session, item->context);
        g_mutex_unlock (&priv->queue_sources_mutex);
}

static void
soup_session_remove_queue_source (SoupSession  *session,
                                  GMainContext *context)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);
        SoupMessageQueueSource *queue_source;

        queue_source = g_hash_table_lookup (priv->queue_sources, context);
        if (!queue_source)
                return;

        if (--queue_source->num_items > 0)
                return;

        g_source_destroy ((GSource *)queue_source);
        g_hash_table_remove (priv->queue_sources, context);
}

static void
soup_session_remove_queue_source_for_item (SoupSession          *session,
                                           SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);

        if (!item->async)
                return;

        if (item->context == priv->context)
                return;

        g_mutex_lock (&priv->queue_sources_mutex);
        soup_session_remove_queue_source (session, item->context);
        g_mutex_unlock (&priv->queue_sources_mutex);
}

static void
soup_session_init (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupAuthManager *auth_manager;

        priv->context = g_main_context_ref_thread_default ();
        g_mutex_init (&priv->queue_mutex);
	priv->queue = g_queue_new ();
        g_mutex_init (&priv->queue_sources_mutex);

        priv->io_timeout = priv->idle_timeout = 60;

        priv->conn_manager = soup_connection_manager_new (session,
                                                          SOUP_SESSION_MAX_CONNS_DEFAULT,
                                                          SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT);

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
destroy_queue_source (gpointer key,
                      GSource *source)
{
        g_source_destroy (source);
}

static void
soup_session_dispose (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	soup_session_abort (session);
	g_warn_if_fail (soup_connection_manager_get_num_conns (priv->conn_manager) == 0);

	while (priv->features)
		soup_session_remove_feature (session, priv->features->data);

        if (priv->queue_sources)
                g_hash_table_foreach (priv->queue_sources, (GHFunc)destroy_queue_source, NULL);

	G_OBJECT_CLASS (soup_session_parent_class)->dispose (object);
}

static void
soup_session_finalize (GObject *object)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	g_warn_if_fail (g_queue_is_empty (priv->queue));
	g_queue_free (priv->queue);
        g_mutex_clear (&priv->queue_mutex);
        g_clear_pointer (&priv->queue_sources, g_hash_table_destroy);
        g_mutex_clear (&priv->queue_sources_mutex);
        g_main_context_unref (priv->context);

        g_clear_pointer (&priv->conn_manager, soup_connection_manager_free);

	g_free (priv->user_agent);
	g_free (priv->accept_language);

	g_clear_object (&priv->tlsdb);
	g_clear_object (&priv->tls_interaction);

	g_clear_object (&priv->local_addr);

	g_clear_object (&priv->proxy_resolver);

	g_clear_pointer (&priv->socket_props, soup_socket_properties_unref);

	G_OBJECT_CLASS (soup_session_parent_class)->finalize (object);
}

GMainContext *
soup_session_get_context (SoupSession *session)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);

        return priv->context;
}

SoupSocketProperties *
soup_session_ensure_socket_props (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (priv->socket_props)
		return priv->socket_props;

	priv->socket_props = soup_socket_properties_new (priv->local_addr,
							 priv->tls_interaction,
							 priv->io_timeout,
							 priv->idle_timeout);
	if (!priv->proxy_use_default)
		soup_socket_properties_set_proxy_resolver (priv->socket_props, priv->proxy_resolver);
	if (!priv->tlsdb_use_default)
		soup_socket_properties_set_tls_database (priv->socket_props, priv->tlsdb);

        return priv->socket_props;
}

static void
socket_props_changed (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (!priv->socket_props)
		return;

	soup_socket_properties_unref (priv->socket_props);
	priv->socket_props = NULL;
	soup_session_ensure_socket_props (session);
}

static void
soup_session_set_property (GObject *object, guint prop_id,
			   const GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = g_value_dup_object (value);
		socket_props_changed (session);
		break;
	case PROP_PROXY_RESOLVER:
		soup_session_set_proxy_resolver (session, g_value_get_object (value));
		break;
	case PROP_MAX_CONNS:
                soup_connection_manager_set_max_conns (priv->conn_manager, g_value_get_int (value));
		break;
	case PROP_MAX_CONNS_PER_HOST:
                soup_connection_manager_set_max_conns_per_host (priv->conn_manager, g_value_get_int (value));
		break;
	case PROP_TLS_DATABASE:
		soup_session_set_tls_database (session, g_value_get_object (value));
		break;
	case PROP_TLS_INTERACTION:
		soup_session_set_tls_interaction (session, g_value_get_object (value));
		break;
	case PROP_TIMEOUT:
		soup_session_set_timeout (session, g_value_get_uint (value));
		break;
	case PROP_USER_AGENT:
		soup_session_set_user_agent (session, g_value_get_string (value));
		break;
	case PROP_ACCEPT_LANGUAGE:
		soup_session_set_accept_language (session, g_value_get_string (value));
		break;
	case PROP_ACCEPT_LANGUAGE_AUTO:
		soup_session_set_accept_language_auto (session, g_value_get_boolean (value));
		break;
	case PROP_REMOTE_CONNECTABLE:
                soup_connection_manager_set_remote_connectable (priv->conn_manager, g_value_get_object (value));
		break;
	case PROP_IDLE_TIMEOUT:
		soup_session_set_idle_timeout (session, g_value_get_uint (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_session_get_property (GObject *object, guint prop_id,
			   GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, soup_session_get_local_address (session));
		break;
	case PROP_PROXY_RESOLVER:
		g_value_set_object (value, soup_session_get_proxy_resolver (session));
		break;
	case PROP_MAX_CONNS:
		g_value_set_int (value, soup_session_get_max_conns (session));
		break;
	case PROP_MAX_CONNS_PER_HOST:
		g_value_set_int (value, soup_session_get_max_conns_per_host (session));
		break;
	case PROP_TLS_DATABASE:
		g_value_set_object (value, soup_session_get_tls_database (session));
		break;
	case PROP_TLS_INTERACTION:
		g_value_set_object (value, soup_session_get_tls_interaction (session));
		break;
	case PROP_TIMEOUT:
		g_value_set_uint (value, soup_session_get_timeout (session));
		break;
	case PROP_USER_AGENT:
		g_value_set_string (value, soup_session_get_user_agent (session));
		break;
	case PROP_ACCEPT_LANGUAGE:
		g_value_set_string (value, soup_session_get_accept_language (session));
		break;
	case PROP_ACCEPT_LANGUAGE_AUTO:
		g_value_set_boolean (value, soup_session_get_accept_language_auto (session));
		break;
	case PROP_REMOTE_CONNECTABLE:
		g_value_set_object (value, soup_session_get_remote_connectable (session));
		break;
	case PROP_IDLE_TIMEOUT:
		g_value_set_uint (value, soup_session_get_idle_timeout (session));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/**
 * soup_session_new:
 *
 * Creates a [class@Session] with the default options.
 *
 * Returns: (transfer full): the new session.
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
 * Creates a [class@Session] with the specified options.
 *
 * Returns: the new session.
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

/**
 * soup_session_get_local_address: (attributes org.gtk.Method.get_property=local-address)
 * @session: a #SoupSession
 *
 * Get the [class@Gio.InetSocketAddress] to use for the client side of
 * connections in @session.
 *
 * Returns: (transfer none) (nullable): a #GInetSocketAddress
 */
GInetSocketAddress *
soup_session_get_local_address (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return priv->local_addr;
}

/**
 * soup_session_get_max_conns: (attributes org.gtk.Method.set_property=max-conns)
 * @session: a #SoupSession
 *
 * Get the maximum number of connections that @session can open at once.
 *
 * Returns: the maximum number of connections
 */
guint
soup_session_get_max_conns (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), 0);

	priv = soup_session_get_instance_private (session);
	return soup_connection_manager_get_max_conns (priv->conn_manager);
}

/**
 * soup_session_get_max_conns_per_host: (attributes org.gtk.Method.get_property=max-conns-per-host)
 * @session: a #SoupSession
 *
 * Get the maximum number of connections that @session can open at once to a
 * given host.
 *
 * Returns: the maximum number of connections per host
 */
guint
soup_session_get_max_conns_per_host (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), 0);

	priv = soup_session_get_instance_private (session);
	return soup_connection_manager_get_max_conns_per_host (priv->conn_manager);
}

/**
 * soup_session_set_proxy_resolver: (attributes org.gtk.Method.set_property=proxy-resolver)
 * @session: a #SoupSession
 * @proxy_resolver: (nullable): a #GProxyResolver or %NULL
 *
 * Set a [iface@Gio.ProxyResolver] to be used by @session on new connections.
 *
 * If @proxy_resolver is %NULL then no proxies will be used. See
 * [property@Session:proxy-resolver] for more information.
 */
void
soup_session_set_proxy_resolver (SoupSession    *session,
				 GProxyResolver *proxy_resolver)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (proxy_resolver == NULL || G_IS_PROXY_RESOLVER (proxy_resolver));

	priv = soup_session_get_instance_private (session);
	priv->proxy_use_default = FALSE;
	if (priv->proxy_resolver == proxy_resolver)
		return;

	g_clear_object (&priv->proxy_resolver);
	priv->proxy_resolver = proxy_resolver ? g_object_ref (proxy_resolver) : NULL;
	socket_props_changed (session);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_PROXY_RESOLVER]);
}

/**
 * soup_session_get_proxy_resolver: (attributes org.gtk.Method.get_property=proxy-resolver)
 * @session: a #SoupSession
 *
 * Get the [iface@Gio.ProxyResolver] currently used by @session.
 *
 * Returns: (transfer none) (nullable): a #GProxyResolver or %NULL if proxies
 *   are disabled in @session
 */
GProxyResolver *
soup_session_get_proxy_resolver (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return !priv->proxy_use_default ? priv->proxy_resolver : g_proxy_resolver_get_default ();
}

/**
 * soup_session_set_tls_database: (attributes org.gtk.Method.set_property=tls-database)
 * @session: a #SoupSession
 * @tls_database: (nullable): a #GTlsDatabase
 *
 * Set a [class@Gio.TlsDatabase] to be used by @session on new connections.
 *
 * If @tls_database is %NULL then certificate validation will always fail. See
 * [property@Session:tls-database] for more information.
 */
void
soup_session_set_tls_database (SoupSession  *session,
			       GTlsDatabase *tls_database)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (tls_database == NULL || G_IS_TLS_DATABASE (tls_database));

	priv = soup_session_get_instance_private (session);
	priv->tlsdb_use_default = FALSE;
	if (priv->tlsdb == tls_database)
		return;

	g_clear_object (&priv->tlsdb);
	priv->tlsdb = tls_database ? g_object_ref (tls_database) : NULL;
	socket_props_changed (session);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_TLS_DATABASE]);
}

/**
 * soup_session_get_tls_database: (attributes org.gtk.Method.get_property=tls-database)
 * @session: a #SoupSession
 *
 * Get the [class@Gio.TlsDatabase] currently used by @session.
 *
 * Returns: (transfer none) (nullable): a #GTlsDatabase
 */
GTlsDatabase *
soup_session_get_tls_database (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	if (priv->tlsdb_use_default && !priv->tlsdb)
		priv->tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());

	return priv->tlsdb;
}

/**
 * soup_session_set_tls_interaction: (attributes org.gtk.Method.set_property=tls-interaction)
 * @session: a #SoupSession
 * @tls_interaction: (nullable): a #GTlsInteraction
 *
 * Set a [class@Gio.TlsInteraction] to be used by @session on new connections.
 *
 * If @tls_interaction is %NULL then client certificate validation will always
 * fail.
 *
 * See [property@Session:tls-interaction] for more information.
 */
void
soup_session_set_tls_interaction (SoupSession     *session,
				  GTlsInteraction *tls_interaction)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (tls_interaction == NULL || G_IS_TLS_INTERACTION (tls_interaction));

	priv = soup_session_get_instance_private (session);
	if (priv->tls_interaction == tls_interaction)
		return;

	g_clear_object (&priv->tls_interaction);
	priv->tls_interaction = tls_interaction ? g_object_ref (tls_interaction) : NULL;
	socket_props_changed (session);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_TLS_INTERACTION]);
}

/**
 * soup_session_get_tls_interaction: (attributes org.gtk.Method.get_property=tls-interaction)
 * @session: a #SoupSession
 *
 * Get the [class@Gio.TlsInteraction] currently used by @session.
 *
 * Returns: (transfer none) (nullable): a #GTlsInteraction
 */
GTlsInteraction *
soup_session_get_tls_interaction (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return priv->tls_interaction;
}

/**
 * soup_session_set_timeout: (attributes org.gtk.Method.set_property=timeout)
 * @session: a #SoupSession
 * @timeout: a timeout in seconds
 *
 * Set a timeout in seconds for socket I/O operations to be used by @session
 * on new connections.
 *
 * See [property@Session:timeout] for more information.
 */
void
soup_session_set_timeout (SoupSession *session,
			  guint        timeout)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (priv->io_timeout == timeout)
		return;

	priv->io_timeout = timeout;
	socket_props_changed (session);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_TIMEOUT]);
}

/**
 * soup_session_get_timeout: (attributes org.gtk.Method.get_property=timeout)
 * @session: a #SoupSession
 *
 * Get the timeout in seconds for socket I/O operations currently used by
 * @session.
 *
 * Returns: the timeout in seconds
 */
guint
soup_session_get_timeout (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), 0);

	priv = soup_session_get_instance_private (session);
	return priv->io_timeout;
}

/**
 * soup_session_set_idle_timeout: (attributes org.gtk.Method.set_property=idle-timeout)
 * @session: a #SoupSession
 * @timeout: a timeout in seconds
 *
 * Set a timeout in seconds for idle connection lifetime to be used by @session
 * on new connections.
 *
 * See [property@Session:idle-timeout] for more information.
 */
void
soup_session_set_idle_timeout (SoupSession *session,
			       guint        timeout)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (priv->idle_timeout == timeout)
		return;

	priv->idle_timeout = timeout;
	socket_props_changed (session);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_IDLE_TIMEOUT]);
}

/**
 * soup_session_get_idle_timeout: (attributes org.gtk.Method.get_property=idle-timeout)
 * @session: a #SoupSession
 *
 * Get the timeout in seconds for idle connection lifetime currently used by
 * @session.
 *
 * Returns: the timeout in seconds
 */
guint
soup_session_get_idle_timeout (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), 0);

	priv = soup_session_get_instance_private (session);
	return priv->idle_timeout;
}

/**
 * soup_session_set_user_agent: (attributes org.gtk.Method.set_property=user-agent)
 * @session: a #SoupSession
 * @user_agent: the user agent string
 *
 * Set the value to use for the "User-Agent" header on [class@Message]s sent
 * from @session.
 *
 * If @user_agent has trailing whitespace, @session will append its own product
 * token (eg, `libsoup/3.0.0`) to the end of the header for you. If @user_agent
 * is %NULL then no "User-Agent" will be included in requests. See
 * [property@Session:user-agent] for more information.
 */
void
soup_session_set_user_agent (SoupSession *session,
			     const char  *user_agent)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (priv->user_agent == NULL && user_agent == NULL)
		return;

	if (user_agent == NULL) {
		g_free (priv->user_agent);
		priv->user_agent = NULL;
	} else if (!*user_agent) {
		if (g_strcmp0 (priv->user_agent, SOUP_SESSION_USER_AGENT_BASE) == 0)
			return;
		g_free (priv->user_agent);
		priv->user_agent = g_strdup (SOUP_SESSION_USER_AGENT_BASE);
	} else if (g_str_has_suffix (user_agent, " ")) {
		char *user_agent_to_set;

		user_agent_to_set = g_strdup_printf ("%s%s", user_agent, SOUP_SESSION_USER_AGENT_BASE);
		if (g_strcmp0 (priv->user_agent, user_agent_to_set) == 0) {
			g_free (user_agent_to_set);
			return;
		}
		g_free (priv->user_agent);
		priv->user_agent = user_agent_to_set;
	} else {
		if (g_strcmp0 (priv->user_agent, user_agent) == 0)
			return;
		g_free (priv->user_agent);
		priv->user_agent = g_strdup (user_agent);
	}

	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_USER_AGENT]);
}

/**
 * soup_session_get_user_agent: (attributes org.gtk.Method.get_property=user-agent)
 * @session: a #SoupSession
 *
 * Get the value used by @session for the "User-Agent" header on new requests.
 *
 * Returns: (transfer none) (nullable): the user agent string
 */
const char *
soup_session_get_user_agent (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return priv->user_agent;
}

/**
 * soup_session_set_accept_language: (attributes org.gtk.Method.set_property=accept-language)
 * @session: a #SoupSession
 * @accept_language: the languages string
 *
 * Set the value to use for the "Accept-Language" header on [class@Message]s
 * sent from @session.
 *
 * If @accept_language is %NULL then no "Accept-Language" will be included in
 * requests. See [property@Session:accept-language] for more information.
 */
void
soup_session_set_accept_language (SoupSession *session,
				  const char  *accept_language)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (g_strcmp0 (priv->accept_language, accept_language) == 0)
		return;

	g_clear_pointer (&priv->accept_language, g_free);
	priv->accept_language = accept_language ? g_strdup (accept_language) : NULL;
	priv->accept_language_auto = FALSE;

	g_object_freeze_notify (G_OBJECT (session));
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_ACCEPT_LANGUAGE]);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_ACCEPT_LANGUAGE_AUTO]);
	g_object_thaw_notify (G_OBJECT (session));
}

/**
 * soup_session_get_accept_language: (attributes org.gtk.Method.get_property=accept-language)
 * @session: a #SoupSession
 *
 * Get the value used by @session for the "Accept-Language" header on new
 * requests.
 *
 * Returns: (transfer none) (nullable): the accept language string
 */
const char *
soup_session_get_accept_language (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return priv->accept_language;
}

/**
 * soup_session_set_accept_language_auto: (attributes org.gtk.Method.set_property=accept-language-auto)
 * @session: a #SoupSession
 * @accept_language_auto: the value to set
 *
 * Set whether @session will automatically set the "Accept-Language" header on
 * requests using a value generated from system languages based on
 * [func@GLib.get_language_names].
 *
 * See [property@Session:accept-language-auto] for more information.
 */
void
soup_session_set_accept_language_auto (SoupSession *session,
				       gboolean     accept_language_auto)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (priv->accept_language_auto == accept_language_auto)
		return;

	priv->accept_language_auto = accept_language_auto;

	g_clear_pointer (&priv->accept_language, g_free);
	if (priv->accept_language_auto)
		priv->accept_language = soup_get_accept_languages_from_system ();

	g_object_freeze_notify (G_OBJECT (session));
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_ACCEPT_LANGUAGE]);
	g_object_notify_by_pspec (G_OBJECT (session), properties[PROP_ACCEPT_LANGUAGE_AUTO]);
	g_object_thaw_notify (G_OBJECT (session));
}

/**
 * soup_session_get_accept_language_auto: (attributes org.gtk.Method.get_property=accept-language-auto)
 * @session: a #SoupSession
 *
 * Gets whether @session automatically sets the "Accept-Language" header on new
 * requests.
 *
 * Returns: %TRUE if @session sets "Accept-Language" header automatically, or
 *   %FALSE otherwise.
 */
gboolean
soup_session_get_accept_language_auto (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), FALSE);

	priv = soup_session_get_instance_private (session);
	return priv->accept_language_auto;
}

/**
 * soup_session_get_remote_connectable: (attributes org.gtk.Method.get_property=remote-connectable)
 * @session: a #SoupSession
 *
 * Gets the remote connectable if one set.
 *
 * Returns: (transfer none) (nullable): the #GSocketConnectable
 */
GSocketConnectable *
soup_session_get_remote_connectable (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);
	return soup_connection_manager_get_remote_connectable (priv->conn_manager);
}

static SoupMessageQueueItem *
soup_session_lookup_queue (SoupSession *session,
			   gpointer     data,
			   GCompareFunc compare_func)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GList *link;

        g_mutex_lock (&priv->queue_mutex);
	link = g_queue_find_custom (priv->queue, data, compare_func);
        g_mutex_unlock (&priv->queue_mutex);
	return link ? (SoupMessageQueueItem *)link->data : NULL;
}

static int
lookup_message (SoupMessageQueueItem *item,
		SoupMessage          *msg)
{
	return item->msg == msg ? 0 : 1;
}

static SoupMessageQueueItem *
soup_session_lookup_queue_item (SoupSession *session,
				SoupMessage *msg)
{
	return soup_session_lookup_queue (session, msg, (GCompareFunc)lookup_message);
}

static int
lookup_connection (SoupMessageQueueItem *item,
		   SoupConnection       *conn)
{
        SoupConnection *connection = soup_message_get_connection (item->msg);
        int retval;

        retval = connection == conn ? 0 : 1;
        g_clear_object (&connection);

        return retval;
}

static SoupMessageQueueItem *
soup_session_lookup_queue_item_by_connection (SoupSession    *session,
					      SoupConnection *conn)
{
	return soup_session_lookup_queue (session, conn, (GCompareFunc)lookup_connection);
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

	new_loc = soup_message_headers_get_one_common (soup_message_get_response_headers (msg),
                                                       SOUP_HEADER_LOCATION);
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
		item->state = SOUP_MESSAGE_REQUEUED;
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
 * redirection that [class@Session] will not perform automatically (eg,
 * redirecting a non-safe method such as DELETE).
 *
 * If @msg's status code indicates that it should be retried as a GET
 * request, then @msg will be modified accordingly.
 *
 * If @msg has already been redirected too many times, this will
 * cause it to fail with %SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS.
 *
 * Returns: %TRUE if a redirection was applied, %FALSE if not
 *   (eg, because there was no Location header, or it could not be
 *   parsed).
 */
static gboolean
soup_session_redirect_message (SoupSession *session,
			       SoupMessage *msg,
			       GError     **error)
{
	GUri *new_uri;

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

        /* Strip all credentials on cross-origin redirect. */
        if (!soup_uri_host_equal (soup_message_get_uri (msg), new_uri)) {
                soup_message_headers_remove_common (soup_message_get_request_headers (msg), SOUP_HEADER_AUTHORIZATION);
                soup_message_set_auth (msg, NULL);
        }

        soup_message_set_request_host_from_uri (msg, new_uri);
	soup_message_set_uri (msg, new_uri);
	g_uri_unref (new_uri);

	return soup_session_requeue_item (session,
					  soup_session_lookup_queue_item (session, msg),
					  error);
}

static const char *
state_to_string (SoupMessageQueueItemState state)
{
        switch (state) {
                case SOUP_MESSAGE_STARTING:
                        return "STARTING";
                case SOUP_MESSAGE_CONNECTING:
                        return "CONNECTING";
                case SOUP_MESSAGE_CONNECTED:
                        return "CONNECTED";
                case SOUP_MESSAGE_TUNNELING:
                        return "TUNNELING";
                case SOUP_MESSAGE_READY:
                        return "READY";
                case SOUP_MESSAGE_RUNNING:
                        return "RUNNING";
                case SOUP_MESSAGE_CACHED:
                        return "CACHED";
                case SOUP_MESSAGE_REQUEUED:
                        return "REQUEUED";
                case SOUP_MESSAGE_RESTARTING:
                        return "RESTARTING";
                case SOUP_MESSAGE_FINISHING:
                        return "FINISHING";
                case SOUP_MESSAGE_FINISHED:
                        return "FINISHED";
        }

        g_assert_not_reached ();
        return "";
}

G_GNUC_PRINTF(2, 0)
static void
session_debug (SoupMessageQueueItem *item, const char *format, ...)
{
        va_list args;
        char *message;

        if (g_log_writer_default_would_drop (G_LOG_LEVEL_DEBUG, G_LOG_DOMAIN))
                return;

	va_start (args, format);
	message = g_strdup_vprintf (format, args);
	va_end (args);

        g_assert (item);
        g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "[SESSION QUEUE] [%p] [%s] %s", item,state_to_string (item->state), message);
        g_free (message);
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
misdirected_handler (SoupMessage *msg,
		     gpointer     user_data)
{
	SoupMessageQueueItem *item = user_data;
	SoupSession *session = item->session;

        /* HTTP/2 messages may get the misdirected request status and MAY
         * try a new connection */
        if (!soup_message_is_misdirected_retry (msg)) {
                soup_message_set_is_misdirected_retry (msg, TRUE);
                soup_session_requeue_item (session,
                                           item,
                                           &item->error);
        }
}

static void
message_restarted (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;
        SoupConnection *conn;

        conn = soup_message_get_connection (item->msg);
	if (conn &&
	    (!soup_message_is_keepalive (msg) ||
	     SOUP_STATUS_IS_REDIRECTION (soup_message_get_status (msg)))) {
                soup_message_set_connection (item->msg, NULL);
	}
        g_clear_object (&conn);

	soup_message_cleanup_response (msg);
}

static int
compare_queue_item (SoupMessageQueueItem *a,
		    SoupMessageQueueItem *b)
{
        SoupMessagePriority a_priority = soup_message_get_priority (a->msg);
        SoupMessagePriority b_priority = soup_message_get_priority (b->msg);

	/* For the same priority we want to append items in the queue */
	return b_priority > a_priority ? 1 : -1;
}

static void
message_priority_changed (SoupMessage          *msg,
                          GParamSpec           *pspec,
                          SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (item->session);

        if (g_atomic_int_get (&priv->in_async_run_queue)) {
                g_atomic_int_set (&priv->needs_queue_sort, TRUE);
                return;
        }

        g_mutex_lock (&priv->queue_mutex);
        g_queue_sort (priv->queue, (GCompareDataFunc)compare_queue_item, NULL);
        g_mutex_unlock (&priv->queue_mutex);
        g_atomic_int_set (&priv->needs_queue_sort, FALSE);
}

static SoupMessageQueueItem *
soup_session_append_queue_item (SoupSession        *session,
				SoupMessage        *msg,
				gboolean            async,
				GCancellable       *cancellable)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	GPtrArray *queue_features = NULL;
	GSList *f;

        soup_message_set_metrics_timestamp (msg, SOUP_MESSAGE_METRICS_FETCH_START);
	soup_message_cleanup_response (msg);
        soup_message_set_is_preconnect (msg, FALSE);

	item = soup_message_queue_item_new (session, msg, async, cancellable);
        g_mutex_lock (&priv->queue_mutex);
	g_queue_insert_sorted (priv->queue,
			       soup_message_queue_item_ref (item),
			       (GCompareDataFunc)compare_queue_item, NULL);
        g_mutex_unlock (&priv->queue_mutex);

        soup_session_add_queue_source_for_item (session, item);

        if (async)
                g_atomic_int_inc (&priv->num_async_items);

	if (!soup_message_query_flags (msg, SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_header_handler (
			msg, "got_body", "Location",
			G_CALLBACK (redirect_handler), item);
	}
        soup_message_add_status_code_handler (msg, "got-body",
                                              SOUP_STATUS_MISDIRECTED_REQUEST,
                                              G_CALLBACK (misdirected_handler), item);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (message_restarted), item);
        g_signal_connect (msg, "notify::priority",
                          G_CALLBACK (message_priority_changed), item);

	for (f = priv->features; f; f = g_slist_next (f)) {
		SoupSessionFeature *feature = SOUP_SESSION_FEATURE (f->data);

		if (queue_features == NULL)
			queue_features = g_ptr_array_new_with_free_func (g_object_unref);
		g_ptr_array_add (queue_features, g_object_ref (feature));
		soup_session_feature_request_queued (feature, msg);
	}

	if (queue_features != NULL) {
		g_object_set_data_full (G_OBJECT (msg), "soup-session-queued-features",
			queue_features, (GDestroyNotify) g_ptr_array_unref);
	}

	g_signal_emit (session, signals[REQUEST_QUEUED], 0, msg);

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
        SoupConnection *conn;

        g_assert (item->context == soup_thread_default_context ());

	request_headers = soup_message_get_request_headers (item->msg);
	if (priv->user_agent)
		soup_message_headers_replace_common (request_headers, SOUP_HEADER_USER_AGENT, priv->user_agent);

	if (priv->accept_language && !soup_message_headers_get_list_common (request_headers, SOUP_HEADER_ACCEPT_LANGUAGE))
		soup_message_headers_append_common (request_headers, SOUP_HEADER_ACCEPT_LANGUAGE, priv->accept_language);

        conn = soup_message_get_connection (item->msg);
        soup_message_set_http_version (item->msg, soup_connection_get_negotiated_protocol (conn));
        g_object_unref (conn);

        soup_message_force_keep_alive_if_needed (item->msg);
        soup_message_update_request_host_if_needed (item->msg);


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
                soup_message_send_item (item->msg, item, completion_cb, item);
}

static void
soup_session_unqueue_item (SoupSession          *session,
			   SoupMessageQueueItem *item)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GPtrArray *queued_features;

        soup_message_set_connection (item->msg, NULL);

	if (item->state != SOUP_MESSAGE_FINISHED) {
		g_warning ("finished an item with state %d", item->state);
		return;
	}

        g_mutex_lock (&priv->queue_mutex);
	g_queue_remove (priv->queue, item);
        g_mutex_unlock (&priv->queue_mutex);

        soup_session_remove_queue_source_for_item (session, item);

        if (item->async)
                g_atomic_int_dec_and_test (&priv->num_async_items);

	/* g_signal_handlers_disconnect_by_func doesn't work if you
	 * have a metamarshal, meaning it doesn't work with
	 * soup_message_add_header_handler()
	 */
	g_signal_handlers_disconnect_matched (item->msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, item);

	queued_features = g_object_get_data (G_OBJECT (item->msg), "soup-session-queued-features");
	if (queued_features) {
		guint ii;

		for (ii = 0; ii < queued_features->len; ii++) {
			SoupSessionFeature *feature = SOUP_SESSION_FEATURE (g_ptr_array_index (queued_features, ii));

			soup_session_feature_request_unqueued (feature, item->msg);
		}
	}
	g_signal_emit (session, signals[REQUEST_UNQUEUED], 0, item->msg);
	soup_message_queue_item_unref (item);
}

static void
message_completed (SoupMessage *msg, SoupMessageIOCompletion completion, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

        g_assert (item->context == soup_thread_default_context ());

        session_debug (item, "Message completed");

	if (item->async)
		soup_session_kick_queue (item->session);

	if (completion == SOUP_MESSAGE_IO_STOLEN) {
		item->state = SOUP_MESSAGE_FINISHED;
		soup_session_unqueue_item (item->session, item);
		return;
	}

        if (item->state == SOUP_MESSAGE_REQUEUED)
                item->state = SOUP_MESSAGE_RESTARTING;

	if (item->state != SOUP_MESSAGE_RESTARTING) {
		item->state = SOUP_MESSAGE_FINISHING;
                soup_session_process_queue_item (item->session, item, !item->async);
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
                SoupConnection *conn = soup_message_get_connection (item->msg);

		soup_connection_disconnect (conn);
                g_object_unref (conn);
                soup_message_set_connection (item->msg, NULL);
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

        g_assert (tunnel_item->context == soup_thread_default_context ());

        if (tunnel_item->state == SOUP_MESSAGE_REQUEUED)
                tunnel_item->state = SOUP_MESSAGE_RESTARTING;

	if (tunnel_item->state == SOUP_MESSAGE_RESTARTING) {
                SoupConnection *conn;

		soup_message_restarted (msg);

                conn = soup_message_get_connection (tunnel_item->msg);
		if (conn) {
                        g_object_unref (conn);
                        g_clear_object (&tunnel_item->error);
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
	if (!SOUP_STATUS_IS_SUCCESSFUL (status) || tunnel_item->error || item->state == SOUP_MESSAGE_RESTARTING) {
		tunnel_complete (tunnel_item, status, g_steal_pointer (&tunnel_item->error));
		return;
	}

	if (tunnel_item->async) {
                SoupConnection *conn = soup_message_get_connection (item->msg);

		soup_connection_tunnel_handshake_async (conn,
							item->io_priority,
							item->cancellable,
							(GAsyncReadyCallback)tunnel_handshake_complete,
							tunnel_item);
                g_object_unref (conn);
	} else {
                SoupConnection *conn = soup_message_get_connection (item->msg);
		GError *error = NULL;

		soup_connection_tunnel_handshake (conn, item->cancellable, &error);
                g_object_unref (conn);
		tunnel_complete (tunnel_item, SOUP_STATUS_OK, error);
	}
}

static void
tunnel_connect (SoupMessageQueueItem *item)
{
	SoupSession *session = item->session;
	SoupMessageQueueItem *tunnel_item;
	SoupMessage *msg;
        SoupConnection *conn;

	item->state = SOUP_MESSAGE_TUNNELING;

	msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT, soup_message_get_uri (item->msg));
	soup_message_add_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	tunnel_item = soup_session_append_queue_item (session, msg,
						      item->async,
						      item->cancellable);
	tunnel_item->io_priority = item->io_priority;
	tunnel_item->related = soup_message_queue_item_ref (item);
        conn = soup_message_get_connection (item->msg);
        soup_message_set_connection (tunnel_item->msg, conn);
        g_clear_object (&conn);
	tunnel_item->state = SOUP_MESSAGE_RUNNING;

	soup_session_send_queue_item (session, tunnel_item,
				      (SoupMessageIOCompletionFn)tunnel_message_completed);
	soup_message_io_run (msg, !item->async);
	g_object_unref (msg);
}

static void
connect_complete (SoupMessageQueueItem *item, SoupConnection *conn, GError *error)
{
	if (!error) {
		item->state = SOUP_MESSAGE_CONNECTED;
		return;
	}

        soup_message_set_metrics_timestamp (item->msg, SOUP_MESSAGE_METRICS_RESPONSE_END);

	item->error = error;
	soup_connection_disconnect (conn);
	if (item->state == SOUP_MESSAGE_CONNECTING) {
                soup_message_set_connection (item->msg, NULL);
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
	if (item->related) {
		SoupMessageQueueItem *new_item = item->related;

		/* Complete the preconnect successfully, since it was stolen. */
		item->state = SOUP_MESSAGE_FINISHING;
		item->related = NULL;
		soup_session_process_queue_item (item->session, item, FALSE);
		soup_message_queue_item_unref (item);

		item = new_item;
	}
	connect_complete (item, conn, error);

	if (item->state == SOUP_MESSAGE_CONNECTED ||
	    item->state == SOUP_MESSAGE_READY)
		async_run_queue (item->session);
	else
		soup_session_kick_queue (item->session);

	soup_message_queue_item_unref (item);
}

gboolean
soup_session_steal_preconnection (SoupSession          *session,
                                  SoupMessageQueueItem *item,
                                  SoupConnection       *conn)
{
        SoupMessageQueueItem *preconnect_item;

        if (!item->async)
                return FALSE;

        if (item->connect_only)
                return FALSE;

        preconnect_item = soup_session_lookup_queue_item_by_connection (session, conn);
        if (!preconnect_item)
                return FALSE;

        if (!preconnect_item->connect_only || preconnect_item->state != SOUP_MESSAGE_CONNECTING)
                return FALSE;

        soup_message_transfer_connection (preconnect_item->msg, item->msg);
        g_assert (preconnect_item->related == NULL);
        preconnect_item->related = soup_message_queue_item_ref (item);

        return TRUE;
}

static gboolean
soup_session_ensure_item_connection (SoupSession          *session,
                                     SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupConnection *conn;

        conn = soup_connection_manager_get_connection (priv->conn_manager, item);
	if (!conn)
		return FALSE;

	switch (soup_connection_get_state (conn)) {
	case SOUP_CONNECTION_IN_USE:
		item->state = SOUP_MESSAGE_READY;
		return TRUE;
	case SOUP_CONNECTION_CONNECTING:
		item->state = SOUP_MESSAGE_CONNECTING;
		return FALSE;
	case SOUP_CONNECTION_NEW:
		break;
	case SOUP_CONNECTION_IDLE:
	case SOUP_CONNECTION_DISCONNECTED:
		g_assert_not_reached ();
	}

	item->state = SOUP_MESSAGE_CONNECTING;

	if (item->async) {
		soup_connection_connect_async (conn,
					       item->io_priority,
					       item->cancellable,
					       connect_async_complete,
					       soup_message_queue_item_ref (item));
		return FALSE;
	} else {
		GError *error = NULL;

		soup_connection_connect (conn, item->cancellable, &error);
		connect_complete (item, conn, error);

		return TRUE;
	}
}

static void
soup_session_process_queue_item (SoupSession          *session,
				 SoupMessageQueueItem *item,
				 gboolean              loop)
{
	g_assert (item->session == session);
        g_assert (item->context == soup_thread_default_context ());

	do {
                session_debug (item, "Processing item, paused=%d state=%d", item->paused, item->state);
		if (item->paused)
			return;

		switch (item->state) {
		case SOUP_MESSAGE_STARTING:
			if (!soup_session_ensure_item_connection (session, item))
				return;
			break;

		case SOUP_MESSAGE_CONNECTED: {
                        SoupConnection *conn = soup_message_get_connection (item->msg);

			if (soup_connection_is_tunnelled (conn))
				tunnel_connect (item);
			else
				item->state = SOUP_MESSAGE_READY;
                        g_object_unref (conn);
			break;
                }
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

                        soup_message_set_metrics_timestamp (item->msg, SOUP_MESSAGE_METRICS_REQUEST_START);

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
                case SOUP_MESSAGE_REQUEUED:
			/* Will be handled elsewhere */
			return;

		case SOUP_MESSAGE_RESTARTING:
			item->state = SOUP_MESSAGE_STARTING;
                        soup_message_set_metrics_timestamp (item->msg, SOUP_MESSAGE_METRICS_FETCH_START);
			soup_message_restarted (item->msg);

			break;

		case SOUP_MESSAGE_FINISHING:
			item->state = SOUP_MESSAGE_FINISHED;
			soup_message_finished (item->msg);
			soup_session_unqueue_item (session, item);
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
collect_queue_item (SoupMessageQueueItem *item,
                    GList               **items)
{
        if (!item->async)
                return;

        if (item->context != soup_thread_default_context ())
                return;

        /* CONNECT messages are handled specially */
        if (soup_message_get_method (item->msg) == SOUP_METHOD_CONNECT)
                return;

        *items = g_list_prepend (*items, item);
}

static void
async_run_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
        GList *items = NULL;
        GList *i;

        g_atomic_int_inc (&priv->in_async_run_queue);
	soup_connection_manager_cleanup (priv->conn_manager, FALSE);

        g_mutex_lock (&priv->queue_mutex);
        g_queue_foreach (priv->queue, (GFunc)collect_queue_item, &items);
        g_mutex_unlock (&priv->queue_mutex);

        items = g_list_reverse (items);

        for (i = items; i != NULL; i = g_list_next (i)) {
                SoupMessageQueueItem *item = (SoupMessageQueueItem *)i->data;
                soup_session_process_queue_item (item->session, item, TRUE);
        }

        g_list_free (items);

        if (g_atomic_int_dec_and_test (&priv->in_async_run_queue) && g_atomic_int_get (&priv->needs_queue_sort)) {
                g_mutex_lock (&priv->queue_mutex);
                g_queue_sort (priv->queue, (GCompareDataFunc)compare_queue_item, NULL);
                g_mutex_unlock (&priv->queue_mutex);
                g_atomic_int_set (&priv->needs_queue_sort, FALSE);
        }
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
	SoupMessageQueueItem *item = soup_session_lookup_queue_item (session, msg);

	soup_session_requeue_item (session, item, &item->error);
}

/**
 * soup_session_pause_message:
 * @session: a #SoupSession
 * @msg: a #SoupMessage currently running on @session
 *
 * Pauses HTTP I/O on @msg. Call [method@Session.unpause_message] to resume I/O.
 **/
void
soup_session_pause_message (SoupSession *session,
			    SoupMessage *msg)
{
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	item = soup_session_lookup_queue_item (session, msg);
	g_return_if_fail (item != NULL);
	g_return_if_fail (item->async);

	item->paused = TRUE;
	if (item->state == SOUP_MESSAGE_RUNNING)
		soup_message_io_pause (msg);
}

static void
kick_queue_source (gpointer key,
                   GSource *source)
{
        g_source_set_ready_time (source, 0);
}

void
soup_session_kick_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

        if (g_atomic_int_get (&priv->num_async_items) <= 0)
                return;

        g_mutex_lock (&priv->queue_sources_mutex);
        if (priv->queue_sources)
                g_hash_table_foreach (priv->queue_sources, (GHFunc)kick_queue_source, NULL);
        g_mutex_unlock (&priv->queue_sources_mutex);
}

/**
 * soup_session_unpause_message:
 * @session: a #SoupSession
 * @msg: a #SoupMessage currently running on @session
 *
 * Resumes HTTP I/O on @msg. Use this to resume after calling
 * [method@Session.pause_message].
 *
 * If @msg is being sent via blocking I/O, this will resume reading or
 * writing immediately. If @msg is using non-blocking I/O, then
 * reading or writing won't resume until you return to the main loop.
 **/
void
soup_session_unpause_message (SoupSession *session,
			      SoupMessage *msg)
{
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	item = soup_session_lookup_queue_item (session, msg);
        if (!item)
                return;

	g_return_if_fail (item->async);

	item->paused = FALSE;
	if (item->state == SOUP_MESSAGE_RUNNING)
		soup_message_io_unpause (msg);

	soup_session_kick_queue (session);
}

void
soup_session_cancel_message (SoupSession *session,
			     SoupMessage *msg)
{
	SoupMessageQueueItem *item = soup_session_lookup_queue_item (session, msg);

        /* If the message is already ending, don't do anything */
	if (item)
		soup_message_queue_item_cancel (item);
}

/**
 * soup_session_abort:
 * @session: the session
 *
 * Cancels all pending requests in @session and closes all idle
 * persistent connections.
 */
void
soup_session_abort (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);

	/* Cancel everything */
        g_mutex_lock (&priv->queue_mutex);
	g_queue_foreach (priv->queue, (GFunc)soup_message_queue_item_cancel, NULL);
        g_mutex_unlock (&priv->queue_mutex);

	/* Close all idle connections */
        soup_connection_manager_cleanup (priv->conn_manager, TRUE);
}

static gboolean
feature_already_added (SoupSession *session, GType feature_type)
{
        if (soup_session_has_feature (session, feature_type)) {
                g_warning ("SoupSession already has a %s, ignoring new feature",
                           g_type_name (feature_type));
                return TRUE;
        }

        return FALSE;
}

/**
 * soup_session_add_feature:
 * @session: a #SoupSession
 * @feature: an object that implements #SoupSessionFeature
 *
 * Adds @feature's functionality to @session. You cannot add multiple
 * features of the same [alias@GObject.Type] to a session.
 *
 * See the main [class@Session] documentation for information on what
 * features are present in sessions by default.
 **/
void
soup_session_add_feature (SoupSession *session, SoupSessionFeature *feature)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_SESSION_FEATURE (feature));

	priv = soup_session_get_instance_private (session);

        if (feature_already_added (session, G_TYPE_FROM_INSTANCE (feature)))
                return;

	priv->features = g_slist_prepend (priv->features, g_object_ref (feature));
	soup_session_feature_attach (feature, session);
}

/**
 * soup_session_add_feature_by_type:
 * @session: a #SoupSession
 * @feature_type: a #GType
 *
 * If @feature_type is the type of a class that implements
 * [iface@SessionFeature], this creates a new feature of that type and
 * adds it to @session as with [method@Session.add_feature]. You can use
 * this when you don't need to customize the new feature in any way.
 * Adding multiple features of the same @feature_type is not allowed.
 *
 * If @feature_type is not a [iface@SessionFeature] type, this gives each
 * existing feature on @session the chance to accept @feature_type as
 * a "subfeature". This can be used to add new [class@Auth] types, for instance.
 *
 * See the main [class@Session] documentation for information on what
 * features are present in sessions by default.
 **/
void
soup_session_add_feature_by_type (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);

	if (g_type_is_a (feature_type, SOUP_TYPE_SESSION_FEATURE)) {
		SoupSessionFeature *feature;

                if (feature_already_added (session, feature_type))
                        return;

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
 **/
void
soup_session_remove_feature (SoupSession *session, SoupSessionFeature *feature)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));

	priv = soup_session_get_instance_private (session);
	if (g_slist_find (priv->features, feature)) {
		priv->features = g_slist_remove (priv->features, feature);
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
 * @feature_type) from @session.
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
 * be the type of either a [iface@SessionFeature], or else a subtype of
 * some class managed by another feature, such as [class@Auth]).
 *
 * Returns: %TRUE or %FALSE
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
 *   a list of features. You must free the list, but not its contents
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
 * Gets the feature in @session of type @feature_type.
 *
 * Returns: (nullable) (transfer none): a #SoupSessionFeature, or %NULL. The
 *   feature is owned by @session.
 **/
SoupSessionFeature *
soup_session_get_feature (SoupSession *session, GType feature_type)
{
	SoupSessionPrivate *priv;
	SoupSessionFeature *feature;
	GSList *f;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);

	for (f = priv->features; f; f = f->next) {
		feature = f->data;
		if (G_TYPE_CHECK_INSTANCE_TYPE (feature, feature_type))
			return feature;
	}
	return NULL;
}

/**
 * soup_session_get_feature_for_message:
 * @session: a #SoupSession
 * @feature_type: the #GType of the feature to get
 * @msg: a #SoupMessage
 *
 * Gets the feature in @session of type @feature_type, provided
 * that it is not disabled for @msg.
 *
 * Returns: (nullable) (transfer none): a #SoupSessionFeature. The feature is
 *   owned by @session.
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

static gint
processing_stage_cmp (gconstpointer a,
                      gconstpointer b)
{
        SoupProcessingStage stage_a = soup_content_processor_get_processing_stage (SOUP_CONTENT_PROCESSOR ((gpointer)a));
        SoupProcessingStage stage_b = soup_content_processor_get_processing_stage (SOUP_CONTENT_PROCESSOR ((gpointer)b));

        if (stage_a > stage_b)
                return 1;
        if (stage_a == stage_b)
                return 0;
        return -1;
}

GInputStream *
soup_session_setup_message_body_input_stream (SoupSession        *session,
                                              SoupMessage        *msg,
                                              GInputStream       *body_stream,
                                              SoupProcessingStage start_at_stage)
{
        GInputStream *istream;
        GSList *p, *processors;

        istream = g_object_ref (body_stream);

        processors = soup_session_get_features (session, SOUP_TYPE_CONTENT_PROCESSOR);
        processors = g_slist_sort (processors, processing_stage_cmp);

        for (p = processors; p; p = g_slist_next (p)) {
                GInputStream *wrapper;
                SoupContentProcessor *processor;

                processor = SOUP_CONTENT_PROCESSOR (p->data);
                if (soup_message_disables_feature (msg, p->data) ||
                    soup_content_processor_get_processing_stage (processor) < start_at_stage)
                        continue;

                wrapper = soup_content_processor_wrap_input (processor, istream, msg, NULL);
                if (wrapper) {
                        g_object_unref (istream);
                        istream = wrapper;
                }
        }

        g_slist_free (processors);

        return istream;
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
	 * When sending a request, first [signal@Session::request-queued]
	 * is emitted, indicating that the session has become aware of
	 * the request.
	 *
	 * After a connection is available to send the request various
	 * [class@Message] signals are emitted as the message is
	 * processed. If the message is requeued, it will emit
	 * [signal@Message::restarted], which will then be followed by other
	 * [class@Message] signals when the message is re-sent.
	 *
	 * Eventually, the message will emit [signal@Message::finished].
	 * Normally, this signals the completion of message
	 * processing. However, it is possible that the application
	 * will requeue the message from the "finished" handler.
	 * In that case the process will loop back.
	 *
	 * Eventually, a message will reach "finished" and not be
	 * requeued. At that point, the session will emit
	 * [signal@Session::request-unqueued] to indicate that it is done
	 * with the message.
	 *
	 * To sum up: [signal@Session::request-queued] and
	 * [signal@Session::request-unqueued] are guaranteed to be emitted
	 * exactly once, but [signal@Message::finished] (and all of the other
	 * [class@Message] signals) may be invoked multiple times for a given
	 * message.
	 **/
	signals[REQUEST_QUEUED] =
		g_signal_new ("request-queued",
			      G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (SoupSessionClass, request_queued),
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
	 * indicating that @session is done with it.
	 *
	 * See [signal@Session::request-queued] for a detailed description of
	 * the message lifecycle within a session.
	 **/
	signals[REQUEST_UNQUEUED] =
		g_signal_new ("request-unqueued",
			      G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              G_STRUCT_OFFSET (SoupSessionClass, request_unqueued),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_MESSAGE);

	/* properties */
	/**
	 * SoupSession:proxy-resolver: (attributes org.gtk.Property.get=soup_session_get_proxy_resolver org.gtk.Property.set=soup_session_set_proxy_resolver)
	 *
	 * A [iface@Gio.ProxyResolver] to use with this session.
	 *
	 * If no proxy resolver is set, then the default proxy resolver
	 * will be used. See [func@Gio.ProxyResolver.get_default].
	 * You can set it to %NULL if you don't want to use proxies, or
	 * set it to your own [iface@Gio.ProxyResolver] if you want to control
	 * what proxies get used.
	 */
        properties[PROP_PROXY_RESOLVER] =
		g_param_spec_object ("proxy-resolver",
				     "Proxy Resolver",
				     "The GProxyResolver to use for this session",
				     G_TYPE_PROXY_RESOLVER,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS);
	/**
	 * SoupSession:max-conns: (attributes org.gtk.Property.get=soup_session_get_max_conns)
	 *
	 * The maximum number of connections that the session can open at once.
	 */
        properties[PROP_MAX_CONNS] =
		g_param_spec_int ("max-conns",
				  "Max Connection Count",
				  "The maximum number of connections that the session can open at once",
				  1,
				  G_MAXINT,
				  SOUP_SESSION_MAX_CONNS_DEFAULT,
				  G_PARAM_READWRITE |
				  G_PARAM_CONSTRUCT_ONLY |
				  G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:max-conns-per-host: (attributes org.gtk.Property.get=soup_session_get_max_conns_per_host)
	 *
	 * The maximum number of connections that the session can open at once
	 * to a given host.
	 */
        properties[PROP_MAX_CONNS_PER_HOST] =
		g_param_spec_int ("max-conns-per-host",
				  "Max Per-Host Connection Count",
				  "The maximum number of connections that the session can open at once to a given host",
				  1,
				  G_MAXINT,
				  SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT,
				  G_PARAM_READWRITE |
				  G_PARAM_CONSTRUCT_ONLY |
				  G_PARAM_STATIC_STRINGS);
	/**
	 * SoupSession:idle-timeout: (attributes org.gtk.Property.get=soup_session_get_idle_timeout org.gtk.Property.set=soup_session_set_idle_timeout)
	 *
	 * Connection lifetime (in seconds) when idle. Any connection
	 * left idle longer than this will be closed.
	 *
	 * Although you can change this property at any time, it will
	 * only affect newly-created connections, not currently-open
	 * ones. You can call [method@Session.abort] after setting this
	 * if you want to ensure that all future connections will have
	 * this timeout value.
	 **/
        properties[PROP_IDLE_TIMEOUT] =
		g_param_spec_uint ("idle-timeout",
				   "Idle Timeout",
				   "Connection lifetime when idle",
				   0, G_MAXUINT, 60,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:tls-database: (attributes org.gtk.Property.get=soup_session_get_tls_database org.gtk.Property.set=soup_session_set_tls_database)
	 *
	 * Sets the [class@Gio.TlsDatabase] to use for validating SSL/TLS
	 * certificates.
	 *
	 * If no certificate database is set, then the default database will be
	 * used. See [method@Gio.TlsBackend.get_default_database].
	 **/
        properties[PROP_TLS_DATABASE] =
		g_param_spec_object ("tls-database",
				     "TLS Database",
				     "TLS database to use",
				     G_TYPE_TLS_DATABASE,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:timeout: (attributes org.gtk.Property.get=soup_session_get_timeout org.gtk.Property.set=soup_session_set_timeout)
	 *
	 * The timeout (in seconds) for socket I/O operations
	 * (including connecting to a server, and waiting for a reply
	 * to an HTTP request).
	 *
	 * Although you can change this property at any time, it will
	 * only affect newly-created connections, not currently-open
	 * ones. You can call [method@Session.abort] after setting this
	 * if you want to ensure that all future connections will have
	 * this timeout value.
	 *
	 * Not to be confused with [property@Session:idle-timeout] (which is
	 * the length of time that idle persistent connections will be
	 * kept open).
	 */
        properties[PROP_TIMEOUT] =
		g_param_spec_uint ("timeout",
				   "Timeout value",
				   "Value in seconds to timeout a blocking I/O",
				   0, G_MAXUINT, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:user-agent: (attributes org.gtk.Property.get=soup_session_get_user_agent org.gtk.Property.set=soup_session_set_user_agent)
	 *
	 * User-Agent string.
	 *
	 * If non-%NULL, the value to use for the "User-Agent" header
	 * on [class@Message]s sent from this session.
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
	 * If you set a [property@Session:user-agent] property that has trailing
	 * whitespace, [class@Session] will append its own product token
	 * (eg, `libsoup/2.3.2`) to the end of the
	 * header for you.
	 **/
        properties[PROP_USER_AGENT] =
		g_param_spec_string ("user-agent",
				     "User-Agent string",
				     "User-Agent string",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:accept-language: (attributes org.gtk.Property.get=soup_session_get_accept_language org.gtk.Property.set=soup_session_set_accept_language)
	 *
	 * If non-%NULL, the value to use for the "Accept-Language" header
	 * on [class@Message]s sent from this session.
	 *
	 * Setting this will disable [property@Session:accept-language-auto].
	 **/
        properties[PROP_ACCEPT_LANGUAGE] =
		g_param_spec_string ("accept-language",
				     "Accept-Language string",
				     "Accept-Language string",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:accept-language-auto: (attributes org.gtk.Property.get=soup_session_get_accept_language_auto org.gtk.Property.set=soup_session_set_accept_language_auto)
	 *
	 * If %TRUE, [class@Session] will automatically set the string
	 * for the "Accept-Language" header on every [class@Message]
	 * sent, based on the return value of [func@GLib.get_language_names].
	 *
	 * Setting this will override any previous value of
	 * [property@Session:accept-language].
	 **/
        properties[PROP_ACCEPT_LANGUAGE_AUTO] =
		g_param_spec_boolean ("accept-language-auto",
				      "Accept-Language automatic mode",
				      "Accept-Language automatic mode",
				      FALSE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:remote-connectable: (attributes org.gtk.Property.get=soup_session_get_remote_connectable)
	 *
	 * Sets a socket to make outgoing connections on. This will override the default
	 * behaviour of opening TCP/IP sockets to the hosts specified in the URIs.
	 *
	 * This function is not required for common HTTP usage, but only when connecting
	 * to a HTTP service that is not using standard TCP/IP sockets. An example of
	 * this is a local service that uses HTTP over UNIX-domain sockets, in that case
	 * a [class@Gio.UnixSocketAddress] can be passed to this function.
	 **/
        properties[PROP_REMOTE_CONNECTABLE] =
		g_param_spec_object ("remote-connectable",
				     "Remote Connectable",
				     "Socket to connect to make outgoing connections on",
				     G_TYPE_SOCKET_CONNECTABLE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:local-address: (attributes org.gtk.Property.get=soup_session_get_local_address)
	 *
	 * Sets the [class@Gio.InetSocketAddress] to use for the client side of
	 * the connection.
	 *
	 * Use this property if you want for instance to bind the
	 * local socket to a specific IP address.
	 **/
        properties[PROP_LOCAL_ADDRESS] =
		g_param_spec_object ("local-address",
				     "Local address",
				     "Address of local end of socket",
				     G_TYPE_INET_SOCKET_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupSession:tls-interaction: (attributes org.gtk.Property.get=soup_session_get_tls_interaction org.gtk.Property.set=soup_session_set_tls_interaction)
	 *
	 * A [class@Gio.TlsInteraction] object that will be passed on to any
	 * [class@Gio.TlsConnection]s created by the session.
	 *
	 * This can be used to provide client-side certificates, for example.
	 **/
        properties[PROP_TLS_INTERACTION] =
		g_param_spec_object ("tls-interaction",
				     "TLS Interaction",
				     "TLS interaction to use",
				     G_TYPE_TLS_INTERACTION,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
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

        if (soup_message_get_status (msg) == SOUP_STATUS_MISDIRECTED_REQUEST)
                return TRUE;

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

        /* This cancellable was set for the send operation that is done now */
        g_object_unref (item->cancellable);
        item->cancellable = g_cancellable_new ();

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
		ostream = g_memory_output_stream_new_resizable ();
		g_object_set_data_full (G_OBJECT (item->task), "SoupSession:ostream",
					ostream, g_object_unref);

		g_object_set_data (G_OBJECT (ostream), "istream", stream);

		/* We don't use CLOSE_SOURCE because we need to control when the
		 * side effects of closing the SoupClientInputStream happen.
		 */
		g_output_stream_splice_async (ostream, stream,
					      G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
					      item->io_priority,
					      item->cancellable,
					      send_async_spliced,
					      soup_message_queue_item_ref (item));
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

        session_debug (item, "run_until_read_done");

	soup_message_io_run_until_read_finish (msg, result, &error);
	if (error && (!item->io_started || item->state == SOUP_MESSAGE_RESTARTING)) {
		/* Message was restarted, we'll try again. */
		g_error_free (error);
                soup_message_queue_item_unref (item);
		return;
	}

	if (!error)
		stream = soup_message_io_get_response_istream (msg, &error);

	if (stream) {
		send_async_maybe_complete (item, stream);
                soup_message_queue_item_unref (item);
	        return;
	}

	if (item->state != SOUP_MESSAGE_FINISHED) {
		if (soup_message_io_in_progress (msg))
			soup_message_io_finished (msg);
		item->paused = FALSE;
		if (item->state != SOUP_MESSAGE_FINISHED) {
			item->state = SOUP_MESSAGE_FINISHING;
			soup_session_process_queue_item (item->session, item, FALSE);
		}
	}
	async_send_request_return_result (item, NULL, error);
        soup_message_queue_item_unref (item);
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
						      soup_message_queue_item_ref (item));
		return;
	}

	soup_message_io_run (item->msg, FALSE);
}

static void
cache_stream_finished (GInputStream         *stream,
		       SoupMessageQueueItem *item)
{
        soup_message_set_metrics_timestamp (item->msg, SOUP_MESSAGE_METRICS_RESPONSE_END);

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
		g_clear_error (&error);
		return;
	}
	g_object_unref (stream);
	g_clear_error (&error);

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

                session_debug (item, "Had fresh cache response");
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

                session_debug (item, "Needs validation");

		conditional_msg = soup_cache_generate_conditional_request (cache, item->msg);
		if (!conditional_msg)
			return FALSE;

		/* Detect any quick cancellation before the cache is able to return data. */
		data = g_slice_new0 (AsyncCacheConditionalData);
		data->cache = g_object_ref (cache);
		data->conditional_msg = conditional_msg;
		data->item = soup_message_queue_item_ref (item);
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

static gboolean
soup_session_return_error_if_message_already_in_queue (SoupSession         *session,
                                                       SoupMessage         *msg,
                                                       GCancellable        *cancellable,
                                                       GAsyncReadyCallback  callback,
                                                       gpointer             user_data)
{
        SoupMessageQueueItem *item;
        GTask *task;

        if (!soup_session_lookup_queue_item (session, msg))
                return FALSE;

        /* Set a new SoupMessageQueueItem in finished state as task data for
         * soup_session_get_async_result_message() and soup_session_send_finish().
         */
        item = soup_message_queue_item_new (session, msg, TRUE, cancellable);
        item->state = SOUP_MESSAGE_FINISHED;
        item->error = g_error_new_literal (SOUP_SESSION_ERROR,
                                           SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE,
                                           _("Message is already in session queue"));
        task = g_task_new (session, cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_session_return_error_if_message_already_in_queue);
        g_task_set_task_data (task, item, (GDestroyNotify)soup_message_queue_item_unref);
        g_task_return_error (task, g_error_copy (item->error));
        g_object_unref (task);

        return TRUE;
}

/**
 * soup_session_send_async:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @io_priority: the I/O priority of the request
 * @cancellable: (nullable): a #GCancellable
 * @callback: (scope async): the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously sends @msg and waits for the beginning of a response.
 *
 * When @callback is called, then either @msg has been sent, and its response
 * headers received, or else an error has occurred. Call
 * [method@Session.send_finish] to get a [class@Gio.InputStream] for reading the
 * response body.
 *
 * See [method@Session.send] for more details on the general semantics.
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

        if (soup_session_return_error_if_message_already_in_queue (session, msg, cancellable, callback, user_data))
            return;

	item = soup_session_append_queue_item (session, msg, TRUE, cancellable);
	item->io_priority = io_priority;
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (async_send_request_restarted), item);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (async_send_request_finished), item);

	item->task = g_task_new (session, item->cancellable, callback, user_data);
	g_task_set_source_tag (item->task, soup_session_send_async);
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
 * Gets the response to a [method@Session.send_async] call.
 *
 * If successful returns a [class@Gio.InputStream] that can be used to read the
 * response body.
 *
 * Returns: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
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

                if (!g_error_matches (item->error, SOUP_SESSION_ERROR, SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE)) {
                        if (soup_message_io_in_progress (item->msg))
                                soup_message_io_finished (item->msg);
                        else if (item->state != SOUP_MESSAGE_FINISHED)
                                item->state = SOUP_MESSAGE_FINISHING;

                        if (item->state != SOUP_MESSAGE_FINISHED)
                                soup_session_process_queue_item (session, item, FALSE);
                }
	}

	return g_task_propagate_pointer (task, error);
}

/**
 * soup_session_send:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @cancellable: (nullable): a #GCancellable
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously sends @msg and waits for the beginning of a response.
 *
 * On success, a [class@Gio.InputStream] will be returned which you can use to
 * read the response body. ("Success" here means only that an HTTP
 * response was received and understood; it does not necessarily mean
 * that a 2xx class status code was received.)
 *
 * If non-%NULL, @cancellable can be used to cancel the request;
 * [method@Session.send] will return a %G_IO_ERROR_CANCELLED error. Note that
 * with requests that have side effects (eg, `POST`, `PUT`, `DELETE`) it is
 * possible that you might cancel the request after the server acts on it, but
 * before it returns a response, leaving the remote resource in an unknown
 * state.
 *
 * If @msg is requeued due to a redirect or authentication, the
 * initial (`3xx/401/407`) response body will be suppressed, and
 * [method@Session.send] will only return once a final response has been
 * received.
 *
 * Possible error domains include [error@SessionError], [error@Gio.IOErrorEnum],
 * and [error@Gio.TlsError] which you may want to specifically handle.
 *
 * Returns: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
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

        if (soup_session_lookup_queue_item (session, msg)) {
                g_set_error_literal (error,
                                     SOUP_SESSION_ERROR,
                                     SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE,
                                     _("Message is already in session queue"));
                return NULL;
        }

	item = soup_session_append_queue_item (session, msg, FALSE, cancellable);

	while (!stream) {
		/* Get a connection, etc */
		soup_session_process_queue_item (session, item, TRUE);
		if (item->state != SOUP_MESSAGE_RUNNING)
			break;

		/* Send request, read headers */
		if (!soup_message_io_run_until_read (msg, item->cancellable, &my_error)) {
			if (item->state == SOUP_MESSAGE_RESTARTING) {
				/* Message was restarted, we'll try again. */
				g_clear_error (&my_error);
				continue;
			}
                        session_debug (item, "Did not reach read: %s", my_error->message);
			break;
		}

		stream = soup_message_io_get_response_istream (msg, &my_error);
		if (!stream) {
                        session_debug (item, "Did not get a response stream");
			break;
                }

		if (!expected_to_be_requeued (session, msg))
			break;

		/* Gather the current message body... */
                session_debug (item, "Reading response stream");
		ostream = g_memory_output_stream_new_resizable ();
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
                        session_debug (item, "Restarting item");
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

        /* This cancellable was set for the send operation that is done now */
        g_object_unref (item->cancellable);
        item->cancellable = g_cancellable_new ();

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
			soup_session_process_queue_item (session, item, TRUE);
	}

	soup_message_queue_item_unref (item);
	return stream;
}

static void
send_and_read_splice_ready_cb (SoupSession  *session,
			       GAsyncResult *result,
			       GTask        *task)
{
	GOutputStream *ostream;
	GError *error = NULL;

        ostream = g_task_get_task_data (task);

        // In order for soup_session_get_async_result_message() to work it must
        // have the task data for the task it wrapped
        SoupMessageQueueItem *item = g_task_get_task_data (G_TASK (result));
        g_task_set_task_data (task, soup_message_queue_item_ref (item), (GDestroyNotify)soup_message_queue_item_unref);

        if (soup_session_send_and_splice_finish (session, result, &error) != -1) {
                g_task_return_pointer (task,
                                       g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream)),
                                       (GDestroyNotify)g_bytes_unref);
        } else {
                g_task_return_error (task, error);
        }
        g_object_unref (task);
}

/**
 * soup_session_send_and_read_async:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @io_priority: the I/O priority of the request
 * @cancellable: (nullable): a #GCancellable
 * @callback: (scope async): the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously sends @msg and reads the response body.
 *
 * When @callback is called, then either @msg has been sent, and its response
 * body read, or else an error has occurred. This function should only be used
 * when the resource to be retrieved is not too long and can be stored in
 * memory. Call [method@Session.send_and_read_finish] to get a
 * [struct@GLib.Bytes] with the response body.
 *
 * See [method@Session.send] for more details on the general semantics.
 */
void
soup_session_send_and_read_async (SoupSession        *session,
				  SoupMessage        *msg,
				  int                 io_priority,
				  GCancellable       *cancellable,
				  GAsyncReadyCallback callback,
				  gpointer            user_data)
{
	GTask *task;
        GOutputStream *ostream;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

        ostream = g_memory_output_stream_new_resizable ();
	task = g_task_new (session, cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_session_send_and_read_async);
	g_task_set_priority (task, io_priority);
        g_task_set_task_data (task, ostream, g_object_unref);

        soup_session_send_and_splice_async (session, msg, ostream,
                                            G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                            G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                            g_task_get_priority (task),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)send_and_read_splice_ready_cb,
                                            task);
}

/**
 * soup_session_send_and_read_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the response to a [method@Session.send_and_read_async].
 *
 * If successful, returns a [struct@GLib.Bytes] with the response body.
 *
 * Returns: (transfer full): a #GBytes, or %NULL on error.
 */
GBytes *
soup_session_send_and_read_finish (SoupSession  *session,
				   GAsyncResult *result,
				   GError      **error)
{
	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	g_return_val_if_fail (g_task_is_valid (result, session), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

/**
 * soup_session_send_and_read:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @cancellable: (nullable): a #GCancellable
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously sends @msg and reads the response body.
 *
 * On success, a [struct@GLib.Bytes] will be returned with the response body.
 * This function should only be used when the resource to be retrieved
 * is not too long and can be stored in memory.
 *
 * See [method@Session.send] for more details on the general semantics.
 *
 * Returns: (transfer full): a #GBytes, or %NULL on error.
 */
GBytes *
soup_session_send_and_read (SoupSession  *session,
			    SoupMessage  *msg,
			    GCancellable *cancellable,
			    GError      **error)
{
	GOutputStream *ostream;
	GBytes *bytes = NULL;

        ostream = g_memory_output_stream_new_resizable ();
        if (soup_session_send_and_splice (session, msg, ostream,
                                          G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                          G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                          cancellable, error) != -1)
                bytes = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream));
        g_object_unref (ostream);

	return bytes;
}

typedef struct {
        GOutputStream *out_stream;
        GOutputStreamSpliceFlags flags;
        GTask *task;
} SendAndSpliceAsyncData;

static void
send_and_splice_async_data_free (SendAndSpliceAsyncData *data)
{
        g_clear_object (&data->out_stream);
        g_clear_object (&data->task);

        g_free (data);
}

static void
send_and_splice_ready_cb (GOutputStream *ostream,
                          GAsyncResult  *result,
                          GTask         *task)
{
        GError *error = NULL;
        gssize retval;

        retval = g_output_stream_splice_finish (ostream, result, &error);
        if (retval != -1)
                g_task_return_int (task, retval);
        else
                g_task_return_error (task, error);
        g_object_unref (task);
}

static void
send_and_splice_stream_ready_cb (SoupSession            *session,
                                 GAsyncResult           *result,
                                 SendAndSpliceAsyncData *data)
{
        GInputStream *stream;
        GTask *task;
        GError *error = NULL;

        // In order for soup_session_get_async_result_message() to work it must
        // have the task data for the task it wrapped
        SoupMessageQueueItem *item = g_task_get_task_data (G_TASK (result));
        g_task_set_task_data (data->task, soup_message_queue_item_ref (item), (GDestroyNotify)soup_message_queue_item_unref);

        stream = soup_session_send_finish (session, result, &error);
        if (!stream) {
                g_task_return_error (data->task, error);
                send_and_splice_async_data_free (data);
                return;
        }

        task = g_steal_pointer (&data->task);
        g_output_stream_splice_async (data->out_stream, stream, data->flags,
                                      g_task_get_priority (task),
                                      g_task_get_cancellable (task),
                                      (GAsyncReadyCallback)send_and_splice_ready_cb,
                                      task);
        g_object_unref (stream);
        send_and_splice_async_data_free (data);
}

/**
 * soup_session_send_and_splice_async:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @out_stream: (transfer none): a #GOutputStream
 * @flags: a set of #GOutputStreamSpliceFlags
 * @io_priority: the I/O priority of the request
 * @cancellable: (nullable): a #GCancellable
 * @callback: (scope async): the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously sends @msg and splices the response body stream into @out_stream.
 * When @callback is called, then either @msg has been sent and its response body
 * spliced, or else an error has occurred.
 *
 * See [method@Session.send] for more details on the general semantics.
 *
 * Since: 3.4
 */
void
soup_session_send_and_splice_async (SoupSession             *session,
                                    SoupMessage             *msg,
                                    GOutputStream           *out_stream,
                                    GOutputStreamSpliceFlags flags,
                                    int                      io_priority,
                                    GCancellable            *cancellable,
                                    GAsyncReadyCallback      callback,
                                    gpointer                 user_data)
{
        SendAndSpliceAsyncData *data;

        g_return_if_fail (SOUP_IS_SESSION (session));
        g_return_if_fail (SOUP_IS_MESSAGE (msg));
        g_return_if_fail (G_IS_OUTPUT_STREAM (out_stream));

        data = g_new (SendAndSpliceAsyncData, 1);
        data->out_stream = g_object_ref (out_stream);
        data->flags = flags;
        data->task = g_task_new (session, cancellable, callback, user_data);
        g_task_set_source_tag (data->task, soup_session_send_and_splice_async);
        g_task_set_priority (data->task, io_priority);

        soup_session_send_async (session, msg,
                                 g_task_get_priority (data->task),
                                 g_task_get_cancellable (data->task),
                                 (GAsyncReadyCallback)send_and_splice_stream_ready_cb,
                                 data);
}

/**
 * soup_session_send_and_splice_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the response to a [method@Session.send_and_splice_async].
 *
 * Returns: a #gssize containing the size of the data spliced, or -1 if an error occurred.
 *
 * Since: 3.4
 */
gssize
soup_session_send_and_splice_finish (SoupSession  *session,
                                     GAsyncResult *result,
                                     GError      **error)
{
        g_return_val_if_fail (SOUP_IS_SESSION (session), -1);
        g_return_val_if_fail (g_task_is_valid (result, session), -1);

        return g_task_propagate_int (G_TASK (result), error);
}

/**
 * soup_session_send_and_splice:
 * @session: a #SoupSession
 * @msg: (transfer none): a #SoupMessage
 * @out_stream: (transfer none): a #GOutputStream
 * @flags: a set of #GOutputStreamSpliceFlags
 * @cancellable: (nullable): a #GCancellable
 * @error: return location for a #GError, or %NULL
 *
 * Synchronously sends @msg and splices the response body stream into @out_stream.
 *
 * See [method@Session.send] for more details on the general semantics.
 *
 * Returns: a #gssize containing the size of the data spliced, or -1 if an error occurred.
 *
 * Since: 3.4
 */
gssize
soup_session_send_and_splice (SoupSession             *session,
                              SoupMessage             *msg,
                              GOutputStream           *out_stream,
                              GOutputStreamSpliceFlags flags,
                              GCancellable            *cancellable,
                              GError                 **error)
{
        GInputStream *stream;
        gssize retval;

        g_return_val_if_fail (G_IS_OUTPUT_STREAM (out_stream), -1);

        stream = soup_session_send (session, msg, cancellable, error);
        if (!stream)
                return -1;

        retval = g_output_stream_splice (out_stream, stream, flags, cancellable, error);
        g_object_unref (stream);

        return retval;
}

/**
 * soup_session_get_async_result_message:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 *
 * Gets the [class@Message] of the @result asynchronous operation This is useful
 * to get the [class@Message] of an asynchronous operation started by @session
 * from its [callback@Gio.AsyncReadyCallback].
 *
 * Returns: (transfer none) (nullable): a #SoupMessage or
 *   %NULL if @result is not a valid @session async operation result.
 */
SoupMessage *
soup_session_get_async_result_message (SoupSession  *session,
                                       GAsyncResult *result)
{
        SoupMessageQueueItem *item;

        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (g_task_is_valid (result, session), NULL);

        item = g_task_get_task_data (G_TASK (result));
        return item ? item->msg : NULL;
}

/**
 * soup_session_steal_connection:
 * @session: a #SoupSession
 * @msg: the message whose connection is to be stolen
 *
 * "Steals" the HTTP connection associated with @msg from @session.
 *
 * This happens immediately, regardless of the current state of the
 * connection, and @msg's callback will not be called. You can steal
 * the connection from a [class@Message] signal handler if you need to
 * wait for part or all of the response to be received first.
 *
 * Calling this function may cause @msg to be freed if you are not
 * holding any other reference to it.
 *
 * Returns: (transfer full): the #GIOStream formerly associated
 *   with @msg (or %NULL if @msg was no longer associated with a
 *   connection). No guarantees are made about what kind of #GIOStream
 *   is returned.
 */
static GIOStream *
soup_session_steal_connection (SoupSession *session,
			       SoupMessage *msg)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);

        return soup_connection_manager_steal_connection (priv->conn_manager, msg);
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

static void
websocket_connect_async_complete (SoupMessage *msg, gpointer user_data)
{
	GTask *task = user_data;
	SoupMessageQueueItem *item = g_task_get_task_data (task);

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

	supported_extensions = soup_session_get_supported_websocket_extensions_for_message (session, msg);
	if (soup_websocket_client_verify_handshake (item->msg, supported_extensions, &accepted_extensions, &error)) {
                g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
                                                      0, 0, NULL, NULL, task);
		stream = soup_session_steal_connection (item->session, item->msg);
		client = soup_websocket_connection_new (stream,
							soup_message_get_uri (item->msg),
							SOUP_WEBSOCKET_CONNECTION_CLIENT,
							soup_message_headers_get_one_common (soup_message_get_request_headers (msg), SOUP_HEADER_ORIGIN),
							soup_message_headers_get_one_common (soup_message_get_response_headers (msg), SOUP_HEADER_SEC_WEBSOCKET_PROTOCOL),
							accepted_extensions);
		g_object_unref (stream);
		g_task_return_pointer (task, client, g_object_unref);
		g_object_unref (task);

		return;
	}

        g_assert (!item->error);
        item->error = error;
        soup_message_io_finished (item->msg);
}

/**
 * soup_session_websocket_connect_async:
 * @session: a #SoupSession
 * @msg: #SoupMessage indicating the WebSocket server to connect to
 * @origin: (nullable): origin of the connection
 * @protocols: (nullable) (array zero-terminated=1): a
 *   %NULL-terminated array of protocols supported
 * @io_priority: the I/O priority of the request
 * @cancellable: (nullable): a #GCancellable
 * @callback: (scope async): the callback to invoke
 * @user_data: data for @callback
 *
 * Asynchronously creates a [class@WebsocketConnection] to communicate with a
 * remote server.
 *
 * All necessary WebSocket-related headers will be added to @msg, and
 * it will then be sent and asynchronously processed normally
 * (including handling of redirection and HTTP authentication).
 *
 * If the server returns "101 Switching Protocols", then @msg's status
 * code and response headers will be updated, and then the WebSocket
 * handshake will be completed. On success,
 * [method@Session.websocket_connect_finish] will return a new
 * [class@WebsocketConnection]. On failure it will return a #GError.
 *
 * If the server returns a status other than "101 Switching Protocols", then
 * @msg will contain the complete response headers and body from the server's
 * response, and [method@Session.websocket_connect_finish] will return
 * %SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET.
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

        if (soup_session_return_error_if_message_already_in_queue (session, msg, cancellable, callback, user_data))
                return;

	supported_extensions = soup_session_get_supported_websocket_extensions_for_message (session, msg);
	soup_websocket_client_prepare_handshake (msg, origin, protocols, supported_extensions);

	/* When the client is to _Establish a WebSocket Connection_ given a set
	 * of (/host/, /port/, /resource name/, and /secure/ flag), along with a
	 * list of /protocols/ and /extensions/ to be used, and an /origin/ in
	 * the case of web browsers, it MUST open a connection, send an opening
	 * handshake, and read the server's handshake in response.
	 */
	soup_message_add_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);

        /* WebSocket negotiation over HTTP/2 is not currently supported
         * and in practice all websocket servers support HTTP1.x with
         * HTTP/2 not providing a tangible benefit */
        soup_message_set_force_http_version (msg, SOUP_HTTP_1_1);

	item = soup_session_append_queue_item (session, msg, TRUE, cancellable);
	item->io_priority = io_priority;

        task = g_task_new (session, item->cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_session_websocket_connect_async);
	g_task_set_task_data (task, item, (GDestroyNotify) soup_message_queue_item_unref);

	soup_message_add_status_code_handler (msg, "got-informational",
					      SOUP_STATUS_SWITCHING_PROTOCOLS,
					      G_CALLBACK (websocket_connect_async_stop), task);
        g_signal_connect_object (msg, "finished",
                                 G_CALLBACK (websocket_connect_async_complete),
                                 task, 0);
	soup_session_kick_queue (session);
}

/**
 * soup_session_websocket_connect_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the [class@WebsocketConnection] response to a
 * [method@Session.websocket_connect_async] call.
 *
 * If successful, returns a [class@WebsocketConnection] that can be used to
 * communicate with the server.
 *
 * Returns: (transfer full): a new #SoupWebsocketConnection, or
 *   %NULL on error.
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
	SoupMessageQueueItem *item;

	item = soup_session_lookup_queue_item (session, msg);
	if (!item)
                return msg;

	if (soup_message_get_method (msg) != SOUP_METHOD_CONNECT)
		return msg;

	return item->related ? item->related->msg : msg;
}

static void
preconnect_async_complete (SoupMessage *msg,
                           GTask       *task)
{
        SoupMessageQueueItem *item = g_task_get_task_data (task);

        if (item->error)
                g_task_return_error (task, g_error_copy (item->error));
        else
                g_task_return_boolean (task, TRUE);
        g_object_unref (task);
}

/**
 * soup_session_preconnect_async:
 * @session: a #SoupSession
 * @msg: a #SoupMessage
 * @io_priority: the I/O priority of the request
 * @cancellable: (nullable): a #GCancellable
 * @callback: (nullable) (scope async): the callback to invoke when the operation finishes
 * @user_data: data for @progress_callback and @callback
 *
 * Start a preconnection to @msg.
 *
 * Once the connection is done, it will remain in idle state so that it can be
 * reused by future requests. If there's already an idle connection for the
 * given @msg host, the operation finishes successfully without creating a new
 * connection. If a new request for the given @msg host is made while the
 * preconnect is still ongoing, the request will take the ownership of the
 * connection and the preconnect operation will finish successfully (if there's
 * a connection error it will be handled by the request).
 *
 * The operation finishes when the connection is done or an error occurred.
 */
void
soup_session_preconnect_async (SoupSession        *session,
                               SoupMessage        *msg,
                               int                 io_priority,
                               GCancellable       *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer            user_data)
{
        SoupMessageQueueItem *item;
        GTask *task;

        g_return_if_fail (SOUP_IS_SESSION (session));
        g_return_if_fail (SOUP_IS_MESSAGE (msg));

        if (soup_session_return_error_if_message_already_in_queue (session, msg, cancellable, callback, user_data))
                return;

        item = soup_session_append_queue_item (session, msg, TRUE, cancellable);
        item->connect_only = TRUE;
        item->io_priority = io_priority;
        soup_message_set_is_preconnect (msg, TRUE);

        task = g_task_new (session, item->cancellable, callback, user_data);
        g_task_set_source_tag (task, soup_session_preconnect_async);
        g_task_set_priority (task, io_priority);
        g_task_set_task_data (task, item, (GDestroyNotify)soup_message_queue_item_unref);

        g_signal_connect_object (msg, "finished",
                                 G_CALLBACK (preconnect_async_complete),
                                 task, 0);

        soup_session_kick_queue (session);
}

/**
 * soup_session_preconnect_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Complete a preconnect async operation started with [method@Session.preconnect_async].
 *
 * Return value: %TRUE if the preconnect succeeded, or %FALSE in case of error.
 */
gboolean
soup_session_preconnect_finish (SoupSession  *session,
                                GAsyncResult *result,
                                GError      **error)
{
        g_return_val_if_fail (SOUP_IS_SESSION (session), FALSE);
        g_return_val_if_fail (g_task_is_valid (result, session), FALSE);

        return g_task_propagate_boolean (G_TASK (result), error);
}
