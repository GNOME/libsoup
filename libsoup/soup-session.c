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
#include "soup-auth-manager.h"
#include "soup-cache-private.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup-message-queue.h"
#include "soup-proxy-resolver-wrapper.h"
#include "soup-session-private.h"
#include "soup-socket-private.h"
#include "soup-websocket.h"
#include "soup-websocket-connection.h"
#include "soup-websocket-extension-manager-private.h"

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
 * In the past, #SoupSession was an abstract class, and users needed
 * to choose between #SoupSessionAsync (which always uses
 * #GMainLoop<!-- -->-based I/O), or #SoupSessionSync (which always uses
 * blocking I/O and can be used from multiple threads simultaneously).
 * This is no longer necessary; you can (and should) use a plain
 * #SoupSession, which supports both synchronous and asynchronous use.
 * (When using a plain #SoupSession, soup_session_queue_message()
 * behaves like it traditionally did on a #SoupSessionAsync, and
 * soup_session_send_message() behaves like it traditionally did on a
 * #SoupSessionSync.)
 *
 * Additional #SoupSession functionality is provided by
 * #SoupSessionFeature objects, which can be added to a session with
 * soup_session_add_feature() or soup_session_add_feature_by_type()
 * (or at construct time with the %SOUP_SESSION_ADD_FEATURE_BY_TYPE
 * pseudo-property). For example, #SoupLogger provides support for
 * logging HTTP traffic, #SoupContentDecoder provides support for
 * compressed response handling, and #SoupContentSniffer provides
 * support for HTML5-style response body content sniffing.
 * Additionally, subtypes of #SoupAuth and #SoupRequest can be added
 * as features, to add support for additional authentication and URI
 * types.
 *
 * All #SoupSessions are created with a #SoupAuthManager, and support
 * for %SOUP_TYPE_AUTH_BASIC and %SOUP_TYPE_AUTH_DIGEST. For
 * #SoupRequest types, #SoupRequestHTTP, #SoupRequestFile, and
 * #SoupRequestData are supported. Additionally, sessions using the
 * plain #SoupSession class (rather than one of its deprecated
 * subtypes) have a #SoupContentDecoder by default.
 **/

typedef struct {
	SoupURI     *uri;
	SoupAddress *addr;

	GSList      *connections;      /* CONTAINS: SoupConnection */
	guint        num_conns;

	guint        num_messages;

	GSource     *keep_alive_src;
	SoupSession *session;
} SoupSessionHost;
static guint soup_host_uri_hash (gconstpointer key);
static gboolean soup_host_uri_equal (gconstpointer v1, gconstpointer v2);

typedef struct {
	gboolean disposed;

	GTlsDatabase *tlsdb;
	GTlsInteraction *tls_interaction;
	char *ssl_ca_file;
	gboolean ssl_strict;
	gboolean tlsdb_use_default;

	guint io_timeout, idle_timeout;
	SoupAddress *local_addr;

	GResolver *resolver;
	GProxyResolver *proxy_resolver;
	gboolean proxy_use_default;
	SoupURI *proxy_uri;

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
	gboolean use_thread_context;

	char **http_aliases, **https_aliases;

	GHashTable *request_types;
} SoupSessionPrivate;

#define SOUP_IS_PLAIN_SESSION(o) (G_TYPE_FROM_INSTANCE (o) == SOUP_TYPE_SESSION)

static void free_host (SoupSessionHost *host);
static void connection_state_changed (GObject *object, GParamSpec *param,
				      gpointer user_data);
static void connection_disconnected (SoupConnection *conn, gpointer user_data);
static void drop_connection (SoupSession *session, SoupSessionHost *host,
			     SoupConnection *conn);

static void auth_manager_authenticate (SoupAuthManager *manager,
				       SoupMessage *msg, SoupAuth *auth,
				       gboolean retrying, gpointer user_data);

static void async_run_queue (SoupSession *session);

static void async_send_request_running (SoupSession *session, SoupMessageQueueItem *item);

#define SOUP_SESSION_MAX_CONNS_DEFAULT 10
#define SOUP_SESSION_MAX_CONNS_PER_HOST_DEFAULT 2

#define SOUP_SESSION_MAX_RESEND_COUNT 20

#define SOUP_SESSION_USER_AGENT_BASE "libsoup/" PACKAGE_VERSION

G_DEFINE_TYPE_WITH_PRIVATE (SoupSession, soup_session, G_TYPE_OBJECT)

enum {
	REQUEST_QUEUED,
	REQUEST_STARTED,
	REQUEST_UNQUEUED,
	AUTHENTICATE,
	CONNECTION_CREATED,
	TUNNELING,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_PROXY_URI,
	PROP_PROXY_RESOLVER,
	PROP_MAX_CONNS,
	PROP_MAX_CONNS_PER_HOST,
	PROP_USE_NTLM,
	PROP_SSL_CA_FILE,
	PROP_SSL_USE_SYSTEM_CA_FILE,
	PROP_TLS_DATABASE,
	PROP_SSL_STRICT,
	PROP_ASYNC_CONTEXT,
	PROP_USE_THREAD_CONTEXT,
	PROP_TIMEOUT,
	PROP_USER_AGENT,
	PROP_ACCEPT_LANGUAGE,
	PROP_ACCEPT_LANGUAGE_AUTO,
	PROP_IDLE_TIMEOUT,
	PROP_ADD_FEATURE,
	PROP_ADD_FEATURE_BY_TYPE,
	PROP_REMOVE_FEATURE_BY_TYPE,
	PROP_HTTP_ALIASES,
	PROP_HTTPS_ALIASES,
	PROP_LOCAL_ADDRESS,
	PROP_TLS_INTERACTION,

	LAST_PROP
};

static void
soup_session_init (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupAuthManager *auth_manager;

	priv->queue = soup_message_queue_new (session);

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
	g_signal_connect (auth_manager, "authenticate",
			  G_CALLBACK (auth_manager_authenticate), session);
	soup_session_feature_add_feature (SOUP_SESSION_FEATURE (auth_manager),
					  SOUP_TYPE_AUTH_BASIC);
	soup_session_feature_add_feature (SOUP_SESSION_FEATURE (auth_manager),
					  SOUP_TYPE_AUTH_DIGEST);
	soup_session_add_feature (session, SOUP_SESSION_FEATURE (auth_manager));
	g_object_unref (auth_manager);

	/* We'll be doing DNS continuously-ish while the session is active,
	 * so hold a ref on the default GResolver.
	 */
	priv->resolver = g_resolver_get_default ();

	priv->ssl_strict = TRUE;

	priv->http_aliases = g_new (char *, 2);
	priv->http_aliases[0] = (char *)g_intern_string ("*");
	priv->http_aliases[1] = NULL;

	priv->request_types = g_hash_table_new (soup_str_case_hash,
						soup_str_case_equal);
	soup_session_add_feature_by_type (session, SOUP_TYPE_REQUEST_HTTP);
	soup_session_add_feature_by_type (session, SOUP_TYPE_REQUEST_FILE);
	soup_session_add_feature_by_type (session, SOUP_TYPE_REQUEST_DATA);
}

static GObject *
soup_session_constructor (GType                  type,
			  guint                  n_construct_properties,
			  GObjectConstructParam *construct_params)
{
	GObject *object;
	SoupSession *session;
	SoupSessionPrivate *priv;

	object = G_OBJECT_CLASS (soup_session_parent_class)->constructor (type, n_construct_properties, construct_params);
	session = SOUP_SESSION (object);
	priv = soup_session_get_instance_private (session);

	priv->tlsdb_use_default = TRUE;

	/* If this is a "plain" SoupSession, fix up the default
	 * properties values, etc.
	 */
	if (type == SOUP_TYPE_SESSION) {
		g_clear_pointer (&priv->async_context, g_main_context_unref);
		priv->async_context = g_main_context_ref_thread_default ();
		priv->use_thread_context = TRUE;

		priv->io_timeout = priv->idle_timeout = 60;

		priv->http_aliases[0] = NULL;

		/* If the user overrides the proxy or tlsdb during construction,
		 * we don't want to needlessly resolve the extension point. So
		 * we just set flags saying to do it later.
		 */
		priv->proxy_use_default = TRUE;

		soup_session_add_feature_by_type (session, SOUP_TYPE_CONTENT_DECODER);
	}

	return object;
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
	g_free (priv->ssl_ca_file);

	g_clear_pointer (&priv->async_context, g_main_context_unref);
	g_clear_object (&priv->local_addr);

	g_hash_table_destroy (priv->features_cache);

	g_object_unref (priv->resolver);
	g_clear_object (&priv->proxy_resolver);
	g_clear_pointer (&priv->proxy_uri, soup_uri_free);

	g_free (priv->http_aliases);
	g_free (priv->https_aliases);

	g_hash_table_destroy (priv->request_types);

	g_clear_pointer (&priv->socket_props, soup_socket_properties_unref);

	G_OBJECT_CLASS (soup_session_parent_class)->finalize (object);
}

/* requires conn_lock */
static void
ensure_socket_props (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	gboolean ssl_strict;

	if (priv->socket_props)
		return;

	if (priv->proxy_use_default) {
		priv->proxy_resolver = g_object_ref (g_proxy_resolver_get_default ());
		priv->proxy_use_default = FALSE;
	}
	if (priv->tlsdb_use_default) {
		priv->tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
		priv->tlsdb_use_default = FALSE;
	}

	ssl_strict = priv->ssl_strict && (priv->tlsdb != NULL ||
					  SOUP_IS_PLAIN_SESSION (session));

	priv->socket_props = soup_socket_properties_new (priv->async_context,
							 priv->use_thread_context,
							 priv->proxy_resolver,
							 priv->local_addr,
							 priv->tlsdb,
							 priv->tls_interaction,
							 ssl_strict,
							 priv->io_timeout,
							 priv->idle_timeout);
}

/* Converts a language in POSIX format and to be RFC2616 compliant    */
/* Based on code from epiphany-webkit (ephy_langs_append_languages()) */
static gchar *
posix_lang_to_rfc2616 (const gchar *language)
{
	/* Don't include charset variants, etc */
	if (strchr (language, '.') || strchr (language, '@'))
		return NULL;

	/* Ignore "C" locale, which g_get_language_names() always
	 * includes as a fallback.
	 */
	if (!strcmp (language, "C"))
		return NULL;

	return g_strdelimit (g_ascii_strdown (language, -1), "_", '-');
}

/* Converts @quality from 0-100 to 0.0-1.0 and appends to @str */
static gchar *
add_quality_value (const gchar *str, int quality)
{
	g_return_val_if_fail (str != NULL, NULL);

	if (quality >= 0 && quality < 100) {
		/* We don't use %.02g because of "." vs "," locale issues */
		if (quality % 10)
			return g_strdup_printf ("%s;q=0.%02d", str, quality);
		else
			return g_strdup_printf ("%s;q=0.%d", str, quality / 10);
	} else
		return g_strdup (str);
}

/* Returns a RFC2616 compliant languages list from system locales */
static gchar *
accept_languages_from_system (void)
{
	const char * const * lang_names;
	GPtrArray *langs = NULL;
	char *lang, *langs_str;
	int delta;
	guint i;

	lang_names = g_get_language_names ();
	g_return_val_if_fail (lang_names != NULL, NULL);

	/* Build the array of languages */
	langs = g_ptr_array_new_with_free_func (g_free);
	for (i = 0; lang_names[i] != NULL; i++) {
		lang = posix_lang_to_rfc2616 (lang_names[i]);
		if (lang)
			g_ptr_array_add (langs, lang);
	}

	/* Add quality values */
	if (langs->len < 10)
		delta = 10;
	else if (langs->len < 20)
		delta = 5;
	else
		delta = 1;

	for (i = 0; i < langs->len; i++) {
		lang = langs->pdata[i];
		langs->pdata[i] = add_quality_value (lang, 100 - i * delta);
		g_free (lang);
	}

	/* Fallback: add "en" if list is empty */
	if (langs->len == 0)
		g_ptr_array_add (langs, g_strdup ("en"));

	g_ptr_array_add (langs, NULL);
	langs_str = g_strjoinv (", ", (char **)langs->pdata);
	g_ptr_array_free (langs, TRUE);

	return langs_str;
}

static void
set_tlsdb (SoupSession *session, GTlsDatabase *tlsdb)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GTlsDatabase *system_default;

	priv->tlsdb_use_default = FALSE;
	if (tlsdb == priv->tlsdb)
		return;

	g_object_freeze_notify (G_OBJECT (session));

	system_default = g_tls_backend_get_default_database (g_tls_backend_get_default ());
	if (system_default) {
		if (priv->tlsdb == system_default || tlsdb == system_default) {
			g_object_notify (G_OBJECT (session), "ssl-use-system-ca-file");
		}
		g_object_unref (system_default);
	}

	if (priv->ssl_ca_file) {
		g_free (priv->ssl_ca_file);
		priv->ssl_ca_file = NULL;
		g_object_notify (G_OBJECT (session), "ssl-ca-file");
	}

	if (priv->tlsdb)
		g_object_unref (priv->tlsdb);
	priv->tlsdb = tlsdb;
	if (priv->tlsdb)
		g_object_ref (priv->tlsdb);

	g_object_notify (G_OBJECT (session), "tls-database");
	g_object_thaw_notify (G_OBJECT (session));
}

static void
set_use_system_ca_file (SoupSession *session, gboolean use_system_ca_file)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GTlsDatabase *system_default;

	priv->tlsdb_use_default = FALSE;

	system_default = g_tls_backend_get_default_database (g_tls_backend_get_default ());

	if (use_system_ca_file)
		set_tlsdb (session, system_default);
	else if (priv->tlsdb == system_default)
		set_tlsdb (session, NULL);

	g_clear_object (&system_default);
}

static void
set_ssl_ca_file (SoupSession *session, const char *ssl_ca_file)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	GTlsDatabase *tlsdb;
	GError *error = NULL;

	priv->tlsdb_use_default = FALSE;
	if (!g_strcmp0 (priv->ssl_ca_file, ssl_ca_file))
		return;

	g_object_freeze_notify (G_OBJECT (session));

	if (g_path_is_absolute (ssl_ca_file))
		tlsdb = g_tls_file_database_new (ssl_ca_file, &error);
	else {
		char *path, *cwd;

		cwd = g_get_current_dir ();
		path = g_build_filename (cwd, ssl_ca_file, NULL);
		tlsdb = g_tls_file_database_new (path, &error);
		g_free (path);
		g_free (cwd);
	}

	if (error) {
		if (!g_error_matches (error, G_TLS_ERROR, G_TLS_ERROR_UNAVAILABLE)) {
			g_warning ("Could not set SSL credentials from '%s': %s",
				   ssl_ca_file, error->message);

			tlsdb = g_tls_file_database_new ("/dev/null", NULL);
		}
		g_error_free (error);
	}

	set_tlsdb (session, tlsdb);
	if (tlsdb) {
		g_object_unref (tlsdb);

		priv->ssl_ca_file = g_strdup (ssl_ca_file);
		g_object_notify (G_OBJECT (session), "ssl-ca-file");
	} else if (priv->ssl_ca_file) {
		g_clear_pointer (&priv->ssl_ca_file, g_free);
		g_object_notify (G_OBJECT (session), "ssl-ca-file");
	}

	g_object_thaw_notify (G_OBJECT (session));
}

/* priv->http_aliases and priv->https_aliases are stored as arrays of
 * *interned* strings, so we can't just use g_strdupv() to set them.
 */
static void
set_aliases (char ***variable, char **value)
{
	int len, i;

	if (*variable)
		g_free (*variable);

	if (!value) {
		*variable = NULL;
		return;
	}

	len = g_strv_length (value);
	*variable = g_new (char *, len + 1);
	for (i = 0; i < len; i++)
		(*variable)[i] = (char *)g_intern_string (value[i]);
	(*variable)[i] = NULL;
}

static void
set_proxy_resolver (SoupSession *session, SoupURI *uri,
		    SoupProxyURIResolver *soup_resolver,
		    GProxyResolver *g_resolver)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	soup_session_remove_feature_by_type (session, SOUP_TYPE_PROXY_URI_RESOLVER);
	G_GNUC_END_IGNORE_DEPRECATIONS;
	g_clear_object (&priv->proxy_resolver);
	g_clear_pointer (&priv->proxy_uri, soup_uri_free);
	priv->proxy_use_default = FALSE;

	if (uri) {
		char *uri_string;

		priv->proxy_uri = soup_uri_copy (uri);
		uri_string = soup_uri_to_string_internal (uri, FALSE, TRUE, TRUE);
		priv->proxy_resolver = g_simple_proxy_resolver_new (uri_string, NULL);
		g_free (uri_string);
	} else if (soup_resolver) {
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		if (SOUP_IS_PROXY_RESOLVER_DEFAULT (soup_resolver))
			priv->proxy_resolver = g_object_ref (g_proxy_resolver_get_default ());
		else
			priv->proxy_resolver = soup_proxy_resolver_wrapper_new (soup_resolver);
		G_GNUC_END_IGNORE_DEPRECATIONS;
	} else if (g_resolver)
		priv->proxy_resolver = g_object_ref (g_resolver);
}

static void
soup_session_set_property (GObject *object, guint prop_id,
			   const GValue *value, GParamSpec *pspec)
{
	SoupSession *session = SOUP_SESSION (object);
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	const char *user_agent;
	SoupSessionFeature *feature;
	GMainContext *async_context;
	gboolean socket_props_changed = FALSE;

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = g_value_dup_object (value);
		socket_props_changed = TRUE;
		break;
	case PROP_PROXY_URI:
		set_proxy_resolver (session, g_value_get_boxed (value),
				    NULL, NULL);
		soup_session_abort (session);
		socket_props_changed = TRUE;
		break;
	case PROP_PROXY_RESOLVER:
		set_proxy_resolver (session, NULL, NULL,
				    g_value_get_object (value));
		socket_props_changed = TRUE;
		break;
	case PROP_MAX_CONNS:
		priv->max_conns = g_value_get_int (value);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		priv->max_conns_per_host = g_value_get_int (value);
		break;
	case PROP_USE_NTLM:
		g_return_if_fail (!SOUP_IS_PLAIN_SESSION (session));
		feature = soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER);
		if (feature) {
			if (g_value_get_boolean (value))
				soup_session_feature_add_feature (feature, SOUP_TYPE_AUTH_NTLM);
			else
				soup_session_feature_remove_feature (feature, SOUP_TYPE_AUTH_NTLM);
		} else
			g_warning ("Trying to set use-ntlm on session with no auth-manager");
		break;
	case PROP_SSL_CA_FILE:
		set_ssl_ca_file (session, g_value_get_string (value));
		socket_props_changed = TRUE;
		break;
	case PROP_SSL_USE_SYSTEM_CA_FILE:
		set_use_system_ca_file (session, g_value_get_boolean (value));
		socket_props_changed = TRUE;
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
	case PROP_SSL_STRICT:
		priv->ssl_strict = g_value_get_boolean (value);
		socket_props_changed = TRUE;
		break;
	case PROP_ASYNC_CONTEXT:
		async_context = g_value_get_pointer (value);
		if (async_context && async_context != g_main_context_get_thread_default ())
			g_return_if_fail (!SOUP_IS_PLAIN_SESSION (session));
		priv->async_context = async_context;
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
		socket_props_changed = TRUE;
		break;
	case PROP_USE_THREAD_CONTEXT:
		if (!g_value_get_boolean (value))
			g_return_if_fail (!SOUP_IS_PLAIN_SESSION (session));
		priv->use_thread_context = g_value_get_boolean (value);
		if (priv->use_thread_context) {
			if (priv->async_context)
				g_main_context_unref (priv->async_context);
			priv->async_context = g_main_context_get_thread_default ();
			if (priv->async_context)
				g_main_context_ref (priv->async_context);
		}
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
			priv->accept_language = accept_languages_from_system ();
		break;
	case PROP_IDLE_TIMEOUT:
		priv->idle_timeout = g_value_get_uint (value);
		socket_props_changed = TRUE;
		break;
	case PROP_ADD_FEATURE:
		soup_session_add_feature (session, g_value_get_object (value));
		break;
	case PROP_ADD_FEATURE_BY_TYPE:
		soup_session_add_feature_by_type (session, g_value_get_gtype (value));
		break;
	case PROP_REMOVE_FEATURE_BY_TYPE:
		soup_session_remove_feature_by_type (session, g_value_get_gtype (value));
		break;
	case PROP_HTTP_ALIASES:
		set_aliases (&priv->http_aliases, g_value_get_boxed (value));
		break;
	case PROP_HTTPS_ALIASES:
		set_aliases (&priv->https_aliases, g_value_get_boxed (value));
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
	SoupSessionFeature *feature;
	GTlsDatabase *tlsdb;

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, priv->local_addr);
		break;
	case PROP_PROXY_URI:
		g_value_set_boxed (value, priv->proxy_uri);
		break;
	case PROP_PROXY_RESOLVER:
		g_mutex_lock (&priv->conn_lock);
		ensure_socket_props (session);
		g_mutex_unlock (&priv->conn_lock);
		g_value_set_object (value, priv->proxy_resolver);
		break;
	case PROP_MAX_CONNS:
		g_value_set_int (value, priv->max_conns);
		break;
	case PROP_MAX_CONNS_PER_HOST:
		g_value_set_int (value, priv->max_conns_per_host);
		break;
	case PROP_USE_NTLM:
		feature = soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER);
		if (feature)
			g_value_set_boolean (value, soup_session_feature_has_feature (feature, SOUP_TYPE_AUTH_NTLM));
		else
			g_value_set_boolean (value, FALSE);
		break;
	case PROP_SSL_CA_FILE:
		g_value_set_string (value, priv->ssl_ca_file);
		break;
	case PROP_SSL_USE_SYSTEM_CA_FILE:
		tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());
		g_mutex_lock (&priv->conn_lock);
		ensure_socket_props (session);
		g_mutex_unlock (&priv->conn_lock);
		g_value_set_boolean (value, priv->tlsdb == tlsdb);
		g_clear_object (&tlsdb);
		break;
	case PROP_TLS_DATABASE:
		g_mutex_lock (&priv->conn_lock);
		ensure_socket_props (session);
		g_mutex_unlock (&priv->conn_lock);
		g_value_set_object (value, priv->tlsdb);
		break;
	case PROP_TLS_INTERACTION:
		g_value_set_object (value, priv->tls_interaction);
		break;
	case PROP_SSL_STRICT:
		g_value_set_boolean (value, priv->ssl_strict);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	case PROP_USE_THREAD_CONTEXT:
		g_value_set_boolean (value, priv->use_thread_context);
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
	case PROP_HTTP_ALIASES:
		g_value_set_boxed (value, priv->http_aliases);
		break;
	case PROP_HTTPS_ALIASES:
		g_value_set_boxed (value, priv->https_aliases);
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
 * Return value: the new session.
 *
 * Since: 2.42
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
 * Return value: the new session.
 *
 * Since: 2.42
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
 * soup_session_get_async_context:
 * @session: a #SoupSession
 *
 * Gets @session's #SoupSession:async-context. This does not add a ref
 * to the context, so you will need to ref it yourself if you want it
 * to outlive its session.
 *
 * For a modern #SoupSession, this will always just return the
 * thread-default #GMainContext, and so is not especially useful.
 *
 * Return value: (nullable) (transfer none): @session's #GMainContext,
 * which may be %NULL
 **/
GMainContext *
soup_session_get_async_context (SoupSession *session)
{
	SoupSessionPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	priv = soup_session_get_instance_private (session);

	if (priv->use_thread_context)
		return g_main_context_get_thread_default ();
	else
		return priv->async_context;
}

/* Hosts */

/* Note that we can't use soup_uri_host_hash() and soup_uri_host_equal()
 * because we want to ignore the protocol; http://example.com and
 * webcal://example.com are the same host.
 */
static guint
soup_host_uri_hash (gconstpointer key)
{
	const SoupURI *uri = key;

	g_return_val_if_fail (uri != NULL && uri->host != NULL, 0);

	return uri->port + soup_str_case_hash (uri->host);
}

static gboolean
soup_host_uri_equal (gconstpointer v1, gconstpointer v2)
{
	const SoupURI *one = v1;
	const SoupURI *two = v2;

	g_return_val_if_fail (one != NULL && two != NULL, one == two);
	g_return_val_if_fail (one->host != NULL && two->host != NULL, one->host == two->host);

	if (one->port != two->port)
		return FALSE;

	return g_ascii_strcasecmp (one->host, two->host) == 0;
}


static SoupSessionHost *
soup_session_host_new (SoupSession *session, SoupURI *uri)
{
	SoupSessionHost *host;

	host = g_slice_new0 (SoupSessionHost);
	host->uri = soup_uri_copy_host (uri);
	if (host->uri->scheme != SOUP_URI_SCHEME_HTTP &&
	    host->uri->scheme != SOUP_URI_SCHEME_HTTPS) {
		SoupSessionPrivate *priv = soup_session_get_instance_private (session);

		if (soup_uri_is_https (host->uri, priv->https_aliases))
			host->uri->scheme = SOUP_URI_SCHEME_HTTPS;
		else
			host->uri->scheme = SOUP_URI_SCHEME_HTTP;
	}

	host->addr = g_object_new (SOUP_TYPE_ADDRESS,
				   SOUP_ADDRESS_NAME, host->uri->host,
				   SOUP_ADDRESS_PORT, host->uri->port,
				   SOUP_ADDRESS_PROTOCOL, host->uri->scheme,
				   NULL);
	host->keep_alive_src = NULL;
	host->session = session;

	return host;
}

/* Requires conn_lock to be locked */
static SoupSessionHost *
get_host_for_uri (SoupSession *session, SoupURI *uri)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;
	gboolean https;
	SoupURI *uri_tmp = NULL;

	https = soup_uri_is_https (uri, priv->https_aliases);
	if (https)
		host = g_hash_table_lookup (priv->https_hosts, uri);
	else
		host = g_hash_table_lookup (priv->http_hosts, uri);
	if (host)
		return host;

	if (uri->scheme != SOUP_URI_SCHEME_HTTP &&
	    uri->scheme != SOUP_URI_SCHEME_HTTPS) {
		uri = uri_tmp = soup_uri_copy (uri);
		uri->scheme = https ? SOUP_URI_SCHEME_HTTPS : SOUP_URI_SCHEME_HTTP;
	}
	host = soup_session_host_new (session, uri);
	if (uri_tmp)
		soup_uri_free (uri_tmp);

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

	soup_uri_free (host->uri);
	g_object_unref (host->addr);
	g_slice_free (SoupSessionHost, host);
}

static void
auth_manager_authenticate (SoupAuthManager *manager, SoupMessage *msg,
			   SoupAuth *auth, gboolean retrying,
			   gpointer session)
{
	g_signal_emit (session, signals[AUTHENTICATE], 0, msg, auth, retrying);
}

#define SOUP_SESSION_WOULD_REDIRECT_AS_GET(session, msg) \
	((msg)->status_code == SOUP_STATUS_SEE_OTHER || \
	 ((msg)->status_code == SOUP_STATUS_FOUND && \
	  !SOUP_METHOD_IS_SAFE ((msg)->method)) || \
	 ((msg)->status_code == SOUP_STATUS_MOVED_PERMANENTLY && \
	  (msg)->method == SOUP_METHOD_POST))

#define SOUP_SESSION_WOULD_REDIRECT_AS_SAFE(session, msg) \
	(((msg)->status_code == SOUP_STATUS_MOVED_PERMANENTLY || \
	  (msg)->status_code == SOUP_STATUS_PERMANENT_REDIRECT || \
	  (msg)->status_code == SOUP_STATUS_TEMPORARY_REDIRECT || \
	  (msg)->status_code == SOUP_STATUS_FOUND) && \
	 SOUP_METHOD_IS_SAFE ((msg)->method))

static inline SoupURI *
redirection_uri (SoupMessage *msg)
{
	const char *new_loc;
	SoupURI *new_uri;

	new_loc = soup_message_headers_get_one (msg->response_headers,
						"Location");
	if (!new_loc)
		return NULL;
	new_uri = soup_uri_new_with_base (soup_message_get_uri (msg), new_loc);
	if (!new_uri || !new_uri->host) {
		if (new_uri)
			soup_uri_free (new_uri);
		return NULL;
	}

	return new_uri;
}

/**
 * soup_session_would_redirect:
 * @session: a #SoupSession
 * @msg: a #SoupMessage that has response headers
 *
 * Checks if @msg contains a response that would cause @session to
 * redirect it to a new URL (ignoring @msg's %SOUP_MESSAGE_NO_REDIRECT
 * flag, and the number of times it has already been redirected).
 *
 * Return value: whether @msg would be redirected
 *
 * Since: 2.38
 */
gboolean
soup_session_would_redirect (SoupSession *session, SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupURI *new_uri;

	/* It must have an appropriate status code and method */
	if (!SOUP_SESSION_WOULD_REDIRECT_AS_GET (session, msg) &&
	    !SOUP_SESSION_WOULD_REDIRECT_AS_SAFE (session, msg))
		return FALSE;

	/* and a Location header that parses to an http URI */
	if (!soup_message_headers_get_one (msg->response_headers, "Location"))
		return FALSE;
	new_uri = redirection_uri (msg);
	if (!new_uri)
		return FALSE;
	if (!new_uri->host || !*new_uri->host ||
	    (!soup_uri_is_http (new_uri, priv->http_aliases) &&
	     !soup_uri_is_https (new_uri, priv->https_aliases))) {
		soup_uri_free (new_uri);
		return FALSE;
	}

	soup_uri_free (new_uri);
	return TRUE;
}

/**
 * soup_session_redirect_message:
 * @session: the session
 * @msg: a #SoupMessage that has received a 3xx response
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
 * Return value: %TRUE if a redirection was applied, %FALSE if not
 * (eg, because there was no Location header, or it could not be
 * parsed).
 *
 * Since: 2.38
 */
gboolean
soup_session_redirect_message (SoupSession *session, SoupMessage *msg)
{
	SoupURI *new_uri;

	new_uri = redirection_uri (msg);
	if (!new_uri)
		return FALSE;

	if (SOUP_SESSION_WOULD_REDIRECT_AS_GET (session, msg)) {
		if (msg->method != SOUP_METHOD_HEAD) {
			g_object_set (msg,
				      SOUP_MESSAGE_METHOD, SOUP_METHOD_GET,
				      NULL);
		}
		soup_message_set_request (msg, NULL,
					  SOUP_MEMORY_STATIC, NULL, 0);
		soup_message_headers_set_encoding (msg->request_headers,
						   SOUP_ENCODING_NONE);
	}

	soup_message_set_uri (msg, new_uri);
	soup_uri_free (new_uri);

	soup_session_requeue_message (session, msg);
	return TRUE;
}

static void
redirect_handler (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;
	SoupSession *session = item->session;

	if (!soup_session_would_redirect (session, msg)) {
		SoupURI *new_uri = redirection_uri (msg);
		gboolean invalid = !new_uri || !new_uri->host;

		if (new_uri)
			soup_uri_free (new_uri);
		if (invalid && !item->new_api) {
			soup_message_set_status_full (msg,
						      SOUP_STATUS_MALFORMED,
						      "Invalid Redirect URL");
		}
		return;
	}

	soup_session_redirect_message (session, msg);
}

static void
re_emit_connection_event (SoupConnection      *conn,
			  GSocketClientEvent   event,
			  GIOStream           *connection,
			  gpointer             user_data)
{
	SoupMessageQueueItem *item = user_data;

	soup_message_network_event (item->msg, event, connection);
}

static void
soup_session_set_item_connection (SoupSession          *session,
				  SoupMessageQueueItem *item,
				  SoupConnection       *conn)
{
	if (item->conn) {
		g_signal_handlers_disconnect_by_func (item->conn, re_emit_connection_event, item);
		g_object_unref (item->conn);
	}

	item->conn = conn;
	item->conn_is_dedicated = FALSE;
	soup_message_set_connection (item->msg, conn);

	if (item->conn) {
		g_object_ref (item->conn);
		g_signal_connect (item->conn, "event",
				  G_CALLBACK (re_emit_connection_event), item);
	}
}

static void
message_restarted (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

	if (item->conn &&
	    (!soup_message_is_keepalive (msg) ||
	     SOUP_STATUS_IS_REDIRECTION (msg->status_code))) {
		if (soup_connection_get_state (item->conn) == SOUP_CONNECTION_IN_USE)
			soup_connection_set_state (item->conn, SOUP_CONNECTION_IDLE);
		soup_session_set_item_connection (item->session, item, NULL);
	}

	soup_message_cleanup_response (msg);
}

SoupMessageQueueItem *
soup_session_append_queue_item (SoupSession *session, SoupMessage *msg,
				gboolean async, gboolean new_api,
				SoupSessionCallback callback, gpointer user_data)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	SoupSessionHost *host;

	soup_message_cleanup_response (msg);

	item = soup_message_queue_append (priv->queue, msg, callback, user_data);
	item->async = async;
	item->new_api = new_api;

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_message (session, item->msg);
	host->num_messages++;
	g_mutex_unlock (&priv->conn_lock);

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_NO_REDIRECT)) {
		soup_message_add_header_handler (
			msg, "got_body", "Location",
			G_CALLBACK (redirect_handler), item);
	}
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (message_restarted), item);

	g_signal_emit (session, signals[REQUEST_QUEUED], 0, msg);

	soup_message_queue_item_ref (item);
	return item;
}

static void
soup_session_send_queue_item (SoupSession *session,
			      SoupMessageQueueItem *item,
			      SoupMessageCompletionFn completion_cb)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	if (priv->user_agent) {
		soup_message_headers_replace (item->msg->request_headers,
					      "User-Agent", priv->user_agent);
	}

	if (priv->accept_language &&
	    !soup_message_headers_get_list (item->msg->request_headers,
					    "Accept-Language")) {
		soup_message_headers_append (item->msg->request_headers,
					     "Accept-Language",
					     priv->accept_language);
	}

	/* Force keep alive connections for HTTP 1.0. Performance will
	 * improve when issuing multiple requests to the same host in
	 * a short period of time, as we wouldn't need to establish
	 * new connections. Keep alive is implicit for HTTP 1.1.
	 */
	if (!soup_message_headers_header_contains (item->msg->request_headers,
						   "Connection", "Keep-Alive") &&
	    !soup_message_headers_header_contains (item->msg->request_headers,
						   "Connection", "close") &&
	    !soup_message_headers_header_contains (item->msg->request_headers,
						   "Connection", "Upgrade")) {
		soup_message_headers_append (item->msg->request_headers,
					     "Connection", "Keep-Alive");
	}

	g_signal_emit (session, signals[REQUEST_STARTED], 0,
		       item->msg, soup_connection_get_socket (item->conn));
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
	if (host->uri->scheme == SOUP_URI_SCHEME_HTTPS)
		g_hash_table_remove (priv->https_hosts, host->uri);
	else
		g_hash_table_remove (priv->http_hosts, host->uri);
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

		/* Free the SoupHost (and its SoupAddress) if there
		 * has not been any new connection to the host during
		 * the last HOST_KEEP_ALIVE msecs.
		 */
		if (host->num_conns == 0) {
			g_assert (host->keep_alive_src == NULL);
			host->keep_alive_src = soup_add_timeout (priv->async_context,
								 HOST_KEEP_ALIVE,
								 free_unused_host,
								 host);
			host->keep_alive_src = g_source_ref (host->keep_alive_src);
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

SoupMessageQueue *
soup_session_get_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);

	return priv->queue;
}

static void
soup_session_unqueue_item (SoupSession          *session,
			   SoupMessageQueueItem *item)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupSessionHost *host;
	SoupConnection *dedicated_conn = NULL;

	if (item->conn) {
		if (item->conn_is_dedicated)
			dedicated_conn = g_object_ref (item->conn);
		else if (item->msg->method != SOUP_METHOD_CONNECT ||
			 !SOUP_STATUS_IS_SUCCESSFUL (item->msg->status_code))
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
	if (dedicated_conn) {
		/* FIXME: Do not drop the connection if current number of connections
		 * is no longer over the limits, just mark it as IDLE so it can be reused.
		 */
		g_hash_table_remove (priv->conns, dedicated_conn);
		drop_connection (session, host, dedicated_conn);
	}
	g_cond_broadcast (&priv->conn_cond);
	g_mutex_unlock (&priv->conn_lock);

	if (dedicated_conn) {
		soup_connection_disconnect (dedicated_conn);
		g_object_unref (dedicated_conn);
	}

	/* g_signal_handlers_disconnect_by_func doesn't work if you
	 * have a metamarshal, meaning it doesn't work with
	 * soup_message_add_header_handler()
	 */
	g_signal_handlers_disconnect_matched (item->msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, item);
	g_signal_emit (session, signals[REQUEST_UNQUEUED], 0, item->msg);
	soup_message_queue_item_unref (item);
}

static void
soup_session_set_item_status (SoupSession          *session,
			      SoupMessageQueueItem *item,
			      guint                 status_code,
			      GError               *error)
{
	SoupURI *uri = NULL;

	switch (status_code) {
	case SOUP_STATUS_CANT_RESOLVE:
	case SOUP_STATUS_CANT_CONNECT:
		uri = soup_message_get_uri (item->msg);
		break;

	case SOUP_STATUS_CANT_RESOLVE_PROXY:
	case SOUP_STATUS_CANT_CONNECT_PROXY:
		if (item->conn)
			uri = soup_connection_get_proxy_uri (item->conn);
		break;

	case SOUP_STATUS_SSL_FAILED:
		if (!g_tls_backend_supports_tls (g_tls_backend_get_default ())) {
			soup_message_set_status_full (item->msg, status_code,
						      "TLS/SSL support not available; install glib-networking");
			return;
		}
		break;

	default:
		break;
	}

	if (error)
		soup_message_set_status_full (item->msg, status_code, error->message);
	else if (uri && uri->host) {
		char *msg = g_strdup_printf ("%s (%s)",
					     soup_status_get_phrase (status_code),
					     uri->host);
		soup_message_set_status_full (item->msg, status_code, msg);
		g_free (msg);
	} else
		soup_message_set_status (item->msg, status_code);
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

		if (item->new_api && !item->async)
			soup_session_process_queue_item (item->session, item, NULL, TRUE);
	}
}

static guint
status_from_connect_error (SoupMessageQueueItem *item, GError *error)
{
	guint status;

	if (!error)
		return SOUP_STATUS_OK;

	if (error->domain == G_TLS_ERROR)
		status = SOUP_STATUS_SSL_FAILED;
	else if (error->domain == G_RESOLVER_ERROR)
		status = SOUP_STATUS_CANT_RESOLVE;
	else if (error->domain == G_IO_ERROR) {
		if (error->code == G_IO_ERROR_CANCELLED)
			status = SOUP_STATUS_CANCELLED;
		else if (error->code == G_IO_ERROR_HOST_UNREACHABLE ||
			 error->code == G_IO_ERROR_NETWORK_UNREACHABLE ||
			 error->code == G_IO_ERROR_CONNECTION_REFUSED)
			status = SOUP_STATUS_CANT_CONNECT;
		else if (error->code == G_IO_ERROR_PROXY_FAILED ||
			 error->code == G_IO_ERROR_PROXY_AUTH_FAILED ||
			 error->code == G_IO_ERROR_PROXY_NEED_AUTH ||
			 error->code == G_IO_ERROR_PROXY_NOT_ALLOWED)
			status = SOUP_STATUS_CANT_CONNECT_PROXY;
		else
			status = SOUP_STATUS_IO_ERROR;
	} else
		status = SOUP_STATUS_IO_ERROR;

	if (item->conn && soup_connection_is_via_proxy (item->conn))
		return soup_status_proxify (status);
	else
		return status;
}

static void
tunnel_complete (SoupMessageQueueItem *tunnel_item,
		 guint status, GError *error)
{
	SoupMessageQueueItem *item = tunnel_item->related;
	SoupSession *session = tunnel_item->session;

	soup_message_finished (tunnel_item->msg);
	soup_message_queue_item_unref (tunnel_item);

	if (item->msg->status_code)
		item->state = SOUP_MESSAGE_FINISHING;
	soup_message_set_https_status (item->msg, item->conn);

	item->error = error;
	if (!status)
		status = status_from_connect_error (item, error);
	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		soup_connection_disconnect (item->conn);
		soup_session_set_item_connection (session, item, NULL);
		if (!item->new_api || item->msg->status_code == 0)
			soup_session_set_item_status (session, item, status, error);
	}

	item->state = SOUP_MESSAGE_READY;
	if (item->async)
		soup_session_kick_queue (session);
	soup_message_queue_item_unref (item);
}

static void
tunnel_handshake_complete (GObject      *object,
			   GAsyncResult *result,
			   gpointer      user_data)
{
	SoupConnection *conn = SOUP_CONNECTION (object);
	SoupMessageQueueItem *tunnel_item = user_data;
	GError *error = NULL;

	soup_connection_start_ssl_finish (conn, result, &error);
	tunnel_complete (tunnel_item, 0, error);
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
						      tunnel_message_completed);
			return;
		}

		soup_message_set_status (msg, SOUP_STATUS_TRY_AGAIN);
	}

	tunnel_item->state = SOUP_MESSAGE_FINISHED;
	soup_session_unqueue_item (session, tunnel_item);

	status = tunnel_item->msg->status_code;
	if (!SOUP_STATUS_IS_SUCCESSFUL (status)) {
		tunnel_complete (tunnel_item, status, NULL);
		return;
	}

	if (tunnel_item->async) {
		soup_connection_start_ssl_async (item->conn, item->cancellable,
						 tunnel_handshake_complete,
						 tunnel_item);
	} else {
		GError *error = NULL;

		soup_connection_start_ssl_sync (item->conn, item->cancellable, &error);
		tunnel_complete (tunnel_item, 0, error);
	}
}

static void
tunnel_connect (SoupMessageQueueItem *item)
{
	SoupSession *session = item->session;
	SoupMessageQueueItem *tunnel_item;
	SoupURI *uri;
	SoupMessage *msg;

	item->state = SOUP_MESSAGE_TUNNELING;

	uri = soup_connection_get_remote_uri (item->conn);
	msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT, uri);
	soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);

	tunnel_item = soup_session_append_queue_item (session, msg,
						      item->async, FALSE,
						      NULL, NULL);
	g_object_unref (msg);
	tunnel_item->related = item;
	soup_message_queue_item_ref (item);
	soup_session_set_item_connection (session, tunnel_item, item->conn);
	tunnel_item->state = SOUP_MESSAGE_RUNNING;

	g_signal_emit (session, signals[TUNNELING], 0, tunnel_item->conn);

	soup_session_send_queue_item (session, tunnel_item,
				      tunnel_message_completed);
}

static void
connect_complete (SoupMessageQueueItem *item, SoupConnection *conn, GError *error)
{
	SoupSession *session = item->session;
	guint status;

	soup_message_set_https_status (item->msg, item->conn);

	if (!error) {
		item->state = SOUP_MESSAGE_CONNECTED;
		return;
	}

	item->error = error;
	status = status_from_connect_error (item, error);
	soup_connection_disconnect (conn);
	if (item->state == SOUP_MESSAGE_CONNECTING) {
		if (!item->new_api || item->msg->status_code == 0)
			soup_session_set_item_status (session, item, status, error);
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
			 gboolean ignore_connection_limits,
			 gboolean *try_cleanup,
			 gboolean *is_dedicated_connection)
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
	if (num_pending > host->num_messages / 2) {
		if (!ignore_connection_limits)
			return NULL;

		*is_dedicated_connection = TRUE;
	}

	if (host->num_conns >= priv->max_conns_per_host) {
		if (!ignore_connection_limits) {
			if (need_new_connection)
				*try_cleanup = TRUE;
			return NULL;
		}

		*is_dedicated_connection = TRUE;
	}

	if (priv->num_conns >= priv->max_conns) {
		if (!ignore_connection_limits) {
			*try_cleanup = TRUE;
			return NULL;
		}

		*is_dedicated_connection = TRUE;
	}

	ensure_socket_props (session);
	conn = g_object_new (SOUP_TYPE_CONNECTION,
			     SOUP_CONNECTION_REMOTE_URI, host->uri,
			     SOUP_CONNECTION_SSL, soup_uri_is_https (host->uri, priv->https_aliases),
			     SOUP_CONNECTION_SOCKET_PROPERTIES, priv->socket_props,
			     NULL);

	g_signal_connect (conn, "disconnected",
			  G_CALLBACK (connection_disconnected),
			  session);
	g_signal_connect (conn, "notify::state",
			  G_CALLBACK (connection_state_changed),
			  session);

	/* This is a debugging-related signal, and so can ignore the
	 * usual rule about not emitting signals while holding
	 * conn_lock.
	 */
	g_signal_emit (session, signals[CONNECTION_CREATED], 0, conn);

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
	gboolean ignore_connection_limits;
	gboolean is_dedicated_connection = FALSE;

	soup_session_cleanup_connections (session, FALSE);

	need_new_connection =
		(soup_message_get_flags (item->msg) & SOUP_MESSAGE_NEW_CONNECTION) ||
		(!(soup_message_get_flags (item->msg) & SOUP_MESSAGE_IDEMPOTENT) &&
		 !SOUP_METHOD_IS_IDEMPOTENT (item->msg->method));
	ignore_connection_limits =
		(soup_message_get_flags (item->msg) & SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS);

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_message (session, item->msg);
	while (TRUE) {
		conn = get_connection_for_host (session, item, host,
						need_new_connection,
						ignore_connection_limits,
						&my_should_cleanup,
						&is_dedicated_connection);
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
	item->conn_is_dedicated = is_dedicated_connection;

	if (soup_connection_get_state (item->conn) != SOUP_CONNECTION_NEW) {
		item->state = SOUP_MESSAGE_READY;
		soup_message_set_https_status (item->msg, item->conn);
		return TRUE;
	}

	item->state = SOUP_MESSAGE_CONNECTING;

	if (item->async) {
		soup_message_queue_item_ref (item);
		soup_connection_connect_async (item->conn, item->cancellable,
					       connect_async_complete, item);
		return FALSE;
	} else {
		GError *error = NULL;

		soup_connection_connect_sync (item->conn, item->cancellable, &error);
		connect_complete (item, conn, error);

		return TRUE;
	}
}

void
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

			if (item->msg->status_code) {
				if (item->msg->status_code == SOUP_STATUS_TRY_AGAIN) {
					soup_message_cleanup_response (item->msg);
					item->state = SOUP_MESSAGE_STARTING;
				} else
					item->state = SOUP_MESSAGE_FINISHING;
				break;
			}

			item->state = SOUP_MESSAGE_RUNNING;

			soup_session_send_queue_item (session, item, message_completed);

			if (item->new_api) {
				if (item->async)
					async_send_request_running (session, item);
				return;
			}
			break;

		case SOUP_MESSAGE_RUNNING:
			if (item->async)
				return;

			g_warn_if_fail (item->new_api);
			item->state = SOUP_MESSAGE_FINISHING;
			break;

		case SOUP_MESSAGE_CACHED:
			/* Will be handled elsewhere */
			return;

		case SOUP_MESSAGE_RESTARTING:
			item->state = SOUP_MESSAGE_STARTING;
			soup_message_restarted (item->msg);
			break;

		case SOUP_MESSAGE_FINISHING:
			item->state = SOUP_MESSAGE_FINISHED;
			soup_message_finished (item->msg);
			if (item->state != SOUP_MESSAGE_FINISHED) {
				g_return_if_fail (!item->new_api);
				break;
			}

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
		if (msg->method == SOUP_METHOD_CONNECT)
			continue;

		if (!item->async ||
		    item->async_context != soup_session_get_async_context (session))
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
 * SoupSessionCallback:
 * @session: the session
 * @msg: the message that has finished
 * @user_data: the data passed to soup_session_queue_message
 *
 * Prototype for the callback passed to soup_session_queue_message(),
 * qv.
 **/

static void
soup_session_real_queue_message (SoupSession *session, SoupMessage *msg,
				 SoupSessionCallback callback, gpointer user_data)
{
	SoupMessageQueueItem *item;

	item = soup_session_append_queue_item (session, msg, TRUE, FALSE,
					       callback, user_data);
	soup_session_kick_queue (session);
	soup_message_queue_item_unref (item);
}

/**
 * soup_session_queue_message:
 * @session: a #SoupSession
 * @msg: (transfer full): the message to queue
 * @callback: (allow-none) (scope async): a #SoupSessionCallback which will
 * be called after the message completes or when an unrecoverable error occurs.
 * @user_data: (allow-none): a pointer passed to @callback.
 * 
 * Queues the message @msg for asynchronously sending the request and
 * receiving a response in the current thread-default #GMainContext.
 * If @msg has been processed before, any resources related to the
 * time it was last sent are freed.
 *
 * Upon message completion, the callback specified in @callback will
 * be invoked. If after returning from this callback the message has not
 * been requeued, @msg will be unreffed.
 *
 * (The behavior above applies to a plain #SoupSession; if you are
 * using #SoupSessionAsync or #SoupSessionSync, then the #GMainContext
 * that is used depends on the settings of #SoupSession:async-context
 * and #SoupSession:use-thread-context, and for #SoupSessionSync, the
 * message will actually be sent and processed in another thread, with
 * only the final callback occurring in the indicated #GMainContext.)
 *
 * Contrast this method with soup_session_send_async(), which also
 * asynchronously sends a message, but returns before reading the
 * response body, and allows you to read the response via a
 * #GInputStream.
 */
void
soup_session_queue_message (SoupSession *session, SoupMessage *msg,
			    SoupSessionCallback callback, gpointer user_data)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_SESSION_GET_CLASS (session)->queue_message (session, msg,
							 callback, user_data);
	/* The SoupMessageQueueItem will hold a ref on @msg until it is
	 * finished, so we can drop the ref adopted from the caller now.
	 */
	g_object_unref (msg);
}

static void
soup_session_real_requeue_message (SoupSession *session, SoupMessage *msg)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;

	item = soup_message_queue_lookup (priv->queue, msg);
	g_return_if_fail (item != NULL);

	if (item->resend_count >= SOUP_SESSION_MAX_RESEND_COUNT) {
		if (SOUP_STATUS_IS_REDIRECTION (msg->status_code))
			soup_message_set_status (msg, SOUP_STATUS_TOO_MANY_REDIRECTS);
		else
			g_warning ("SoupMessage %p stuck in infinite loop?", msg);
	} else {
		item->resend_count++;
		item->state = SOUP_MESSAGE_RESTARTING;
	}

	soup_message_queue_item_unref (item);
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

static guint
soup_session_real_send_message (SoupSession *session, SoupMessage *msg)
{
	SoupMessageQueueItem *item;
	guint status;

	item = soup_session_append_queue_item (session, msg, FALSE, FALSE,
					       NULL, NULL);
	soup_session_process_queue_item (session, item, NULL, TRUE);
	status = msg->status_code;
	soup_message_queue_item_unref (item);
	return status;
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
 * Unlike with soup_session_queue_message(), @msg is not freed upon
 * return.
 *
 * (Note that if you call this method on a #SoupSessionAsync, it will
 * still use asynchronous I/O internally, running the glib main loop
 * to process the message, which may also cause other events to be
 * processed.)
 *
 * Contrast this method with soup_session_send(), which also
 * synchronously sends a message, but returns before reading the
 * response body, and allows you to read the response via a
 * #GInputStream.
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


/**
 * soup_session_pause_message:
 * @session: a #SoupSession
 * @msg: a #SoupMessage currently running on @session
 *
 * Pauses HTTP I/O on @msg. Call soup_session_unpause_message() to
 * resume I/O.
 *
 * This may only be called for asynchronous messages (those sent on a
 * #SoupSessionAsync or using soup_session_queue_message()).
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
soup_session_real_kick_queue (SoupSession *session)
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
			GMainContext *context = item->async_context ? item->async_context : g_main_context_default ();

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

void
soup_session_kick_queue (SoupSession *session)
{
	SOUP_SESSION_GET_CLASS (session)->kick (session);
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
 *
 * This may only be called for asynchronous messages (those sent on a
 * #SoupSessionAsync or using soup_session_queue_message()).
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


static void
soup_session_real_cancel_message (SoupSession *session, SoupMessage *msg, guint status_code)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;

	item = soup_message_queue_lookup (priv->queue, msg);
	g_return_if_fail (item != NULL);

	if (item->paused) {
		item->paused = FALSE;

		if (soup_message_io_in_progress (msg))
			soup_message_io_unpause (msg);
	}

	soup_message_set_status (msg, status_code);
	g_cancellable_cancel (item->cancellable);

	soup_session_kick_queue (item->session);
	soup_message_queue_item_unref (item);
}

/**
 * soup_session_cancel_message:
 * @session: a #SoupSession
 * @msg: the message to cancel
 * @status_code: status code to set on @msg (generally
 * %SOUP_STATUS_CANCELLED)
 *
 * Causes @session to immediately finish processing @msg (regardless
 * of its current state) with a final status_code of @status_code. You
 * may call this at any time after handing @msg off to @session; if
 * @session has started sending the request but has not yet received
 * the complete response, then it will close the request's connection.
 * Note that with requests that have side effects (eg,
 * <literal>POST</literal>, <literal>PUT</literal>,
 * <literal>DELETE</literal>) it is possible that you might cancel the
 * request after the server acts on it, but before it returns a
 * response, leaving the remote resource in an unknown state.
 *
 * If the message is cancelled while its response body is being read,
 * then the response body in @msg will be left partially-filled-in.
 * The response headers, on the other hand, will always be either
 * empty or complete.
 *
 * Beware that with the deprecated #SoupSessionAsync, messages queued
 * with soup_session_queue_message() will have their callbacks invoked
 * before soup_session_cancel_message() returns. The plain
 * #SoupSession does not have this behavior; cancelling an
 * asynchronous message will merely queue its callback to be run after
 * returning to the main loop.
 **/
void
soup_session_cancel_message (SoupSession *session, SoupMessage *msg,
			     guint status_code)
{
	SoupSessionPrivate *priv;
	SoupMessageQueueItem *item;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_session_get_instance_private (session);
	item = soup_message_queue_lookup (priv->queue, msg);
	/* If the message is already ending, don't do anything */
	if (!item)
		return;
	if (item->state == SOUP_MESSAGE_FINISHED) {
		soup_message_queue_item_unref (item);
		return;
	}

	SOUP_SESSION_GET_CLASS (session)->cancel_message (session, msg, status_code);
	soup_message_queue_item_unref (item);
}

static void
soup_session_real_flush_queue (SoupSession *session)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	GHashTable *current = NULL;
	gboolean done = FALSE;

	if (SOUP_IS_SESSION_SYNC (session)) {
		/* Record the current contents of the queue */
		current = g_hash_table_new (NULL, NULL);
		for (item = soup_message_queue_first (priv->queue);
		     item;
		     item = soup_message_queue_next (priv->queue, item))
			g_hash_table_insert (current, item, item);
	}

	/* Cancel everything */
	for (item = soup_message_queue_first (priv->queue);
	     item;
	     item = soup_message_queue_next (priv->queue, item)) {
		soup_session_cancel_message (session, item->msg,
					     SOUP_STATUS_CANCELLED);
	}

	if (SOUP_IS_SESSION_SYNC (session)) {
		/* Wait until all of the items in @current have been
		 * removed from the queue. (This is not the same as
		 * "wait for the queue to be empty", because the app
		 * may queue new requests in response to the
		 * cancellation of the old ones. We don't try to
		 * cancel those requests as well, since we'd likely
		 * just end up looping forever.)
		 */
		g_mutex_lock (&priv->conn_lock);
		do {
			done = TRUE;
			for (item = soup_message_queue_first (priv->queue);
			     item;
			     item = soup_message_queue_next (priv->queue, item)) {
				if (g_hash_table_lookup (current, item))
					done = FALSE;
			}

			if (!done)
				g_cond_wait (&priv->conn_cond, &priv->conn_lock);
		} while (!done);
		g_mutex_unlock (&priv->conn_lock);

		g_hash_table_destroy (current);
	}
}

/**
 * soup_session_abort:
 * @session: the session
 *
 * Cancels all pending requests in @session and closes all idle
 * persistent connections.
 *
 * The message cancellation has the same semantics as with
 * soup_session_cancel_message(); asynchronous requests on a
 * #SoupSessionAsync will have their callback called before
 * soup_session_abort() returns. Requests on a plain #SoupSession will
 * not.
 **/
void
soup_session_abort (SoupSession *session)
{
	SoupSessionPrivate *priv;
	GSList *conns, *c;
	GHashTableIter iter;
	gpointer conn, host;

	g_return_if_fail (SOUP_IS_SESSION (session));
	priv = soup_session_get_instance_private (session);

	SOUP_SESSION_GET_CLASS (session)->flush_queue (session);

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

static void
prefetch_uri (SoupSession *session, SoupURI *uri,
	      GCancellable *cancellable,
	      SoupAddressCallback callback, gpointer user_data)
{
	SoupSessionPrivate *priv;
	SoupSessionHost *host;
	SoupAddress *addr;

	priv = soup_session_get_instance_private (session);

	g_mutex_lock (&priv->conn_lock);
	host = get_host_for_uri (session, uri);
	addr = g_object_ref (host->addr);
	g_mutex_unlock (&priv->conn_lock);

	soup_address_resolve_async (addr,
				    soup_session_get_async_context (session),
				    cancellable, callback, user_data);
	g_object_unref (addr);
}

/**
 * soup_session_prepare_for_uri:
 * @session: a #SoupSession
 * @uri: a #SoupURI which may be required
 *
 * Tells @session that @uri may be requested shortly, and so the
 * session can try to prepare (resolving the domain name, obtaining
 * proxy address, etc.) in order to work more quickly once the URI is
 * actually requested.
 *
 * Since: 2.30
 *
 * Deprecated: 2.38: use soup_session_prefetch_dns() instead
 **/
void
soup_session_prepare_for_uri (SoupSession *session, SoupURI *uri)
{
	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (uri != NULL);

	if (!uri->host)
		return;

	prefetch_uri (session, uri, NULL, NULL, NULL);
}

/**
* soup_session_prefetch_dns:
* @session: a #SoupSession
* @hostname: a hostname to be resolved
* @cancellable: (allow-none): a #GCancellable object, or %NULL
* @callback: (scope async) (allow-none): callback to call with the
*     result, or %NULL
* @user_data: data for @callback
*
* Tells @session that an URI from the given @hostname may be requested
* shortly, and so the session can try to prepare by resolving the
* domain name in advance, in order to work more quickly once the URI
* is actually requested.
*
* If @cancellable is non-%NULL, it can be used to cancel the
* resolution. @callback will still be invoked in this case, with a
* status of %SOUP_STATUS_CANCELLED.
*
* Since: 2.38
**/
void
soup_session_prefetch_dns (SoupSession *session, const char *hostname,
			   GCancellable *cancellable,
			   SoupAddressCallback callback, gpointer user_data)
{
	SoupURI *uri;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (hostname != NULL);

	/* FIXME: Prefetching should work for both HTTP and HTTPS */
	uri = soup_uri_new (NULL);
	soup_uri_set_scheme (uri, SOUP_URI_SCHEME_HTTP);
	soup_uri_set_host (uri, hostname);
	soup_uri_set_path (uri, "");

	prefetch_uri (session, uri, cancellable, callback, user_data);
	soup_uri_free (uri);
}

/**
 * soup_session_add_feature:
 * @session: a #SoupSession
 * @feature: an object that implements #SoupSessionFeature
 *
 * Adds @feature's functionality to @session. You can also add a
 * feature to the session at construct time by using the
 * %SOUP_SESSION_ADD_FEATURE property.
 *
 * See the main #SoupSession documentation for information on what
 * features are present in sessions by default.
 *
 * Since: 2.24
 **/
void
soup_session_add_feature (SoupSession *session, SoupSessionFeature *feature)
{
	SoupSessionPrivate *priv;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (SOUP_IS_SESSION_FEATURE (feature));

	priv = soup_session_get_instance_private (session);

	G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
	if (SOUP_IS_PROXY_URI_RESOLVER (feature)) {
		set_proxy_resolver (session, NULL,
				    SOUP_PROXY_URI_RESOLVER (feature),
				    NULL);
	}
	G_GNUC_END_IGNORE_DEPRECATIONS;

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
 * a "subfeature". This can be used to add new #SoupAuth or
 * #SoupRequest types, for instance.
 *
 * You can also add a feature to the session at construct time by
 * using the %SOUP_SESSION_ADD_FEATURE_BY_TYPE property.
 *
 * See the main #SoupSession documentation for information on what
 * features are present in sessions by default.
 *
 * Since: 2.24
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
	} else if (g_type_is_a (feature_type, SOUP_TYPE_REQUEST)) {
		SoupRequestClass *request_class;
		int i;

		request_class = g_type_class_ref (feature_type);
		for (i = 0; request_class->schemes[i]; i++) {
			g_hash_table_insert (priv->request_types,
					     (char *)request_class->schemes[i],
					     GSIZE_TO_POINTER (feature_type));
		}
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
 * Since: 2.24
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

		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		if (SOUP_IS_PROXY_URI_RESOLVER (feature)) {
			if (SOUP_IS_PROXY_RESOLVER_WRAPPER (priv->proxy_resolver) &&
			    SOUP_PROXY_RESOLVER_WRAPPER (priv->proxy_resolver)->soup_resolver == SOUP_PROXY_URI_RESOLVER (feature))
				g_clear_object (&priv->proxy_resolver);
		}
		G_GNUC_END_IGNORE_DEPRECATIONS;

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
 * %SOUP_SESSION_REMOVE_FEATURE_BY_TYPE property.
 *
 * Since: 2.24
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
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		if (g_type_is_a (feature_type, SOUP_TYPE_PROXY_URI_RESOLVER))
			priv->proxy_use_default = FALSE;
		G_GNUC_END_IGNORE_DEPRECATIONS;
	} else if (g_type_is_a (feature_type, SOUP_TYPE_REQUEST)) {
		SoupRequestClass *request_class;
		int i;

		request_class = g_type_class_peek (feature_type);
		if (!request_class)
			return;
		for (i = 0; request_class->schemes[i]; i++) {
			g_hash_table_remove (priv->request_types,
					     request_class->schemes[i]);
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
 * some class managed by another feature, such as #SoupAuth or
 * #SoupRequest).
 *
 * Return value: %TRUE or %FALSE
 *
 * Since: 2.42
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
	} else if (g_type_is_a (feature_type, SOUP_TYPE_REQUEST)) {
		SoupRequestClass *request_class;
		int i;

		request_class = g_type_class_peek (feature_type);
		if (!request_class)
			return FALSE;

		for (i = 0; request_class->schemes[i]; i++) {
			gpointer type;

			type = g_hash_table_lookup (priv->request_types,
						    request_class->schemes[i]);
			if (type && g_type_is_a (GPOINTER_TO_SIZE (type), feature_type))
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
 * Return value: (transfer container) (element-type Soup.SessionFeature):
 * a list of features. You must free the list, but not its contents
 *
 * Since: 2.26
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
 * Return value: (nullable) (transfer none): a #SoupSessionFeature, or
 * %NULL. The feature is owned by @session.
 *
 * Since: 2.26
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
 * Return value: (nullable) (transfer none): a #SoupSessionFeature, or %NULL. The
 * feature is owned by @session.
 *
 * Since: 2.28
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

	/* virtual method definition */
	session_class->queue_message = soup_session_real_queue_message;
	session_class->send_message = soup_session_real_send_message;
	session_class->requeue_message = soup_session_real_requeue_message;
	session_class->cancel_message = soup_session_real_cancel_message;
	session_class->flush_queue = soup_session_real_flush_queue;
	session_class->kick = soup_session_real_kick_queue;

	/* virtual method override */
	object_class->constructor = soup_session_constructor;
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
	 * Emitted when a request is queued on @session. (Note that
	 * "queued" doesn't just mean soup_session_queue_message();
	 * soup_session_send_message() implicitly queues the message
	 * as well.)
	 *
	 * When sending a request, first #SoupSession::request_queued
	 * is emitted, indicating that the session has become aware of
	 * the request.
	 *
	 * Once a connection is available to send the request on, the
	 * session emits #SoupSession::request_started. Then, various
	 * #SoupMessage signals are emitted as the message is
	 * processed. If the message is requeued, it will emit
	 * #SoupMessage::restarted, which will then be followed by
	 * another #SoupSession::request_started and another set of
	 * #SoupMessage signals when the message is re-sent.
	 *
	 * Eventually, the message will emit #SoupMessage::finished.
	 * Normally, this signals the completion of message
	 * processing. However, it is possible that the application
	 * will requeue the message from the "finished" handler (or
	 * equivalently, from the soup_session_queue_message()
	 * callback). In that case, the process will loop back to
	 * #SoupSession::request_started.
	 *
	 * Eventually, a message will reach "finished" and not be
	 * requeued. At that point, the session will emit
	 * #SoupSession::request_unqueued to indicate that it is done
	 * with the message.
	 *
	 * To sum up: #SoupSession::request_queued and
	 * #SoupSession::request_unqueued are guaranteed to be emitted
	 * exactly once, but #SoupSession::request_started and
	 * #SoupMessage::finished (and all of the other #SoupMessage
	 * signals) may be invoked multiple times for a given message.
	 *
	 * Since: 2.24
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
	 * SoupSession::request-started:
	 * @session: the session
	 * @msg: the request being sent
	 * @socket: the socket the request is being sent on
	 *
	 * Emitted just before a request is sent. See
	 * #SoupSession::request_queued for a detailed description of
	 * the message lifecycle within a session.
	 *
	 * Deprecated: 2.50. Use #SoupMessage::starting instead.
	 **/
	signals[REQUEST_STARTED] =
		g_signal_new ("request-started",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSessionClass, request_started),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_SOCKET);

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
	 * Since: 2.24
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

	/**
	 * SoupSession::authenticate:
	 * @session: the session
	 * @msg: the #SoupMessage being sent
	 * @auth: the #SoupAuth to authenticate
	 * @retrying: %TRUE if this is the second (or later) attempt
	 *
	 * Emitted when the session requires authentication. If
	 * credentials are available call soup_auth_authenticate() on
	 * @auth. If these credentials fail, the signal will be
	 * emitted again, with @retrying set to %TRUE, which will
	 * continue until you return without calling
	 * soup_auth_authenticate() on @auth.
	 *
	 * Note that this may be emitted before @msg's body has been
	 * fully read.
	 *
	 * If you call soup_session_pause_message() on @msg before
	 * returning, then you can authenticate @auth asynchronously
	 * (as long as you g_object_ref() it to make sure it doesn't
	 * get destroyed), and then unpause @msg when you are ready
	 * for it to continue.
	 **/
	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupSessionClass, authenticate),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 3,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_AUTH,
			      G_TYPE_BOOLEAN);

	/**
	 * SoupSession::connection-created:
	 * @session: the #SoupSession
	 * @connection: the connection
	 *
	 * Emitted when a new connection is created. This is an
	 * internal signal intended only to be used for debugging
	 * purposes, and may go away in the future.
	 *
	 * Since: 2.30
	 */
	signals[CONNECTION_CREATED] =
		g_signal_new ("connection-created",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      /* SoupConnection is private, so we can't use
			       * SOUP_TYPE_CONNECTION here.
			       */
			      G_TYPE_OBJECT);

	/**
	 * SoupSession::tunneling:
	 * @session: the #SoupSession
	 * @connection: the connection
	 *
	 * Emitted when an SSL tunnel is being created on a proxy
	 * connection. This is an internal signal intended only to be
	 * used for debugging purposes, and may go away in the future.
	 *
	 * Since: 2.30
	 */
	signals[TUNNELING] =
		g_signal_new ("tunneling",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      /* SoupConnection is private, so we can't use
			       * SOUP_TYPE_CONNECTION here.
			       */
			      G_TYPE_OBJECT);


	/* properties */
	/**
	 * SoupSession:proxy-uri:
	 *
	 * A proxy to use for all http and https requests in this
	 * session. Setting this will clear the
	 * #SoupSession:proxy-resolver property, and remove any
	 * <type>SoupProxyURIResolver</type> features that have been
	 * added to the session. Setting this property will also
	 * cancel all currently pending messages.
	 *
	 * Note that #SoupSession will normally handle looking up the
	 * user's proxy settings for you; you should only use
	 * #SoupSession:proxy-uri if you need to override the user's
	 * normal proxy settings.
	 *
	 * Also note that this proxy will be used for
	 * <emphasis>all</emphasis> requests; even requests to
	 * <literal>localhost</literal>. If you need more control over
	 * proxies, you can create a #GSimpleProxyResolver and set the
	 * #SoupSession:proxy-resolver property.
	 *
	 * Deprecated: 2.70: Use SoupSession:proxy-resolver along with #GSimpleProxyResolver.
	 */
	/**
	 * SOUP_SESSION_PROXY_URI:
	 *
	 * Alias for the #SoupSession:proxy-uri property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_PROXY_URI,
		g_param_spec_boxed (SOUP_SESSION_PROXY_URI,
				    "Proxy URI",
				    "The HTTP Proxy to use for this session",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS |
				    G_PARAM_DEPRECATED));
	/**
	 * SoupSession:proxy-resolver:
	 *
	 * A #GProxyResolver to use with this session. Setting this
	 * will clear the #SoupSession:proxy-uri property, and remove
	 * any <type>SoupProxyURIResolver</type> features that have
	 * been added to the session.
	 *
	 * By default, in a plain #SoupSession, this is set to the
	 * default #GProxyResolver, but you can set it to %NULL if you
	 * don't want to use proxies, or set it to your own
	 * #GProxyResolver if you want to control what proxies get
	 * used.
	 *
	 * Since: 2.42
	 */
	/**
	 * SOUP_SESSION_PROXY_RESOLVER:
	 *
	 * Alias for the #SoupSession:proxy-resolver property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_PROXY_RESOLVER,
		g_param_spec_object (SOUP_SESSION_PROXY_RESOLVER,
				     "Proxy Resolver",
				     "The GProxyResolver to use for this session",
				     G_TYPE_PROXY_RESOLVER,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_MAX_CONNS:
	 *
	 * Alias for the #SoupSession:max-conns property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS,
		g_param_spec_int (SOUP_SESSION_MAX_CONNS,
				  "Max Connection Count",
				  "The maximum number of connections that the session can open at once",
				  1,
				  G_MAXINT,
				  SOUP_SESSION_MAX_CONNS_DEFAULT,
				  G_PARAM_READWRITE |
				  G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_MAX_CONNS_PER_HOST:
	 *
	 * Alias for the #SoupSession:max-conns-per-host property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_MAX_CONNS_PER_HOST,
		g_param_spec_int (SOUP_SESSION_MAX_CONNS_PER_HOST,
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
	 * Note that the default value of 60 seconds only applies to
	 * plain #SoupSessions. If you are using #SoupSessionAsync or
	 * #SoupSessionSync, the default value is 0 (meaning idle
	 * connections will never time out).
	 *
	 * Since: 2.24
	 **/
	/**
	 * SOUP_SESSION_IDLE_TIMEOUT:
	 *
	 * Alias for the #SoupSession:idle-timeout property, qv.
	 *
	 * Since: 2.24
	 **/
	g_object_class_install_property (
		object_class, PROP_IDLE_TIMEOUT,
		g_param_spec_uint (SOUP_SESSION_IDLE_TIMEOUT,
				   "Idle Timeout",
				   "Connection lifetime when idle",
				   0, G_MAXUINT, 60,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:use-ntlm:
	 *
	 * Whether or not to use NTLM authentication.
	 *
	 * Deprecated: use soup_session_add_feature_by_type() with
	 * #SOUP_TYPE_AUTH_NTLM.
	 **/
	/**
	 * SOUP_SESSION_USE_NTLM:
	 *
	 * Alias for the #SoupSession:use-ntlm property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_USE_NTLM,
		g_param_spec_boolean (SOUP_SESSION_USE_NTLM,
				      "Use NTLM",
				      "Whether or not to use NTLM authentication",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_DEPRECATED |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:ssl-ca-file:
	 *
	 * File containing SSL CA certificates.
	 *
	 * If the specified file does not exist or cannot be read,
	 * then libsoup will print a warning, and then behave as
	 * though it had read in a empty CA file, meaning that all SSL
	 * certificates will be considered invalid.
	 *
	 * Deprecated: use #SoupSession:ssl-use-system-ca-file, or
	 * else #SoupSession:tls-database with a #GTlsFileDatabase
	 * (which allows you to do explicit error handling).
	 **/
	/**
	 * SOUP_SESSION_SSL_CA_FILE:
	 *
	 * Alias for the #SoupSession:ssl-ca-file property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_SSL_CA_FILE,
		g_param_spec_string (SOUP_SESSION_SSL_CA_FILE,
				     "SSL CA file",
				     "File containing SSL CA certificates",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_DEPRECATED |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE:
	 *
	 * Alias for the #SoupSession:ssl-use-system-ca-file property,
	 * qv.
	 *
	 * Since: 2.38
	 **/
	/**
	 * SoupSession:ssl-use-system-ca-file:
	 *
	 * Setting this to %TRUE is equivalent to setting
	 * #SoupSession:tls-database to the default system CA database.
	 * (and likewise, setting #SoupSession:tls-database to the
	 * default database by hand will cause this property to
	 * become %TRUE).
	 *
	 * Setting this to %FALSE (when it was previously %TRUE) will
	 * clear the #SoupSession:tls-database field.
	 *
	 * See #SoupSession:ssl-strict for more information on how
	 * https certificate validation is handled.
	 *
	 * If you are using #SoupSessionAsync or
	 * #SoupSessionSync, on libsoup older than 2.74.0, the default value
	 * is %FALSE, for backward compatibility.
	 *
	 * Since: 2.38
	 **/
	g_object_class_install_property (
		object_class, PROP_SSL_USE_SYSTEM_CA_FILE,
		g_param_spec_boolean (SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE,
				      "Use system CA file",
				      "Use the system certificate database",
				      TRUE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_TLS_DATABASE:
	 *
	 * Alias for the #SoupSession:tls-database property, qv.
	 *
	 * Since: 2.38
	 **/
	/**
	 * SoupSession:tls-database:
	 *
	 * Sets the #GTlsDatabase to use for validating SSL/TLS
	 * certificates.
	 *
	 * Note that setting the #SoupSession:ssl-ca-file or
	 * #SoupSession:ssl-use-system-ca-file property will cause
	 * this property to be set to a #GTlsDatabase corresponding to
	 * the indicated file or system default.
	 *
	 * See #SoupSession:ssl-strict for more information on how
	 * https certificate validation is handled.
	 *
	 * If you are using a plain #SoupSession then
	 * #SoupSession:ssl-use-system-ca-file will be %TRUE by
	 * default, and so this property will be a copy of the system
	 * CA database. If you are using #SoupSessionAsync or
	 * #SoupSessionSync, on libsoup older than 2.74.0, this property
	 * will be %NULL by default.
	 *
	 * Since: 2.38
	 **/
	g_object_class_install_property (
		object_class, PROP_TLS_DATABASE,
		g_param_spec_object (SOUP_SESSION_TLS_DATABASE,
				     "TLS Database",
				     "TLS database to use",
				     G_TYPE_TLS_DATABASE,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_SSL_STRICT:
	 *
	 * Alias for the #SoupSession:ssl-strict property, qv.
	 *
	 * Since: 2.30
	 **/
	/**
	 * SoupSession:ssl-strict:
	 *
	 * Normally, if #SoupSession:tls-database is set (including if
	 * it was set via #SoupSession:ssl-use-system-ca-file or
	 * #SoupSession:ssl-ca-file), then libsoup will reject any
	 * certificate that is invalid (ie, expired) or that is not
	 * signed by one of the given CA certificates, and the
	 * #SoupMessage will fail with the status
	 * %SOUP_STATUS_SSL_FAILED.
	 *
	 * If you set #SoupSession:ssl-strict to %FALSE, then all
	 * certificates will be accepted, and you will need to call
	 * soup_message_get_https_status() to distinguish valid from
	 * invalid certificates. (This can be used, eg, if you want to
	 * accept invalid certificates after giving some sort of
	 * warning.)
	 *
	 * For a plain #SoupSession, if the session has no CA file or
	 * TLS database, and this property is %TRUE, then all
	 * certificates will be rejected. However, beware that the
	 * deprecated #SoupSession subclasses (#SoupSessionAsync and
	 * #SoupSessionSync) have the opposite behavior: if there is
	 * no CA file or TLS database, then all certificates are always
	 * accepted, and this property has no effect.
	 *
	 * Since: 2.30
	 */
	g_object_class_install_property (
		object_class, PROP_SSL_STRICT,
		g_param_spec_boolean (SOUP_SESSION_SSL_STRICT,
				      "Strictly validate SSL certificates",
				      "Whether certificate errors should be considered a connection error",
				      TRUE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:async-context:
	 *
	 * The #GMainContext that miscellaneous session-related
	 * asynchronous callbacks are invoked on. (Eg, setting
	 * #SoupSession:idle-timeout will add a timeout source on this
	 * context.)
	 *
	 * For a plain #SoupSession, this property is always set to
	 * the #GMainContext that is the thread-default at the time
	 * the session was created, and cannot be overridden. For the
	 * deprecated #SoupSession subclasses, the default value is
	 * %NULL, meaning to use the global default #GMainContext.
	 *
	 * If #SoupSession:use-thread-context is %FALSE, this context
	 * will also be used for asynchronous HTTP I/O.
	 */
	/**
	 * SOUP_SESSION_ASYNC_CONTEXT:
	 *
	 * Alias for the #SoupSession:async-context property, qv.
	 */
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_SESSION_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "The GMainContext to dispatch async I/O in",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				      G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SESSION_USE_THREAD_CONTEXT:
	 *
	 * Alias for the #SoupSession:use-thread-context property, qv.
	 *
	 * Since: 2.38
	 */
	/**
	 * SoupSession:use-thread-context:
	 *
	 * If %TRUE (which it always is on a plain #SoupSession),
	 * asynchronous HTTP requests in this session will run in
	 * whatever the thread-default #GMainContext is at the time
	 * they are started, rather than always occurring in
	 * #SoupSession:async-context.
	 *
	 * Since: 2.38
	 */
	g_object_class_install_property (
		object_class, PROP_USE_THREAD_CONTEXT,
		g_param_spec_boolean (SOUP_SESSION_USE_THREAD_CONTEXT,
				      "Use thread-default GMainContext",
				      "Whether to use thread-default main contexts",
				      FALSE,
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
	 * Note that the default value of 60 seconds only applies to
	 * plain #SoupSessions. If you are using #SoupSessionAsync or
	 * #SoupSessionSync, the default value is 0 (meaning socket I/O
	 * will not time out).
	 *
	 * Not to be confused with #SoupSession:idle-timeout (which is
	 * the length of time that idle persistent connections will be
	 * kept open).
	 */
	/**
	 * SOUP_SESSION_TIMEOUT:
	 *
	 * Alias for the #SoupSession:timeout property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_TIMEOUT,
		g_param_spec_uint (SOUP_SESSION_TIMEOUT,
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
	/**
	 * SOUP_SESSION_USER_AGENT:
	 *
	 * Alias for the #SoupSession:user-agent property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_USER_AGENT,
		g_param_spec_string (SOUP_SESSION_USER_AGENT,
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
	 * Since: 2.30
	 **/
	/**
	 * SOUP_SESSION_ACCEPT_LANGUAGE:
	 *
	 * Alias for the #SoupSession:accept-language property, qv.
	 *
	 * Since: 2.30
	 **/
	g_object_class_install_property (
		object_class, PROP_ACCEPT_LANGUAGE,
		g_param_spec_string (SOUP_SESSION_ACCEPT_LANGUAGE,
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
	 * Since: 2.30
	 **/
	/**
	 * SOUP_SESSION_ACCEPT_LANGUAGE_AUTO:
	 *
	 * Alias for the #SoupSession:accept-language-auto property, qv.
	 *
	 * Since: 2.30
	 **/
	g_object_class_install_property (
		object_class, PROP_ACCEPT_LANGUAGE_AUTO,
		g_param_spec_boolean (SOUP_SESSION_ACCEPT_LANGUAGE_AUTO,
				      "Accept-Language automatic mode",
				      "Accept-Language automatic mode",
				      FALSE,
				      G_PARAM_READWRITE |
				      G_PARAM_STATIC_STRINGS));

	/**
	 * SoupSession:add-feature: (skip)
	 *
	 * Add a feature object to the session. (Shortcut for calling
	 * soup_session_add_feature().)
	 *
	 * Since: 2.24
	 **/
	/**
	 * SOUP_SESSION_ADD_FEATURE: (skip)
	 *
	 * Alias for the #SoupSession:add-feature property, qv.
	 *
	 * Since: 2.24
	 **/
	g_object_class_install_property (
		object_class, PROP_ADD_FEATURE,
		g_param_spec_object (SOUP_SESSION_ADD_FEATURE,
				     "Add Feature",
				     "Add a feature object to the session",
				     SOUP_TYPE_SESSION_FEATURE,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:add-feature-by-type: (skip)
	 *
	 * Add a feature object of the given type to the session.
	 * (Shortcut for calling soup_session_add_feature_by_type().)
	 *
	 * Since: 2.24
	 **/
	/**
	 * SOUP_SESSION_ADD_FEATURE_BY_TYPE: (skip)
	 *
	 * Alias for the #SoupSession:add-feature-by-type property, qv.
	 *
	 * Since: 2.24
	 **/
	g_object_class_install_property (
		object_class, PROP_ADD_FEATURE_BY_TYPE,
		g_param_spec_gtype (SOUP_SESSION_ADD_FEATURE_BY_TYPE,
				    "Add Feature By Type",
				    "Add a feature object of the given type to the session",
				    G_TYPE_OBJECT,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:remove-feature-by-type: (skip)
	 *
	 * Remove feature objects from the session. (Shortcut for
	 * calling soup_session_remove_feature_by_type().)
	 *
	 * Since: 2.24
	 **/
	/**
	 * SOUP_SESSION_REMOVE_FEATURE_BY_TYPE: (skip)
	 *
	 * Alias for the #SoupSession:remove-feature-by-type property,
	 * qv.
	 *
	 * Since: 2.24
	 **/
	g_object_class_install_property (
		object_class, PROP_REMOVE_FEATURE_BY_TYPE,
		g_param_spec_gtype (SOUP_SESSION_REMOVE_FEATURE_BY_TYPE,
				    "Remove Feature By Type",
				    "Remove features of the given type from the session",
				    G_TYPE_OBJECT,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:http-aliases:
	 *
	 * A %NULL-terminated array of URI schemes that should be
	 * considered to be aliases for "http". Eg, if this included
	 * <literal>"dav"</literal>, than a URI of
	 * <literal>dav://example.com/path</literal> would be treated
	 * identically to <literal>http://example.com/path</literal>.
	 *
	 * In a plain #SoupSession, the default value is %NULL,
	 * meaning that only "http" is recognized as meaning "http".
	 * In #SoupSessionAsync and #SoupSessionSync, for backward
	 * compatibility, the default value is an array containing the
	 * single element <literal>"*"</literal>, a special value
	 * which means that any scheme except "https" is considered to
	 * be an alias for "http".
	 *
	 * See also #SoupSession:https-aliases.
	 *
	 * Since: 2.38
	 */
	/**
	 * SOUP_SESSION_HTTP_ALIASES:
	 *
	 * Alias for the #SoupSession:http-aliases property, qv.
	 *
	 * Since: 2.38
	 */
	g_object_class_install_property (
		object_class, PROP_HTTP_ALIASES,
		g_param_spec_boxed (SOUP_SESSION_HTTP_ALIASES,
				    "http aliases",
				    "URI schemes that are considered aliases for 'http'",
				    G_TYPE_STRV,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 * SoupSession:https-aliases:
	 *
	 * A comma-delimited list of URI schemes that should be
	 * considered to be aliases for "https". See
	 * #SoupSession:http-aliases for more information.
	 *
	 * The default value is %NULL, meaning that no URI schemes
	 * are considered aliases for "https".
	 *
	 * Since: 2.38
	 */
	/**
	 * SOUP_SESSION_HTTPS_ALIASES:
	 *
	 * Alias for the #SoupSession:https-aliases property, qv.
	 *
	 * Since: 2.38
	 **/
	g_object_class_install_property (
		object_class, PROP_HTTPS_ALIASES,
		g_param_spec_boxed (SOUP_SESSION_HTTPS_ALIASES,
				    "https aliases",
				    "URI schemes that are considered aliases for 'https'",
				    G_TYPE_STRV,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));

	/**
	 * SOUP_SESSION_LOCAL_ADDRESS:
	 *
	 * Alias for the #SoupSession:local-address property, qv.
	 *
	 * Since: 2.42
	 **/
	/**
	 * SoupSession:local-address:
	 *
	 * Sets the #SoupAddress to use for the client side of
	 * the connection.
	 *
	 * Use this property if you want for instance to bind the
	 * local socket to a specific IP address.
	 *
	 * Since: 2.42
	 **/
	g_object_class_install_property (
		object_class, PROP_LOCAL_ADDRESS,
		g_param_spec_object (SOUP_SESSION_LOCAL_ADDRESS,
				     "Local address",
				     "Address of local end of socket",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));

	/**
	 * SOUP_SESSION_TLS_INTERACTION:
	 *
	 * Alias for the #SoupSession:tls-interaction property, qv.
	 *
	 * Since: 2.48
	 **/
	/**
	 * SoupSession:tls-interaction:
	 *
	 * A #GTlsInteraction object that will be passed on to any
	 * #GTlsConnections created by the session. (This can be used to
	 * provide client-side certificates, for example.)
	 *
	 * Since: 2.48
	 **/
	g_object_class_install_property (
		object_class, PROP_TLS_INTERACTION,
		g_param_spec_object (SOUP_SESSION_TLS_INTERACTION,
				     "TLS Interaction",
				     "TLS interaction to use",
				     G_TYPE_TLS_INTERACTION,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
}


static gboolean
expected_to_be_requeued (SoupSession *session, SoupMessage *msg)
{
	if (msg->status_code == SOUP_STATUS_UNAUTHORIZED ||
	    msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		SoupSessionFeature *feature =
			soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER);
		return !feature || !soup_message_disables_feature (msg, feature);
	}

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_NO_REDIRECT))
		return soup_session_would_redirect (session, msg);

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

	if (item->io_source) {
		g_source_destroy (item->io_source);
		g_clear_pointer (&item->io_source, g_source_unref);
	}

	if (error)
		g_task_return_error (task, error);
	else if (item->error) {
		if (stream)
			g_object_unref (stream);
		g_task_return_error (task, g_error_copy (item->error));
	} else if (SOUP_STATUS_IS_TRANSPORT_ERROR (item->msg->status_code)) {
		if (stream)
			g_object_unref (stream);
		g_task_return_new_error (task, SOUP_HTTP_ERROR,
					 item->msg->status_code,
					 "%s",
					 item->msg->reason_phrase);
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
					      G_PRIORITY_DEFAULT,
					      item->cancellable,
					      send_async_spliced, item);
		return;
	}

	async_send_request_return_result (item, stream, NULL);
}

static void try_run_until_read (SoupMessageQueueItem *item);

static gboolean
read_ready_cb (SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;

	g_clear_pointer (&item->io_source, g_source_unref);
	try_run_until_read (item);
	return FALSE;
}

static void
try_run_until_read (SoupMessageQueueItem *item)
{
	GError *error = NULL;
	GInputStream *stream = NULL;

	if (soup_message_io_run_until_read (item->msg, FALSE, item->cancellable, &error))
		stream = soup_message_io_get_response_istream (item->msg, &error);
	if (stream) {
		send_async_maybe_complete (item, stream);
		return;
	}

	if (g_error_matches (error, SOUP_HTTP_ERROR, SOUP_STATUS_TRY_AGAIN)) {
		item->state = SOUP_MESSAGE_RESTARTING;
		soup_message_io_finished (item->msg);
		g_error_free (error);
		return;
	}

	if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
		if (item->state != SOUP_MESSAGE_FINISHED) {
			if (soup_message_io_in_progress (item->msg))
				soup_message_io_finished (item->msg);
			item->state = SOUP_MESSAGE_FINISHING;
			soup_session_process_queue_item (item->session, item, NULL, FALSE);
		}
		async_send_request_return_result (item, NULL, error);
		return;
	}

	g_clear_error (&error);
	item->io_source = soup_message_io_get_source (item->msg, item->cancellable,
						      read_ready_cb, item);
	g_source_attach (item->io_source, soup_session_get_async_context (item->session));
}

static void
async_send_request_running (SoupSession *session, SoupMessageQueueItem *item)
{
	item->io_started = TRUE;
	try_run_until_read (item);
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

	content_type = soup_message_headers_get_content_type (item->msg->response_headers, &params);
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
} AsyncCacheCancelData;


static void
free_async_cache_cancel_data (AsyncCacheCancelData *data)
{
	g_object_unref (data->conditional_msg);
	g_object_unref (data->cache);
	g_slice_free (AsyncCacheCancelData, data);
}

static void
cancel_cache_response (SoupMessageQueueItem *item)
{
	item->paused = FALSE;
	item->state = SOUP_MESSAGE_FINISHING;
	soup_message_set_status (item->msg, SOUP_STATUS_CANCELLED);
	soup_session_kick_queue (item->session);
}

static void
conditional_request_cancelled_cb (GCancellable *cancellable, AsyncCacheCancelData *data)
{
	soup_cache_cancel_conditional_request (data->cache, data->conditional_msg);
}

static void
conditional_get_ready_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	SoupMessageQueueItem *item = user_data;
	GInputStream *stream;
	SoupCache *cache;

	if (g_cancellable_is_cancelled (item->cancellable)) {
		cancel_cache_response (item);
		return;
	} else {
		gulong handler_id = GPOINTER_TO_SIZE (g_object_get_data (G_OBJECT (msg), "SoupSession:handler-id"));
		g_cancellable_disconnect (item->cancellable, handler_id);
	}

	cache = (SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE);
	soup_cache_update_from_conditional_request (cache, msg);

	if (msg->status_code == SOUP_STATUS_NOT_MODIFIED) {
		stream = soup_cache_send_response (cache, item->msg);
		if (stream) {
			async_return_from_cache (item, stream);
			g_object_unref (stream);
			return;
		}
	}

	/* The resource was modified or the server returned a 200
	 * OK. Either way we reload it. FIXME.
	 */
	item->state = SOUP_MESSAGE_STARTING;
	soup_session_kick_queue (session);
}

static gboolean
idle_return_from_cache_cb (gpointer data)
{
	GTask *task = data;
	SoupMessageQueueItem *item = g_task_get_task_data (task);
	GInputStream *istream;

	if (item->state == SOUP_MESSAGE_FINISHED) {
		/* The original request was cancelled using
		 * soup_session_cancel_message () so it has been
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
		AsyncCacheCancelData *data;
		gulong handler_id;

		conditional_msg = soup_cache_generate_conditional_request (cache, item->msg);
		if (!conditional_msg)
			return FALSE;

		/* Detect any quick cancellation before the cache is able to return data. */
		data = g_slice_new0 (AsyncCacheCancelData);
		data->cache = g_object_ref (cache);
		data->conditional_msg = g_object_ref (conditional_msg);
		handler_id = g_cancellable_connect (item->cancellable, G_CALLBACK (conditional_request_cancelled_cb),
						    data, (GDestroyNotify) free_async_cache_cancel_data);

		g_object_set_data (G_OBJECT (conditional_msg), "SoupSession:handler-id",
				   GSIZE_TO_POINTER (handler_id));
		soup_session_queue_message (session, conditional_msg,
					    conditional_get_ready_cb,
					    item);


		return TRUE;
	} else
		return FALSE;
}

static void
cancel_cancellable (G_GNUC_UNUSED GCancellable *cancellable, GCancellable *chained_cancellable)
{
	g_cancellable_cancel (chained_cancellable);
}

/**
 * soup_session_send_async:
 * @session: a #SoupSession
 * @msg: a #SoupMessage
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
 * Contrast this method with soup_session_queue_message(), which also
 * asynchronously sends a #SoupMessage, but doesn't invoke its
 * callback until the response has been completely read.
 *
 * (Note that this method cannot be called on the deprecated
 * #SoupSessionSync subclass, and can only be called on
 * #SoupSessionAsync if you have set the
 * #SoupSession:use-thread-context property.)
 *
 * Since: 2.42
 */
void
soup_session_send_async (SoupSession         *session,
			 SoupMessage         *msg,
			 GCancellable        *cancellable,
			 GAsyncReadyCallback  callback,
			 gpointer             user_data)
{
	SoupMessageQueueItem *item;
	gboolean use_thread_context;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (!SOUP_IS_SESSION_SYNC (session));

	g_object_get (G_OBJECT (session),
		      SOUP_SESSION_USE_THREAD_CONTEXT, &use_thread_context,
		      NULL);
	g_return_if_fail (use_thread_context);

	item = soup_session_append_queue_item (session, msg, TRUE, TRUE,
					       NULL, NULL);
	g_signal_connect (msg, "restarted",
			  G_CALLBACK (async_send_request_restarted), item);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (async_send_request_finished), item);

	if (cancellable) {
		g_cancellable_connect (cancellable, G_CALLBACK (cancel_cancellable),
				       g_object_ref (item->cancellable),
				       (GDestroyNotify) g_object_unref);
	}

	item->new_api = TRUE;
	item->task = g_task_new (session, item->cancellable, callback, user_data);
	g_task_set_task_data (item->task, item, (GDestroyNotify) soup_message_queue_item_unref);

	/* Do not check for cancellations as we do not want to
	 * overwrite custom error messages set during cancellations
	 * (for example SOUP_HTTP_ERROR is set for cancelled messages
	 * in async_send_request_return_result() (status_code==1
	 * means CANCEL and is considered a TRANSPORT_ERROR)).
	 */
	g_task_set_check_cancellable (item->task, FALSE);

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
 * Return value: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
 *
 * Since: 2.42
 */
GInputStream *
soup_session_send_finish (SoupSession   *session,
			  GAsyncResult  *result,
			  GError       **error)
{
	GTask *task;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
	g_return_val_if_fail (!SOUP_IS_SESSION_SYNC (session), NULL);
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
 * Contrast this method with soup_session_send_message(), which also
 * synchronously sends a #SoupMessage, but doesn't return until the
 * response has been completely read.
 *
 * (Note that this method cannot be called on the deprecated
 * #SoupSessionAsync subclass.)
 *
 * Return value: (transfer full): a #GInputStream for reading the
 *   response body, or %NULL on error.
 *
 * Since: 2.42
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
	g_return_val_if_fail (!SOUP_IS_SESSION_ASYNC (session), NULL);

	item = soup_session_append_queue_item (session, msg, FALSE, TRUE,
					       NULL, NULL);

	item->new_api = TRUE;
	if (cancellable) {
		g_cancellable_connect (cancellable, G_CALLBACK (cancel_cancellable),
				       g_object_ref (item->cancellable),
				       (GDestroyNotify) g_object_unref);
	}

	while (!stream) {
		/* Get a connection, etc */
		soup_session_process_queue_item (session, item, NULL, TRUE);
		if (item->state != SOUP_MESSAGE_RUNNING)
			break;

		/* Send request, read headers */
		if (!soup_message_io_run_until_read (msg, TRUE, item->cancellable, &my_error)) {
			if (g_error_matches (my_error, SOUP_HTTP_ERROR, SOUP_STATUS_TRY_AGAIN)) {
				item->state = SOUP_MESSAGE_RESTARTING;
				soup_message_io_finished (item->msg);
				g_clear_error (&my_error);
				continue;
			} else
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
	} else if (SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code)) {
		g_clear_object (&stream);
		g_set_error_literal (error, SOUP_HTTP_ERROR, msg->status_code,
				     msg->reason_phrase);
	} else if (!stream)
		stream = g_memory_input_stream_new ();

	if (!stream) {
		if (soup_message_io_in_progress (msg))
			soup_message_io_finished (msg);
		else if (item->state != SOUP_MESSAGE_FINISHED)
			item->state = SOUP_MESSAGE_FINISHING;

		if (item->state != SOUP_MESSAGE_FINISHED)
			soup_session_process_queue_item (session, item, NULL, TRUE);
	}

	soup_message_queue_item_unref (item);
	return stream;
}

/**
 * soup_session_request:
 * @session: a #SoupSession
 * @uri_string: a URI, in string form
 * @error: return location for a #GError, or %NULL
 *
 * Creates a #SoupRequest for retrieving @uri_string.
 *
 * Return value: (transfer full): a new #SoupRequest, or
 *   %NULL on error.
 *
 * Since: 2.42
 */
SoupRequest *
soup_session_request (SoupSession *session, const char *uri_string,
		      GError **error)
{
	SoupURI *uri;
	SoupRequest *req;

	uri = soup_uri_new (uri_string);
	if (!uri) {
		g_set_error (error, SOUP_REQUEST_ERROR,
			     SOUP_REQUEST_ERROR_BAD_URI,
			     _("Could not parse URI “%s”"), uri_string);
		return NULL;
	}

	req = soup_session_request_uri (session, uri, error);
	soup_uri_free (uri);
	return req;
}

/**
 * soup_session_request_uri:
 * @session: a #SoupSession
 * @uri: a #SoupURI representing the URI to retrieve
 * @error: return location for a #GError, or %NULL
 *
 * Creates a #SoupRequest for retrieving @uri.
 *
 * Return value: (transfer full): a new #SoupRequest, or
 *   %NULL on error.
 *
 * Since: 2.42
 */
SoupRequest *
soup_session_request_uri (SoupSession *session, SoupURI *uri,
			  GError **error)
{
	SoupSessionPrivate *priv;
	GType request_type;

	g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);

	priv = soup_session_get_instance_private (session);

	request_type = (GType)GPOINTER_TO_SIZE (g_hash_table_lookup (priv->request_types, uri->scheme));
	if (!request_type) {
		g_set_error (error, SOUP_REQUEST_ERROR,
			     SOUP_REQUEST_ERROR_UNSUPPORTED_URI_SCHEME,
			     _("Unsupported URI scheme “%s”"), uri->scheme);
		return NULL;
	}

	return g_initable_new (request_type, NULL, error,
			       "uri", uri,
			       "session", session,
			       NULL);
}

static SoupRequestHTTP *
initialize_http_request (SoupRequest  *req,
			 const char   *method,
			 GError      **error)
{
	SoupRequestHTTP *http;
	SoupMessage *msg;

	if (!SOUP_IS_REQUEST_HTTP (req)) {
		g_object_unref (req);
		g_set_error (error, SOUP_REQUEST_ERROR,
			     SOUP_REQUEST_ERROR_BAD_URI,
			     _("Not an HTTP URI"));
		return NULL;
	}

	http = SOUP_REQUEST_HTTP (req);
	msg = soup_request_http_get_message (http);
	g_object_set (G_OBJECT (msg),
		      SOUP_MESSAGE_METHOD, method,
		      NULL);
	g_object_unref (msg);

	return http;
}

/**
 * soup_session_request_http:
 * @session: a #SoupSession
 * @method: an HTTP method
 * @uri_string: a URI, in string form
 * @error: return location for a #GError, or %NULL
 *
 * Creates a #SoupRequest for retrieving @uri_string, which must be an
 * "http" or "https" URI (or another protocol listed in @session's
 * #SoupSession:http-aliases or #SoupSession:https-aliases).
 *
 * Return value: (transfer full): a new #SoupRequestHTTP, or
 *   %NULL on error.
 *
 * Since: 2.42
 */
SoupRequestHTTP *
soup_session_request_http (SoupSession  *session,
			   const char   *method,
			   const char   *uri_string,
			   GError      **error)
{
	SoupRequest *req;

	req = soup_session_request (session, uri_string, error);
	if (!req)
		return NULL;

	return initialize_http_request (req, method, error);
}

/**
 * soup_session_request_http_uri:
 * @session: a #SoupSession
 * @method: an HTTP method
 * @uri: a #SoupURI representing the URI to retrieve
 * @error: return location for a #GError, or %NULL
 *
 * Creates a #SoupRequest for retrieving @uri, which must be an
 * "http" or "https" URI (or another protocol listed in @session's
 * #SoupSession:http-aliases or #SoupSession:https-aliases).
 *
 * Return value: (transfer full): a new #SoupRequestHTTP, or
 *   %NULL on error.
 *
 * Since: 2.42
 */
SoupRequestHTTP *
soup_session_request_http_uri (SoupSession  *session,
			       const char   *method,
			       SoupURI      *uri,
			       GError      **error)
{
	SoupRequest *req;

	req = soup_session_request_uri (session, uri, error);
	if (!req)
		return NULL;

	return initialize_http_request (req, method, error);
}

/**
 * SOUP_REQUEST_ERROR:
 *
 * A #GError domain for #SoupRequest<!-- -->-related errors. Used with
 * #SoupRequestError.
 *
 * Since: 2.42
 */
/**
 * SoupRequestError:
 * @SOUP_REQUEST_ERROR_BAD_URI: the URI could not be parsed
 * @SOUP_REQUEST_ERROR_UNSUPPORTED_URI_SCHEME: the URI scheme is not
 *   supported by this #SoupSession
 * @SOUP_REQUEST_ERROR_PARSING: the server's response could not
 *   be parsed
 * @SOUP_REQUEST_ERROR_ENCODING: the server's response was in an
 *   unsupported format
 *
 * A #SoupRequest error.
 *
 * Since: 2.42
 */

GQuark
soup_request_error_quark (void)
{
	static GQuark error;
	if (!error)
		error = g_quark_from_static_string ("soup_request_error_quark");
	return error;
}

static GIOStream *
steal_connection (SoupSession          *session,
                  SoupMessageQueueItem *item)
{
        SoupSessionPrivate *priv = soup_session_get_instance_private (session);
        SoupConnection *conn;
        SoupSocket *sock;
        SoupSessionHost *host;
        GIOStream *stream;

        conn = g_object_ref (item->conn);
        soup_session_set_item_connection (session, item, NULL);

        g_mutex_lock (&priv->conn_lock);
        host = get_host_for_message (session, item->msg);
        g_hash_table_remove (priv->conns, conn);
        drop_connection (session, host, conn);
        g_mutex_unlock (&priv->conn_lock);

        sock = soup_connection_get_socket (conn);
        g_object_set (sock,
                      SOUP_SOCKET_TIMEOUT, 0,
                      NULL);

	if (item->connect_only)
		stream = g_object_ref (soup_socket_get_connection (sock));
	else
		stream = soup_message_io_steal (item->msg);
        g_object_set_data_full (G_OBJECT (stream), "GSocket",
                                soup_socket_steal_gsocket (sock),
                                g_object_unref);
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
 * Return value: (transfer full): the #GIOStream formerly associated
 *   with @msg (or %NULL if @msg was no longer associated with a
 *   connection). No guarantees are made about what kind of #GIOStream
 *   is returned.
 *
 * Since: 2.50
 **/
GIOStream *
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

	/* Disconnect websocket_connect_async_stop() handler. */
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, task);

	g_task_return_new_error (task,
				 SOUP_WEBSOCKET_ERROR, SOUP_WEBSOCKET_ERROR_NOT_WEBSOCKET,
				 "%s", _("The server did not accept the WebSocket handshake."));
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
	if (soup_websocket_client_verify_handshake_with_extensions (item->msg, supported_extensions, &accepted_extensions, &error)) {
		stream = soup_session_steal_connection (item->session, item->msg);
		client = soup_websocket_connection_new_with_extensions (stream,
									soup_message_get_uri (item->msg),
									SOUP_WEBSOCKET_CONNECTION_CLIENT,
									soup_message_headers_get_one (msg->request_headers, "Origin"),
									soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol"),
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
 * Since: 2.50
 */
void
soup_session_websocket_connect_async (SoupSession          *session,
				      SoupMessage          *msg,
				      const char           *origin,
				      char                **protocols,
				      GCancellable         *cancellable,
				      GAsyncReadyCallback   callback,
				      gpointer              user_data)
{
	SoupSessionPrivate *priv = soup_session_get_instance_private (session);
	SoupMessageQueueItem *item;
	GTask *task;
	GPtrArray *supported_extensions;
	SoupMessageFlags flags;

	g_return_if_fail (SOUP_IS_SESSION (session));
	g_return_if_fail (priv->use_thread_context);
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	supported_extensions = soup_session_get_supported_websocket_extensions_for_message (session, msg);
	soup_websocket_client_prepare_handshake_with_extensions (msg, origin, protocols, supported_extensions);

	/* When the client is to _Establish a WebSocket Connection_ given a set
	 * of (/host/, /port/, /resource name/, and /secure/ flag), along with a
	 * list of /protocols/ and /extensions/ to be used, and an /origin/ in
	 * the case of web browsers, it MUST open a connection, send an opening
	 * handshake, and read the server's handshake in response.
	 */
	flags = soup_message_get_flags (msg);
	soup_message_set_flags (msg, flags | SOUP_MESSAGE_NEW_CONNECTION);

	task = g_task_new (session, cancellable, callback, user_data);
	item = soup_session_append_queue_item (session, msg, TRUE, FALSE,
					       websocket_connect_async_complete, task);
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
 * Return value: (transfer full): a new #SoupWebsocketConnection, or
 *   %NULL on error.
 *
 * Since: 2.50
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

/**
 * SoupSessionConnectProgressCallback:
 * @session: the #SoupSession
 * @event: a #GSocketClientEvent
 * @connection: the current state of the network connection
 * @user_data: the data passed to soup_session_connect_async().
 *
 * Prototype for the progress callback passed to soup_session_connect_async().
 *
 * Since: 2.62
 */

typedef struct {
        SoupMessageQueueItem *item;
        SoupSessionConnectProgressCallback progress_callback;
        gpointer user_data;
} ConnectAsyncData;

static ConnectAsyncData *
connect_async_data_new (SoupMessageQueueItem              *item,
                        SoupSessionConnectProgressCallback progress_callback,
                        gpointer                           user_data)
{
        ConnectAsyncData *data;

        soup_message_queue_item_ref (item);

        data = g_slice_new (ConnectAsyncData);
        data->item = item;
        data->progress_callback = progress_callback;
        data->user_data = user_data;

        return data;
}

static void
connect_async_data_free (ConnectAsyncData *data)
{
        soup_message_queue_item_unref (data->item);

        g_slice_free (ConnectAsyncData, data);
}

static void
connect_async_message_network_event (SoupMessage        *msg,
                                     GSocketClientEvent  event,
                                     GIOStream          *connection,
                                     GTask              *task)
{
        ConnectAsyncData *data = g_task_get_task_data (task);

        if (data->progress_callback)
                data->progress_callback (data->item->session, event, connection, data->user_data);
}

static void
connect_async_message_finished (SoupMessage *msg,
                                GTask       *task)
{
        ConnectAsyncData *data = g_task_get_task_data (task);
        SoupMessageQueueItem *item = data->item;

        if (!item->conn || item->error) {
                g_task_return_error (task, g_error_copy (item->error));
        } else {
                g_task_return_pointer (task,
                                       steal_connection (item->session, item),
                                       g_object_unref);
        }
        g_object_unref (task);
}

/**
 * soup_session_connect_async:
 * @session: a #SoupSession
 * @uri: a #SoupURI to connect to
 * @cancellable: a #GCancellable
 * @progress_callback: (allow-none) (scope async): a #SoupSessionConnectProgressCallback which
 * will be called for every network event that occurs during the connection.
 * @callback: (allow-none) (scope async): the callback to invoke when the operation finishes
 * @user_data: data for @progress_callback and @callback
 *
 * Start a connection to @uri. The operation can be monitored by providing a @progress_callback
 * and finishes when the connection is done or an error ocurred.
 *
 * Call soup_session_connect_finish() to get the #GIOStream to communicate with the server.
 *
 * Since: 2.62
 */
void
soup_session_connect_async (SoupSession                       *session,
                            SoupURI                           *uri,
                            GCancellable                      *cancellable,
                            SoupSessionConnectProgressCallback progress_callback,
                            GAsyncReadyCallback                callback,
                            gpointer                           user_data)
{
        SoupSessionPrivate *priv;
        SoupMessage *msg;
        SoupMessageQueueItem *item;
        ConnectAsyncData *data;
        GTask *task;

        g_return_if_fail (SOUP_IS_SESSION (session));
        g_return_if_fail (!SOUP_IS_SESSION_SYNC (session));
        priv = soup_session_get_instance_private (session);
        g_return_if_fail (priv->use_thread_context);
        g_return_if_fail (uri != NULL);

        task = g_task_new (session, cancellable, callback, user_data);

        msg = soup_message_new_from_uri (SOUP_METHOD_HEAD, uri);
        soup_message_set_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);
        g_signal_connect_object (msg, "finished",
                                 G_CALLBACK (connect_async_message_finished),
                                 task, 0);
        if (progress_callback) {
                g_signal_connect_object (msg, "network-event",
                                         G_CALLBACK (connect_async_message_network_event),
                                         task, 0);
        }

        item = soup_session_append_queue_item (session, msg, TRUE, FALSE, NULL, NULL);
        item->connect_only = TRUE;
        data = connect_async_data_new (item, progress_callback, user_data);
        g_task_set_task_data (task, data, (GDestroyNotify) connect_async_data_free);
        soup_session_kick_queue (session);
        soup_message_queue_item_unref (item);
        g_object_unref (msg);
}

/**
 * soup_session_connect_finish:
 * @session: a #SoupSession
 * @result: the #GAsyncResult passed to your callback
 * @error: return location for a #GError, or %NULL
 *
 * Gets the #GIOStream created for the connection to communicate with the server.
 *
 * Return value: (transfer full): a new #GIOStream, or %NULL on error.
 *
 * Since: 2.62
 */
GIOStream *
soup_session_connect_finish (SoupSession  *session,
                             GAsyncResult *result,
                             GError      **error)
{
        g_return_val_if_fail (SOUP_IS_SESSION (session), NULL);
        g_return_val_if_fail (g_task_is_valid (result, session), NULL);

        return g_task_propagate_pointer (G_TASK (result), error);
}
