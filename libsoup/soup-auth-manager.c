/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-auth-manager.c: SoupAuth manager for SoupSession
 *
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-auth-manager.h"
#include "soup.h"
#include "soup-connection-auth.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-path-map.h"
#include "soup-session-private.h"

/**
 * SECTION:soup-auth-manager
 * @short_description: HTTP client-side authentication handler
 * @see_also: #SoupSession, #SoupAuth
 *
 * #SoupAuthManager is the #SoupSessionFeature that handles HTTP
 * authentication for a #SoupSession.
 *
 * A #SoupAuthManager is added to the session by default, and normally
 * you don't need to worry about it at all. However, if you want to
 * disable HTTP authentication, you can remove the feature from the
 * session with soup_session_remove_feature_by_type(), or disable it on
 * individual requests with soup_message_disable_feature().
 *
 * Since: 2.42
 **/

/**
 * SOUP_TYPE_AUTH_MANAGER:
 *
 * The #GType of #SoupAuthManager; you can use this with
 * soup_session_remove_feature_by_type() or
 * soup_message_disable_feature().
 *
 * (Although this type has only been publicly visible since libsoup
 * 2.42, it has always existed in the background, and you can use
 * <literal><code>g_type_from_name ("SoupAuthManager")</code></literal>
 * to get its #GType in earlier releases.)
 *
 * Since: 2.42
 */
static void soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);
static SoupSessionFeatureInterface *soup_session_feature_default_interface;

enum {
	AUTHENTICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


struct SoupAuthManagerPrivate {
	SoupSession *session;
	GPtrArray *auth_types;
	gboolean auto_ntlm;

	GMutex lock;
	SoupAuth *proxy_auth;
	GHashTable *auth_hosts;
};

typedef struct {
	SoupURI     *uri;
	SoupPathMap *auth_realms;      /* path -> scheme:realm */
	GHashTable  *auths;            /* scheme:realm -> SoupAuth */
} SoupAuthHost;

G_DEFINE_TYPE_WITH_CODE (SoupAuthManager, soup_auth_manager, G_TYPE_OBJECT,
                         G_ADD_PRIVATE (SoupAuthManager)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_auth_manager_session_feature_init))

static void soup_auth_host_free (SoupAuthHost *host);
static SoupAuth *record_auth_for_uri (SoupAuthManagerPrivate *priv,
				      SoupURI *uri, SoupAuth *auth,
				      gboolean prior_auth_failed);

static void
soup_auth_manager_init (SoupAuthManager *manager)
{
	SoupAuthManagerPrivate *priv;

	priv = manager->priv = soup_auth_manager_get_instance_private (manager);

	priv->auth_types = g_ptr_array_new_with_free_func ((GDestroyNotify)g_type_class_unref);
	priv->auth_hosts = g_hash_table_new_full (soup_uri_host_hash,
						  soup_uri_host_equal,
						  NULL,
						  (GDestroyNotify)soup_auth_host_free);
	g_mutex_init (&priv->lock);
}

static void
soup_auth_manager_finalize (GObject *object)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (object)->priv;

	g_ptr_array_free (priv->auth_types, TRUE);

	g_hash_table_destroy (priv->auth_hosts);

	g_clear_object (&priv->proxy_auth);

	g_mutex_clear (&priv->lock);

	G_OBJECT_CLASS (soup_auth_manager_parent_class)->finalize (object);
}

static void
soup_auth_manager_class_init (SoupAuthManagerClass *auth_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_manager_class);

	object_class->finalize = soup_auth_manager_finalize;

	/**
	 * SoupAuthManager::authenticate:
	 * @manager: the #SoupAuthManager
	 * @msg: the #SoupMessage being sent
	 * @auth: the #SoupAuth to authenticate
	 * @retrying: %TRUE if this is the second (or later) attempt
	 *
	 * Emitted when the manager requires the application to
	 * provide authentication credentials.
	 *
	 * #SoupSession connects to this signal and emits its own
	 * #SoupSession::authenticate signal when it is emitted, so
	 * you shouldn't need to use this signal directly.
	 */
	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupAuthManagerClass, authenticate),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 3,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_AUTH,
			      G_TYPE_BOOLEAN);

}

static int
auth_type_compare_func (gconstpointer a, gconstpointer b)
{
	SoupAuthClass **auth1 = (SoupAuthClass **)a;
	SoupAuthClass **auth2 = (SoupAuthClass **)b;

	return (*auth1)->strength - (*auth2)->strength;
}

static gboolean
soup_auth_manager_add_feature (SoupSessionFeature *feature, GType type)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (feature)->priv;
	SoupAuthClass *auth_class;

	if (!g_type_is_a (type, SOUP_TYPE_AUTH))
		return FALSE;

	auth_class = g_type_class_ref (type);
	g_ptr_array_add (priv->auth_types, auth_class);
	g_ptr_array_sort (priv->auth_types, auth_type_compare_func);

	/* Plain SoupSession does not get the backward-compat
	 * auto-NTLM behavior; SoupSession subclasses do.
	 */
	if (type == SOUP_TYPE_AUTH_NTLM &&
	    G_TYPE_FROM_INSTANCE (priv->session) != SOUP_TYPE_SESSION)
		priv->auto_ntlm = TRUE;

	return TRUE;
}

static gboolean
soup_auth_manager_remove_feature (SoupSessionFeature *feature, GType type)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (feature)->priv;
	SoupAuthClass *auth_class;
	guint i;

	if (!g_type_is_a (type, SOUP_TYPE_AUTH))
		return FALSE;

	auth_class = g_type_class_peek (type);

	for (i = 0; i < priv->auth_types->len; i++) {
		if (priv->auth_types->pdata[i] == (gpointer)auth_class) {
			if (type == SOUP_TYPE_AUTH_NTLM)
				priv->auto_ntlm = FALSE;

			g_ptr_array_remove_index (priv->auth_types, i);
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
soup_auth_manager_has_feature (SoupSessionFeature *feature, GType type)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (feature)->priv;
	SoupAuthClass *auth_class;
	guint i;

	if (!g_type_is_a (type, SOUP_TYPE_AUTH))
		return FALSE;

	auth_class = g_type_class_peek (type);
	for (i = 0; i < priv->auth_types->len; i++) {
		if (priv->auth_types->pdata[i] == (gpointer)auth_class)
			return TRUE;
	}
	return FALSE;
}

static void
soup_auth_manager_attach (SoupSessionFeature *feature, SoupSession *session)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (feature)->priv;

	/* FIXME: should support multiple sessions */
	priv->session = session;

	soup_session_feature_default_interface->attach (feature, session);
}

static inline const char *
auth_header_for_message (SoupMessage *msg)
{
	if (msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		return soup_message_headers_get_list (msg->response_headers,
						      "Proxy-Authenticate");
	} else {
		return soup_message_headers_get_list (msg->response_headers,
						      "WWW-Authenticate");
	}
}

static GSList *
next_challenge_start (GSList *items)
{
	/* The relevant grammar (from httpbis):
	 *
	 * WWW-Authenticate   = 1#challenge
	 * Proxy-Authenticate = 1#challenge
	 * challenge          = auth-scheme [ 1*SP ( b64token / #auth-param ) ]
	 * auth-scheme        = token
	 * auth-param         = token BWS "=" BWS ( token / quoted-string )
	 * b64token           = 1*( ALPHA / DIGIT /
	 *                          "-" / "." / "_" / "~" / "+" / "/" ) *"="
	 *
	 * The fact that quoted-strings can contain commas, equals
	 * signs, and auth scheme names makes it tricky to "cheat" on
	 * the parsing. So soup_auth_manager_extract_challenge() will
	 * have used soup_header_parse_list() to split the header into
	 * items. Given the grammar above, the possible items are:
	 *
	 *   auth-scheme
	 *   auth-scheme 1*SP b64token
	 *   auth-scheme 1*SP auth-param
	 *   auth-param
	 *
	 * where the first three represent the start of a new challenge and
	 * the last one does not.
	 */

	for (; items; items = items->next) {
		const char *item = items->data;
		const char *sp = strpbrk (item, "\t\r\n ");
		const char *eq = strchr (item, '=');

		if (!eq) {
			/* No "=", so it can't be an auth-param */
			return items;
		}
		if (!sp || sp > eq) {
			/* No space, or first space appears after the "=",
			 * so it must be an auth-param.
			 */
			continue;
		}
		while (g_ascii_isspace (*++sp))
			;
		if (sp == eq) {
			/* First "=" appears immediately after the first
			 * space, so this must be an auth-param with
			 * space around the "=".
			 */
			continue;
		}

		/* "auth-scheme auth-param" or "auth-scheme b64token" */
		return items;
	}

	return NULL;
}

static char *
soup_auth_manager_extract_challenge (const char *challenges, const char *scheme)
{
	GSList *items, *i, *next;
	int schemelen = strlen (scheme);
	char *item;
	GString *challenge;

	items = soup_header_parse_list (challenges);

	/* First item will start with the scheme name, followed by
	 * either nothing, or else a space and then the first
	 * auth-param.
	 */
	for (i = items; i; i = next_challenge_start (i->next)) {
		item = i->data;
		if (!g_ascii_strncasecmp (item, scheme, schemelen) &&
		    (!item[schemelen] || g_ascii_isspace (item[schemelen])))
			break;
	}
	if (!i) {
		soup_header_free_list (items);
		return NULL;
	}

	next = next_challenge_start (i->next);
	challenge = g_string_new (item);
	for (i = i->next; i != next; i = i->next) {
		item = i->data;
		g_string_append (challenge, ", ");
		g_string_append (challenge, item);
	}

	soup_header_free_list (items);
	return g_string_free (challenge, FALSE);
}

static SoupAuth *
create_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	const char *header;
	SoupAuthClass *auth_class;
	char *challenge = NULL;
	SoupAuth *auth = NULL;
	int i;

	header = auth_header_for_message (msg);
	if (!header)
		return NULL;

	for (i = priv->auth_types->len - 1; i >= 0; i--) {
		auth_class = priv->auth_types->pdata[i];
		challenge = soup_auth_manager_extract_challenge (header, auth_class->scheme_name);
		if (!challenge)
			continue;
		auth = soup_auth_new (G_TYPE_FROM_CLASS (auth_class), msg, challenge);
		g_free (challenge);
		if (auth)
			break;
	}

	return auth;
}

static gboolean
check_auth (SoupMessage *msg, SoupAuth *auth)
{
	const char *header, *scheme;
	char *challenge = NULL;
	gboolean ok = TRUE;

	scheme = soup_auth_get_scheme_name (auth);

	header = auth_header_for_message (msg);
	if (header)
		challenge = soup_auth_manager_extract_challenge (header, scheme);
	if (!challenge) {
		ok = FALSE;
		challenge = g_strdup (scheme);
	}

	if (!soup_auth_update (auth, msg, challenge))
		ok = FALSE;
	g_free (challenge);
	return ok;
}

static SoupAuthHost *
get_auth_host_for_uri (SoupAuthManagerPrivate *priv, SoupURI *uri)
{
	SoupAuthHost *host;

	host = g_hash_table_lookup (priv->auth_hosts, uri);
	if (host)
		return host;

	host = g_slice_new0 (SoupAuthHost);
	host->uri = soup_uri_copy_host (uri);
	g_hash_table_insert (priv->auth_hosts, host->uri, host);

	return host;
}

static void
soup_auth_host_free (SoupAuthHost *host)
{
	g_clear_pointer (&host->auth_realms, soup_path_map_free);
	g_clear_pointer (&host->auths, g_hash_table_destroy);

	soup_uri_free (host->uri);
	g_slice_free (SoupAuthHost, host);
}

static gboolean
make_auto_ntlm_auth (SoupAuthManagerPrivate *priv, SoupAuthHost *host)
{
	SoupAuth *auth;

	if (!priv->auto_ntlm)
		return FALSE;

	auth = g_object_new (SOUP_TYPE_AUTH_NTLM,
			     SOUP_AUTH_HOST, host->uri->host,
			     NULL);
	record_auth_for_uri (priv, host->uri, auth, FALSE);
	g_object_unref (auth);
	return TRUE;
}

static void
update_authorization_header (SoupMessage *msg, SoupAuth *auth, gboolean is_proxy)
{
	const char *authorization_header = is_proxy ? "Proxy-Authorization" : "Authorization";
	char *token;

	if (soup_message_get_auth (msg))
		soup_message_headers_remove (msg->request_headers, authorization_header);

	if (!auth)
		return;

	token = soup_auth_get_authorization (auth, msg);
	if (!token)
		return;

	soup_message_headers_replace (msg->request_headers, authorization_header, token);
	g_free (token);
}

static SoupAuth *
lookup_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupAuthHost *host;
	const char *path, *realm;
	SoupAuth *auth;

	/* If the message already has a ready auth, use that instead */
	auth = soup_message_get_auth (msg);
	if (auth && soup_auth_is_ready (auth, msg))
		return auth;

	if (soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)
		return NULL;

	host = get_auth_host_for_uri (priv, soup_message_get_uri (msg));
	if (!host->auth_realms && !make_auto_ntlm_auth (priv, host))
		return NULL;

	/* Cannot change the above '&&' into '||', because make_auto_ntlm_auth() is used
	 * to populate host->auth_realms when it's not set yet. Even the make_auto_ntlm_auth()
	 * returns TRUE only if it also populates the host->auth_realms, this extra test
	 * is required to mute a FORWARD_NULL Coverity Scan warning, which is a false-positive
	 * here */
	if (!host->auth_realms)
		return NULL;

	path = soup_message_get_uri (msg)->path;
	if (!path)
		path = "/";
	realm = soup_path_map_lookup (host->auth_realms, path);
	if (realm)
		return g_hash_table_lookup (host->auths, realm);

	return NULL;
}

static SoupAuth *
lookup_proxy_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupAuth *auth;

	/* If the message already has a ready auth, use that instead */
	auth = soup_message_get_proxy_auth (msg);
	if (auth && soup_auth_is_ready (auth, msg))
		return auth;

	if (soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)
		return NULL;

	return priv->proxy_auth;
}

static void
authenticate_auth (SoupAuthManager *manager, SoupAuth *auth,
		   SoupMessage *msg, gboolean prior_auth_failed,
		   gboolean proxy, gboolean can_interact)
{
	SoupAuthManagerPrivate *priv = manager->priv;
	SoupURI *uri;

	if (!soup_auth_can_authenticate (auth))
		return;

	if (proxy) {
		SoupMessageQueue *queue;
		SoupMessageQueueItem *item;

		queue = soup_session_get_queue (priv->session);
		item = soup_message_queue_lookup (queue, msg);
		if (!item)
			return;

		/* When loaded from the disk cache, the connection is NULL. */
		uri = item->conn ? soup_connection_get_proxy_uri (item->conn) : NULL;
		soup_message_queue_item_unref (item);
		if (!uri)
			return;
	} else
		uri = soup_message_get_uri (msg);

	/* If a password is specified explicitly in the URI, use it
	 * even if the auth had previously already been authenticated.
	 */
	if (uri->password && uri->user) {
		soup_auth_authenticate (auth, uri->user, uri->password);
		soup_uri_set_password (uri, NULL);
		soup_uri_set_user (uri, NULL);
	} else if (!soup_auth_is_authenticated (auth) && can_interact) {
		g_signal_emit (manager, signals[AUTHENTICATE], 0,
			       msg, auth, prior_auth_failed);
	}
}

static SoupAuth *
record_auth_for_uri (SoupAuthManagerPrivate *priv, SoupURI *uri,
		     SoupAuth *auth, gboolean prior_auth_failed)
{
	SoupAuthHost *host;
	SoupAuth *old_auth;
	const char *path;
	char *auth_info, *old_auth_info;
	GSList *pspace, *p;

	host = get_auth_host_for_uri (priv, uri);
	auth_info = soup_auth_get_info (auth);

	if (!host->auth_realms) {
		host->auth_realms = soup_path_map_new (g_free);
		host->auths = g_hash_table_new_full (g_str_hash, g_str_equal,
						     g_free, g_object_unref);
	}

	/* Record where this auth realm is used. */
	pspace = soup_auth_get_protection_space (auth, uri);
	for (p = pspace; p; p = p->next) {
		path = p->data;
		old_auth_info = soup_path_map_lookup (host->auth_realms, path);
		if (old_auth_info) {
			if (!strcmp (old_auth_info, auth_info))
				continue;
			soup_path_map_remove (host->auth_realms, path);
		}

		soup_path_map_add (host->auth_realms, path,
				   g_strdup (auth_info));
	}
	soup_auth_free_protection_space (auth, pspace);

	/* Now, make sure the auth is recorded. (If there's a
	 * pre-existing good auth, we keep that rather than the new one,
	 * since the old one might already be authenticated.)
	 */
	old_auth = g_hash_table_lookup (host->auths, auth_info);
	if (old_auth && (old_auth != auth || !prior_auth_failed)) {
		g_free (auth_info);
		return old_auth;
	} else {
		g_hash_table_insert (host->auths, auth_info,
				     g_object_ref (auth));
		return auth;
	}
}

static void
auth_got_headers (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (manager)->priv;
	SoupAuth *auth, *prior_auth;
	gboolean prior_auth_failed = FALSE;

	g_mutex_lock (&priv->lock);

	/* See if we used auth last time */
	prior_auth = soup_message_get_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		auth = g_object_ref (prior_auth);
		if (!soup_auth_is_ready (auth, msg))
			prior_auth_failed = TRUE;
	} else {
		auth = create_auth (priv, msg);
		if (!auth) {
			g_mutex_unlock (&priv->lock);
			return;
		}
	}

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)) {
		SoupAuth *new_auth;

		new_auth = record_auth_for_uri (priv, soup_message_get_uri (msg),
						auth, prior_auth_failed);
		g_object_unref (auth);
		auth = g_object_ref (new_auth);
	}

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, auth, msg,
			   prior_auth_failed, FALSE, TRUE);
	soup_message_set_auth (msg, auth);
	g_object_unref (auth);
	g_mutex_unlock (&priv->lock);
}

static void
auth_got_body (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (manager)->priv;
	SoupAuth *auth;

	g_mutex_lock (&priv->lock);
	auth = lookup_auth (priv, msg);
	if (auth && soup_auth_is_ready (auth, msg)) {
		if (SOUP_IS_CONNECTION_AUTH (auth)) {
			SoupMessageFlags flags;

			flags = soup_message_get_flags (msg);
			soup_message_set_flags (msg, flags & ~SOUP_MESSAGE_NEW_CONNECTION);
		}

		/* When not using cached credentials, update the Authorization header
		 * right before requeuing the message.
		 */
		if (soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)
			update_authorization_header (msg, auth, FALSE);

		soup_session_requeue_message (priv->session, msg);
	}
	g_mutex_unlock (&priv->lock);
}

static void
proxy_auth_got_headers (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (manager)->priv;
	SoupAuth *auth = NULL, *prior_auth;
	gboolean prior_auth_failed = FALSE;

	g_mutex_lock (&priv->lock);

	/* See if we used auth last time */
	prior_auth = soup_message_get_proxy_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		if (!soup_auth_is_ready (prior_auth, msg))
			prior_auth_failed = TRUE;
	}

	if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
		auth = priv->proxy_auth ? g_object_ref (priv->proxy_auth) : NULL;

	if (!auth) {
		auth = create_auth (priv, msg);
		if (!auth) {
			g_mutex_unlock (&priv->lock);
			return;
		}
		if (!(soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
			priv->proxy_auth = g_object_ref (auth);
	}

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, auth, msg,
			   prior_auth_failed, TRUE, TRUE);
	soup_message_set_proxy_auth (msg, auth);
	g_object_unref (auth);
	g_mutex_unlock (&priv->lock);
}

static void
proxy_auth_got_body (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (manager)->priv;
	SoupAuth *auth;

	g_mutex_lock (&priv->lock);

	auth = lookup_proxy_auth (priv, msg);
	if (auth && soup_auth_is_ready (auth, msg)) {
		/* When not using cached credentials, update the Authorization header
		 * right before requeuing the message.
		 */
		if (soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)
			update_authorization_header (msg, auth, TRUE);
		soup_session_requeue_message (priv->session, msg);
	}

	g_mutex_unlock (&priv->lock);
}

static void
auth_msg_starting (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER (manager)->priv;
	SoupAuth *auth;

	if (soup_message_get_flags (msg) & SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)
		return;

	g_mutex_lock (&priv->lock);

	if (msg->method != SOUP_METHOD_CONNECT) {
		auth = lookup_auth (priv, msg);
		if (auth) {
			authenticate_auth (manager, auth, msg, FALSE, FALSE, FALSE);
			if (!soup_auth_is_ready (auth, msg))
				auth = NULL;
		}
		soup_message_set_auth (msg, auth);
		update_authorization_header (msg, auth, FALSE);
	}

	auth = lookup_proxy_auth (priv, msg);
	if (auth) {
		authenticate_auth (manager, auth, msg, FALSE, TRUE, FALSE);
		if (!soup_auth_is_ready (auth, msg))
			auth = NULL;
	}
	soup_message_set_proxy_auth (msg, auth);
	update_authorization_header (msg, auth, TRUE);

	g_mutex_unlock (&priv->lock);
}

static void
soup_auth_manager_request_queued (SoupSessionFeature *manager,
				  SoupSession *session,
				  SoupMessage *msg)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (auth_msg_starting), manager);

	soup_message_add_status_code_handler (
		msg, "got_headers", SOUP_STATUS_UNAUTHORIZED,
		G_CALLBACK (auth_got_headers), manager);
	soup_message_add_status_code_handler (
		msg, "got_body", SOUP_STATUS_UNAUTHORIZED,
		G_CALLBACK (auth_got_body), manager);

	soup_message_add_status_code_handler (
		msg, "got_headers", SOUP_STATUS_PROXY_UNAUTHORIZED,
		G_CALLBACK (proxy_auth_got_headers), manager);
	soup_message_add_status_code_handler (
		msg, "got_body", SOUP_STATUS_PROXY_UNAUTHORIZED,
		G_CALLBACK (proxy_auth_got_body), manager);
}

static void
soup_auth_manager_request_unqueued (SoupSessionFeature *manager,
				    SoupSession *session,
				    SoupMessage *msg)
{
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, manager);
}

/**
 * soup_auth_manager_use_auth:
 * @manager: a #SoupAuthManager
 * @uri: the #SoupURI under which @auth is to be used
 * @auth: the #SoupAuth to use
 *
 * Records that @auth is to be used under @uri, as though a
 * WWW-Authenticate header had been received at that URI. This can be
 * used to "preload" @manager's auth cache, to avoid an extra HTTP
 * round trip in the case where you know ahead of time that a 401
 * response will be returned.
 *
 * This is only useful for authentication types where the initial
 * Authorization header does not depend on any additional information
 * from the server. (Eg, Basic or NTLM, but not Digest.)
 *
 * Since: 2.42
 */
void
soup_auth_manager_use_auth (SoupAuthManager *manager,
			    SoupURI         *uri,
			    SoupAuth        *auth)
{
	SoupAuthManagerPrivate *priv = manager->priv;

	g_mutex_lock (&priv->lock);
	record_auth_for_uri (priv, uri, auth, FALSE);
	g_mutex_unlock (&priv->lock);
}

/**
 * soup_auth_manager_clear_cached_credentials:
 * @manager: a #SoupAuthManager
 *
 * Clear all credentials cached by @manager
 *
 * Since: 2.58
 */
void
soup_auth_manager_clear_cached_credentials (SoupAuthManager *manager)
{
	SoupAuthManagerPrivate *priv;

	g_return_if_fail (SOUP_IS_AUTH_MANAGER (manager));

	priv = manager->priv;
	g_mutex_lock (&priv->lock);
	g_hash_table_remove_all (priv->auth_hosts);
	g_mutex_unlock (&priv->lock);
}

static void
soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					gpointer interface_data)
{
	soup_session_feature_default_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = soup_auth_manager_attach;
	feature_interface->request_queued = soup_auth_manager_request_queued;
	feature_interface->request_unqueued = soup_auth_manager_request_unqueued;
	feature_interface->add_feature = soup_auth_manager_add_feature;
	feature_interface->remove_feature = soup_auth_manager_remove_feature;
	feature_interface->has_feature = soup_auth_manager_has_feature;
}
