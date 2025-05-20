/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
#include "soup-message-headers-private.h"
#include "soup-path-map.h"
#include "soup-session-private.h"
#include "soup-session-feature-private.h"
#include "soup-uri-utils-private.h"

/**
 * SoupAuthManager:
 *
 * HTTP client-side authentication handler.
 *
 * [class@AuthManager] is the [iface@SessionFeature] that handles HTTP
 * authentication for a [class@Session].
 *
 * A [class@AuthManager] is added to the session by default, and normally
 * you don't need to worry about it at all. However, if you want to
 * disable HTTP authentication, you can remove the feature from the
 * session with [method@Session.remove_feature_by_type] or disable it on
 * individual requests with [method@Message.disable_feature].
 *
 * You can use this with [method@Session.remove_feature_by_type] or
 * [method@Message.disable_feature].
 *
 * (Although this type has only been publicly visible since libsoup 2.42, it has
 * always existed in the background, and you can use `g_type_from_name
 * ("SoupAuthManager")` to get its [alias@GObject.Type] in earlier releases.)
 **/
static void soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

struct _SoupAuthManager {
        GObject parent_instance;
};

typedef struct {
	SoupSession *session;
	GPtrArray *auth_types;
	gboolean auto_ntlm;

	SoupAuth *proxy_auth;
        GMutex mutex;
	GHashTable *auth_hosts;
} SoupAuthManagerPrivate;

typedef struct {
	GUri        *uri;
	SoupPathMap *auth_realms;      /* path -> scheme:realm */
	GHashTable  *auths;            /* scheme:realm -> SoupAuth */
} SoupAuthHost;

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupAuthManager, soup_auth_manager, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupAuthManager)
			       G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						      soup_auth_manager_session_feature_init))

static void soup_auth_host_free (SoupAuthHost *host);
static SoupAuth *record_auth_for_uri (SoupAuthManagerPrivate *priv,
				      GUri *uri, SoupAuth *auth,
				      gboolean prior_auth_failed);

static void
soup_auth_manager_init (SoupAuthManager *manager)
{
	SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);

	priv->auth_types = g_ptr_array_new_with_free_func ((GDestroyNotify)g_type_class_unref);
	priv->auth_hosts = g_hash_table_new_full (soup_uri_host_hash,
						  soup_uri_host_equal,
						  NULL,
						  (GDestroyNotify)soup_auth_host_free);
        g_mutex_init (&priv->mutex);
}

static void
soup_auth_manager_finalize (GObject *object)
{
	SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private ((SoupAuthManager*)object);

	g_ptr_array_free (priv->auth_types, TRUE);

	g_hash_table_destroy (priv->auth_hosts);

	g_clear_object (&priv->proxy_auth);

        g_mutex_clear (&priv->mutex);

	G_OBJECT_CLASS (soup_auth_manager_parent_class)->finalize (object);
}

static void
soup_auth_manager_class_init (SoupAuthManagerClass *auth_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_manager_class);

	object_class->finalize = soup_auth_manager_finalize;
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
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private ((SoupAuthManager*)feature);
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
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private ((SoupAuthManager*)feature);
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
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private ((SoupAuthManager*)feature);
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
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private ((SoupAuthManager*)feature);

	/* FIXME: should support multiple sessions */
	priv->session = session;
}

static inline const char *
auth_header_for_message (SoupMessage *msg)
{
	if (soup_message_get_status (msg) == SOUP_STATUS_PROXY_UNAUTHORIZED) {
		return soup_message_headers_get_list_common (soup_message_get_response_headers (msg),
                                                             SOUP_HEADER_PROXY_AUTHENTICATE);
	} else {
		return soup_message_headers_get_list_common (soup_message_get_response_headers (msg),
                                                             SOUP_HEADER_WWW_AUTHENTICATE);
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

static GStrv
soup_auth_manager_extract_challenges (const char *challenges, const char *scheme)
{
        GPtrArray *challenge_list = g_ptr_array_new ();
	GSList *items, *i, *next;
	int schemelen = strlen (scheme);
	char *item;
	GString *challenge;

	i = items = soup_header_parse_list (challenges);

        /* We need to split this list into individual challenges. */
        while (i) {
                /* First item will start with the scheme name, followed by
                * either nothing, or else a space and then the first
                * auth-param.
                */
                for (; i; i = next_challenge_start (i->next)) {
                        item = i->data;
                        if (!g_ascii_strncasecmp (item, scheme, schemelen) &&
                            (!item[schemelen] || g_ascii_isspace (item[schemelen])))
                                break;
                }
                if (!i)
                        break;

                next = next_challenge_start (i->next);
                challenge = g_string_new (item);
                for (i = i->next; i != next; i = i->next) {
                        item = i->data;
                        g_string_append (challenge, ", ");
                        g_string_append (challenge, item);
                }

                i = next;
                g_ptr_array_add (challenge_list, g_string_free (challenge, FALSE));
        };

	soup_header_free_list (items);

        if (challenge_list->len)
                g_ptr_array_add (challenge_list, NULL); /* Trailing NULL for GStrv. */
        return (GStrv)g_ptr_array_free (challenge_list, FALSE);
}

static SoupAuth *
create_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	const char *header;
	SoupAuthClass *auth_class;
        GStrv challenges;
	SoupAuth *auth = NULL;
	int i;

	header = auth_header_for_message (msg);
	if (!header)
		return NULL;

	for (i = priv->auth_types->len - 1; i >= 0; i--) {
		auth_class = priv->auth_types->pdata[i];
                challenges = soup_auth_manager_extract_challenges (header, auth_class->scheme_name);
                if (!challenges)
                        continue;

                for (int j = 0; challenges[j]; j++) {
                        /* TODO: We use the first successfully parsed auth, in the future this should
                         * prioritise more secure ones when they are supported. */
                        auth = soup_auth_new (G_TYPE_FROM_CLASS (auth_class), msg, challenges[j]);
                        if (auth) {
                                g_strfreev (challenges);
                                return auth;
                        }
                }

		g_strfreev (challenges);
	}

	return NULL;
}

static gboolean
check_auth (SoupMessage *msg, SoupAuth *auth)
{
	const char *header, *scheme;
        GStrv challenges = NULL;
	gboolean ok = TRUE;
        gboolean a_challenge_was_ok = FALSE;

	scheme = soup_auth_get_scheme_name (auth);

	header = auth_header_for_message (msg);
	if (header)
                challenges = soup_auth_manager_extract_challenges (header, scheme);
	if (!challenges) {
                challenges = g_new0 (char*, 2);
                challenges[0] = g_strdup (scheme);
                ok = FALSE;
	}

        for (int i = 0; challenges[i]; i++) {
                if (soup_auth_update (auth, msg, challenges[i])) {
                        a_challenge_was_ok = TRUE;
                        break;
                }
        }

        if (!a_challenge_was_ok)
                ok = FALSE;

        g_strfreev (challenges);
	return ok;
}

static SoupAuthHost *
get_auth_host_for_uri (SoupAuthManagerPrivate *priv, GUri *uri)
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

	g_uri_unref (host->uri);
	g_slice_free (SoupAuthHost, host);
}

static gboolean
make_auto_ntlm_auth (SoupAuthManagerPrivate *priv, SoupAuthHost *host)
{
	SoupAuth *auth;
	char *authority;

	if (!priv->auto_ntlm)
		return FALSE;

	authority = g_strdup_printf ("%s:%d", g_uri_get_host (host->uri), g_uri_get_port (host->uri));
	auth = g_object_new (SOUP_TYPE_AUTH_NTLM,
			     "authority", authority,
			     NULL);
	record_auth_for_uri (priv, host->uri, auth, FALSE);
	g_object_unref (auth);
	g_free (authority);
	return TRUE;
}

static void
update_authorization_header (SoupMessage *msg, SoupAuth *auth, gboolean is_proxy)
{
        SoupHeaderName authorization_header = is_proxy ? SOUP_HEADER_PROXY_AUTHORIZATION : SOUP_HEADER_AUTHORIZATION;
	char *token;

	if (soup_message_get_auth (msg))
		soup_message_headers_remove_common (soup_message_get_request_headers (msg), authorization_header);

	if (!auth)
		return;

	token = soup_auth_get_authorization (auth, msg);
	if (!token)
		return;

	soup_message_headers_replace_common (soup_message_get_request_headers (msg), authorization_header, token);
	g_free (token);
}

static SoupAuth *
lookup_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupAuthHost *host;
	const char *path, *realm;
	SoupAuth *auth;
	GUri *uri;

	/* If the message already has a ready auth, use that instead */
	auth = soup_message_get_auth (msg);
	if (auth && soup_auth_is_ready (auth, msg))
		return auth;

	if (soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
		return NULL;

	uri = soup_message_get_uri_for_auth (msg);
	if (!uri)
		return NULL;

	host = get_auth_host_for_uri (priv, uri);
	if (!host->auth_realms && !make_auto_ntlm_auth (priv, host))
		return NULL;

	/* Cannot change the above '&&' into '||', because make_auto_ntlm_auth() is used
	 * to populate host->auth_realms when it's not set yet. Even the make_auto_ntlm_auth()
	 * returns TRUE only if it also populates the host->auth_realms, this extra test
	 * is required to mute a FORWARD_NULL Coverity Scan warning, which is a false-positive
	 * here */
	if (!host->auth_realms)
		return NULL;

	path = g_uri_get_path (uri);
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

	if (soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
		return NULL;

	return priv->proxy_auth;
}

static void
async_auth_finished (SoupAuth    *auth,
		     GParamSpec  *pspec,
		     SoupMessage *msg)
{
	SoupSession *session;

	session = g_object_steal_data (G_OBJECT (msg), "auth-msg-session");
	if (!session)
		return;

	soup_session_unpause_message (session, msg);
	g_object_unref (session);
}

static void
authenticate_auth (SoupAuthManager *manager, SoupAuth *auth,
		   SoupMessage *msg, gboolean prior_auth_failed,
		   gboolean proxy, gboolean can_interact)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	GUri *uri;

	if (!soup_auth_can_authenticate (auth))
		return;

	uri = soup_message_get_uri_for_auth (msg);

	/* If a password is specified explicitly in the URI, use it
	 * even if the auth had previously already been authenticated.
	 */
	if (g_uri_get_user (uri)) {
		const char *password = g_uri_get_password (uri);
		soup_auth_authenticate (auth, g_uri_get_user (uri), password ? password : "");

                GUri *new_uri = soup_uri_copy (uri, SOUP_URI_USER, NULL, SOUP_URI_PASSWORD, NULL, SOUP_URI_NONE);
                soup_message_set_uri (msg, new_uri); // QUESTION: This didn't emit a signal previously
                g_uri_unref (new_uri);
	} else if (!soup_auth_is_authenticated (auth) && can_interact) {
		SoupMessage *original_msg;
		gboolean handled;

		original_msg = soup_session_get_original_message_for_authentication (priv->session,
										     msg);
		handled = soup_message_authenticate (original_msg, auth, prior_auth_failed);
		if (handled && !soup_auth_is_authenticated (auth) && !soup_auth_is_cancelled (auth)) {
			soup_session_pause_message (priv->session, msg);
			g_object_set_data_full (G_OBJECT (msg), "auth-msg-session",
						g_object_ref (priv->session),
						g_object_unref);
			g_signal_connect_object (auth, "notify::is-authenticated",
						 G_CALLBACK (async_auth_finished),
						 msg, 0);
			g_signal_connect_object (auth, "notify::is-cancelled",
						 G_CALLBACK (async_auth_finished),
						 msg, 0);
		}
	}
}

static SoupAuth *
record_auth_for_uri (SoupAuthManagerPrivate *priv, GUri *uri,
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
	if (old_auth && (old_auth != auth || !prior_auth_failed) && !soup_auth_is_cancelled (old_auth)) {
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
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	SoupAuth *auth, *prior_auth;
	gboolean prior_auth_failed = FALSE;

        g_mutex_lock (&priv->mutex);

	/* See if we used auth last time */
	prior_auth = soup_message_get_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		auth = g_object_ref (prior_auth);
		if (!soup_auth_is_ready (auth, msg))
			prior_auth_failed = TRUE;
	} else {
		auth = create_auth (priv, msg);
		if (!auth) {
                        g_mutex_unlock (&priv->mutex);
			return;
                }
	}

	if (!soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE)) {
		SoupAuth *new_auth;

		new_auth = record_auth_for_uri (priv, soup_message_get_uri_for_auth (msg),
						auth, prior_auth_failed);
		g_object_unref (auth);
		auth = g_object_ref (new_auth);
	}

        g_mutex_unlock (&priv->mutex);

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, auth, msg,
			   prior_auth_failed, FALSE, TRUE);
	soup_message_set_auth (msg, auth);
	g_object_unref (auth);
}

static void
auth_got_body (SoupMessage *msg, gpointer manager)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	SoupAuth *auth;

        g_mutex_lock (&priv->mutex);

	auth = lookup_auth (priv, msg);
	if (auth && soup_auth_is_ready (auth, msg)) {
		if (SOUP_IS_CONNECTION_AUTH (auth))
			soup_message_remove_flags (msg, SOUP_MESSAGE_NEW_CONNECTION);

		/* When not using cached credentials, update the Authorization header
		 * right before requeuing the message.
		 */
		if (soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
			update_authorization_header (msg, auth, FALSE);

		soup_session_requeue_message (priv->session, msg);
	}

        g_mutex_unlock (&priv->mutex);
}

static void
proxy_auth_got_headers (SoupMessage *msg, gpointer manager)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	SoupAuth *auth = NULL, *prior_auth;
	gboolean prior_auth_failed = FALSE;

        g_mutex_lock (&priv->mutex);

	/* See if we used auth last time */
	prior_auth = soup_message_get_proxy_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		if (!soup_auth_is_ready (prior_auth, msg))
			prior_auth_failed = TRUE;
	}

	if (!soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
		auth = priv->proxy_auth ? g_object_ref (priv->proxy_auth) : NULL;

	if (!auth) {
		auth = create_auth (priv, msg);
		if (!auth) {
                        g_mutex_unlock (&priv->mutex);
			return;
                }

		if (!soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
			priv->proxy_auth = g_object_ref (auth);
	}

        g_mutex_unlock (&priv->mutex);

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, auth, msg,
			   prior_auth_failed, TRUE, TRUE);
	soup_message_set_proxy_auth (msg, auth);
	g_object_unref (auth);
}

static void
proxy_auth_got_body (SoupMessage *msg, gpointer manager)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	SoupAuth *auth;

        g_mutex_lock (&priv->mutex);

	auth = lookup_proxy_auth (priv, msg);
	if (auth && soup_auth_is_ready (auth, msg)) {
		/* When not using cached credentials, update the Authorization header
		 * right before requeuing the message.
		 */
		if (soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
			update_authorization_header (msg, auth, TRUE);
		soup_session_requeue_message (priv->session, msg);
	}

        g_mutex_unlock (&priv->mutex);
}

static void
auth_msg_starting (SoupMessage *msg, gpointer manager)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);
	SoupAuth *auth;

	if (soup_message_query_flags (msg, SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE))
		return;

        g_mutex_lock (&priv->mutex);

	if (soup_message_get_method (msg) != SOUP_METHOD_CONNECT) {
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

        g_mutex_unlock (&priv->mutex);
}

static void
soup_auth_manager_request_queued (SoupSessionFeature *manager,
				  SoupMessage        *msg)
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
				    SoupMessage        *msg)
{
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, manager);
}

/**
 * soup_auth_manager_use_auth:
 * @manager: a #SoupAuthManager
 * @uri: the #GUri under which @auth is to be used
 * @auth: the #SoupAuth to use
 *
 * Records that @auth is to be used under @uri, as though a
 * WWW-Authenticate header had been received at that URI.
 *
 * This can be used to "preload" @manager's auth cache, to avoid an extra HTTP
 * round trip in the case where you know ahead of time that a 401 response will
 * be returned.
 *
 * This is only useful for authentication types where the initial
 * Authorization header does not depend on any additional information
 * from the server. (Eg, Basic or NTLM, but not Digest.)
 *
 */
void
soup_auth_manager_use_auth (SoupAuthManager *manager,
			    GUri            *uri,
			    SoupAuth        *auth)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);

        g_mutex_lock (&priv->mutex);
	record_auth_for_uri (priv, uri, auth, FALSE);
        g_mutex_unlock (&priv->mutex);
}

/**
 * soup_auth_manager_clear_cached_credentials:
 * @manager: a #SoupAuthManager
 *
 * Clear all credentials cached by @manager.
 *
 */
void
soup_auth_manager_clear_cached_credentials (SoupAuthManager *manager)
{
        SoupAuthManagerPrivate *priv = soup_auth_manager_get_instance_private (manager);

	g_return_if_fail (SOUP_IS_AUTH_MANAGER (manager));

        g_mutex_lock (&priv->mutex);
	g_hash_table_remove_all (priv->auth_hosts);
        g_mutex_unlock (&priv->mutex);
}

static void
soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					gpointer interface_data)
{
	feature_interface->attach = soup_auth_manager_attach;
	feature_interface->request_queued = soup_auth_manager_request_queued;
	feature_interface->request_unqueued = soup_auth_manager_request_unqueued;
	feature_interface->add_feature = soup_auth_manager_add_feature;
	feature_interface->remove_feature = soup_auth_manager_remove_feature;
	feature_interface->has_feature = soup_auth_manager_has_feature;
}
