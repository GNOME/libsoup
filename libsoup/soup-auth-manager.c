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
#include "soup-marshal.h"
#include "soup-message-private.h"
#include "soup-message-queue.h"
#include "soup-path-map.h"
#include "soup-session-private.h"

static void soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);
static SoupSessionFeatureInterface *soup_session_feature_default_interface;

enum {
	AUTHENTICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_TYPE_WITH_CODE (SoupAuthManager, soup_auth_manager, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_auth_manager_session_feature_init))

typedef struct {
	SoupSession *session;
	GPtrArray *auth_types;
	gboolean has_ntlm;

	SoupAuth *proxy_auth;
	GHashTable *auth_hosts;

	GHashTable *connauths;
	GHashTable *sockets_by_msg;
} SoupAuthManagerPrivate;
#define SOUP_AUTH_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_AUTH_MANAGER, SoupAuthManagerPrivate))

typedef struct {
	SoupURI     *uri;
	SoupPathMap *auth_realms;      /* path -> scheme:realm */
	GHashTable  *auths;            /* scheme:realm -> SoupAuth */
} SoupAuthHost;

static void soup_auth_host_free (SoupAuthHost *host);

static void
soup_auth_manager_init (SoupAuthManager *manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);

	priv->auth_types = g_ptr_array_new_with_free_func ((GDestroyNotify)g_type_class_unref);
	priv->auth_hosts = g_hash_table_new_full (soup_uri_host_hash,
						  soup_uri_host_equal,
						  NULL,
						  (GDestroyNotify)soup_auth_host_free);

	priv->connauths = g_hash_table_new_full (NULL, NULL,
						 NULL, g_object_unref);
	priv->sockets_by_msg = g_hash_table_new (NULL, NULL);
}

static void
soup_auth_manager_finalize (GObject *object)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (object);

	g_ptr_array_free (priv->auth_types, TRUE);

	g_hash_table_destroy (priv->auth_hosts);

	g_clear_object (&priv->proxy_auth);

	g_hash_table_destroy (priv->connauths);
	g_hash_table_destroy (priv->sockets_by_msg);

	G_OBJECT_CLASS (soup_auth_manager_parent_class)->finalize (object);
}

static void
soup_auth_manager_class_init (SoupAuthManagerClass *auth_manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (auth_manager_class);

	g_type_class_add_private (auth_manager_class, sizeof (SoupAuthManagerPrivate));

	object_class->finalize = soup_auth_manager_finalize;

	signals[AUTHENTICATE] =
		g_signal_new ("authenticate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupAuthManagerClass, authenticate),
			      NULL, NULL,
			      _soup_marshal_NONE__OBJECT_OBJECT_BOOLEAN,
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
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (feature);
	SoupAuthClass *auth_class;

	if (!g_type_is_a (type, SOUP_TYPE_AUTH))
		return FALSE;

	auth_class = g_type_class_ref (type);
	g_ptr_array_add (priv->auth_types, auth_class);
	g_ptr_array_sort (priv->auth_types, auth_type_compare_func);

	if (type == SOUP_TYPE_AUTH_NTLM)
		priv->has_ntlm = TRUE;

	return TRUE;
}

static gboolean
soup_auth_manager_remove_feature (SoupSessionFeature *feature, GType type)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (feature);
	SoupAuthClass *auth_class;
	int i;

	if (!g_type_is_a (type, SOUP_TYPE_AUTH))
		return FALSE;

	auth_class = g_type_class_peek (type);

	for (i = 0; i < priv->auth_types->len; i++) {
		if (priv->auth_types->pdata[i] == (gpointer)auth_class) {
			if (type == SOUP_TYPE_AUTH_NTLM)
				priv->has_ntlm = FALSE;

			g_ptr_array_remove_index (priv->auth_types, i);
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
soup_auth_manager_has_feature (SoupSessionFeature *feature, GType type)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (feature);
	SoupAuthClass *auth_class;
	int i;

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
soup_auth_manager_attach (SoupSessionFeature *manager, SoupSession *session)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);

	/* FIXME: should support multiple sessions */
	priv->session = session;

	soup_session_feature_default_interface->attach (manager, session);
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
	SoupAuth *auth;
	int i;

	header = auth_header_for_message (msg);
	if (!header)
		return NULL;

	for (i = priv->auth_types->len - 1; i >= 0; i--) {
		auth_class = priv->auth_types->pdata[i];
		challenge = soup_auth_manager_extract_challenge (header, auth_class->scheme_name);
		if (challenge)
			break;
	}
	if (!challenge)
		return NULL;

	auth = soup_auth_new (G_TYPE_FROM_CLASS (auth_class), msg, challenge);
	g_free (challenge);
	return auth;
}

static gboolean
check_auth (SoupMessage *msg, SoupAuth *auth)
{
	const char *header;
	char *challenge;
	gboolean ok;

	header = auth_header_for_message (msg);
	if (!header)
		return FALSE;

	challenge = soup_auth_manager_extract_challenge (header, soup_auth_get_scheme_name (auth));
	if (!challenge)
		return FALSE;

	ok = soup_auth_update (auth, msg, challenge);
	g_free (challenge);
	return ok;
}

static SoupAuthHost *
get_auth_host_for_message (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupAuthHost *host;
	SoupURI *uri = soup_message_get_uri (msg);

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

static SoupAuth *
lookup_auth (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupAuthHost *host;
	const char *path, *realm;

	host = get_auth_host_for_message (priv, msg);
	if (!host->auth_realms)
		return NULL;

	path = soup_message_get_uri (msg)->path;
	if (!path)
		path = "/";
	realm = soup_path_map_lookup (host->auth_realms, path);
	if (realm)
		return g_hash_table_lookup (host->auths, realm);
	else
		return NULL;
}

static gboolean
authenticate_auth (SoupAuthManager *manager, SoupAuth *auth,
		   SoupMessage *msg, gboolean prior_auth_failed,
		   gboolean proxy, gboolean can_interact)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupURI *uri;

	if (proxy) {
		SoupMessageQueue *queue;
		SoupMessageQueueItem *item;

		queue = soup_session_get_queue (priv->session);
		item = soup_message_queue_lookup (queue, msg);
		if (item) {
			uri = soup_connection_get_proxy_uri (item->conn);
			soup_message_queue_item_unref (item);
		} else
			uri = NULL;

		if (!uri)
			return FALSE;
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

	return soup_auth_is_authenticated (auth);
}

static void
delete_connauth (SoupSocket *socket, gpointer user_data)
{
	SoupAuthManagerPrivate *priv = user_data;

	g_hash_table_remove (priv->connauths, socket);
	g_signal_handlers_disconnect_by_func (socket, delete_connauth, priv);
}

static SoupAuth *
get_connauth (SoupAuthManagerPrivate *priv, SoupSocket *socket)
{
	SoupAuth *auth;

	if (!priv->has_ntlm)
		return NULL;

	auth = g_hash_table_lookup (priv->connauths, socket);
	if (!auth) {
		auth = g_object_new (SOUP_TYPE_AUTH_NTLM, NULL);
		g_hash_table_insert (priv->connauths, socket, auth);
		g_signal_connect (socket, "disconnected",
				  G_CALLBACK (delete_connauth), priv);
	}

	return auth;
}

static void
unset_socket (SoupMessage *msg, gpointer user_data)
{
	SoupAuthManagerPrivate *priv = user_data;

	g_hash_table_remove (priv->sockets_by_msg, msg);
	g_signal_handlers_disconnect_by_func (msg, unset_socket, priv);
}

static void
set_socket_for_msg (SoupAuthManagerPrivate *priv,
		    SoupMessage *msg, SoupSocket *sock)
{
	if (!g_hash_table_lookup (priv->sockets_by_msg, msg)) {
		g_signal_connect (msg, "finished",
				  G_CALLBACK (unset_socket), priv);
		g_signal_connect (msg, "restarted",
				  G_CALLBACK (unset_socket), priv);
	}
	g_hash_table_insert (priv->sockets_by_msg, msg, sock);
}

static SoupAuth *
get_connauth_for_msg (SoupAuthManagerPrivate *priv, SoupMessage *msg)
{
	SoupSocket *sock;

	sock = g_hash_table_lookup (priv->sockets_by_msg, msg);
	if (sock)
		return g_hash_table_lookup (priv->connauths, sock);
	else
		return NULL;
}

static void
auth_got_headers (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupAuthHost *host;
	SoupAuth *auth, *prior_auth, *old_auth;
	const char *path;
	char *auth_info, *old_auth_info;
	GSList *pspace, *p;
	gboolean prior_auth_failed = FALSE;

	auth = get_connauth_for_msg (priv, msg);
	if (auth) {
		const char *header;

		header = auth_header_for_message (msg);
		if (header && soup_auth_update (auth, msg, header)) {
			if (!soup_auth_is_authenticated (auth)) {
				g_signal_emit (manager, signals[AUTHENTICATE], 0,
					       msg, auth, FALSE);
			}
			return;
		}
	}

	host = get_auth_host_for_message (priv, msg);

	/* See if we used auth last time */
	prior_auth = soup_message_get_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		auth = prior_auth;
		if (!soup_auth_is_authenticated (auth))
			prior_auth_failed = TRUE;
	} else {
		auth = create_auth (priv, msg);
		if (!auth)
			return;
	}
	auth_info = soup_auth_get_info (auth);

	if (!host->auth_realms) {
		host->auth_realms = soup_path_map_new (g_free);
		host->auths = g_hash_table_new_full (g_str_hash, g_str_equal,
						     g_free, g_object_unref);
	}

	/* Record where this auth realm is used. */
	pspace = soup_auth_get_protection_space (auth, soup_message_get_uri (msg));
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
	 * pre-existing auth, we keep that rather than the new one,
	 * since the old one might already be authenticated.)
	 */
	old_auth = g_hash_table_lookup (host->auths, auth_info);
	if (old_auth) {
		g_free (auth_info);
		if (auth != old_auth && auth != prior_auth) {
			g_object_unref (auth);
			auth = old_auth;
		}
	} else {
		g_hash_table_insert (host->auths, auth_info, auth);
	}

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, auth, msg,
			   prior_auth_failed, FALSE, TRUE);
}

static void
auth_got_body (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupAuth *auth;

	auth = get_connauth_for_msg (priv, msg);
	if (auth && soup_auth_is_authenticated (auth)) {
		SoupMessageFlags flags;

		flags = soup_message_get_flags (msg);
		soup_message_set_flags (msg, flags & ~SOUP_MESSAGE_NEW_CONNECTION);
	} else
		auth = lookup_auth (priv, msg);
	if (auth && soup_auth_is_authenticated (auth))
		soup_session_requeue_message (priv->session, msg);
}

static void
proxy_auth_got_headers (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupAuth *prior_auth;
	gboolean prior_auth_failed = FALSE;

	/* See if we used auth last time */
	prior_auth = soup_message_get_proxy_auth (msg);
	if (prior_auth && check_auth (msg, prior_auth)) {
		if (!soup_auth_is_authenticated (prior_auth))
			prior_auth_failed = TRUE;
	}

	if (!priv->proxy_auth) {
		priv->proxy_auth = create_auth (priv, msg);
		if (!priv->proxy_auth)
			return;
	}

	/* If we need to authenticate, try to do it. */
	authenticate_auth (manager, priv->proxy_auth, msg,
			   prior_auth_failed, TRUE, TRUE);
}

static void
proxy_auth_got_body (SoupMessage *msg, gpointer manager)
{
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupAuth *auth = priv->proxy_auth;

	if (auth && soup_auth_is_authenticated (auth))
		soup_session_requeue_message (priv->session, msg);
}

static void
soup_auth_manager_request_queued (SoupSessionFeature *manager,
				  SoupSession *session,
				  SoupMessage *msg)
{
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
soup_auth_manager_request_started (SoupSessionFeature *feature,
				   SoupSession *session,
				   SoupMessage *msg,
				   SoupSocket *socket)
{
	SoupAuthManager *manager = SOUP_AUTH_MANAGER (feature);
	SoupAuthManagerPrivate *priv = SOUP_AUTH_MANAGER_GET_PRIVATE (manager);
	SoupAuth *auth;

	set_socket_for_msg (priv, msg, socket);
	auth = lookup_auth (priv, msg);
	if (auth) {
		if (!authenticate_auth (manager, auth, msg, FALSE, FALSE, FALSE))
			auth = NULL;
	} else
		auth = get_connauth (priv, socket);
	soup_message_set_auth (msg, auth);

	auth = priv->proxy_auth;
	if (!auth || !authenticate_auth (manager, auth, msg, FALSE, TRUE, FALSE))
		auth = NULL;
	soup_message_set_proxy_auth (msg, auth);
}

static void
soup_auth_manager_request_unqueued (SoupSessionFeature *manager,
				    SoupSession *session,
				    SoupMessage *msg)
{
	g_signal_handlers_disconnect_matched (msg, G_SIGNAL_MATCH_DATA,
					      0, 0, NULL, NULL, manager);
}

static void
soup_auth_manager_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					gpointer interface_data)
{
	soup_session_feature_default_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = soup_auth_manager_attach;
	feature_interface->request_queued = soup_auth_manager_request_queued;
	feature_interface->request_started = soup_auth_manager_request_started;
	feature_interface->request_unqueued = soup_auth_manager_request_unqueued;
	feature_interface->add_feature = soup_auth_manager_add_feature;
	feature_interface->remove_feature = soup_auth_manager_remove_feature;
	feature_interface->has_feature = soup_auth_manager_has_feature;
}
