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
#include "soup-message-private.h"
#include "soup-path-map.h"
#include "soup-session.h"
#include "soup-session-private.h"
#include "soup-uri.h"

static void session_request_started (SoupSession *session, SoupMessage *msg,
				     gpointer data);

struct SoupAuthManager {
	SoupSession *session;
	GHashTable *auth_types;

	SoupAuth *proxy_auth;
	GHashTable *auth_hosts;
};

typedef struct {
	SoupURI     *root_uri;
	SoupPathMap *auth_realms;      /* path -> scheme:realm */
	GHashTable  *auths;            /* scheme:realm -> SoupAuth */
} SoupAuthHost;

/* temporary until we fix this to index hosts by SoupAddress */
extern guint     soup_uri_host_hash  (gconstpointer  key);
extern gboolean  soup_uri_host_equal (gconstpointer  v1,
				      gconstpointer  v2);
extern SoupURI  *soup_uri_copy_root  (const SoupURI *uri);

SoupAuthManager *
soup_auth_manager_new (SoupSession *session)
{
	SoupAuthManager *manager;

	manager = g_new0 (SoupAuthManager, 1);
	manager->session = session;
	manager->auth_types = g_hash_table_new (g_str_hash, g_str_equal);
	manager->auth_hosts = g_hash_table_new (soup_uri_host_hash,
						soup_uri_host_equal);

	g_signal_connect (session, "request_started",
			  G_CALLBACK (session_request_started), manager);
	return manager;
}

static gboolean
foreach_free_host (gpointer key, gpointer value, gpointer data)
{
	SoupAuthHost *host = value;

	if (host->auth_realms)
		soup_path_map_free (host->auth_realms);
	if (host->auths)
		g_hash_table_destroy (host->auths);

	soup_uri_free (host->root_uri);
	g_free (host);

	return TRUE;
}

void
soup_auth_manager_free (SoupAuthManager *manager)
{
	g_signal_handlers_disconnect_by_func (
		manager->session,
		G_CALLBACK (session_request_started), manager);

	g_hash_table_destroy (manager->auth_types);

	g_hash_table_foreach_remove (manager->auth_hosts, foreach_free_host, NULL);
	g_hash_table_destroy (manager->auth_hosts);

	if (manager->proxy_auth)
		g_object_unref (manager->proxy_auth);

	g_free (manager);
}

void
soup_auth_manager_add_type (SoupAuthManager *manager, GType type)
{
	SoupAuthClass *auth_class;

	g_return_if_fail (g_type_is_a (type, SOUP_TYPE_AUTH));

	auth_class = g_type_class_ref (type);
	g_hash_table_insert (manager->auth_types,
			     (char *)auth_class->scheme_name,
			     auth_class);
}

void
soup_auth_manager_remove_type (SoupAuthManager *manager, GType type)
{
	SoupAuthClass *auth_class;

	g_return_if_fail (g_type_is_a (type, SOUP_TYPE_AUTH));

	auth_class = g_type_class_peek (type);
	g_hash_table_remove (manager->auth_types, auth_class->scheme_name);
	g_type_class_unref (auth_class);
}

static inline const char *
header_name_for_message (SoupMessage *msg)
{
	if (msg->status_code == SOUP_STATUS_PROXY_UNAUTHORIZED)
		return "Proxy-Authenticate";
	else
		return "WWW-Authenticate";
}

static SoupAuthClass *
auth_class_for_header (SoupAuthManager *manager, const char *header)
{
	char *scheme;
	SoupAuthClass *auth_class;

	scheme = g_strndup (header, strcspn (header, " "));
	auth_class = g_hash_table_lookup (manager->auth_types, scheme);
	g_free (scheme);
	return auth_class;
}

static SoupAuth *
create_auth (SoupAuthManager *manager, SoupMessage *msg)
{
	const char *header_name, *tryheader, *header = NULL;
	SoupAuthClass *auth_class = NULL, *try_class;
	int i;

	header_name = header_name_for_message (msg);

	for (i = 0; (tryheader = soup_message_headers_find_nth (msg->response_headers, header_name, i)); i++) {
		try_class = auth_class_for_header (manager, tryheader);
		if (!try_class)
			continue;
		if (!auth_class ||
		    auth_class->strength < try_class->strength) {
			header = tryheader;
			auth_class = try_class;
		}
	}

	if (!auth_class)
		return NULL;
	return soup_auth_new (G_TYPE_FROM_CLASS (auth_class), msg, header);
}

static gboolean
check_auth (SoupAuthManager *manager, SoupMessage *msg, SoupAuth *auth)
{
	const char *header_name, *tryheader, *scheme_name;
	int scheme_len, i;

	header_name = header_name_for_message (msg);
	scheme_name = soup_auth_get_scheme_name (auth);
	scheme_len = strlen (scheme_name);

	for (i = 0; (tryheader = soup_message_headers_find_nth (msg->response_headers, header_name, i)); i++) {
		if (!strncmp (tryheader, scheme_name, scheme_len) &&
		    (!tryheader[scheme_len] || tryheader[scheme_len] == ' '))
			break;
	}

	if (!tryheader)
		return FALSE;

	return soup_auth_update (auth, msg, tryheader);
}

static SoupAuthHost *
get_auth_host_for_message (SoupAuthManager *manager, SoupMessage *msg)
{
	SoupAuthHost *host;
	const SoupURI *source = soup_message_get_uri (msg);

	host = g_hash_table_lookup (manager->auth_hosts, source);
	if (host)
		return host;

	host = g_new0 (SoupAuthHost, 1);
	host->root_uri = soup_uri_copy_root (source);
	g_hash_table_insert (manager->auth_hosts, host->root_uri, host);

	return host;
}

static SoupAuth *
lookup_auth (SoupAuthManager *manager, SoupMessage *msg)
{
	SoupAuthHost *host;
	const char *path, *realm;

	host = get_auth_host_for_message (manager, msg);
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
		   gboolean proxy)
{
	char *username = NULL, *password = NULL;
	SoupURI *uri;

	if (soup_auth_is_authenticated (auth))
		return TRUE;

	if (proxy) {
		g_object_get (G_OBJECT (manager->session),
			      SOUP_SESSION_PROXY_URI, &uri,
			      NULL);
	} else
		uri = soup_uri_copy (soup_message_get_uri (msg));

	if (uri->password && !prior_auth_failed) {
		soup_auth_authenticate (auth, uri->user, uri->password);
		soup_uri_free (uri);
		return TRUE;
	}
	soup_uri_free (uri);

	if (prior_auth_failed) {
		soup_session_emit_reauthenticate (
			manager->session, msg, soup_auth_get_scheme_name (auth),
			soup_auth_get_realm (auth), &username, &password,
			NULL);
	} else {
		soup_session_emit_authenticate (
			manager->session, msg, soup_auth_get_scheme_name (auth),
			soup_auth_get_realm (auth), &username, &password,
			NULL);
	}
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
update_auth (SoupAuthManager *manager, SoupMessage *msg)
{
	SoupAuthHost *host;
	SoupAuth *auth, *prior_auth, *old_auth;
	const char *path;
	char *auth_info, *old_auth_info;
	GSList *pspace, *p;
	gboolean prior_auth_failed = FALSE;

	host = get_auth_host_for_message (manager, msg);

	/* See if we used auth last time */
	prior_auth = soup_message_get_auth (msg);
	if (prior_auth && check_auth (manager, msg, prior_auth)) {
		auth = prior_auth;
		if (!soup_auth_is_authenticated (auth))
			prior_auth_failed = TRUE;
	} else {
		auth = create_auth (manager, msg);
		if (!auth)
			return FALSE;
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
	return authenticate_auth (manager, auth, msg,
				  prior_auth_failed, FALSE);
}

static gboolean
update_proxy_auth (SoupAuthManager *manager, SoupMessage *msg)
{
	SoupAuth *prior_auth;
	gboolean prior_auth_failed = FALSE;

	/* See if we used auth last time */
	prior_auth = soup_message_get_proxy_auth (msg);
	if (prior_auth && check_auth (manager, msg, prior_auth)) {
		if (!soup_auth_is_authenticated (prior_auth))
			prior_auth_failed = TRUE;
	}

	if (!manager->proxy_auth) {
		manager->proxy_auth = create_auth (manager, msg);
		if (!manager->proxy_auth)
			return FALSE;
	}

	/* If we need to authenticate, try to do it. */
	return authenticate_auth (manager, manager->proxy_auth, msg,
				  prior_auth_failed, TRUE);
}

static void
authorize_handler (SoupMessage *msg, gpointer user_data)
{
	SoupAuthManager *manager = user_data;

	if (update_auth (manager, msg))
		soup_session_requeue_message (manager->session, msg);
}

static void
proxy_authorize_handler (SoupMessage *msg, gpointer user_data)
{
	SoupAuthManager *manager = user_data;

	if (update_proxy_auth (manager, msg))
		soup_session_requeue_message (manager->session, msg);
}

static void
session_request_started (SoupSession *session, SoupMessage *msg,
			 gpointer data)
{
	SoupAuthManager *manager = data;
	SoupAuth *auth;

	auth = lookup_auth (manager, msg);
	if (!auth || !authenticate_auth (manager, auth, msg, FALSE, FALSE))
		auth = NULL;
	soup_message_set_auth (msg, auth);
	soup_message_add_status_code_handler (
		msg, "got_body", SOUP_STATUS_UNAUTHORIZED,
		G_CALLBACK (authorize_handler), manager);

	auth = manager->proxy_auth;
	if (!auth || !authenticate_auth (manager, auth, msg, FALSE, TRUE))
		auth = NULL;
	soup_message_set_proxy_auth (msg, auth);
	soup_message_add_status_code_handler (
		msg, "got_body", SOUP_STATUS_PROXY_UNAUTHORIZED,
		G_CALLBACK (proxy_authorize_handler), manager);
}


