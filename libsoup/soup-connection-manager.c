/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2022 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-connection-manager.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-session-private.h"
#include "soup-uri-utils-private.h"
#include "soup.h"

struct _SoupConnectionManager {
        SoupSession *session;

        GMutex mutex;
        GCond cond;
        GSocketConnectable *remote_connectable;
        guint max_conns;
        guint max_conns_per_host;
        guint num_conns;

        GHashTable *http_hosts;
        GHashTable *https_hosts;
        GHashTable *conns;

        guint64 last_connection_id;
};

typedef struct {
        GUri *uri;
        GMutex *mutex;
        GHashTable *owner_map;
        GNetworkAddress *addr;

        GList *conns;
        guint  num_conns;

        GMainContext *context;
        GSource *keep_alive_src;
} SoupHost;

#define HOST_KEEP_ALIVE (5 * 60 * 1000) /* 5 min in msecs */

static SoupHost *
soup_host_new (GUri         *uri,
               GHashTable   *owner_map,
               GMutex       *mutex,
               GMainContext *context)
{
        SoupHost *host;
        const char *scheme = g_uri_get_scheme (uri);

        host = g_new0 (SoupHost, 1);
        host->owner_map = owner_map;
        host->mutex = mutex;
        if (g_strcmp0 (scheme, "http") != 0 && g_strcmp0 (scheme, "https") != 0) {
                host->uri = soup_uri_copy (uri,
                                           SOUP_URI_SCHEME, soup_uri_is_https (uri) ? "https" : "http",
                                           SOUP_URI_NONE);
        } else
                host->uri = g_uri_ref (uri);

        host->addr = g_object_new (G_TYPE_NETWORK_ADDRESS,
                                   "hostname", g_uri_get_host (host->uri),
                                   "port", g_uri_get_port (host->uri),
                                   "scheme", g_uri_get_scheme (host->uri),
                                   NULL);

        host->context = context;

        g_hash_table_insert (host->owner_map, host->uri, host);

        return host;
}

static void
soup_host_free (SoupHost *host)
{
        g_warn_if_fail (host->conns == NULL);

        if (host->keep_alive_src) {
                g_source_destroy (host->keep_alive_src);
                g_source_unref (host->keep_alive_src);
        }

        g_uri_unref (host->uri);
        g_object_unref (host->addr);
        g_free (host);
}

/* Note that we can't use soup_uri_host_hash() and soup_uri_host_equal()
 * because we want to ignore the protocol; http://example.com and
 * webcal://example.com are the same host.
 */
static guint
soup_host_uri_hash (gconstpointer key)
{
        GUri *uri = (GUri*)key;

        g_warn_if_fail (uri != NULL && g_uri_get_host (uri) != NULL);

        return g_uri_get_port (uri) + soup_str_case_hash (g_uri_get_host (uri));
}

static gboolean
soup_host_uri_equal (gconstpointer v1, gconstpointer v2)
{
        GUri *one = (GUri*)v1;
        GUri *two = (GUri*)v2;

        g_warn_if_fail (one != NULL && two != NULL);

        const char *one_host = g_uri_get_host (one);
        const char *two_host = g_uri_get_host (two);
        g_warn_if_fail (one_host != NULL && two_host != NULL);

        if (g_uri_get_port (one) != g_uri_get_port (two))
                return FALSE;

        return g_ascii_strcasecmp (one_host, two_host) == 0;
}

static gboolean
free_unused_host (gpointer user_data)
{
        SoupHost *host = (SoupHost *)user_data;
        GMutex *mutex = host->mutex;

        g_mutex_lock (mutex);

        g_clear_pointer (&host->keep_alive_src, g_source_unref);

        if (!host->conns) {
                /* This will free the host in addition to removing it from the hash table */
                g_hash_table_remove (host->owner_map, host->uri);
        }

        g_mutex_unlock (mutex);

        return G_SOURCE_REMOVE;
}

static void
soup_host_add_connection (SoupHost       *host,
                          SoupConnection *conn)
{
        host->conns = g_list_prepend (host->conns, conn);
        host->num_conns++;

        if (host->keep_alive_src) {
                g_source_destroy (host->keep_alive_src);
                g_source_unref (host->keep_alive_src);
                host->keep_alive_src = NULL;
        }
}

static void
soup_host_remove_connection (SoupHost       *host,
                             SoupConnection *conn)
{
        host->conns = g_list_remove (host->conns, conn);
        host->num_conns--;

        /* Free the SoupHost (and its GNetworkAddress) if there
         * has not been any new connection to the host during
         * the last HOST_KEEP_ALIVE msecs.
         */
        if (host->num_conns == 0) {
                g_assert (host->keep_alive_src == NULL);
                host->keep_alive_src = soup_add_timeout (host->context,
                                                         HOST_KEEP_ALIVE,
                                                         free_unused_host,
                                                         host);
        }
}

static SoupHost *
soup_connection_manager_get_host_for_message (SoupConnectionManager *manager,
                                              SoupMessage           *msg)
{
        GUri *uri = soup_message_get_uri (msg);
        GHashTable *map;

        map = soup_uri_is_https (uri) ?  manager->https_hosts : manager->http_hosts;
        return g_hash_table_lookup (map, uri);
}

static SoupHost *
soup_connection_manager_get_or_create_host_for_item (SoupConnectionManager *manager,
                                                     SoupMessageQueueItem  *item)
{
        GUri *uri = soup_message_get_uri (item->msg);
        GHashTable *map;
        SoupHost *host;

        map = soup_uri_is_https (uri) ?  manager->https_hosts : manager->http_hosts;
        host = g_hash_table_lookup (map, uri);
        if (!host)
                host = soup_host_new (uri, map, &manager->mutex, soup_session_get_context (item->session));

        return host;
}

static void
soup_connection_manager_drop_connection (SoupConnectionManager *manager,
                                         SoupConnection        *conn)
{
        g_signal_handlers_disconnect_by_data (conn, manager);
        manager->num_conns--;
        g_object_unref (conn);

        g_cond_broadcast (&manager->cond);
}

static void
remove_connection (gpointer key,
                   gpointer value,
                   gpointer user_data)
{
        SoupConnectionManager *manager = user_data;
        soup_connection_manager_drop_connection (manager, key);
}

SoupConnectionManager *
soup_connection_manager_new (SoupSession *session,
                             guint        max_conns,
                             guint        max_conns_per_host)
{
        SoupConnectionManager *manager;

        manager = g_new0 (SoupConnectionManager, 1);
        manager->session = session;
        manager->max_conns = max_conns;
        manager->max_conns_per_host = max_conns_per_host;
        manager->http_hosts = g_hash_table_new_full (soup_host_uri_hash,
                                                     soup_host_uri_equal,
                                                     NULL,
                                                     (GDestroyNotify)soup_host_free);
        manager->https_hosts = g_hash_table_new_full (soup_host_uri_hash,
                                                      soup_host_uri_equal,
                                                      NULL,
                                                      (GDestroyNotify)soup_host_free);
        manager->conns = g_hash_table_new (NULL, NULL);
        g_mutex_init (&manager->mutex);
        g_cond_init (&manager->cond);

        return manager;
}

void
soup_connection_manager_free (SoupConnectionManager *manager)
{
        g_hash_table_foreach (manager->conns, remove_connection, manager);
        g_assert (manager->num_conns == 0);

        g_clear_object (&manager->remote_connectable);
        g_hash_table_destroy (manager->http_hosts);
        g_hash_table_destroy (manager->https_hosts);
        g_hash_table_destroy (manager->conns);
        g_mutex_clear (&manager->mutex);
        g_cond_clear (&manager->cond);

        g_free (manager);
}

void
soup_connection_manager_set_max_conns (SoupConnectionManager *manager,
                                       guint                  max_conns)
{
        g_assert (manager->num_conns == 0);
        manager->max_conns = max_conns;
}

guint
soup_connection_manager_get_max_conns (SoupConnectionManager *manager)
{
        return manager->max_conns;
}

void
soup_connection_manager_set_max_conns_per_host (SoupConnectionManager *manager,
                                                guint                  max_conns_per_host)
{
        g_assert (manager->num_conns == 0);
        manager->max_conns_per_host = max_conns_per_host;
}

guint
soup_connection_manager_get_max_conns_per_host (SoupConnectionManager *manager)
{
        return manager->max_conns_per_host;
}

void
soup_connection_manager_set_remote_connectable (SoupConnectionManager *manager,
                                                GSocketConnectable    *connectable)
{
        g_assert (manager->num_conns == 0);
        manager->remote_connectable = connectable ? g_object_ref (connectable) : NULL;
}

GSocketConnectable *
soup_connection_manager_get_remote_connectable (SoupConnectionManager *manager)
{
        return manager->remote_connectable;
}

guint
soup_connection_manager_get_num_conns (SoupConnectionManager *manager)
{
        return manager->num_conns;
}

static void
soup_connection_list_disconnect_all (GList *conns)
{
        GList *c;

        for (c = conns; c; c = g_list_next (c)) {
                SoupConnection *conn = (SoupConnection *)c->data;

                soup_connection_disconnect (conn);
                g_object_unref (conn);
	}
        g_list_free (conns);
}

static GList *
soup_connection_manager_cleanup_locked (SoupConnectionManager *manager,
                                        gboolean               cleanup_idle)
{
        GList *conns = NULL;
        GHashTableIter iter;
        SoupConnection *conn;
        SoupHost *host;

        g_hash_table_iter_init (&iter, manager->conns);
        while (g_hash_table_iter_next (&iter, (gpointer *)&conn, (gpointer *)&host)) {
                SoupConnectionState state;

                state = soup_connection_get_state (conn);
                if (state == SOUP_CONNECTION_IDLE && (cleanup_idle || !soup_connection_is_idle_open (conn))) {
                        conns = g_list_prepend (conns, g_object_ref (conn));
                        g_hash_table_iter_remove (&iter);
                        soup_host_remove_connection (host, conn);
                        soup_connection_manager_drop_connection (manager, conn);
                }
        }

        return conns;
}

static void
connection_disconnected (SoupConnection        *conn,
                         SoupConnectionManager *manager)
{
        SoupHost *host = NULL;

        g_mutex_lock (&manager->mutex);
        g_hash_table_steal_extended (manager->conns, conn, NULL, (gpointer *)&host);
        if (host)
                soup_host_remove_connection (host, conn);
        soup_connection_manager_drop_connection (manager, conn);
        g_mutex_unlock (&manager->mutex);

        soup_session_kick_queue (manager->session);
}

static void
connection_state_changed (SoupConnection        *conn,
                          GParamSpec            *param,
                          SoupConnectionManager *manager)
{
        if (soup_connection_get_state (conn) != SOUP_CONNECTION_IDLE)
                return;

        g_mutex_lock (&manager->mutex);
        g_cond_broadcast (&manager->cond);
        g_mutex_unlock (&manager->mutex);

        soup_session_kick_queue (manager->session);
}

static SoupConnection *
soup_connection_manager_get_connection_locked (SoupConnectionManager *manager,
                                               SoupMessageQueueItem  *item)
{
        static int env_force_http1 = -1;
        SoupMessage *msg = item->msg;
        gboolean need_new_connection;
        SoupConnection *conn;
        SoupSocketProperties *socket_props;
        SoupHost *host;
        guint8 force_http_version;
        GList *l;
        GSocketConnectable *remote_connectable;
        gboolean try_cleanup = TRUE;

        if (env_force_http1 == -1)
                env_force_http1 = g_getenv ("SOUP_FORCE_HTTP1") != NULL ? 1 : 0;

        need_new_connection =
                (soup_message_query_flags (msg, SOUP_MESSAGE_NEW_CONNECTION)) ||
                (soup_message_is_misdirected_retry (msg)) ||
                (!soup_message_query_flags (msg, SOUP_MESSAGE_IDEMPOTENT) &&
                 !SOUP_METHOD_IS_IDEMPOTENT (soup_message_get_method (msg)));

        host = soup_connection_manager_get_or_create_host_for_item (manager, item);

        force_http_version = env_force_http1 ? SOUP_HTTP_1_1 : soup_message_get_force_http_version (msg);
        while (TRUE) {
                for (l = host->conns; l && l->data; l = g_list_next (l)) {
                        SoupHTTPVersion http_version;

                        conn = (SoupConnection *)l->data;

                        http_version = soup_connection_get_negotiated_protocol (conn);
                        if (force_http_version <= SOUP_HTTP_2_0 && http_version != force_http_version)
                                continue;

                        switch (soup_connection_get_state (conn)) {
                        case SOUP_CONNECTION_IN_USE:
                                if (!need_new_connection && http_version == SOUP_HTTP_2_0 && soup_connection_get_owner (conn) == g_thread_self () && soup_connection_is_reusable (conn))
                                        return conn;
                                break;
                        case SOUP_CONNECTION_IDLE:
                                if (!need_new_connection && soup_connection_is_idle_open (conn))
                                        return conn;
                                break;
                        case SOUP_CONNECTION_CONNECTING:
                                if (soup_session_steal_preconnection (item->session, item, conn))
                                        return conn;

                                /* Always wait if we have a pending connection as it may be
                                 * an h2 connection which will be shared. http/1.x connections
                                 * will only be slightly delayed. */
                                if (force_http_version > SOUP_HTTP_1_1 && !need_new_connection && !item->connect_only && item->async && soup_connection_get_owner (conn) == g_thread_self ())
                                        return NULL;
                        default:
                                break;
                        }
                }

                if (host->num_conns >= manager->max_conns_per_host) {
                        if (need_new_connection && try_cleanup) {
                                GList *conns;

                                try_cleanup = FALSE;
                                conns = soup_connection_manager_cleanup_locked (manager, TRUE);
                                if (conns) {
                                        /* The connection has already been removed and the signals disconnected so,
                                         * it's ok to disconnect with the mutex locked.
                                         */
                                        soup_connection_list_disconnect_all (conns);
                                        continue;
                                }
                        }

                        if (item->async)
                                return NULL;

                        g_cond_wait (&manager->cond, &manager->mutex);
                        try_cleanup = TRUE;
                        continue;
                }

                if (manager->num_conns >= manager->max_conns) {
                        if (try_cleanup) {
                                GList *conns;

                                try_cleanup = FALSE;
                                conns = soup_connection_manager_cleanup_locked (manager, TRUE);
                                if (conns) {
                                        /* The connection has already been removed and the signals disconnected so,
                                         * it's ok to disconnect with the mutex locked.
                                         */
                                        soup_connection_list_disconnect_all (conns);
                                        continue;
                                }
                        }

                        if (item->async)
                                return NULL;

                        g_cond_wait (&manager->cond, &manager->mutex);
                        try_cleanup = TRUE;
                        continue;
                }

                break;
        }

        /* Create a new connection */
        remote_connectable = manager->remote_connectable ? manager->remote_connectable : G_SOCKET_CONNECTABLE (host->addr);
        socket_props = soup_session_ensure_socket_props (item->session);
        conn = g_object_new (SOUP_TYPE_CONNECTION,
                             "id", ++manager->last_connection_id,
                             "context", soup_session_get_context (item->session),
                             "remote-connectable", remote_connectable,
                             "ssl", soup_uri_is_https (host->uri),
                             "socket-properties", socket_props,
                             "force-http-version", force_http_version,
                             NULL);

        g_signal_connect (conn, "disconnected",
                          G_CALLBACK (connection_disconnected),
                          manager);
        g_signal_connect (conn, "notify::state",
                          G_CALLBACK (connection_state_changed),
                          manager);

        g_hash_table_insert (manager->conns, conn, host);

        manager->num_conns++;
        soup_host_add_connection (host, conn);

        return conn;
}

SoupConnection *
soup_connection_manager_get_connection (SoupConnectionManager *manager,
                                        SoupMessageQueueItem  *item)
{
        SoupConnection *conn;

        soup_connection_manager_cleanup (manager, FALSE);

        conn = soup_message_get_connection (item->msg);
        if (conn) {
                g_warn_if_fail (soup_connection_get_state (conn) != SOUP_CONNECTION_DISCONNECTED);
                g_object_unref (conn);
                return conn;
        }

        g_mutex_lock (&manager->mutex);
        conn = soup_connection_manager_get_connection_locked (manager, item);
        if (conn)
                soup_message_set_connection (item->msg, conn);
        g_mutex_unlock (&manager->mutex);

        return conn;
}

gboolean
soup_connection_manager_cleanup (SoupConnectionManager *manager,
                                 gboolean               cleanup_idle)
{
        GList *conns;

        g_mutex_lock (&manager->mutex);
        conns = soup_connection_manager_cleanup_locked (manager, cleanup_idle);
        g_mutex_unlock (&manager->mutex);

        if (conns) {
                soup_connection_list_disconnect_all (conns);

                return TRUE;
        }

        return FALSE;
}

GIOStream *
soup_connection_manager_steal_connection (SoupConnectionManager *manager,
                                          SoupMessage           *msg)
{
        SoupConnection *conn;
        SoupHost *host;
        GIOStream *stream;

        conn = soup_message_get_connection (msg);
        if (!conn)
                return NULL;

        if (soup_connection_get_state (conn) != SOUP_CONNECTION_IN_USE) {
                g_object_unref (conn);
                return NULL;
        }

        g_mutex_lock (&manager->mutex);
        host = soup_connection_manager_get_host_for_message (manager, msg);
        g_hash_table_remove (manager->conns, conn);
        soup_host_remove_connection (host, conn);
        soup_connection_manager_drop_connection (manager, conn);
        g_mutex_unlock (&manager->mutex);

        stream = soup_connection_steal_iostream (conn);
        soup_message_set_connection (msg, NULL);
        g_object_unref (conn);

        return stream;
}
