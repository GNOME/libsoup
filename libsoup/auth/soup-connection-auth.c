/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-connection-auth.c: Abstract base class for hacky Microsoft
 * connection-based auth mechanisms (NTLM and Negotiate)
 *
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <string.h>

#include "soup-connection-auth.h"
#include "soup.h"
#include "soup-connection.h"
#include "soup-message-private.h"

typedef struct {
	GHashTable *conns;
	GMutex lock;
} SoupConnectionAuthPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (SoupConnectionAuth, soup_connection_auth, SOUP_TYPE_AUTH)

static void
soup_connection_auth_init (SoupConnectionAuth *auth)
{
	SoupConnectionAuthPrivate *priv = soup_connection_auth_get_instance_private (auth);

	g_mutex_init (&priv->lock);
	priv->conns = g_hash_table_new (NULL, NULL);
}

static void connection_disconnected (SoupConnection *conn, gpointer user_data);

static void
soup_connection_auth_free_connection_state (SoupConnectionAuth *auth,
					    SoupConnection     *conn,
					    gpointer            state)
{
	g_signal_handlers_disconnect_by_func (conn, G_CALLBACK (connection_disconnected), auth);
	SOUP_CONNECTION_AUTH_GET_CLASS (auth)->free_connection_state (auth, state);
}

static void
connection_disconnected (SoupConnection *conn, gpointer user_data)
{
	SoupConnectionAuth *auth = user_data;
        SoupConnectionAuthPrivate *priv = soup_connection_auth_get_instance_private (auth);
	gpointer state;

	g_mutex_lock (&priv->lock);
	state = g_hash_table_lookup (priv->conns, conn);
	g_hash_table_remove (priv->conns, conn);
	g_mutex_unlock (&priv->lock);
	soup_connection_auth_free_connection_state (auth, conn, state);
}

static void
soup_connection_auth_finalize (GObject *object)
{
	SoupConnectionAuth *auth = SOUP_CONNECTION_AUTH (object);
        SoupConnectionAuthPrivate *priv = soup_connection_auth_get_instance_private (auth);
	GHashTableIter iter;
	gpointer conn, state;

	g_mutex_lock (&priv->lock);
	g_hash_table_iter_init (&iter, priv->conns);
	while (g_hash_table_iter_next (&iter, &conn, &state)) {
		soup_connection_auth_free_connection_state (auth, conn, state);
		g_hash_table_iter_remove (&iter);
	}
	g_hash_table_destroy (priv->conns);
	g_mutex_unlock (&priv->lock);
	g_mutex_clear (&priv->lock);

	G_OBJECT_CLASS (soup_connection_auth_parent_class)->finalize (object);
}


/**
 * soup_connection_auth_get_connection_state_for_message:
 * @auth: a #SoupConnectionAuth
 * @msg: a #SoupMessage
 *
 * Returns an associated connection state object for the given @auth and @msg.
 *
 * This function is only useful from within implementations of SoupConnectionAuth
 * subclasses.
 *
 * Returns: (transfer none): the connection state
 *
 **/
gpointer
soup_connection_auth_get_connection_state_for_message (SoupConnectionAuth *auth,
						       SoupMessage *msg)
{
        SoupConnectionAuthPrivate *priv = soup_connection_auth_get_instance_private (auth);
	SoupConnection *conn;
	gpointer state;

	g_return_val_if_fail (SOUP_IS_CONNECTION_AUTH (auth), NULL);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	conn = soup_message_get_connection (msg);
	g_mutex_lock (&priv->lock);
	state = g_hash_table_lookup (priv->conns, conn);
	if (!state) {
                state = SOUP_CONNECTION_AUTH_GET_CLASS (auth)->create_connection_state (auth);
                g_hash_table_insert (priv->conns, conn, state);
                g_mutex_unlock (&priv->lock);
                if (conn) {
                        g_signal_connect_object (conn, "disconnected",
                                                 G_CALLBACK (connection_disconnected), auth, 0);
                }
        } else {
                g_mutex_unlock (&priv->lock);
	}
        g_clear_object (&conn);

	return state;
}

static gboolean
soup_connection_auth_update (SoupAuth    *auth,
			     SoupMessage *msg,
			     GHashTable  *auth_params)
{
	SoupConnectionAuth *cauth = SOUP_CONNECTION_AUTH (auth);
	gpointer conn = soup_connection_auth_get_connection_state_for_message (cauth, msg);
	GHashTableIter iter;
	GString *auth_header;
	gpointer key, value;
	gboolean result;

	/* Recreate @auth_header out of @auth_params. If the
	 * base64 data ended with 1 or more "="s, then it
	 * will have been parsed as key=value. Otherwise
	 * it will all have been parsed as key, and value
	 * will be %NULL.
	 */
	auth_header = g_string_new (soup_auth_get_scheme_name (auth));
	g_hash_table_iter_init (&iter, auth_params);
	if (g_hash_table_iter_next (&iter, &key, &value)) {
		if (value) {
			g_string_append_printf (auth_header, " %s=%s",
						(char *)key,
						(char *)value);
		} else {
			g_string_append_printf (auth_header, " %s",
						(char *)key);
		}

		if (g_hash_table_iter_next (&iter, &key, &value)) {
			g_string_free (auth_header, TRUE);
			return FALSE;
		}
	}

	result = SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
		update_connection (cauth, msg, auth_header->str, conn);

	g_string_free (auth_header, TRUE);
	return result;
}

static char *
soup_connection_auth_get_authorization (SoupAuth    *auth,
					SoupMessage *msg)
{
	SoupConnectionAuth *cauth = SOUP_CONNECTION_AUTH (auth);
	gpointer conn = soup_connection_auth_get_connection_state_for_message (cauth, msg);

	return SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
		get_connection_authorization (cauth, msg, conn);
}

static gboolean
soup_connection_auth_is_ready (SoupAuth    *auth,
			       SoupMessage *msg)
{
	SoupConnectionAuth *cauth = SOUP_CONNECTION_AUTH (auth);
	gpointer conn = soup_connection_auth_get_connection_state_for_message (cauth, msg);

	return SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
		is_connection_ready (SOUP_CONNECTION_AUTH (auth), msg, conn);
}

static void
soup_connection_auth_class_init (SoupConnectionAuthClass *connauth_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (connauth_class);
	GObjectClass *object_class = G_OBJECT_CLASS (connauth_class);

	auth_class->update = soup_connection_auth_update;
	auth_class->get_authorization = soup_connection_auth_get_authorization;
	auth_class->is_ready = soup_connection_auth_is_ready;

	object_class->finalize = soup_connection_auth_finalize;
}
