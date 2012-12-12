/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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

G_DEFINE_ABSTRACT_TYPE (SoupConnectionAuth, soup_connection_auth, SOUP_TYPE_AUTH)

struct SoupConnectionAuthPrivate {
	GHashTable *conns;
};

static void
soup_connection_auth_init (SoupConnectionAuth *auth)
{
	auth->priv = G_TYPE_INSTANCE_GET_PRIVATE (auth, SOUP_TYPE_CONNECTION_AUTH, SoupConnectionAuthPrivate);

	auth->priv->conns = g_hash_table_new (NULL, NULL);
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
	gpointer state;

	state = g_hash_table_lookup (auth->priv->conns, conn);
	g_hash_table_remove (auth->priv->conns, conn);
	soup_connection_auth_free_connection_state (auth, conn, state);
}

static void
soup_connection_auth_finalize (GObject *object)
{
	SoupConnectionAuth *auth = SOUP_CONNECTION_AUTH (object);
	GHashTableIter iter;
	gpointer conn, state;

	g_hash_table_iter_init (&iter, auth->priv->conns);
	while (g_hash_table_iter_next (&iter, &conn, &state)) {
		soup_connection_auth_free_connection_state (auth, conn, state);
		g_hash_table_iter_remove (&iter);
	}
	g_hash_table_destroy (auth->priv->conns);

	G_OBJECT_CLASS (soup_connection_auth_parent_class)->finalize (object);
}

static gpointer
get_connection_state_for_message (SoupConnectionAuth *auth, SoupMessage *msg)
{
	SoupConnection *conn;
	gpointer state;

	conn = soup_message_get_connection (msg);
	state = g_hash_table_lookup (auth->priv->conns, conn);
	if (state)
		return state;

	state = SOUP_CONNECTION_AUTH_GET_CLASS (auth)->create_connection_state (auth);
	if (conn) {
		g_signal_connect (conn, "disconnected",
				  G_CALLBACK (connection_disconnected), auth);
	}

	g_hash_table_insert (auth->priv->conns, conn, state);
	return state;
}

static gboolean
soup_connection_auth_update (SoupAuth    *auth,
			     SoupMessage *msg,
			     GHashTable  *auth_params)
{
	SoupConnectionAuth *cauth = SOUP_CONNECTION_AUTH (auth);
	gpointer conn = get_connection_state_for_message (cauth, msg);
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
	gpointer conn = get_connection_state_for_message (cauth, msg);

	return SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
		get_connection_authorization (cauth, msg, conn);
}

static gboolean
soup_connection_auth_is_ready (SoupAuth    *auth,
			       SoupMessage *msg)
{
	SoupConnectionAuth *cauth = SOUP_CONNECTION_AUTH (auth);
	gpointer conn = get_connection_state_for_message (cauth, msg);

	return SOUP_CONNECTION_AUTH_GET_CLASS (auth)->
		is_connection_ready (SOUP_CONNECTION_AUTH (auth), msg, conn);
}

static void
soup_connection_auth_class_init (SoupConnectionAuthClass *connauth_class)
{
	SoupAuthClass *auth_class = SOUP_AUTH_CLASS (connauth_class);
	GObjectClass *object_class = G_OBJECT_CLASS (connauth_class);

	g_type_class_add_private (connauth_class, sizeof (SoupConnectionAuthPrivate));

	auth_class->update = soup_connection_auth_update;
	auth_class->get_authorization = soup_connection_auth_get_authorization;
	auth_class->is_ready = soup_connection_auth_is_ready;

	object_class->finalize = soup_connection_auth_finalize;
}
