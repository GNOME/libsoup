/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-connection.c: A single HTTP/HTTPS connection
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include <fcntl.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

#include "soup-connection.h"
#include "soup-private.h"
#include "soup-marshal.h"
#include "soup-misc.h"
#include "soup-socket.h"
#include "soup-ssl.h"

struct SoupConnectionPrivate {
	SoupSocket *socket;
	gboolean    in_use, new;
	time_t      last_used;
	guint       death_tag;
};

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

enum {
	CONNECT_RESULT,
	DISCONNECTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
init (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	conn->priv = g_new0 (SoupConnectionPrivate, 1);
	conn->priv->in_use = FALSE;
	conn->priv->new = TRUE;
}

static void
finalize (GObject *object)
{
	SoupConnection *conn = SOUP_CONNECTION (object);

	soup_connection_disconnect (conn);
	g_free (conn->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;

	/* signals */
	signals[CONNECT_RESULT] =
		g_signal_new ("connect_result",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, connect_result),
			      NULL, NULL,
			      soup_marshal_NONE__INT,
			      G_TYPE_NONE, 1,
			      G_TYPE_INT);
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupConnectionClass, disconnected),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
}

SOUP_MAKE_TYPE (soup_connection, SoupConnection, class_init, init, PARENT_TYPE)


static void
socket_disconnected (SoupSocket *sock, gpointer conn)
{
	soup_connection_disconnect (conn);
}

static void
socket_connected (SoupSocket *sock, SoupKnownErrorCode status, gpointer conn)
{
	g_signal_emit (conn, signals[CONNECT_RESULT], 0, status);
}

/**
 * soup_connection_new:
 * @uri: remote machine to connect to
 * @callback: callback to call after connecting
 * @user_data: data for @callback
 *
 * Creates a connection to @uri. @callback will be called when the
 * connection completes (or fails).
 *
 * Return value: the new connection (not yet ready for use).
 **/
SoupConnection *
soup_connection_new (const SoupUri *uri,
		     SoupConnectionCallback callback, gpointer user_data)
{
	SoupConnection *conn;

	conn = g_object_new (SOUP_TYPE_CONNECTION, NULL);

	soup_signal_connect_once (conn, "connect_result",
				  G_CALLBACK (callback), user_data);
	conn->priv->socket = soup_socket_client_new (uri->host, uri->port,
						     uri->protocol == SOUP_PROTOCOL_HTTPS,
						     socket_connected, conn);
	g_signal_connect (conn->priv->socket, "disconnected",
			  G_CALLBACK (socket_disconnected), conn);
	return conn;
}

/**
 * soup_connection_disconnect:
 * @conn: a connection
 *
 * Disconnects @conn's socket and emits a %disconnected signal.
 * After calling this, @conn will be essentially useless.
 **/
void
soup_connection_disconnect (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	if (conn->priv->death_tag) {
		g_source_remove (conn->priv->death_tag);
		conn->priv->death_tag = 0;
	}

	if (conn->priv->socket) {
		g_object_unref (conn->priv->socket);
		conn->priv->socket = NULL;
		g_signal_emit (conn, signals[DISCONNECTED], 0);
	}
}

gboolean
soup_connection_is_connected (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->socket != NULL;
}

/**
 * soup_connection_get_socket:
 * @conn: a #SoupConnection.
 *
 * Return value: @conn's socket
 */
SoupSocket *
soup_connection_get_socket (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), NULL);

	return conn->priv->socket;
}


static gboolean
connection_died (GIOChannel   *iochannel,
		  GIOCondition  condition,
		  gpointer      conn)
{
	soup_connection_disconnect (conn);
	return FALSE;
}

/**
 * soup_connection_set_in_use:
 * @conn: a connection
 * @in_use: whether or not @conn is in_use
 *
 * Marks @conn as being either in use or not. If @in_use is %FALSE,
 * @conn's last-used time is updated.
 **/
void
soup_connection_set_in_use (SoupConnection *conn, gboolean in_use)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	if (!conn->priv->socket) {
		if (in_use)
			g_warning ("Trying to use disconnected socket");
		return;
	}

	if (!in_use)
		conn->priv->last_used = time (NULL);

	if (in_use == conn->priv->in_use)
		return;

	conn->priv->in_use = in_use;
	if (!conn->priv->in_use) {
		conn->priv->death_tag = 
			g_io_add_watch (soup_socket_get_iochannel (conn->priv->socket),
					G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					connection_died,
					conn);
	} else if (conn->priv->death_tag) {
		g_source_remove (conn->priv->death_tag);
		conn->priv->death_tag = 0;
	}
}

/**
 * soup_connection_is_in_use:
 * @conn: a connection
 *
 * Return value: whether or not @conn is being used.
 **/
gboolean
soup_connection_is_in_use (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->in_use;
}

/**
 * soup_connection_last_used:
 * @conn: a #SoupConnection.
 *
 * Return value: the last time soup_connection_mark_used() was called
 * on @conn, or 0 if @conn has not been used yet.
 */
time_t
soup_connection_last_used (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->last_used;
}

/**
 * soup_connection_is_new:
 * @conn: a connection
 *
 * Return value: whether or not @conn is "new". (That is, it has not
 * yet completed a whole HTTP transaction.)
 **/
gboolean
soup_connection_is_new (SoupConnection *conn)
{
	g_return_val_if_fail (SOUP_IS_CONNECTION (conn), FALSE);

	return conn->priv->new;
}

/**
 * soup_connection_mark_old:
 * @conn: a #SoupConnection.
 *
 * Marks @conn as being no longer "new".
 * FIXME: some day, this should happen automatically.
 */
void
soup_connection_mark_old (SoupConnection *conn)
{
	g_return_if_fail (SOUP_IS_CONNECTION (conn));

	conn->priv->new = FALSE;
}
