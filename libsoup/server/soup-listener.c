/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-listener.c: Socket listening networking code.
 *
 * Copyright (C) 2022 Igalia S.L.
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>
#include <gio/gnetworking.h>

#include "soup-listener.h"
#include "soup.h"
#include "soup-io-stream.h"
#include "soup-server-connection.h"

enum {
        NEW_CONNECTION,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
        PROP_0,

        PROP_SOCKET,
        PROP_TLS_CERTIFICATE,
        PROP_TLS_DATABASE,
        PROP_TLS_AUTH_MODE,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupListener {
        GObject parent_instance;
};

typedef struct {
        GSocket *socket;
        GIOStream *conn;
        GIOStream *iostream;
        GInetSocketAddress *local_addr;

        GTlsCertificate *tls_certificate;
        GTlsDatabase *tls_database;
        GTlsAuthenticationMode tls_auth_mode;

        GSource *source;
} SoupListenerPrivate;

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupListener, soup_listener, G_TYPE_OBJECT)

static void
soup_listener_init (SoupListener *listener)
{
}

static gboolean
listen_watch (GObject      *pollable,
              SoupListener *listener)
{
        SoupListenerPrivate *priv = soup_listener_get_instance_private (listener);
        GSocket *socket;
        SoupServerConnection *conn;

        socket = g_socket_accept (priv->socket, NULL, NULL);
        if (!socket)
                return G_SOURCE_REMOVE;

        conn = soup_server_connection_new (socket, priv->tls_certificate, priv->tls_database, priv->tls_auth_mode);
        g_object_unref (socket);

        g_signal_emit (listener, signals[NEW_CONNECTION], 0, conn);
        g_object_unref (conn);

        return G_SOURCE_CONTINUE;
}

static void
soup_listener_constructed (GObject *object)
{
        SoupListener *listener = SOUP_LISTENER (object);
        SoupListenerPrivate *priv = soup_listener_get_instance_private (listener);

        g_socket_set_option (priv->socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);

        priv->conn = (GIOStream *)g_socket_connection_factory_create_connection (priv->socket);
        priv->iostream = soup_io_stream_new (priv->conn, FALSE);
        priv->source = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (g_io_stream_get_input_stream (priv->iostream)), NULL);
        g_source_set_static_name (priv->source, "SoupListener");
        g_source_set_callback (priv->source, (GSourceFunc)listen_watch, listener, NULL);
        g_source_attach (priv->source, g_main_context_get_thread_default ());

        G_OBJECT_CLASS (soup_listener_parent_class)->constructed (object);
}

static void
soup_listener_finalize (GObject *object)
{
        SoupListener *listener = SOUP_LISTENER (object);
        SoupListenerPrivate *priv = soup_listener_get_instance_private (listener);

        if (priv->conn) {
                g_io_stream_close (priv->conn, NULL, NULL);
                g_clear_object (&priv->conn);
        }

        g_clear_object (&priv->socket);
        g_clear_object (&priv->iostream);
        g_clear_object (&priv->local_addr);

        g_clear_object (&priv->tls_certificate);
        g_clear_object (&priv->tls_database);

        if (priv->source) {
                g_source_destroy (priv->source);
                g_source_unref (priv->source);
        }

        G_OBJECT_CLASS (soup_listener_parent_class)->finalize (object);
}

static void
soup_listener_set_property (GObject      *object,
                            guint         prop_id,
                            const GValue *value,
                            GParamSpec   *pspec)
{
        SoupListener *listener = SOUP_LISTENER (object);
        SoupListenerPrivate *priv = soup_listener_get_instance_private (listener);

        switch (prop_id) {
        case PROP_SOCKET:
                priv->socket = g_value_dup_object (value);
                break;
        case PROP_TLS_CERTIFICATE:
                priv->tls_certificate = g_value_dup_object (value);
                break;
        case PROP_TLS_DATABASE:
                priv->tls_database = g_value_dup_object (value);
                break;
        case PROP_TLS_AUTH_MODE:
                priv->tls_auth_mode = g_value_get_enum (value);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
soup_listener_get_property (GObject    *object,
                            guint       prop_id,
                            GValue     *value,
                            GParamSpec *pspec)
{
        SoupListener *listener = SOUP_LISTENER (object);
        SoupListenerPrivate *priv = soup_listener_get_instance_private (listener);

        switch (prop_id) {
        case PROP_SOCKET:
                g_value_set_object (value, priv->socket);
                break;
        case PROP_TLS_CERTIFICATE:
                g_value_set_object (value, priv->tls_certificate);
                break;
        case PROP_TLS_DATABASE:
                g_value_set_object (value, priv->tls_database);
                break;
        case PROP_TLS_AUTH_MODE:
                g_value_set_enum (value, priv->tls_auth_mode);
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
soup_listener_class_init (SoupListenerClass *listener_class)
{
        GObjectClass *object_class = G_OBJECT_CLASS (listener_class);

        object_class->constructed = soup_listener_constructed;
        object_class->finalize = soup_listener_finalize;
        object_class->set_property = soup_listener_set_property;
        object_class->get_property = soup_listener_get_property;

        /**
         * SoupListener::new-connection:
         * @listener: the listener
         * @conn: the new connection
         *
         * Emitted when a listening socket receives a new connection.
         *
         * You must ref the @new if you want to keep it; otherwise it
         * will be destroyed after the signal is emitted.
         **/
        signals[NEW_CONNECTION] =
                g_signal_new ("new-connection",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 1,
                              SOUP_TYPE_SERVER_CONNECTION);

        /* properties */
        properties[PROP_SOCKET] =
                g_param_spec_object ("socket",
                                     "Socket",
                                     "The underlying GSocket",
                                     G_TYPE_SOCKET,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_CERTIFICATE] =
                g_param_spec_object ("tls-certificate",
                                     "TLS Certificate",
                                     "The server TLS certificate",
                                     G_TYPE_TLS_CERTIFICATE,
                                     G_PARAM_READWRITE |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_DATABASE] =
                g_param_spec_object ("tls-database",
                                     "TLS Database",
                                     "The server TLS database",
                                     G_TYPE_TLS_DATABASE,
                                     G_PARAM_READWRITE |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_AUTH_MODE] =
                g_param_spec_enum ("tls-auth-mode",
                                   "TLS Authentication Mode",
                                   "The server TLS authentication mode",
                                   G_TYPE_TLS_AUTHENTICATION_MODE,
                                   G_TLS_AUTHENTICATION_NONE,
                                   G_PARAM_READWRITE |
                                   G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

SoupListener *
soup_listener_new (GSocket *socket,
                   GError **error)
{
        int listening;

        g_return_val_if_fail (G_IS_SOCKET (socket), NULL);
        g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        if (!g_socket_get_option (socket, SOL_SOCKET, SO_ACCEPTCONN, &listening, error)) {
                g_prefix_error (error, _("Could not import existing socket: "));
                return NULL;
        }

        if (!listening && !g_socket_is_connected (socket)) {
                g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                     _("Can’t import unconnected socket"));
                return NULL;
        }

        return g_object_new (SOUP_TYPE_LISTENER, "socket", socket, NULL);
}

SoupListener *
soup_listener_new_for_address (GSocketAddress *address,
                               GError        **error)
{
        GSocket *socket;
        GSocketFamily family;
        SoupListener *listener;

        g_return_val_if_fail (G_IS_SOCKET_ADDRESS (address), NULL);
        g_return_val_if_fail (error == NULL || *error == NULL, NULL);

        family = g_socket_address_get_family (address);
        socket = g_socket_new (family, G_SOCKET_TYPE_STREAM, G_SOCKET_PROTOCOL_DEFAULT, error);
        if (!socket)
                return NULL;

        if (family == G_SOCKET_FAMILY_IPV6) {
                GError *option_error = NULL;

                g_socket_set_option (socket, IPPROTO_IPV6, IPV6_V6ONLY, TRUE, &option_error);
                if (option_error) {
                        g_warning ("Failed to set IPv6 only on socket: %s", option_error->message);
                        g_error_free (option_error);
                }
        }

        if (!g_socket_bind (socket, address, TRUE, error)) {
                g_object_unref (socket);

                return NULL;
        }

        if (!g_socket_listen (socket, error)) {
                g_object_unref (socket);

                return NULL;
        }

        listener = g_object_new (SOUP_TYPE_LISTENER, "socket", socket, NULL);
        g_object_unref (socket);

        return listener;
}

GSocket *
soup_listener_get_socket (SoupListener *listener)
{
        SoupListenerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_LISTENER (listener), NULL);

        priv = soup_listener_get_instance_private (listener);

        return priv->socket;
}

void
soup_listener_disconnect (SoupListener *listener)
{
        SoupListenerPrivate *priv;

        g_return_if_fail (SOUP_IS_LISTENER (listener));

        priv = soup_listener_get_instance_private (listener);
        g_clear_object (&priv->socket);
        if (priv->conn) {
                g_io_stream_close (priv->conn, NULL, NULL);
                g_clear_object (&priv->conn);
        }
}

gboolean
soup_listener_is_ssl (SoupListener *listener)
{
        SoupListenerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_LISTENER (listener), FALSE);

        priv = soup_listener_get_instance_private (listener);

        return priv->tls_certificate != NULL;
}

GInetSocketAddress *
soup_listener_get_address (SoupListener *listener)
{
        SoupListenerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_LISTENER (listener), NULL);

        priv = soup_listener_get_instance_private (listener);

        if (!priv->local_addr) {
                GError *error = NULL;

                priv->local_addr = G_INET_SOCKET_ADDRESS (g_socket_get_local_address (priv->socket, &error));
                if (priv->local_addr == NULL) {
                        g_warning ("%s: %s", G_STRLOC, error->message);
                        g_error_free (error);
                        return NULL;
                }
        }

        return priv->local_addr;
}
