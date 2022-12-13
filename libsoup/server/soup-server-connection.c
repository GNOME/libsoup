/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-server-connection.c: Connection networking code.
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

#include "soup-server-connection.h"
#include "soup.h"
#include "soup-io-stream.h"
#include "soup-server-message-private.h"
#include "soup-server-message-io-http1.h"
#include "soup-server-message-io-http2.h"

enum {
        CONNECTED,
        DISCONNECTED,
        ACCEPT_CERTIFICATE,
        REQUEST_STARTED,
        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
        PROP_0,

        PROP_SOCKET,
        PROP_CONNECTION,
        PROP_LOCAL_ADDRESS,
        PROP_REMOTE_ADDRESS,
        PROP_TLS_CERTIFICATE,
        PROP_TLS_DATABASE,
        PROP_TLS_AUTH_MODE,
        PROP_TLS_PEER_CERTIFICATE,
        PROP_TLS_PEER_CERTIFICATE_ERRORS,

        LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupServerConnection {
        GObject parent_instance;
};

typedef struct {
        GSocket *socket;
        GIOStream *conn;
        GIOStream *iostream;
        SoupServerMessage *initial_msg;
        gboolean advertise_http2;
        SoupHTTPVersion http_version;
        SoupServerMessageIO *io_data;

        GSocketAddress *local_addr;
        GSocketAddress *remote_addr;

        GTlsCertificate *tls_certificate;
        GTlsDatabase *tls_database;
        GTlsAuthenticationMode tls_auth_mode;
} SoupServerConnectionPrivate;

G_DEFINE_FINAL_TYPE_WITH_PRIVATE (SoupServerConnection, soup_server_connection, G_TYPE_OBJECT)

static void
request_started_cb (SoupServerMessage    *msg,
                    SoupServerConnection *conn)
{
        g_signal_emit (conn, signals[REQUEST_STARTED], 0, msg);
}

static void
soup_server_connection_init (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        priv->http_version = SOUP_HTTP_1_1;
}

static void
disconnect_internal (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        g_clear_object (&priv->socket);

        g_io_stream_close (priv->conn, NULL, NULL);
        g_signal_handlers_disconnect_by_data (priv->conn, conn);
        g_clear_object (&priv->conn);
        g_clear_object (&priv->initial_msg);

        g_clear_pointer (&priv->io_data, soup_server_message_io_destroy);
}

static void
soup_server_connection_finalize (GObject *object)
{
        SoupServerConnection *conn = SOUP_SERVER_CONNECTION (object);
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        if (priv->conn) {
                disconnect_internal (conn);
        } else {
                g_clear_object (&priv->socket);
                g_clear_pointer (&priv->io_data, soup_server_message_io_destroy);
        }

        g_clear_object (&priv->iostream);

        g_clear_object (&priv->local_addr);
        g_clear_object (&priv->remote_addr);

        g_clear_object (&priv->tls_certificate);
        g_clear_object (&priv->tls_database);

        G_OBJECT_CLASS (soup_server_connection_parent_class)->finalize (object);
}

static void
soup_server_connection_set_property (GObject      *object,
                                     guint         prop_id,
                                     const GValue *value,
                                     GParamSpec   *pspec)
{
        SoupServerConnection *conn = SOUP_SERVER_CONNECTION (object);
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        switch (prop_id) {
        case PROP_SOCKET:
                priv->socket = g_value_dup_object (value);
                break;
        case PROP_CONNECTION:
                priv->conn = g_value_dup_object (value);
                if (priv->conn)
                        priv->iostream = soup_io_stream_new (priv->conn, FALSE);
                break;
        case PROP_LOCAL_ADDRESS:
                priv->local_addr = g_value_dup_object (value);
                break;
        case PROP_REMOTE_ADDRESS:
                priv->remote_addr = g_value_dup_object (value);
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
soup_server_connection_get_property (GObject    *object,
                                     guint       prop_id,
                                     GValue     *value,
                                     GParamSpec *pspec)
{
        SoupServerConnection *conn = SOUP_SERVER_CONNECTION (object);
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        switch (prop_id) {
        case PROP_SOCKET:
                g_value_set_object (value, priv->socket);
                break;
        case PROP_CONNECTION:
                g_value_set_object (value, priv->conn);
                break;
        case PROP_LOCAL_ADDRESS:
                g_value_set_object (value, soup_server_connection_get_local_address (conn));
                break;
        case PROP_REMOTE_ADDRESS:
                g_value_set_object (value, soup_server_connection_get_remote_address (conn));
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
        case PROP_TLS_PEER_CERTIFICATE:
                g_value_set_object (value, soup_server_connection_get_tls_peer_certificate (conn));
                break;
        case PROP_TLS_PEER_CERTIFICATE_ERRORS:
                g_value_set_flags (value, soup_server_connection_get_tls_peer_certificate_errors (conn));
                break;
        default:
                G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
                break;
        }
}

static void
soup_server_connection_class_init (SoupServerConnectionClass *conn_class)
{
        GObjectClass *object_class = G_OBJECT_CLASS (conn_class);

        object_class->finalize = soup_server_connection_finalize;
        object_class->set_property = soup_server_connection_set_property;
        object_class->get_property = soup_server_connection_get_property;

        signals[CONNECTED] =
                g_signal_new ("connected",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerConnection::disconnected:
         * @conn: the connection
         *
         * Emitted when the connection is disconnected, for whatever reason.
         **/
        signals[DISCONNECTED] =
                g_signal_new ("disconnected",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        signals[ACCEPT_CERTIFICATE] =
                g_signal_new ("accept-certificate",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              g_signal_accumulator_true_handled, NULL,
                              NULL,
                              G_TYPE_BOOLEAN, 2,
                              G_TYPE_TLS_CERTIFICATE,
                              G_TYPE_TLS_CERTIFICATE_FLAGS);
        signals[REQUEST_STARTED] =
                g_signal_new ("request-started",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 1,
                              SOUP_TYPE_SERVER_MESSAGE);

        /* properties */
        properties[PROP_SOCKET] =
                g_param_spec_object ("socket",
                                     "Socket",
                                     "The connection underlying GSocket",
                                     G_TYPE_SOCKET,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);
        properties[PROP_CONNECTION] =
                g_param_spec_object ("connection",
                                     "GIOStream",
                                     "The socket's underlying GIOStream",
                                     G_TYPE_IO_STREAM,
                                     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_LOCAL_ADDRESS] =
                g_param_spec_object ("local-address",
                                     "Local address",
                                     "Address of local end of socket",
                                     G_TYPE_SOCKET_ADDRESS,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_REMOTE_ADDRESS] =
                g_param_spec_object ("remote-address",
                                     "Remote address",
                                     "Address of remote end of socket",
                                     G_TYPE_SOCKET_ADDRESS,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_CERTIFICATE] =
                g_param_spec_object ("tls-certificate",
                                     "TLS Certificate",
                                     "The server TLS certificate",
                                     G_TYPE_TLS_CERTIFICATE,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_DATABASE] =
                g_param_spec_object ("tls-database",
                                     "TLS Database",
                                     "The server TLS database",
                                     G_TYPE_TLS_DATABASE,
                                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_AUTH_MODE] =
                g_param_spec_enum ("tls-auth-mode",
                                   "TLS Authentication Mode",
                                   "The server TLS authentication mode",
                                   G_TYPE_TLS_AUTHENTICATION_MODE,
                                   G_TLS_AUTHENTICATION_NONE,
                                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
                                   G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_PEER_CERTIFICATE] =
                g_param_spec_object ("tls-peer-certificate",
                                     "TLS Peer Certificate",
                                     "The TLS peer certificate associated with the message",
                                     G_TYPE_TLS_CERTIFICATE,
                                     G_PARAM_READABLE |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_TLS_PEER_CERTIFICATE_ERRORS] =
                g_param_spec_flags ("tls-peer-certificate-errors",
                                    "TLS Peer Certificate Errors",
                                    "The verification errors on the message's TLS peer certificate",
                                    G_TYPE_TLS_CERTIFICATE_FLAGS, 0,
                                    G_PARAM_READABLE |
                                    G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

SoupServerConnection *
soup_server_connection_new (GSocket               *socket,
                            GTlsCertificate       *tls_certificate,
                            GTlsDatabase          *tls_database,
                            GTlsAuthenticationMode tls_auth_mode)
{
        g_return_val_if_fail (G_IS_SOCKET (socket), NULL);
        g_return_val_if_fail (!tls_certificate || G_IS_TLS_CERTIFICATE (tls_certificate), NULL);
        g_return_val_if_fail (!tls_database || G_IS_TLS_DATABASE (tls_database), NULL);

        return g_object_new (SOUP_TYPE_SERVER_CONNECTION,
                             "socket", socket,
                             "tls-certificate", tls_certificate,
                             "tls-database", tls_database,
                             "tls-auth-mode", tls_auth_mode,
                             NULL);
}

SoupServerConnection *
soup_server_connection_new_for_connection (GIOStream      *connection,
                                           GSocketAddress *local_addr,
                                           GSocketAddress *remote_addr)
{
        g_return_val_if_fail (G_IS_IO_STREAM (connection), NULL);
        g_return_val_if_fail (G_IS_SOCKET_ADDRESS (local_addr), NULL);
        g_return_val_if_fail (G_IS_SOCKET_ADDRESS (remote_addr), NULL);

        return g_object_new (SOUP_TYPE_SERVER_CONNECTION,
                             "connection", connection,
                             "local-address", local_addr,
                             "remote-address", remote_addr,
                             NULL);
}

SoupServerMessageIO *
soup_server_connection_get_io_data (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        return priv->io_data;
}

static void
soup_server_connection_connected (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        g_assert (!priv->io_data);
        switch (priv->http_version) {
        case SOUP_HTTP_1_0:
        case SOUP_HTTP_1_1:
                priv->io_data = soup_server_message_io_http1_new (conn,
                                                                  g_steal_pointer (&priv->initial_msg),
                                                                  (SoupMessageIOStartedFn)request_started_cb,
                                                                  conn);
                break;
        case SOUP_HTTP_2_0:
                priv->io_data = soup_server_message_io_http2_new (conn,
                                                                  g_steal_pointer (&priv->initial_msg),
                                                                  (SoupMessageIOStartedFn)request_started_cb,
                                                                  conn);
                break;
        }
        g_signal_emit (conn, signals[CONNECTED], 0);
}

static gboolean
tls_connection_accept_certificate (SoupServerConnection *conn,
                                   GTlsCertificate      *tls_certificate,
                                   GTlsCertificateFlags  tls_errors)
{
        gboolean accept = FALSE;

        g_signal_emit (conn, signals[ACCEPT_CERTIFICATE], 0,
                       tls_certificate, tls_errors, &accept);
        return accept;
}

static void
tls_connection_peer_certificate_changed (SoupServerConnection *conn)
{
       g_object_notify_by_pspec (G_OBJECT (conn), properties[PROP_TLS_CERTIFICATE]);
}

static void
tls_connection_handshake_ready_cb (GTlsConnection       *tls_conn,
                                   GAsyncResult         *result,
                                   SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv = soup_server_connection_get_instance_private (conn);

        if (g_tls_connection_handshake_finish (tls_conn, result, NULL)) {
                const char *protocol = g_tls_connection_get_negotiated_protocol (tls_conn);

                if (g_strcmp0 (protocol, "h2") == 0)
                        priv->http_version = SOUP_HTTP_2_0;
                else if (g_strcmp0 (protocol, "http/1.0") == 0)
                        priv->http_version = SOUP_HTTP_1_0;
                else if (g_strcmp0 (protocol, "http/1.1") == 0)
                        priv->http_version = SOUP_HTTP_1_1;

                soup_server_connection_connected (conn);
        } else {
                soup_server_connection_disconnect (conn);
        }
}

void
soup_server_connection_set_advertise_http2 (SoupServerConnection *conn,
                                            gboolean              advertise_http2)
{
        SoupServerConnectionPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER_CONNECTION (conn));

        priv = soup_server_connection_get_instance_private (conn);
        priv->advertise_http2 = advertise_http2;
}

void
soup_server_connection_accepted (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;
        GIOStream *connection;

        g_return_if_fail (SOUP_IS_SERVER_CONNECTION (conn));

        priv = soup_server_connection_get_instance_private (conn);

        /* We need to create the first message earlier here because SoupServerMessage is used
         * to accept the TLS certificate.
         */
        g_assert (!priv->initial_msg);
        priv->initial_msg = soup_server_message_new (conn);
        g_signal_emit (conn, signals[REQUEST_STARTED], 0, priv->initial_msg);

        if (priv->conn || !priv->socket) {
                soup_server_connection_connected (conn);
                return;
        }

        connection = (GIOStream *)g_socket_connection_factory_create_connection (priv->socket);
        g_socket_set_option (priv->socket, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);

        if (priv->tls_certificate) {
                GPtrArray *advertised_protocols;

                advertised_protocols = g_ptr_array_sized_new (4);
                if (priv->advertise_http2 && priv->tls_auth_mode == G_TLS_AUTHENTICATION_NONE)
                        g_ptr_array_add (advertised_protocols, "h2");
                g_ptr_array_add (advertised_protocols, "http/1.1");
                g_ptr_array_add (advertised_protocols, "http/1.0");
                g_ptr_array_add (advertised_protocols, NULL);

                priv->conn = g_initable_new (g_tls_backend_get_server_connection_type (g_tls_backend_get_default ()),
                                             NULL, NULL,
                                             "base-io-stream", connection,
                                             "certificate", priv->tls_certificate,
                                             "database", priv->tls_database,
                                             "authentication-mode", priv->tls_auth_mode,
                                             "require-close-notify", FALSE,
                                             "advertised-protocols", advertised_protocols->pdata,
                                             NULL);
                g_ptr_array_unref (advertised_protocols);
                g_object_unref (connection);
                if (!priv->conn) {
                        soup_server_connection_disconnect (conn);
                        return;
                }

                priv->iostream = soup_io_stream_new (priv->conn, FALSE);

                g_signal_connect_object (priv->conn, "accept-certificate",
                                         G_CALLBACK (tls_connection_accept_certificate),
                                         conn, G_CONNECT_SWAPPED);
                g_signal_connect_object (priv->conn, "notify::peer-certificate",
                                         G_CALLBACK (tls_connection_peer_certificate_changed),
                                         conn, G_CONNECT_SWAPPED);

                g_tls_connection_handshake_async (G_TLS_CONNECTION (priv->conn),
                                                  G_PRIORITY_DEFAULT, NULL,
                                                  (GAsyncReadyCallback)tls_connection_handshake_ready_cb,
                                                  conn);
                return;
        }

        priv->conn = connection;
        priv->iostream = soup_io_stream_new (priv->conn, FALSE);
        soup_server_connection_connected (conn);
}

GSocket *
soup_server_connection_get_socket (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);

        return priv->socket;
}

GIOStream *
soup_server_connection_steal (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;
        GIOStream *stream;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);

        stream = priv->io_data ? soup_server_message_io_steal (priv->io_data) : NULL;
        if (stream && priv->socket) {
                g_object_set_data_full (G_OBJECT (stream), "GSocket",
                                        g_object_ref (priv->socket),
                                        g_object_unref);
        }

        /* Cache local and remote address */
        soup_server_connection_get_local_address (conn);
        soup_server_connection_get_remote_address (conn);

        g_clear_pointer (&priv->io_data, soup_server_message_io_destroy);
        g_clear_object (&priv->conn);
        g_clear_object (&priv->iostream);

        g_signal_emit (conn, signals[DISCONNECTED], 0);

        return stream;
}

GIOStream *
soup_server_connection_get_iostream (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);

        return priv->iostream;
}

/**
 * soup_server_connection_is_ssl:
 * @conn: a #SoupServerConnection
 *
 * Tests if @sock is doing (or has attempted to do) SSL.
 *
 * Returns: %TRUE if @conn has SSL credentials set
 **/
gboolean
soup_server_connection_is_ssl (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), FALSE);

        priv = soup_server_connection_get_instance_private (conn);

        return G_IS_TLS_CONNECTION (priv->conn) || priv->tls_certificate;
}

/**
 * soup_server_connection_disconnect:
 * @sock: a #SoupServerConnection
 *
 * Disconnects @conn. Any further read or write attempts on it will fail.
 **/
void
soup_server_connection_disconnect (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER_CONNECTION (conn));

        priv = soup_server_connection_get_instance_private (conn);

        if (!priv->conn)
                return;

        disconnect_internal (conn);

        /* Keep ref around signals in case the object is unreferenced
         * in a handler
         */
        g_object_ref (conn);

        /* FIXME: can't disconnect until all data is read */

        /* Then let everyone know we're disconnected */
        g_signal_emit (conn, signals[DISCONNECTED], 0);

        g_object_unref (conn);
}

/**
 * soup_server_connection_is_connected:
 * @conn: a #SoupServerConnection
 *
 * Tests if @conn is connected to another host
 *
 * Returns: %TRUE or %FALSE.
 **/
gboolean
soup_server_connection_is_connected (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), FALSE);

        priv = soup_server_connection_get_instance_private (conn);

        return priv->conn && !g_io_stream_is_closed (priv->conn);
}

/**
 * soup_server_connection_get_local_address:
 * @conn: a #SoupServerConnection
 *
 * Returns the #GInetSocketAddress corresponding to the local end of @conn.
 *
 * Calling this method on an unconnected socket is considered to be
 * an error, and produces undefined results.
 *
 * Returns: (transfer none): the #GSocketAddress
 **/
GSocketAddress *
soup_server_connection_get_local_address (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);
        if (!priv->local_addr) {
                GError *error = NULL;

                priv->local_addr = g_socket_get_local_address (priv->socket, &error);
                if (priv->local_addr == NULL) {
                        g_warning ("%s: %s", G_STRLOC, error->message);
                        g_error_free (error);
                        return NULL;
                }
        }

        return priv->local_addr;
}

/**
 * soup_server_connection_get_remote_address:
 * @conn: a #SoupServerConnection
 *
 * Returns the #GInetSocketAddress corresponding to the remote end of @conn.
 *
 * Calling this method on an unconnected socket is considered to be
 * an error, and produces undefined results.
 *
 * Returns: (transfer none): the #GSocketAddress
 **/
GSocketAddress *
soup_server_connection_get_remote_address (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);

        if (!priv->remote_addr) {
                GError *error = NULL;

                priv->remote_addr = g_socket_get_remote_address (priv->socket, &error);
                if (priv->remote_addr == NULL) {
                        g_warning ("%s: %s", G_STRLOC, error->message);
                        g_error_free (error);
                        return NULL;
                }
        }

        return priv->remote_addr;
}

GTlsCertificate *
soup_server_connection_get_tls_peer_certificate (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), NULL);

        priv = soup_server_connection_get_instance_private (conn);

        if (!G_IS_TLS_CONNECTION (priv->conn))
                return NULL;

        return g_tls_connection_get_peer_certificate (G_TLS_CONNECTION (priv->conn));
}

GTlsCertificateFlags
soup_server_connection_get_tls_peer_certificate_errors (SoupServerConnection *conn)
{
        SoupServerConnectionPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER_CONNECTION (conn), 0);

        priv = soup_server_connection_get_instance_private (conn);

        if (!G_IS_TLS_CONNECTION (priv->conn))
                return 0;

        return g_tls_connection_get_peer_certificate_errors (G_TLS_CONNECTION (priv->conn));
}
