/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-socket.c: Socket networking code.
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>
#include <gio/gnetworking.h>

#include "soup-socket.h"
#include "soup.h"
#include "soup-io-stream.h"

/*<private>
 * SECTION:soup-socket
 * @short_description: A network socket
 *
 * #SoupSocket is libsoup's TCP socket type. While it is primarily
 * intended for internal use, #SoupSocket<!-- -->s are exposed in the
 * API in various places, and some of their methods (eg,
 * soup_socket_get_remote_address()) may be useful to applications.
 **/

enum {
	DISCONNECTED,
	NEW_CONNECTION,
        ACCEPT_CERTIFICATE,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_GSOCKET,
	PROP_IOSTREAM,
	PROP_LOCAL_ADDRESS,
        PROP_REMOTE_ADDRESS,
	PROP_REMOTE_CONNECTABLE,
	PROP_IPV6_ONLY,
	PROP_TLS_CERTIFICATE,
        PROP_TLS_DATABASE,
        PROP_TLS_AUTH_MODE,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

struct _SoupSocket {
	GObject parent_instance;
};

typedef struct {
	GInetSocketAddress *local_addr, *remote_addr;
	GSocketConnectable *remote_connectable;
	GIOStream *conn, *iostream;
	GSocket *gsock;
	GInputStream *istream;
	GOutputStream *ostream;

	guint ipv6_only:1;
	guint ssl:1;
	GTlsCertificate *tls_certificate;
        GTlsDatabase *tls_database;
        GTlsAuthenticationMode tls_auth_mode;

	GMainContext   *async_context;
	GSource        *watch_src;
} SoupSocketPrivate;

static void soup_socket_initable_interface_init (GInitableIface *initable_interface);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupSocket, soup_socket, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupSocket)
			       G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
						      soup_socket_initable_interface_init))

static void finish_socket_setup (SoupSocket *sock);
static void finish_listener_setup (SoupSocket *sock);

static void
soup_socket_init (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

        priv->async_context = g_main_context_ref_thread_default ();
}

static gboolean
soup_socket_initable_init (GInitable     *initable,
			   GCancellable  *cancellable,
			   GError       **error)
{
	SoupSocket *sock = SOUP_SOCKET (initable);
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	if (priv->conn) {
		g_warn_if_fail (priv->gsock == NULL);

		finish_socket_setup (sock);
	}

	if (priv->gsock != NULL) {
		int listening;

		g_warn_if_fail (priv->local_addr == NULL);
		g_warn_if_fail (priv->remote_addr == NULL);

		if (!g_socket_get_option (priv->gsock,
					  SOL_SOCKET, SO_ACCEPTCONN,
					  &listening, error)) {
			g_prefix_error (error, _("Could not import existing socket: "));
			return FALSE;
		}

		finish_socket_setup (sock);
		if (listening)
			finish_listener_setup (sock);
		else if (!g_socket_is_connected (priv->gsock)) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
					     _("Can’t import unconnected socket"));
			return FALSE;
		}
	}

	return TRUE;
}

static void
disconnect_internal (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	g_clear_object (&priv->gsock);
	if (priv->conn) {
		g_io_stream_close (priv->conn, NULL, NULL);
		g_signal_handlers_disconnect_by_data (priv->conn, sock);
		g_clear_object (&priv->conn);
	}
}

static void
soup_socket_finalize (GObject *object)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	if (priv->conn)
		disconnect_internal (SOUP_SOCKET (object));

	g_clear_object (&priv->conn);
	g_clear_object (&priv->iostream);
	g_clear_object (&priv->istream);
	g_clear_object (&priv->ostream);

	g_clear_object (&priv->local_addr);
	g_clear_object (&priv->remote_addr);
        g_clear_object (&priv->remote_connectable);

	g_clear_object (&priv->tls_certificate);
        g_clear_object (&priv->tls_database);

	if (priv->watch_src) {
		g_source_destroy (priv->watch_src);
		g_source_unref (priv->watch_src);
	}
	g_clear_pointer (&priv->async_context, g_main_context_unref);

	G_OBJECT_CLASS (soup_socket_parent_class)->finalize (object);
}

static void
finish_socket_setup (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	if (priv->gsock) {
		if (!priv->conn)
			priv->conn = (GIOStream *)g_socket_connection_factory_create_connection (priv->gsock);

		g_socket_set_option (priv->gsock, IPPROTO_TCP, TCP_NODELAY, TRUE, NULL);
	}

	if (!priv->conn)
		return;

	if (!priv->iostream)
		priv->iostream = soup_io_stream_new (priv->conn, FALSE);
	if (!priv->istream)
		priv->istream = g_object_ref (g_io_stream_get_input_stream (priv->iostream));
	if (!priv->ostream)
		priv->ostream = g_object_ref (g_io_stream_get_output_stream (priv->iostream));
}

static void
soup_socket_set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	switch (prop_id) {
	case PROP_GSOCKET:
		priv->gsock = g_value_dup_object (value);
		break;
	case PROP_IOSTREAM:
		priv->conn = g_value_dup_object (value);
		break;
	case PROP_LOCAL_ADDRESS:
		priv->local_addr = g_value_dup_object (value);
		break;
        case PROP_REMOTE_ADDRESS:
                priv->remote_addr = g_value_dup_object (value);
                break;
	case PROP_REMOTE_CONNECTABLE:
		priv->remote_connectable = g_value_dup_object (value);
		break;
	case PROP_IPV6_ONLY:
		priv->ipv6_only = g_value_get_boolean (value);
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
soup_socket_get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	SoupSocket *sock = SOUP_SOCKET (object);
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	switch (prop_id) {
	case PROP_LOCAL_ADDRESS:
		g_value_set_object (value, soup_socket_get_local_address (sock));
		break;
        case PROP_REMOTE_ADDRESS:
                g_value_set_object (value, soup_socket_get_remote_address (sock));
                break;
	case PROP_REMOTE_CONNECTABLE:
		g_value_set_object (value, priv->remote_connectable);
		break;
	case PROP_IPV6_ONLY:
		g_value_set_boolean (value, priv->ipv6_only);
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
soup_socket_class_init (SoupSocketClass *socket_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (socket_class);

	/* virtual method override */
	object_class->finalize = soup_socket_finalize;
	object_class->set_property = soup_socket_set_property;
	object_class->get_property = soup_socket_get_property;

	/* signals */

	/**
	 * SoupSocket::disconnected:
	 * @sock: the socket
	 *
	 * Emitted when the socket is disconnected, for whatever
	 * reason.
	 **/
	signals[DISCONNECTED] =
		g_signal_new ("disconnected",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupSocket::new-connection:
	 * @sock: the socket
	 * @new: the new socket
	 *
	 * Emitted when a listening socket receives a new connection.
	 *
	 * Has to be set up with [func@soup_socket_listen].
	 *
	 * You must ref the @new if you want to keep it; otherwise it
	 * will be destroyed after the signal is emitted.
	 **/
	signals[NEW_CONNECTION] =
		g_signal_new ("new_connection",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SOCKET);

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

	/* properties */
        properties[PROP_GSOCKET] =
                g_param_spec_object ("gsocket",
                                     "GSocket",
                                     "The socket's underlying GSocket",
                                     G_TYPE_SOCKET,
                                     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);
        properties[PROP_IOSTREAM] =
                g_param_spec_object ("iostream",
                                     "GIOStream",
                                     "The socket's underlying GIOStream",
                                     G_TYPE_IO_STREAM,
                                     G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
                                     G_PARAM_STATIC_STRINGS);

        properties[PROP_LOCAL_ADDRESS] =
		g_param_spec_object ("local-address",
				     "Local address",
				     "Address of local end of socket",
				     G_TYPE_INET_SOCKET_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        properties[PROP_REMOTE_ADDRESS] =
		g_param_spec_object ("remote-address",
				     "Remote address",
				     "Address of remote end of socket",
				     G_TYPE_SOCKET_ADDRESS,
				     G_PARAM_READABLE |
				     G_PARAM_STATIC_STRINGS);

        properties[PROP_REMOTE_CONNECTABLE] =
		g_param_spec_object ("remote-connectable",
				     "Remote address",
				     "Address to connect to",
				     G_TYPE_SOCKET_CONNECTABLE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS);

        properties[PROP_IPV6_ONLY] =
		g_param_spec_boolean ("ipv6-only",
				      "IPv6 only",
				      "IPv6 only",
				      FALSE,
				      G_PARAM_READWRITE |
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

static void
soup_socket_initable_interface_init (GInitableIface *initable_interface)
{
	initable_interface->init = soup_socket_initable_init;
}


/**
 * soup_socket_new:
 * @optname1: name of first property to set (or %NULL)
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates a new (disconnected) socket
 *
 * Returns: the new socket
 **/
SoupSocket *
soup_socket_new (const char *optname1, ...)
{
	SoupSocket *sock;
	va_list ap;

	va_start (ap, optname1);
	sock = (SoupSocket *)g_object_new_valist (SOUP_TYPE_SOCKET,
						  optname1, ap);
	va_end (ap);

	return sock;
}

GSocket *
soup_socket_get_gsocket (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	priv = soup_socket_get_instance_private (sock);

	return priv->gsock;
}

GSocket *
soup_socket_steal_gsocket (SoupSocket *sock)
{
	SoupSocketPrivate *priv;
	GSocket *gsock;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);
	priv = soup_socket_get_instance_private (sock);

	gsock = g_steal_pointer (&priv->gsock);
	g_clear_object (&priv->conn);
	g_clear_object (&priv->iostream);

	return gsock;
}

GIOStream *
soup_socket_get_iostream (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);

	priv = soup_socket_get_instance_private (sock);

	return priv->iostream;
}

static gboolean
tls_connection_accept_certificate (SoupSocket          *sock,
                                   GTlsCertificate     *tls_certificate,
                                   GTlsCertificateFlags tls_errors)
{
        gboolean accept = FALSE;

        g_signal_emit (sock, signals[ACCEPT_CERTIFICATE], 0,
                       tls_certificate, tls_errors, &accept);
        return accept;
}

static gboolean
soup_socket_setup_ssl (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);
	GTlsBackend *backend = g_tls_backend_get_default ();
	GTlsServerConnection *conn;

	if (G_IS_TLS_CONNECTION (priv->conn))
		return TRUE;

	priv->ssl = TRUE;

	conn = g_initable_new (g_tls_backend_get_server_connection_type (backend),
			       NULL, NULL,
			       "base-io-stream", priv->conn,
			       "certificate", priv->tls_certificate,
			       "database", priv->tls_database,
                               "authentication-mode", priv->tls_auth_mode,
			       "require-close-notify", FALSE,
			       NULL);
	if (!conn)
		return FALSE;

	g_object_unref (priv->conn);
	priv->conn = G_IO_STREAM (conn);

        g_signal_connect_object (priv->conn, "accept-certificate",
                                 G_CALLBACK (tls_connection_accept_certificate),
                                 sock, G_CONNECT_SWAPPED);

	g_clear_object (&priv->istream);
	g_clear_object (&priv->ostream);
	g_clear_object (&priv->iostream);
	priv->iostream = soup_io_stream_new (priv->conn, FALSE);
	priv->istream = g_object_ref (g_io_stream_get_input_stream (priv->iostream));
	priv->ostream = g_object_ref (g_io_stream_get_output_stream (priv->iostream));

	return TRUE;
}

static gboolean
listen_watch (GObject *pollable, gpointer data)
{
	SoupSocket *sock = data, *new;
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock), *new_priv;
	GSocket *new_gsock;

	new_gsock = g_socket_accept (priv->gsock, NULL, NULL);
	if (!new_gsock)
		return FALSE;

	new = g_object_new (SOUP_TYPE_SOCKET, NULL);
	new_priv = soup_socket_get_instance_private (new);
	new_priv->gsock = new_gsock;
	new_priv->async_context = g_main_context_ref (priv->async_context);
	new_priv->ssl = priv->ssl;
	if (priv->tls_certificate)
		new_priv->tls_certificate = g_object_ref (priv->tls_certificate);
        if (priv->tls_database)
                new_priv->tls_database = g_object_ref (priv->tls_database);
        new_priv->tls_auth_mode = priv->tls_auth_mode;
	finish_socket_setup (new);

	if (new_priv->tls_certificate) {
		if (!soup_socket_setup_ssl (new)) {
			g_object_unref (new);
			return TRUE;
		}
	}

	g_signal_emit (sock, signals[NEW_CONNECTION], 0, new);
	g_object_unref (new);

	return TRUE;
}

static void
finish_listener_setup (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	priv->watch_src = g_pollable_input_stream_create_source (G_POLLABLE_INPUT_STREAM (priv->istream), NULL);
	g_source_set_callback (priv->watch_src, (GSourceFunc)listen_watch, sock, NULL);
	g_source_attach (priv->watch_src, priv->async_context);
}

/**
 * soup_socket_listen:
 * @sock: a server #SoupSocket (which must not already be connected or listening)
 * @error: error pointer
 *
 * Makes @sock start listening on its local address.
 *
 * When connections come in, @sock will emit #SoupSocket::new_connection.
 *
 * Returns: whether or not @sock is now listening.
 **/
gboolean
soup_socket_listen (SoupSocket *sock,
		    GError    **error)

{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);
	priv = soup_socket_get_instance_private (sock);
	g_return_val_if_fail (priv->gsock == NULL, FALSE);
	g_return_val_if_fail (priv->local_addr != NULL, FALSE);

	/* @local_addr may have its port set to 0. So we intentionally
	 * don't store it in priv->local_addr, so that if the
	 * caller calls soup_socket_get_local_address() later, we'll
	 * have to make a new addr by calling getsockname(), which
	 * will have the right port number.
	 */
	g_return_val_if_fail (priv->local_addr != NULL, FALSE);

	priv->gsock = g_socket_new (g_socket_address_get_family (G_SOCKET_ADDRESS (priv->local_addr)),
				    G_SOCKET_TYPE_STREAM,
				    G_SOCKET_PROTOCOL_DEFAULT,
				    error);
	if (!priv->gsock)
		goto cant_listen;
	finish_socket_setup (sock);

	if (priv->ipv6_only) {
                GError *error = NULL;
                g_socket_set_option (priv->gsock, IPPROTO_IPV6, IPV6_V6ONLY, TRUE, &error);
                if (error) {
                        g_warning ("Failed to set IPv6 only on socket: %s", error->message);
                        g_error_free (error);
                }
	}

	/* Bind */
	if (!g_socket_bind (priv->gsock, G_SOCKET_ADDRESS (priv->local_addr), TRUE, error))
		goto cant_listen;
	/* Force local_addr to be re-resolved now */
        g_clear_object (&priv->local_addr);

	/* Listen */
	if (!g_socket_listen (priv->gsock, error))
		goto cant_listen;
	finish_listener_setup (sock);
	return TRUE;

 cant_listen:
	if (priv->conn)
		disconnect_internal (sock);

	return FALSE;
}

/**
 * soup_socket_is_ssl:
 * @sock: a #SoupSocket
 *
 * Tests if @sock is doing (or has attempted to do) SSL.
 *
 * Returns: %TRUE if @sock has SSL credentials set
 **/
gboolean
soup_socket_is_ssl (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	return priv->ssl || priv->tls_certificate;
}

/**
 * soup_socket_disconnect:
 * @sock: a #SoupSocket
 *
 * Disconnects @sock. Any further read or write attempts on it will
 * fail.
 **/
void
soup_socket_disconnect (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_if_fail (SOUP_IS_SOCKET (sock));
	priv = soup_socket_get_instance_private (sock);

	if (!priv->conn)
		return;

	disconnect_internal (sock);

	/* Keep ref around signals in case the object is unreferenced
	 * in a handler
	 */
	g_object_ref (sock);

	/* FIXME: can't disconnect until all data is read */

	/* Then let everyone know we're disconnected */
	g_signal_emit (sock, signals[DISCONNECTED], 0);

	g_object_unref (sock);
}

/**
 * soup_socket_is_connected:
 * @sock: a #SoupSocket
 *
 * Tests if @sock is connected to another host
 *
 * Returns: %TRUE or %FALSE.
 **/
gboolean
soup_socket_is_connected (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), FALSE);
	priv = soup_socket_get_instance_private (sock);

	return priv->conn && !g_io_stream_is_closed (priv->conn);
}

/**
 * soup_socket_get_local_address:
 * @sock: a #SoupSocket
 *
 * Returns the #GInetSocketAddress corresponding to the local end of @sock.
 *
 * Calling this method on an unconnected socket is considered to be
 * an error, and produces undefined results.
 *
 * Returns: (transfer none): the #GInetSocketAddress
 **/
GInetSocketAddress *
soup_socket_get_local_address (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);
	priv = soup_socket_get_instance_private (sock);

	if (!priv->local_addr) {
		GError *error = NULL;

		if (priv->gsock == NULL) {
			g_warning ("%s: socket not connected", G_STRLOC);
			return NULL;
		}

		priv->local_addr = G_INET_SOCKET_ADDRESS (g_socket_get_local_address (priv->gsock, &error));
		if (priv->local_addr == NULL) {
			g_warning ("%s: %s", G_STRLOC, error->message);
			g_error_free (error);
                        return NULL;
		}
	}

	return priv->local_addr;
}

/**
 * soup_socket_get_remote_address:
 * @sock: a #SoupSocket
 *
 * Returns the #GInetSocketAddress corresponding to the remote end of @sock.
 *
 * Calling this method on an unconnected socket is considered to be
 * an error, and produces undefined results.
 *
 * Returns: (transfer none): the #GInetSocketAddress
 **/
GInetSocketAddress *
soup_socket_get_remote_address (SoupSocket *sock)
{
	SoupSocketPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOCKET (sock), NULL);
	priv = soup_socket_get_instance_private (sock);

        if (!priv->remote_addr) {
                GError *error = NULL;

                // We may be conencting to a socket address rather than a network address
                if (G_IS_INET_SOCKET_ADDRESS (priv->remote_connectable)) {
                        priv->remote_addr = g_object_ref (G_INET_SOCKET_ADDRESS (priv->remote_connectable));
                        return priv->remote_addr;
                }

                if (priv->gsock == NULL) {
		        g_warning ("%s: socket not connected", G_STRLOC);
                        return NULL;
                }

                priv->remote_addr = G_INET_SOCKET_ADDRESS (g_socket_get_remote_address (priv->gsock, &error));
                if (priv->remote_addr == NULL) {
                        g_warning ("%s: %s", G_STRLOC, error->message);
                        g_error_free (error);
                        return NULL;
                }
        }

        return priv->remote_addr;
}

GIOStream *
soup_socket_get_connection (SoupSocket *sock)
{
	SoupSocketPrivate *priv = soup_socket_get_instance_private (sock);

	return priv->conn;
}
