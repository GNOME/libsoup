/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-server.c: Asynchronous HTTP server
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup-server-private.h"
#include "soup-server-message-private.h"
#include "soup-message-headers-private.h"
#include "soup.h"
#include "soup-misc.h"
#include "soup-path-map.h"
#include "soup-listener.h"
#include "soup-uri-utils-private.h"
#include "websocket/soup-websocket.h"
#include "websocket/soup-websocket-connection.h"
#include "websocket/soup-websocket-extension-deflate.h"

/**
 * SoupServer:
 *
 * [class@Server] provides a basic implementation of an HTTP server. The
 * recommended usage of this server is for internal use, tasks like
 * a mock server for tests, a private service for IPC, etc. It is not
 * recommended to be exposed to untrusted clients as it may be vulnerable
 * to denial of service attacks or other exploits.
 *
 * To begin, create a server using [ctor@Server.new]. Add at least one
 * handler by calling [method@Server.add_handler] or
 * [method@Server.add_early_handler]; the handler will be called to
 * process any requests underneath the path you pass. (If you want all
 * requests to go to the same handler, just pass "/" (or %NULL) for
 * the path.)
 *
 * When a new connection is accepted (or a new request is started on
 * an existing persistent connection), the [class@Server] will emit
 * [signal@Server::request-started] and then begin processing the request
 * as described below, but note that once the message is assigned a
 * status-code, then callbacks after that point will be
 * skipped. Note also that it is not defined when the callbacks happen
 * relative to various [class@ServerMessage] signals.
 *
 * Once the headers have been read, [class@Server] will check if there is
 * a [class@AuthDomain] `(qv)` covering the Request-URI; if so, and if the
 * message does not contain suitable authorization, then the
 * [class@AuthDomain] will set a status of %SOUP_STATUS_UNAUTHORIZED on
 * the message.
 *
 * After checking for authorization, [class@Server] will look for "early"
 * handlers (added with [method@Server.add_early_handler]) matching the
 * Request-URI. If one is found, it will be run; in particular, this
 * can be used to connect to signals to do a streaming read of the
 * request body.
 *
 * (At this point, if the request headers contain `Expect:
 * 100-continue`, and a status code has been set, then
 * [class@Server] will skip the remaining steps and return the response.
 * If the request headers contain `Expect:
 * 100-continue` and no status code has been set,
 * [class@Server] will return a %SOUP_STATUS_CONTINUE status before
 * continuing.)
 *
 * The server will then read in the response body (if present). At
 * this point, if there are no handlers at all defined for the
 * Request-URI, then the server will return %SOUP_STATUS_NOT_FOUND to
 * the client.
 *
 * Otherwise (assuming no previous step assigned a status to the
 * message) any "normal" handlers (added with
 * [method@Server.add_handler]) for the message's Request-URI will be
 * run.
 *
 * Then, if the path has a WebSocket handler registered (and has
 * not yet been assigned a status), [class@Server] will attempt to
 * validate the WebSocket handshake, filling in the response and
 * setting a status of %SOUP_STATUS_SWITCHING_PROTOCOLS or
 * %SOUP_STATUS_BAD_REQUEST accordingly.
 *
 * If the message still has no status code at this point (and has not
 * been paused with [method@ServerMessage.pause]), then it will be
 * given a status of %SOUP_STATUS_INTERNAL_SERVER_ERROR (because at
 * least one handler ran, but returned without assigning a status).
 *
 * Finally, the server will emit [signal@Server::request-finished] (or
 * [signal@Server::request-aborted] if an I/O error occurred before
 * handling was completed).
 *
 * If you want to handle the special "*" URI (eg, "OPTIONS *"), you
 * must explicitly register a handler for "*"; the default handler
 * will not be used for that case.
 *
 * If you want to process https connections in addition to (or instead
 * of) http connections, you can set the [property@Server:tls-certificate]
 * property.
 *
 * Once the server is set up, make one or more calls to
 * [method@Server.listen], [method@Server.listen_local], or
 * [method@Server.listen_all] to tell it where to listen for
 * connections. (All ports on a [class@Server] use the same handlers; if
 * you need to handle some ports differently, such as returning
 * different data for http and https, you'll need to create multiple
 * [class@Server]s, or else check the passed-in URI in the handler
 * function.).
 *
 * [class@Server] will begin processing connections as soon as you return
 * to (or start) the main loop for the current thread-default
 * [struct@GLib.MainContext].
 */

enum {
	REQUEST_STARTED,
	REQUEST_READ,
	REQUEST_FINISHED,
	REQUEST_ABORTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	char               *path;

	SoupServerCallback  early_callback;
	GDestroyNotify      early_destroy;
	gpointer            early_user_data;

	SoupServerCallback  callback;
	GDestroyNotify      destroy;
	gpointer            user_data;

	char                         *websocket_origin;
	char                        **websocket_protocols;
	GList                        *websocket_extensions;
	SoupServerWebsocketCallback   websocket_callback;
	GDestroyNotify                websocket_destroy;
	gpointer                      websocket_user_data;
} SoupServerHandler;

typedef struct {
	GSList            *listeners;
	GSList            *clients;

	GTlsCertificate   *tls_cert;
        GTlsDatabase      *tls_database;
        GTlsAuthenticationMode tls_auth_mode;

	char              *server_header;

	GMainContext      *async_context;
	GMainLoop         *loop;

	gboolean           raw_paths;
	SoupPathMap       *handlers;

	GSList            *auth_domains;

	GPtrArray         *websocket_extension_types;

	gboolean           disposed;
        gboolean           http2_enabled;

} SoupServerPrivate;

#define SOUP_SERVER_SERVER_HEADER_BASE "libsoup/" PACKAGE_VERSION

enum {
	PROP_0,

	PROP_TLS_CERTIFICATE,
        PROP_TLS_DATABASE,
        PROP_TLS_AUTH_MODE,
	PROP_RAW_PATHS,
	PROP_SERVER_HEADER,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

G_DEFINE_TYPE_WITH_PRIVATE (SoupServer, soup_server, G_TYPE_OBJECT)

static void request_finished (SoupServerMessage      *msg,
                              SoupMessageIOCompletion completion,
                              SoupServer             *server);

static void
free_handler (SoupServerHandler *handler)
{
	g_free (handler->path);
	g_free (handler->websocket_origin);
	g_strfreev (handler->websocket_protocols);
	g_list_free_full (handler->websocket_extensions, g_object_unref);
	if (handler->early_destroy)
		handler->early_destroy (handler->early_user_data);
	if (handler->destroy)
		handler->destroy (handler->user_data);
	if (handler->websocket_destroy)
		handler->websocket_destroy (handler->websocket_user_data);
	g_slice_free (SoupServerHandler, handler);
}

static void
soup_server_init (SoupServer *server)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

        priv->http2_enabled = !!g_getenv ("SOUP_SERVER_HTTP2");
	priv->handlers = soup_path_map_new ((GDestroyNotify)free_handler);

	priv->websocket_extension_types = g_ptr_array_new_with_free_func ((GDestroyNotify)g_type_class_unref);

	/* Use permessage-deflate extension by default */
	g_ptr_array_add (priv->websocket_extension_types, g_type_class_ref (SOUP_TYPE_WEBSOCKET_EXTENSION_DEFLATE));
}

static void
soup_server_dispose (GObject *object)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	priv->disposed = TRUE;
	soup_server_disconnect (server);

	G_OBJECT_CLASS (soup_server_parent_class)->dispose (object);
}

static void
soup_server_finalize (GObject *object)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	g_clear_object (&priv->tls_cert);
        g_clear_object (&priv->tls_database);

	g_free (priv->server_header);

	soup_path_map_free (priv->handlers);

	g_slist_free_full (priv->auth_domains, g_object_unref);

	g_clear_pointer (&priv->loop, g_main_loop_unref);

	g_ptr_array_free (priv->websocket_extension_types, TRUE);

	G_OBJECT_CLASS (soup_server_parent_class)->finalize (object);
}

static void
soup_server_set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	const char *header;

	switch (prop_id) {
	case PROP_TLS_CERTIFICATE:
                soup_server_set_tls_certificate (server, g_value_get_object (value));
		break;
        case PROP_TLS_DATABASE:
                soup_server_set_tls_database (server, g_value_get_object (value));
                break;
        case PROP_TLS_AUTH_MODE:
                soup_server_set_tls_auth_mode (server, g_value_get_enum (value));
                break;
	case PROP_RAW_PATHS:
		priv->raw_paths = g_value_get_boolean (value);
		break;
	case PROP_SERVER_HEADER:
		g_free (priv->server_header);
		header = g_value_get_string (value);
		if (!header)
			priv->server_header = NULL;
		else if (!*header) {
			priv->server_header =
				g_strdup (SOUP_SERVER_SERVER_HEADER_BASE);
		} else if (g_str_has_suffix (header, " ")) {
			priv->server_header =
				g_strdup_printf ("%s%s", header,
						 SOUP_SERVER_SERVER_HEADER_BASE);
		} else
			priv->server_header = g_strdup (header);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_server_get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	switch (prop_id) {
	case PROP_TLS_CERTIFICATE:
		g_value_set_object (value, priv->tls_cert);
		break;
        case PROP_TLS_DATABASE:
                g_value_set_object (value, priv->tls_database);
                break;
        case PROP_TLS_AUTH_MODE:
                g_value_set_enum (value, priv->tls_auth_mode);
                break;
	case PROP_RAW_PATHS:
		g_value_set_boolean (value, priv->raw_paths);
		break;
	case PROP_SERVER_HEADER:
		g_value_set_string (value, priv->server_header);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_server_class_init (SoupServerClass *server_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (server_class);

	/* virtual method override */
	object_class->dispose = soup_server_dispose;
	object_class->finalize = soup_server_finalize;
	object_class->set_property = soup_server_set_property;
	object_class->get_property = soup_server_get_property;

	/* signals */

	/**
	 * SoupServer::request-started:
	 * @server: the server
	 * @message: the new message
	 *
	 * Emitted when the server has started reading a new request.
	 *
	 * @message will be completely blank; not even the
	 * Request-Line will have been read yet. About the only thing
	 * you can usefully do with it is connect to its signals.
	 *
	 * If the request is read successfully, this will eventually
	 * be followed by a [signal@Server::request_read signal]. If a
	 * response is then sent, the request processing will end with
	 * a [signal@Server::request-finished] signal. If a network error
	 * occurs, the processing will instead end with
	 * [signal@Server::request-aborted].
	 **/
	signals[REQUEST_STARTED] =
		g_signal_new ("request-started",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_started),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SERVER_MESSAGE);

	/**
	 * SoupServer::request-read:
	 * @server: the server
	 * @message: the message
	 *
	 * Emitted when the server has successfully read a request.
	 *
	 * @message will have all of its request-side information
	 * filled in, and if the message was authenticated, @client
	 * will have information about that. This signal is emitted
	 * before any (non-early) handlers are called for the message,
	 * and if it sets the message's #status_code, then normal
	 * handler processing will be skipped.
	 **/
	signals[REQUEST_READ] =
		g_signal_new ("request-read",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_read),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SERVER_MESSAGE);

	/**
	 * SoupServer::request-finished:
	 * @server: the server
	 * @message: the message
	 *
	 * Emitted when the server has finished writing a response to
	 * a request.
	 **/
	signals[REQUEST_FINISHED] =
		g_signal_new ("request-finished",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_finished),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SERVER_MESSAGE);

	/**
	 * SoupServer::request-aborted:
	 * @server: the server
	 * @message: the message
	 *
	 * Emitted when processing has failed for a message.
	 *
	 * This could mean either that it could not be read (if
	 * [signal@Server::request-read] has not been emitted for it yet), or that
	 * the response could not be written back (if [signal@Server::request-read]
	 * has been emitted but [signal@Server::request-finished] has not been).
	 *
	 * @message is in an undefined state when this signal is
	 * emitted; the signal exists primarily to allow the server to
	 * free any state that it may have allocated in
	 * [signal@Server::request-started].
	 **/
	signals[REQUEST_ABORTED] =
		g_signal_new ("request-aborted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_aborted),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      SOUP_TYPE_SERVER_MESSAGE);

	/* properties */
	/**
	 * SoupServer:tls-certificate: (attributes org.gtk.Property.get=soup_server_get_tls_certificate org.gtk.Property.set=soup_server_set_tls_certificate)
	 *
	 * A [class@Gio.TlsCertificate[] that has a
	 * [property@Gio.TlsCertificate:private-key] set.
	 *
	 * If this is set, then the server will be able to speak
	 * https in addition to (or instead of) plain http.
	 */
        properties[PROP_TLS_CERTIFICATE] =
		g_param_spec_object ("tls-certificate",
				     "TLS certificate",
				     "GTlsCertificate to use for https",
				     G_TYPE_TLS_CERTIFICATE,
				     G_PARAM_READWRITE |
                                     G_PARAM_CONSTRUCT |
                                     G_PARAM_STATIC_STRINGS);

        /**
         * SoupServer:tls-database: (attributes org.gtk.Property.get=soup_server_get_tls_database org.gtk.Property.set=soup_server_set_tls_database)
         *
         * A [class@Gio.TlsDatabase] to use for validating SSL/TLS client
         * certificates.
         */
        properties[PROP_TLS_DATABASE] =
                g_param_spec_object ("tls-database",
                                     "TLS database",
                                     "GTlsDatabase to use for validating SSL/TLS client certificates",
                                     G_TYPE_TLS_DATABASE,
                                     G_PARAM_READWRITE |
                                     G_PARAM_CONSTRUCT |
                                     G_PARAM_STATIC_STRINGS);

        /**
         * SoupServer:tls-auth-mode: (attributes org.gtk.Property.get=soup_server_get_tls_auth_mode org.gtk.Property.set=soup_server_set_tls_auth_mode)
         *
         * A [enum@Gio.TlsAuthenticationMode] for SSL/TLS client authentication.
         */
        properties[PROP_TLS_AUTH_MODE] =
                g_param_spec_enum ("tls-auth-mode",
                                   "TLS Authentication Mode",
                                   "GTlsAuthenticationMode to use for SSL/TLS client authentication",
                                   G_TYPE_TLS_AUTHENTICATION_MODE,
                                   G_TLS_AUTHENTICATION_NONE,
                                   G_PARAM_READWRITE |
                                   G_PARAM_CONSTRUCT |
                                   G_PARAM_STATIC_STRINGS);

        /**
         * SoupServer:raw-paths:
         *
         * If %TRUE, percent-encoding in the Request-URI path will not be
         * automatically decoded.
         */
        properties[PROP_RAW_PATHS] =
		g_param_spec_boolean ("raw-paths",
				      "Raw paths",
				      "If %TRUE, percent-encoding in the Request-URI path will not be automatically decoded.",
				      FALSE,
				      G_PARAM_READWRITE |
                                      G_PARAM_CONSTRUCT_ONLY |
                                      G_PARAM_STATIC_STRINGS);

	/**
	 * SoupServer:server-header:
	 *
	 * Server header.
	 *
	 * If non-%NULL, the value to use for the "Server" header on
	 * [class@ServerMessage]s processed by this server.
	 *
	 * The Server header is the server equivalent of the
	 * User-Agent header, and provides information about the
	 * server and its components. It contains a list of one or
	 * more product tokens, separated by whitespace, with the most
	 * significant product token coming first. The tokens must be
	 * brief, ASCII, and mostly alphanumeric (although "-", "_",
	 * and "." are also allowed), and may optionally include a "/"
	 * followed by a version string. You may also put comments,
	 * enclosed in parentheses, between or after the tokens.
	 *
	 * Some HTTP server implementations intentionally do not use
	 * version numbers in their Server header, so that
	 * installations running older versions of the server don't
	 * end up advertising their vulnerability to specific security
	 * holes.
	 *
	 * As with [property@Session:user_agent], if you set a
	 * [property@Server:server-header] property that has trailing
	 * whitespace, [class@Server] will append its own product token (eg,
	 * `libsoup/2.3.2`) to the end of the header for you.
	 **/
        properties[PROP_SERVER_HEADER] =
		g_param_spec_string ("server-header",
				     "Server header",
				     "Server header",
				     NULL,
				     G_PARAM_READWRITE |
                                     G_PARAM_CONSTRUCT |
                                     G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

/**
 * soup_server_new:
 * @optname1: name of first property to set
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates a new [class@Server].
 *
 * This is exactly equivalent to calling [ctor@GObject.Object.new] and
 * specifying %SOUP_TYPE_SERVER as the type.
 *
 * Returns: (nullable): a new #SoupServer. If you are using
 *   certain legacy properties, this may also return %NULL if an error
 *   occurs.
 **/
SoupServer *
soup_server_new (const char *optname1, ...)
{
	SoupServer *server;
	va_list ap;

	va_start (ap, optname1);
	server = (SoupServer *)g_object_new_valist (SOUP_TYPE_SERVER,
						    optname1, ap);
	va_end (ap);

	return server;
}

/**
 * soup_server_set_tls_certificate: (attributes org.gtk.Method.set_property=tls-certificate)
 * @server: a #SoupServer
 * @certificate: a #GTlsCertificate
 *
 * Sets @server up to do https, using the given SSL/TLS @certificate.
 */
void
soup_server_set_tls_certificate (SoupServer      *server,
                                 GTlsCertificate *certificate)
{
        SoupServerPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER (server));

        priv = soup_server_get_instance_private (server);
        if (priv->tls_cert == certificate)
                return;

        g_clear_object (&priv->tls_cert);
        priv->tls_cert = certificate ? g_object_ref (certificate) : NULL;
        g_object_notify_by_pspec (G_OBJECT (server), properties[PROP_TLS_CERTIFICATE]);
}

/**
 * soup_server_get_tls_certificate: (attributes org.gtk.Method.get_property=tls-certificate)
 * @server: a #SoupServer
 *
 * Gets the @server SSL/TLS certificate.
 *
 * Returns: (transfer none) (nullable): a #GTlsCertificate or %NULL
 */
GTlsCertificate *
soup_server_get_tls_certificate (SoupServer *server)
{
        SoupServerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);

        priv = soup_server_get_instance_private (server);
        return priv->tls_cert;
}

/**
 * soup_server_set_tls_database: (attributes org.gtk.Method.set_property=tls-database)
 * @server: a #SoupServer
 * @tls_database: a #GTlsDatabase
 *
 * Sets @server's #GTlsDatabase to use for validating SSL/TLS client certificates.
 */
void
soup_server_set_tls_database (SoupServer   *server,
                              GTlsDatabase *tls_database)
{
        SoupServerPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER (server));

        priv = soup_server_get_instance_private (server);
        if (priv->tls_database == tls_database)
                return;

        g_clear_object (&priv->tls_database);
        priv->tls_database = tls_database ? g_object_ref (tls_database) : NULL;
        g_object_notify_by_pspec (G_OBJECT (server), properties[PROP_TLS_DATABASE]);
}

/**
 * soup_server_get_tls_database: (attributes org.gtk.Method.get_property=tls-database)
 * @server: a #SoupServer
 *
 * Gets the @server SSL/TLS database.
 *
 * Returns: (transfer none) (nullable): a #GTlsDatabase
 */
GTlsDatabase *
soup_server_get_tls_database (SoupServer *server)
{
        SoupServerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);

        priv = soup_server_get_instance_private (server);
        return priv->tls_database;
}

/**
 * soup_server_set_tls_auth_mode: (attributes org.gtk.Method.set_property=tls-auth-mode)
 * @server: a #SoupServer
 * @mode: a #GTlsAuthenticationMode
 *
 * Sets @server's #GTlsAuthenticationMode to use for SSL/TLS client authentication.
 */
void
soup_server_set_tls_auth_mode (SoupServer             *server,
                               GTlsAuthenticationMode  mode)
{
        SoupServerPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER (server));

        priv = soup_server_get_instance_private (server);
        if (priv->tls_auth_mode == mode)
                return;

        priv->tls_auth_mode = mode;
        g_object_notify_by_pspec (G_OBJECT (server), properties[PROP_TLS_AUTH_MODE]);
}

/**
 * soup_server_get_tls_auth_mode: (attributes org.gtk.Method.get_property=tls-auth-mode)
 * @server: a #SoupServer
 *
 * Gets the @server SSL/TLS client authentication mode.
 *
 * Returns: a #GTlsAuthenticationMode
 */
GTlsAuthenticationMode
soup_server_get_tls_auth_mode (SoupServer *server)
{
        SoupServerPrivate *priv;

        g_return_val_if_fail (SOUP_IS_SERVER (server), G_TLS_AUTHENTICATION_NONE);

        priv = soup_server_get_instance_private (server);
        return priv->tls_auth_mode;
}

/**
 * soup_server_is_https:
 * @server: a #SoupServer
 *
 * Checks whether @server is capable of https.
 *
 * In order for a server to run https, you must call
 * [method@Server.set_tls_certificate], or set the
 * [property@Server:tls-certificate] property, to provide it with a
 * certificate to use.
 *
 * If you are using the deprecated single-listener APIs, then a return value of
 * %TRUE indicates that the [class@Server] serves https exclusively. If you are
 * using [method@Server.listen], etc, then a %TRUE return value merely indicates
 * that the server is *able* to do https, regardless of whether it actually
 * currently is or not. Use [method@Server.get_uris] to see if it currently has
 * any https listeners.
 *
 * Returns: %TRUE if @server is configured to serve https.
 **/
gboolean
soup_server_is_https (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);
	priv = soup_server_get_instance_private (server);

	return priv->tls_cert != NULL;
}

/**
 * soup_server_get_listeners:
 * @server: a #SoupServer
 *
 * Gets @server's list of listening sockets.
 *
 * You should treat these sockets as read-only; writing to or
 * modifiying any of these sockets may cause @server to malfunction.
 *
 * Returns: (transfer container) (element-type Gio.Socket): a
 *   list of listening sockets.
 **/
GSList *
soup_server_get_listeners (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *listeners, *iter;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = soup_server_get_instance_private (server);

	listeners = NULL;
	for (iter = priv->listeners; iter; iter = iter->next)
		listeners = g_slist_prepend (listeners, soup_listener_get_socket (iter->data));

	/* priv->listeners has the sockets in reverse order from how
	 * they were added, so listeners now has them back in the
	 * original order.
	 */
	return listeners;
}

GSList *
soup_server_get_clients (SoupServer *server)
{
        SoupServerPrivate *priv = soup_server_get_instance_private (server);

        return priv->clients;
}

/* "" was never documented as meaning the same thing as "/", but it
 * effectively was. We have to special case it now or otherwise it
 * would match "*" too.
 */
#define NORMALIZED_PATH(path) ((path) && *(path) ? (path) : "/")

static const char *
get_msg_path (SoupServerMessage *msg)
{
        /* A GUri cannot hold a path of "*" so we handle that */
        if (soup_server_message_is_options_ping (msg))
                return "*";
        else
                return NORMALIZED_PATH (g_uri_get_path (soup_server_message_get_uri (msg)));
}

static SoupServerHandler *
get_handler (SoupServer        *server,
	     SoupServerMessage *msg)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	return soup_path_map_lookup (priv->handlers, get_msg_path (msg));
}

static void
call_handler (SoupServer        *server,
	      SoupServerHandler *handler,
	      SoupServerMessage *msg,
	      gboolean           early)
{
	GHashTable *form_data_set;
	GUri *uri;

	if (early && !handler->early_callback)
		return;
	else if (!early && !handler->callback)
		return;

	if (soup_server_message_get_status (msg) != 0)
		return;

	uri = soup_server_message_get_uri (msg);
	if (g_uri_get_query (uri))
		form_data_set = soup_form_decode (g_uri_get_query (uri));
	else
		form_data_set = NULL;

	if (early) {
		(*handler->early_callback) (server, msg,
					    get_msg_path (msg), form_data_set,
					    handler->early_user_data);
	} else {
		(*handler->callback) (server, msg,
				      get_msg_path (msg), form_data_set,
				      handler->user_data);
	}

	if (form_data_set)
		g_hash_table_unref (form_data_set);
}

static void
got_headers (SoupServer        *server,
	     SoupServerMessage *msg)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupServerHandler *handler;
	GUri *uri;
	GDateTime *date;
	char *date_string;
	SoupAuthDomain *domain;
	GSList *iter;
	gboolean rejected = FALSE;
	char *auth_user;
	SoupMessageHeaders *headers;
	SoupServerConnection *conn;

	/* Add required response headers */
	headers = soup_server_message_get_response_headers (msg);

	date = g_date_time_new_now_utc ();
	date_string = soup_date_time_to_string (date, SOUP_DATE_HTTP);
	soup_message_headers_replace_common (headers, SOUP_HEADER_DATE, date_string);
	g_free (date_string);
	g_date_time_unref (date);

	if (soup_server_message_get_status (msg) != 0)
		return;

	conn = soup_server_message_get_connection (msg);
	uri = soup_server_message_get_uri (msg);
	if ((soup_server_connection_is_ssl (conn) && !soup_uri_is_https (uri)) ||
	    (!soup_server_connection_is_ssl (conn) && !soup_uri_is_http (uri))) {
		soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
		return;
	}

	if (!priv->raw_paths && g_uri_get_flags (uri) & G_URI_FLAGS_ENCODED_PATH) {
		char *decoded_path;
		GUri *copy;

                decoded_path = g_uri_unescape_string (g_uri_get_path (uri), NULL);

		if (decoded_path == NULL ||
		    strstr (decoded_path, "/../") ||
		    g_str_has_suffix (decoded_path, "/..")
#ifdef G_OS_WIN32
		    ||
		    strstr (decoded_path, "\\..\\") ||
		    strstr (decoded_path, "/..\\") ||
		    strstr (decoded_path, "\\../") ||
		    g_str_has_suffix (decoded_path, "\\..")
#endif
		    ) {
			/* Introducing new ".." segments is not allowed */
			g_free (decoded_path);
			soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
			return;
		}

                copy = soup_uri_copy (uri, SOUP_URI_PATH, decoded_path, SOUP_URI_NONE);
                soup_server_message_set_uri (msg, copy);
		g_free (decoded_path);
		g_uri_unref (copy);
	}

	/* Now handle authentication. (We do this here so that if
	 * the request uses "Expect: 100-continue", we can reject it
	 * immediately rather than waiting for the request body to
	 * be sent.
	 */
	for (iter = priv->auth_domains; iter; iter = iter->next) {
		domain = iter->data;

		if (soup_auth_domain_covers (domain, msg)) {
			auth_user = soup_auth_domain_accepts (domain, msg);
			if (auth_user) {
				soup_server_message_set_auth (msg, g_object_ref (domain), auth_user);
				return;
			}

			rejected = TRUE;
		}
	}

	/* If any auth domain rejected it, then it will need authentication. */
	if (rejected) {
		for (iter = priv->auth_domains; iter; iter = iter->next) {
			domain = iter->data;

			if (soup_auth_domain_covers (domain, msg))
				soup_auth_domain_challenge (domain, msg);
		}
		return;
	}

	/* Otherwise, call the early handlers. */
	handler = get_handler (server, msg);
	if (handler)
		call_handler (server, handler, msg, TRUE);
}

static void
complete_websocket_upgrade (SoupServer        *server,
			    SoupServerMessage *msg)
{
	GUri *uri = soup_server_message_get_uri (msg);
	SoupServerHandler *handler;
	GIOStream *stream;
	SoupWebsocketConnection *conn;

	handler = get_handler (server, msg);
	if (!handler || !handler->websocket_callback)
		return;

	g_object_ref (msg);
	stream = soup_server_message_steal_connection (msg);
	conn = soup_websocket_connection_new (stream, uri,
					      SOUP_WEBSOCKET_CONNECTION_SERVER,
					      soup_message_headers_get_one_common (soup_server_message_get_request_headers (msg), SOUP_HEADER_ORIGIN),
					      soup_message_headers_get_one_common (soup_server_message_get_response_headers (msg), SOUP_HEADER_SEC_WEBSOCKET_PROTOCOL),
					      handler->websocket_extensions);
	handler->websocket_extensions = NULL;
	g_object_unref (stream);

	(*handler->websocket_callback) (server, msg, g_uri_get_path (uri), conn,
					handler->websocket_user_data);
	g_object_unref (conn);
	g_object_unref (msg);
}

static void
got_body (SoupServer        *server,
	  SoupServerMessage *msg)
{
	SoupServerHandler *handler;

	g_signal_emit (server, signals[REQUEST_READ], 0, msg);

	if (soup_server_message_get_status (msg) != 0)
		return;

	handler = get_handler (server, msg);
	if (!handler) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_FOUND, NULL);
		return;
	}

	call_handler (server, handler, msg, FALSE);
	if (soup_server_message_get_status (msg) != 0)
		return;

	if (handler->websocket_callback) {
		SoupServerPrivate *priv;

		priv = soup_server_get_instance_private (server);
		if (soup_websocket_server_process_handshake (msg,
							     handler->websocket_origin,
							     handler->websocket_protocols,
							     priv->websocket_extension_types,
							     &handler->websocket_extensions)) {
			g_signal_connect_object (msg, "wrote-informational",
						 G_CALLBACK (complete_websocket_upgrade),
						 server, G_CONNECT_SWAPPED);
		}
	}
}

static void
message_connected (SoupServer        *server,
                   SoupServerMessage *msg)
{
        soup_server_message_read_request (msg,
                                          (SoupMessageIOCompletionFn)request_finished,
                                          server);
}

static void
client_disconnected (SoupServer           *server,
		     SoupServerConnection *conn)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	priv->clients = g_slist_remove (priv->clients, conn);
        g_object_unref (conn);
}

static void
request_started_cb (SoupServer           *server,
                    SoupServerMessage    *msg,
                    SoupServerConnection *conn)
{
        SoupServerPrivate *priv = soup_server_get_instance_private (server);

        g_signal_connect_object (msg, "got-headers",
                                 G_CALLBACK (got_headers),
                                 server, G_CONNECT_SWAPPED);
        g_signal_connect_object (msg, "got-body",
                                 G_CALLBACK (got_body),
                                 server, G_CONNECT_SWAPPED);

        if (priv->server_header) {
                SoupMessageHeaders *headers;

                headers = soup_server_message_get_response_headers (msg);
                soup_message_headers_append_common (headers, SOUP_HEADER_SERVER,
                                                    priv->server_header);
        }

        g_signal_emit (server, signals[REQUEST_STARTED], 0, msg);

        if (soup_server_message_get_io_data (msg)) {
                message_connected (server, msg);
                return;
        }

        g_signal_connect_object (msg, "connected",
                                 G_CALLBACK (message_connected),
                                 server, G_CONNECT_SWAPPED);
}

static void
soup_server_accept_connection (SoupServer           *server,
                               SoupServerConnection *conn)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

        priv->clients = g_slist_prepend (priv->clients, g_object_ref (conn));
        g_signal_connect_object (conn, "disconnected",
                                 G_CALLBACK (client_disconnected),
                                 server, G_CONNECT_SWAPPED);
        g_signal_connect_object (conn, "request-started",
                                 G_CALLBACK (request_started_cb),
                                 server, G_CONNECT_SWAPPED);

        soup_server_connection_accepted (conn);
}

static void
request_finished (SoupServerMessage      *msg,
		  SoupMessageIOCompletion completion,
		  SoupServer             *server)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupServerConnection *conn = soup_server_message_get_connection (msg);
	gboolean failed;

	if (completion == SOUP_MESSAGE_IO_STOLEN)
		return;

	/* Complete the message, assuming it actually really started. */
	if (soup_server_message_get_method (msg)) {
		soup_server_message_finished (msg);

		failed = (completion == SOUP_MESSAGE_IO_INTERRUPTED ||
			  soup_server_message_get_status (msg) == SOUP_STATUS_INTERNAL_SERVER_ERROR);
		g_signal_emit (server,
			       failed ? signals[REQUEST_ABORTED] : signals[REQUEST_FINISHED],
			       0, msg);
	}

	if (completion == SOUP_MESSAGE_IO_COMPLETE &&
	    soup_server_connection_is_connected (conn) &&
	    soup_server_message_is_keepalive (msg) &&
	    priv->listeners)
		return;

        if (soup_server_message_get_http_version (msg) < SOUP_HTTP_2_0)
                soup_server_connection_disconnect (conn);
}

/**
 * soup_server_accept_iostream:
 * @server: a #SoupServer
 * @stream: a #GIOStream
 * @local_addr: (nullable): the local #GSocketAddress associated with the
 *   @stream
 * @remote_addr: (nullable): the remote #GSocketAddress associated with the
 *   @stream
 * @error: return location for a #GError
 *
 * Adds a new client stream to the @server.
 *
 * Returns: %TRUE on success, %FALSE if the stream could not be
 *   accepted or any other error occurred (in which case @error will be
 *   set).
 **/
gboolean
soup_server_accept_iostream (SoupServer     *server,
			     GIOStream      *stream,
			     GSocketAddress *local_addr,
			     GSocketAddress *remote_addr,
			     GError        **error)
{
	SoupServerConnection *conn;

        conn = soup_server_connection_new_for_connection (stream, local_addr, remote_addr);
	soup_server_accept_connection (server, conn);
	g_object_unref (conn);

	return TRUE;
}

static void
new_connection (SoupListener         *listener,
                SoupServerConnection *conn,
                SoupServer           *server)
{
        SoupServerPrivate *priv = soup_server_get_instance_private (server);

        soup_server_connection_set_advertise_http2 (conn, priv->http2_enabled);
	soup_server_accept_connection (server, conn);
}

/**
 * soup_server_disconnect:
 * @server: a #SoupServer
 *
 * Closes and frees @server's listening sockets.
 *
 * Note that if there are currently requests in progress on @server, that they
 * will continue to be processed if @server's [struct@GLib.MainContext] is still
 * running.
 *
 * You can call [method@Server.listen], etc, after calling this function
 * if you want to start listening again.
 **/
void
soup_server_disconnect (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *listeners, *clients, *iter;
	SoupListener *listener;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	clients = priv->clients;
	priv->clients = NULL;
	listeners = priv->listeners;
	priv->listeners = NULL;

	for (iter = clients; iter; iter = iter->next) {
		SoupServerConnection *conn = iter->data;

		soup_server_connection_disconnect (conn);
	}
	g_slist_free (clients);

	for (iter = listeners; iter; iter = iter->next) {
		listener = iter->data;
		soup_listener_disconnect (listener);
		g_object_unref (listener);
	}
	g_slist_free (listeners);
}

/**
 * SoupServerListenOptions:
 * @SOUP_SERVER_LISTEN_HTTPS: Listen for https connections rather
 *   than plain http.
 * @SOUP_SERVER_LISTEN_IPV4_ONLY: Only listen on IPv4 interfaces.
 * @SOUP_SERVER_LISTEN_IPV6_ONLY: Only listen on IPv6 interfaces.
 *
 * Options to pass to [method@Server.listen], etc.
 *
 * %SOUP_SERVER_LISTEN_IPV4_ONLY and %SOUP_SERVER_LISTEN_IPV6_ONLY
 * only make sense with [method@Server.listen_all] and
 * [method@Server.listen_local], not plain [method@Server.listen] (which
 * simply listens on whatever kind of socket you give it). And you
 * cannot specify both of them in a single call.
 */

static gboolean
soup_server_listen_internal (SoupServer             *server,
                             SoupListener           *listener,
			     SoupServerListenOptions options,
			     GError                **error)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);

	if (options & SOUP_SERVER_LISTEN_HTTPS) {
		if (!priv->tls_cert) {
			g_set_error_literal (error,
					     G_IO_ERROR,
					     G_IO_ERROR_INVALID_ARGUMENT,
					     _("Can’t create a TLS server without a TLS certificate"));
			return FALSE;
		}

                g_object_bind_property (server, "tls-certificate",
                                        listener, "tls-certificate",
                                        G_BINDING_SYNC_CREATE);
                g_object_bind_property (server, "tls-database",
                                        listener, "tls-database",
                                        G_BINDING_SYNC_CREATE);
                g_object_bind_property (server, "tls-auth-mode",
                                        listener, "tls-auth-mode",
                                        G_BINDING_SYNC_CREATE);
	}

	g_signal_connect (listener, "new-connection",
			  G_CALLBACK (new_connection),
                          server);

	/* Note: soup_server_listen_ipv4_ipv6() below relies on the
	 * fact that this does g_slist_prepend().
	 */
	priv->listeners = g_slist_prepend (priv->listeners, g_object_ref (listener));
	return TRUE;
}

/**
 * soup_server_listen:
 * @server: a #SoupServer
 * @address: the address of the interface to listen on
 * @options: listening options for this server
 * @error: return location for a #GError
 *
 * Attempts to set up @server to listen for connections on @address.
 *
 * If @options includes %SOUP_SERVER_LISTEN_HTTPS, and @server has
 * been configured for TLS, then @server will listen for https
 * connections on this port. Otherwise it will listen for plain http.
 *
 * You may call this method (along with the other "listen" methods)
 * any number of times on a server, if you want to listen on multiple
 * ports, or set up both http and https service.
 *
 * After calling this method, @server will begin accepting and processing
 * connections as soon as the appropriate [struct@GLib.MainContext] is run.
 *
 * Note that this API does not make use of dual IPv4/IPv6 sockets; if
 * @address is an IPv6 address, it will only accept IPv6 connections.
 * You must configure IPv4 listening separately.
 *
 * Returns: %TRUE on success, %FALSE if @address could not be
 *   bound or any other error occurred (in which case @error will be
 *   set).
 **/
gboolean
soup_server_listen (SoupServer *server, GSocketAddress *address,
		    SoupServerListenOptions options,
		    GError **error)
{
	SoupServerPrivate *priv;
	SoupListener *listener;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) &&
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	priv = soup_server_get_instance_private (server);
	g_return_val_if_fail (priv->disposed == FALSE, FALSE);

        listener = soup_listener_new_for_address (address, error);
        if (!listener)
                return FALSE;

	success = soup_server_listen_internal (server, listener, options, error);
	g_object_unref (listener);

	return success;
}

static gboolean
soup_server_listen_ipv4_ipv6 (SoupServer *server,
			      GInetAddress *iaddr4,
			      GInetAddress *iaddr6,
			      guint port,
			      SoupServerListenOptions options,
			      GError **error)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	GSocketAddress *addr4, *addr6;
	GError *my_error = NULL;
	SoupListener *v4sock;
	guint v4port;

	g_return_val_if_fail (iaddr4 != NULL || iaddr6 != NULL, FALSE);

	options &= ~(SOUP_SERVER_LISTEN_IPV4_ONLY | SOUP_SERVER_LISTEN_IPV6_ONLY);

 try_again:
	if (iaddr4) {
		addr4 = g_inet_socket_address_new (iaddr4, port);
		if (!soup_server_listen (server, addr4, options, error)) {
			g_object_unref (addr4);
			return FALSE;
		}
		g_object_unref (addr4);

		v4sock = priv->listeners->data;
		v4port = g_inet_socket_address_get_port (soup_listener_get_address (v4sock));
	} else {
		v4sock = NULL;
		v4port = port;
	}

	if (!iaddr6)
		return TRUE;

	addr6 = g_inet_socket_address_new (iaddr6, v4port);
	if (soup_server_listen (server, addr6, options, &my_error)) {
		g_object_unref (addr6);
		return TRUE;
	}
	g_object_unref (addr6);

	if (v4sock &&
            (g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED) ||
             g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_CONNECTION_REFUSED))) {
		/* No IPv6 support, but IPV6_ONLY wasn't specified, so just
		 * ignore the failure.
		 */
                g_debug ("Ignoring IPv6 listen error, assuming it isn't supported: %s", my_error->message);
		g_error_free (my_error);
		return TRUE;
	}

	if (v4sock) {
		priv->listeners = g_slist_remove (priv->listeners, v4sock);
		soup_listener_disconnect (v4sock);
		g_object_unref (v4sock);
	}

	if (port == 0 && g_error_matches (my_error, G_IO_ERROR, G_IO_ERROR_ADDRESS_IN_USE)) {
		/* The randomly-assigned IPv4 port was in use on the IPv6 side... Try again */
		g_clear_error (&my_error);
		goto try_again;
	}

	g_propagate_error (error, my_error);
	return FALSE;
}

/**
 * soup_server_listen_all:
 * @server: a #SoupServer
 * @port: the port to listen on, or 0
 * @options: listening options for this server
 * @error: return location for a #GError
 *
 * Attempts to set up @server to listen for connections on all interfaces
 * on the system.
 *
 * That is, it listens on the addresses `0.0.0.0` and/or `::`, depending on
 * whether @options includes %SOUP_SERVER_LISTEN_IPV4_ONLY,
 * %SOUP_SERVER_LISTEN_IPV6_ONLY, or neither.) If @port is specified, @server
 * will listen on that port. If it is 0, @server will find an unused port to
 * listen on. (In that case, you can use [method@Server.get_uris] to find out
 * what port it ended up choosing.
 *
 * See [method@Server.listen] for more details.
 *
 * Returns: %TRUE on success, %FALSE if @port could not be bound
 *   or any other error occurred (in which case @error will be set).
 **/
gboolean 
soup_server_listen_all (SoupServer *server, guint port,
			SoupServerListenOptions options,
			GError **error)
{
	GInetAddress *iaddr4, *iaddr6;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) ||
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	if (options & SOUP_SERVER_LISTEN_IPV6_ONLY)
		iaddr4 = NULL;
	else
		iaddr4 = g_inet_address_new_any (G_SOCKET_FAMILY_IPV4);

	if (options & SOUP_SERVER_LISTEN_IPV4_ONLY)
		iaddr6 = NULL;
	else
		iaddr6 = g_inet_address_new_any (G_SOCKET_FAMILY_IPV6);

	success = soup_server_listen_ipv4_ipv6 (server, iaddr4, iaddr6,
						port, options, error);

	g_clear_object (&iaddr4);
	g_clear_object (&iaddr6);

	return success;
}

/**
 * soup_server_listen_local:
 * @server: a #SoupServer
 * @port: the port to listen on, or 0
 * @options: listening options for this server
 * @error: return location for a #GError
 *
 * Attempts to set up @server to listen for connections on "localhost".
 *
 * That is, `127.0.0.1` and/or `::1`, depending on whether @options includes
 * %SOUP_SERVER_LISTEN_IPV4_ONLY, %SOUP_SERVER_LISTEN_IPV6_ONLY, or neither). If
 * @port is specified, @server will listen on that port. If it is 0, @server
 * will find an unused port to listen on. (In that case, you can use
 * [method@Server.get_uris] to find out what port it ended up choosing.
 *
 * See [method@Server.listen] for more details.
 *
 * Returns: %TRUE on success, %FALSE if @port could not be bound
 *   or any other error occurred (in which case @error will be set).
 **/
gboolean
soup_server_listen_local (SoupServer *server, guint port,
			  SoupServerListenOptions options,
			  GError **error)
{
	GInetAddress *iaddr4, *iaddr6;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) ||
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	if (options & SOUP_SERVER_LISTEN_IPV6_ONLY)
		iaddr4 = NULL;
	else
		iaddr4 = g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV4);

	if (options & SOUP_SERVER_LISTEN_IPV4_ONLY)
		iaddr6 = NULL;
	else
		iaddr6 = g_inet_address_new_loopback (G_SOCKET_FAMILY_IPV6);

	success = soup_server_listen_ipv4_ipv6 (server, iaddr4, iaddr6,
						port, options, error);

	g_clear_object (&iaddr4);
	g_clear_object (&iaddr6);

	return success;
}

/**
 * soup_server_listen_socket:
 * @server: a #SoupServer
 * @socket: a listening #GSocket
 * @options: listening options for this server
 * @error: return location for a #GError
 *
 * Attempts to set up @server to listen for connections on @socket.
 *
 * See [method@Server.listen] for more details.
 *
 * Returns: %TRUE on success, %FALSE if an error occurred (in
 *   which case @error will be set).
 **/
gboolean
soup_server_listen_socket (SoupServer *server, GSocket *socket,
			   SoupServerListenOptions options,
			   GError **error)
{
	SoupServerPrivate *priv;
	SoupListener *listener;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (G_IS_SOCKET (socket), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) &&
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	priv = soup_server_get_instance_private (server);
	g_return_val_if_fail (priv->disposed == FALSE, FALSE);

        listener = soup_listener_new (socket, error);
	if (!listener)
		return FALSE;

	success = soup_server_listen_internal (server, listener, options, error);
	g_object_unref (listener);

	return success;
}

/**
 * soup_server_get_uris:
 * @server: a #SoupServer
 *
 * Gets a list of URIs corresponding to the interfaces @server is
 * listening on.
 *
 * These will contain IP addresses, not hostnames, and will also indicate
 * whether the given listener is http or https.
 *
 * Note that if you used [method@Server.listen_all] the returned URIs will use
 * the addresses `0.0.0.0` and `::`, rather than actually returning separate
 * URIs for each interface on the system.
 *
 * Returns: (transfer full) (element-type GUri): a list of [struct@GLib.Uri], which you
 *   must free with each element with [method@GLib.Uri.unref] when you are done with it.
 */
GSList *
soup_server_get_uris (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *uris, *l;
	SoupListener *listener;
	GInetSocketAddress *addr;
	GInetAddress *inet_addr;
	char *ip;
        int port;
	GUri *uri;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = soup_server_get_instance_private (server);

	for (l = priv->listeners, uris = NULL; l; l = l->next) {
		listener = l->data;
		addr = soup_listener_get_address (listener);
		inet_addr = g_inet_socket_address_get_address (addr);
		ip = g_inet_address_to_string (inet_addr);
                port = g_inet_socket_address_get_port (addr);

                if (port == 0)
                        port = -1;

                uri = g_uri_build (SOUP_HTTP_URI_FLAGS,
                                   soup_listener_is_ssl (listener) ? "https" : "http",
                                   NULL, ip, port, "/", NULL, NULL);

		uris = g_slist_prepend (uris, uri);

		g_free (ip);
	}

	return uris;
}

/**
 * SoupServerCallback:
 * @server: the #SoupServer
 * @msg: the message being processed
 * @path: the path component of @msg's Request-URI
 * @query: (element-type utf8 utf8) (nullable): the parsed query
 *   component of @msg's Request-URI
 * @user_data: the data passed to [method@Server.add_handler] or
 *   [method@Server.add_early_handler].
 *
 * A callback used to handle requests to a [class@Server].
 *
 * @path and @query contain the likewise-named components of the
 * Request-URI, subject to certain assumptions. By default,
 * [class@Server] decodes all percent-encoding in the URI path, such that
 * `"/foo%2Fbar"` is treated the same as `"/foo/bar"`. If your
 * server is serving resources in some non-POSIX-filesystem namespace,
 * you may want to distinguish those as two distinct paths. In that
 * case, you can set the [property@Server:raw-paths] property when creating
 * the [class@Server], and it will leave those characters undecoded.
 *
 * @query contains the query component of the Request-URI parsed according to
 * the rules for HTML form handling. Although this is the only commonly-used
 * query string format in HTTP, there is nothing that actually requires that
 * HTTP URIs use that format; if your server needs to use some other format, you
 * can just ignore @query, and call [method@Message.get_uri] and parse the URI's
 * query field yourself.
 *
 * See [method@Server.add_handler] and [method@Server.add_early_handler]
 * for details of what handlers can/should do.
 **/

static SoupServerHandler *
get_or_create_handler (SoupServer *server, const char *exact_path)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupServerHandler *handler;

	exact_path = NORMALIZED_PATH (exact_path);

	handler = soup_path_map_lookup (priv->handlers, exact_path);
	if (handler && !strcmp (handler->path, exact_path))
		return handler;

	handler = g_slice_new0 (SoupServerHandler);
	handler->path = g_strdup (exact_path);
	soup_path_map_add (priv->handlers, exact_path, handler);

	return handler;
}

/**
 * soup_server_add_handler:
 * @server: a #SoupServer
 * @path: (nullable): the toplevel path for the handler
 * @callback: (scope notified) (destroy destroy): callback to invoke for
 *   requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds a handler to @server for requests prefixed by @path.
 *
 * If @path is %NULL or "/", then this will be the default handler for all
 * requests that don't have a more specific handler. (Note though that if you
 * want to handle requests to the special "*" URI, you must explicitly register
 * a handler for "*"; the default handler will not be used for that case.)
 *
 * For requests under @path (that have not already been assigned a
 * status code by a [class@AuthDomain], an early server handler, or a
 * signal handler), @callback will be invoked after receiving the
 * request body; the [class@ServerMessage]'s method, request-headers,
 * and request-body properties will be set.
 *
 * After determining what to do with the request, the callback must at a minimum
 * call [method@ServerMessage.set_status] on the message to set the response
 * status code. Additionally, it may set response headers and/or fill in the
 * response body.
 *
 * If the callback cannot fully fill in the response before returning
 * (eg, if it needs to wait for information from a database, or
 * another network server), it should call [method@ServerMessage.pause]
 * to tell @server to not send the response right away. When the
 * response is ready, call [method@ServerMessage.unpause] to cause it
 * to be sent.
 *
 * To send the response body a bit at a time using "chunked" encoding, first
 * call [method@MessageHeaders.set_encoding] to set %SOUP_ENCODING_CHUNKED on
 * the response-headers. Then call [method@MessageBody.append] (or
 * [method@MessageBody.append_bytes])) to append each chunk as it becomes ready,
 * and [method@ServerMessage.unpause] to make sure it's running. (The server
 * will automatically pause the message if it is using chunked encoding but no
 * more chunks are available.) When you are done, call
 * [method@MessageBody.complete] to indicate that no more chunks are coming.
 **/
void
soup_server_add_handler (SoupServer            *server,
			 const char            *path,
			 SoupServerCallback     callback,
			 gpointer               user_data,
			 GDestroyNotify         destroy)
{
	SoupServerHandler *handler;

	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (callback != NULL);

	handler = get_or_create_handler (server, path);
	if (handler->destroy)
		handler->destroy (handler->user_data);

	handler->callback   = callback;
	handler->destroy    = destroy;
	handler->user_data  = user_data;
}

/**
 * soup_server_add_early_handler:
 * @server: a #SoupServer
 * @path: (nullable): the toplevel path for the handler
 * @callback: (scope notified) (destroy destroy): callback to invoke for
 *   requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds an "early" handler to @server for requests prefixed by @path.
 *
 * Note that "normal" and "early" handlers are matched up together, so if you
 * add a normal handler for "/foo" and an early handler for "/foo/bar", then a
 * request to "/foo/bar" (or any path below it) will run only the early handler.
 * (But if you add both handlers at the same path, then both will get run.)
 *
 * For requests under @path (that have not already been assigned a
 * status code by a [class@AuthDomain] or a signal handler), @callback
 * will be invoked after receiving the request headers, but before
 * receiving the request body; the message's method and
 * request-headers properties will be set.
 *
 * Early handlers are generally used for processing requests with request bodies
 * in a streaming fashion. If you determine that the request will contain a
 * message body, normally you would call [method@MessageBody.set_accumulate] on
 * the message's request-body to turn off request-body accumulation, and connect
 * to the message's [signal@ServerMessage::got-chunk] signal to process each
 * chunk as it comes in.
 *
 * To complete the message processing after the full message body has
 * been read, you can either also connect to [signal@ServerMessage::got-body],
 * or else you can register a non-early handler for @path as well. As
 * long as you have not set the status-code by the time
 * [signal@ServerMessage::got-body] is emitted, the non-early handler will be
 * run as well.
 **/
void
soup_server_add_early_handler (SoupServer            *server,
			       const char            *path,
			       SoupServerCallback     callback,
			       gpointer               user_data,
			       GDestroyNotify         destroy)
{
	SoupServerHandler *handler;

	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (callback != NULL);

	handler = get_or_create_handler (server, path);
	if (handler->early_destroy)
		handler->early_destroy (handler->early_user_data);

	handler->early_callback   = callback;
	handler->early_destroy    = destroy;
	handler->early_user_data  = user_data;
}

/**
 * SoupServerWebsocketCallback:
 * @server: the #SoupServer
 * @path: the path component of @msg's Request-URI
 * @connection: the newly created WebSocket connection
 * @msg: the #SoupServerMessage
 * @user_data: the data passed to @soup_server_add_handler
 *
 * A callback used to handle WebSocket requests to a [class@Server].
 *
 * The callback will be invoked after sending the handshake response back to the
 * client (and is only invoked if the handshake was successful).
 *
 * @path contains the path of the Request-URI, subject to the same
 * rules as [callback@ServerCallback] `(qv)`.
 **/

/**
 * soup_server_add_websocket_handler:
 * @server: a #SoupServer
 * @path: (nullable): the toplevel path for the handler
 * @origin: (nullable): the origin of the connection
 * @protocols: (nullable) (array zero-terminated=1): the protocols
 *   supported by this handler
 * @callback: (scope notified) (destroy destroy): callback to invoke for
 *   successful WebSocket requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds a WebSocket handler to @server for requests prefixed by @path.
 *
 * If @path is %NULL or "/", then this will be the default handler for all
 * requests that don't have a more specific handler.
 *
 * When a path has a WebSocket handler registered, @server will check
 * incoming requests for WebSocket handshakes after all other handlers
 * have run (unless some earlier handler has already set a status code
 * on the message), and update the request's status, response headers,
 * and response body accordingly.
 *
 * If @origin is non-%NULL, then only requests containing a matching
 * "Origin" header will be accepted. If @protocols is non-%NULL, then
 * only requests containing a compatible "Sec-WebSocket-Protocols"
 * header will be accepted. More complicated requirements can be
 * handled by adding a normal handler to @path, and having it perform
 * whatever checks are needed and
 * setting a failure status code if the handshake should be rejected.
 **/
void
soup_server_add_websocket_handler (SoupServer                   *server,
				   const char                   *path,
				   const char                   *origin,
				   char                        **protocols,
				   SoupServerWebsocketCallback   callback,
				   gpointer                      user_data,
				   GDestroyNotify                destroy)
{
	SoupServerHandler *handler;

	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (callback != NULL);

	handler = get_or_create_handler (server, path);
	if (handler->websocket_destroy)
		handler->websocket_destroy (handler->websocket_user_data);
	if (handler->websocket_origin)
		g_free (handler->websocket_origin);
	if (handler->websocket_protocols)
		g_strfreev (handler->websocket_protocols);
	g_list_free_full (handler->websocket_extensions, g_object_unref);

	handler->websocket_callback   = callback;
	handler->websocket_destroy    = destroy;
	handler->websocket_user_data  = user_data;
	handler->websocket_origin     = g_strdup (origin);
	handler->websocket_protocols  = g_strdupv (protocols);
	handler->websocket_extensions = NULL;
}

/**
 * soup_server_remove_handler:
 * @server: a #SoupServer
 * @path: the toplevel path for the handler
 *
 * Removes all handlers (early and normal) registered at @path.
 **/
void
soup_server_remove_handler (SoupServer *server, const char *path)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	soup_path_map_remove (priv->handlers, NORMALIZED_PATH (path));
}

/**
 * soup_server_add_auth_domain:
 * @server: a #SoupServer
 * @auth_domain: a #SoupAuthDomain
 *
 * Adds an authentication domain to @server.
 *
 * Each auth domain will have the chance to require authentication for each
 * request that comes in; normally auth domains will require authentication for
 * requests on certain paths that they have been set up to watch, or that meet
 * other criteria set by the caller. If an auth domain determines that a request
 * requires authentication (and the request doesn't contain authentication),
 * @server will automatically reject the request with an appropriate status (401
 * Unauthorized or 407 Proxy Authentication Required). If the request used the
 * SoupServer:100-continue Expectation, @server will reject it before the
 * request body is sent.
 **/
void
soup_server_add_auth_domain (SoupServer *server, SoupAuthDomain *auth_domain)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	priv->auth_domains = g_slist_append (priv->auth_domains, auth_domain);
	g_object_ref (auth_domain);
}

/**
 * soup_server_remove_auth_domain:
 * @server: a #SoupServer
 * @auth_domain: a #SoupAuthDomain
 *
 * Removes @auth_domain from @server.
 **/
void
soup_server_remove_auth_domain (SoupServer *server, SoupAuthDomain *auth_domain)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	priv->auth_domains = g_slist_remove (priv->auth_domains, auth_domain);
	g_object_unref (auth_domain);
}

/**
 * soup_server_pause_message:
 * @server: a #SoupServer
 * @msg: a #SoupServerMessage associated with @server.
 *
 * Pauses I/O on @msg.
 *
 * This can be used when you need to return from the server handler without
 * having the full response ready yet. Use [method@Server.unpause_message] to
 * resume I/O.
 *
 * This must only be called on a [class@ServerMessage] which was created by the
 * [class@Server] and are currently doing I/O, such as those passed into a
 * [callback@ServerCallback] or emitted in a [signal@Server::request-read]
 * signal.
 *
 * Deprecated: 3.2: Use soup_server_message_pause() instead.
 **/
void
soup_server_pause_message (SoupServer        *server,
			   SoupServerMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));

	soup_server_message_pause (msg);
}

/**
 * soup_server_unpause_message:
 * @server: a #SoupServer
 * @msg: a #SoupServerMessage associated with @server.
 *
 * Resumes I/O on @msg.
 *
 * Use this to resume after calling [method@Server.pause_message], or after
 * adding a new chunk to a chunked response.
 *
 * I/O won't actually resume until you return to the main loop.
 *
 * This must only be called on a [class@ServerMessage] which was created by the
 * [class@Server] and are currently doing I/O, such as those passed into a
 * [callback@ServerCallback] or emitted in a [signal@Server::request-read]
 * signal.
 *
 * Deprecated: 3.2: Use soup_server_message_unpause() instead.
 **/
void
soup_server_unpause_message (SoupServer        *server,
			     SoupServerMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));

	soup_server_message_unpause (msg);
}

/**
 * soup_server_add_websocket_extension:
 * @server: a #SoupServer
 * @extension_type: a #GType
 *
 * Add support for a WebSocket extension of the given @extension_type.
 *
 * When a WebSocket client requests an extension of @extension_type,
 * a new [class@WebsocketExtension] of type @extension_type will be created
 * to handle the request.
 *
 * Note that [class@WebsocketExtensionDeflate] is supported by default, use
 * [method@Server.remove_websocket_extension] if you want to disable it.
 */
void
soup_server_add_websocket_extension (SoupServer *server, GType extension_type)
{
        SoupServerPrivate *priv;

        g_return_if_fail (SOUP_IS_SERVER (server));

        priv = soup_server_get_instance_private (server);
        if (!g_type_is_a (extension_type, SOUP_TYPE_WEBSOCKET_EXTENSION)) {
                g_warning ("Type '%s' is not a SoupWebsocketExtension", g_type_name (extension_type));
                return;
        }

        g_ptr_array_add (priv->websocket_extension_types, g_type_class_ref (extension_type));
}

/**
 * soup_server_remove_websocket_extension:
 * @server: a #SoupServer
 * @extension_type: a #GType
 *
 * Removes support for WebSocket extension of type @extension_type (or any subclass of
 * @extension_type) from @server.
 */
void
soup_server_remove_websocket_extension (SoupServer *server, GType extension_type)
{
        SoupServerPrivate *priv;
        SoupWebsocketExtensionClass *extension_class;
        guint i;

        g_return_if_fail (SOUP_IS_SERVER (server));

        priv = soup_server_get_instance_private (server);
        if (!g_type_is_a (extension_type, SOUP_TYPE_WEBSOCKET_EXTENSION)) {
                g_warning ("Type '%s' is not a SoupWebsocketExtension", g_type_name (extension_type));
                return;
        }

        extension_class = g_type_class_peek (extension_type);
        for (i = 0; i < priv->websocket_extension_types->len; i++) {
                if (priv->websocket_extension_types->pdata[i] == (gpointer)extension_class) {
                        g_ptr_array_remove_index (priv->websocket_extension_types, i);
                        break;
                }
        }
}

void
soup_server_set_http2_enabled (SoupServer *server,
                               gboolean    enabled)
{
        SoupServerPrivate *priv = soup_server_get_instance_private (server);

        priv->http2_enabled = enabled;
}
