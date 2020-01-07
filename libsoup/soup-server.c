/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
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

#include "soup-server.h"
#include "soup.h"
#include "soup-message-private.h"
#include "soup-misc-private.h"
#include "soup-path-map.h" 
#include "soup-socket-private.h"
#include "soup-websocket.h"
#include "soup-websocket-connection.h"
#include "soup-websocket-extension-deflate.h"

/**
 * SECTION:soup-server
 * @short_description: HTTP server
 * @see_also: #SoupAuthDomain
 *
 * #SoupServer implements a simple HTTP server.
 *
 * (The following documentation describes the current #SoupServer API,
 * available in <application>libsoup</application> 2.48 and later. See
 * the section "<link linkend="soup-server-old-api">The Old SoupServer
 * Listening API</link>" in the server how-to documentation for
 * details on the older #SoupServer API.)
 * 
 * To begin, create a server using soup_server_new(). Add at least one
 * handler by calling soup_server_add_handler() or
 * soup_server_add_early_handler(); the handler will be called to
 * process any requests underneath the path you pass. (If you want all
 * requests to go to the same handler, just pass "/" (or %NULL) for
 * the path.)
 *
 * When a new connection is accepted (or a new request is started on
 * an existing persistent connection), the #SoupServer will emit
 * #SoupServer::request-started and then begin processing the request
 * as described below, but note that once the message is assigned a
 * #SoupMessage:status-code, then callbacks after that point will be
 * skipped. Note also that it is not defined when the callbacks happen
 * relative to various #SoupMessage signals.
 *
 * Once the headers have been read, #SoupServer will check if there is
 * a #SoupAuthDomain (qv) covering the Request-URI; if so, and if the
 * message does not contain suitable authorization, then the
 * #SoupAuthDomain will set a status of %SOUP_STATUS_UNAUTHORIZED on
 * the message.
 *
 * After checking for authorization, #SoupServer will look for "early"
 * handlers (added with soup_server_add_early_handler()) matching the
 * Request-URI. If one is found, it will be run; in particular, this
 * can be used to connect to signals to do a streaming read of the
 * request body.
 *
 * (At this point, if the request headers contain "<literal>Expect:
 * 100-continue</literal>", and a status code has been set, then
 * #SoupServer will skip the remaining steps and return the response.
 * If the request headers contain "<literal>Expect:
 * 100-continue</literal>" and no status code has been set,
 * #SoupServer will return a %SOUP_STATUS_CONTINUE status before
 * continuing.)
 *
 * The server will then read in the response body (if present). At
 * this point, if there are no handlers at all defined for the
 * Request-URI, then the server will return %SOUP_STATUS_NOT_FOUND to
 * the client.
 *
 * Otherwise (assuming no previous step assigned a status to the
 * message) any "normal" handlers (added with
 * soup_server_add_handler()) for the message's Request-URI will be
 * run.
 *
 * Then, if the path has a WebSocket handler registered (and has
 * not yet been assigned a status), #SoupServer will attempt to
 * validate the WebSocket handshake, filling in the response and
 * setting a status of %SOUP_STATUS_SWITCHING_PROTOCOLS or
 * %SOUP_STATUS_BAD_REQUEST accordingly.
 *
 * If the message still has no status code at this point (and has not
 * been paused with soup_server_pause_message()), then it will be
 * given a status of %SOUP_STATUS_INTERNAL_SERVER_ERROR (because at
 * least one handler ran, but returned without assigning a status).
 *
 * Finally, the server will emit #SoupServer::request-finished (or
 * #SoupServer::request-aborted if an I/O error occurred before
 * handling was completed).
 *
 * If you want to handle the special "*" URI (eg, "OPTIONS *"), you
 * must explicitly register a handler for "*"; the default handler
 * will not be used for that case.
 * 
 * If you want to process https connections in addition to (or instead
 * of) http connections, you can either set the
 * %SOUP_SERVER_TLS_CERTIFICATE property when creating the server, or
 * else call soup_server_set_ssl_certificate() after creating it.
 *
 * Once the server is set up, make one or more calls to
 * soup_server_listen(), soup_server_listen_local(), or
 * soup_server_listen_all() to tell it where to listen for
 * connections. (All ports on a #SoupServer use the same handlers; if
 * you need to handle some ports differently, such as returning
 * different data for http and https, you'll need to create multiple
 * #SoupServers, or else check the passed-in URI in the handler
 * function.).
 *
 * #SoupServer will begin processing connections as soon as you return
 * to (or start) the main loop for the current thread-default
 * #GMainContext.
 */

enum {
	REQUEST_STARTED,
	REQUEST_READ,
	REQUEST_FINISHED,
	REQUEST_ABORTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct SoupClientContext {
	SoupServer     *server;
	SoupSocket     *sock;
	GSocket        *gsock;
	SoupMessage    *msg;
	SoupAuthDomain *auth_domain;
	char           *auth_user;

	GSocketAddress *remote_addr;
	char           *remote_ip;
	GSocketAddress *local_addr;

	int             ref_count;
};

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

	char              *ssl_cert_file, *ssl_key_file;
	GTlsCertificate   *tls_cert;

	char              *server_header;

	GMainContext      *async_context;
	GMainLoop         *loop;

	gboolean           raw_paths;
	SoupPathMap       *handlers;

	GSList            *auth_domains;

	char             **http_aliases, **https_aliases;

	SoupAddress       *legacy_iface;
	int                legacy_port;

	GPtrArray         *websocket_extension_types;

	gboolean           disposed;

} SoupServerPrivate;

#define SOUP_SERVER_SERVER_HEADER_BASE "libsoup/" PACKAGE_VERSION

enum {
	PROP_0,

	PROP_PORT,
	PROP_INTERFACE,
	PROP_SSL_CERT_FILE,
	PROP_SSL_KEY_FILE,
	PROP_TLS_CERT_FILE,
	PROP_TLS_KEY_FILE,
	PROP_TLS_CERTIFICATE,
	PROP_ASYNC_CONTEXT,
	PROP_RAW_PATHS,
	PROP_SERVER_HEADER,
	PROP_HTTP_ALIASES,
	PROP_HTTPS_ALIASES,
	PROP_ADD_WEBSOCKET_EXTENSION,
	PROP_REMOVE_WEBSOCKET_EXTENSION,

	LAST_PROP
};

G_DEFINE_TYPE_WITH_PRIVATE (SoupServer, soup_server, G_TYPE_OBJECT)

static SoupClientContext *soup_client_context_ref (SoupClientContext *client);
static void soup_client_context_unref (SoupClientContext *client);

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

	priv->handlers = soup_path_map_new ((GDestroyNotify)free_handler);

	priv->http_aliases = g_new (char *, 2);
	priv->http_aliases[0] = (char *)g_intern_string ("*");
	priv->http_aliases[1] = NULL;

	priv->legacy_port = -1;

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

	g_clear_object (&priv->legacy_iface);

	g_free (priv->ssl_cert_file);
	g_free (priv->ssl_key_file);
	g_clear_object (&priv->tls_cert);

	g_free (priv->server_header);

	soup_path_map_free (priv->handlers);

	g_slist_free_full (priv->auth_domains, g_object_unref);

	g_clear_pointer (&priv->loop, g_main_loop_unref);
	g_clear_pointer (&priv->async_context, g_main_context_unref);

	g_free (priv->http_aliases);
	g_free (priv->https_aliases);

	g_ptr_array_free (priv->websocket_extension_types, TRUE);

	G_OBJECT_CLASS (soup_server_parent_class)->finalize (object);
}

static gboolean
soup_server_ensure_listening (SoupServer *server)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupSocket *listener;

	if (priv->listeners)
		return TRUE;

	if (!priv->legacy_iface) {
		priv->legacy_iface =
			soup_address_new_any (SOUP_ADDRESS_FAMILY_IPV4,
					      priv->legacy_port);
	}

	listener = soup_socket_new (SOUP_SOCKET_LOCAL_ADDRESS, priv->legacy_iface,
				    SOUP_SOCKET_SSL_CREDENTIALS, priv->tls_cert,
				    SOUP_SOCKET_ASYNC_CONTEXT, priv->async_context,
				    NULL);
	if (!soup_socket_listen (listener)) {
		g_object_unref (listener);
		return FALSE;
	}

	/* Re-resolve the interface address, in particular in case
	 * the passed-in address had SOUP_ADDRESS_ANY_PORT.
	 */
	g_object_unref (priv->legacy_iface);
	priv->legacy_iface = soup_socket_get_local_address (listener);
	g_object_ref (priv->legacy_iface);
	priv->legacy_port = soup_address_get_port (priv->legacy_iface);

	priv->listeners = g_slist_prepend (priv->listeners, listener);
	return TRUE;
}

static GObject *
soup_server_constructor (GType                  type,
			 guint                  n_construct_properties,
			 GObjectConstructParam *construct_properties)
{
	GObject *server;
	SoupServerPrivate *priv;
	gboolean legacy_port_set;

	server = G_OBJECT_CLASS (soup_server_parent_class)->
		constructor (type, n_construct_properties, construct_properties);
	priv = soup_server_get_instance_private (SOUP_SERVER (server));

	/* For backward compatibility, we have to process the
	 * :ssl-cert-file, :ssl-key-file, :interface, and :port
	 * properties now, and return NULL if they are
	 * invalid/unsatisfiable.
	 */
	if (priv->ssl_cert_file && priv->ssl_key_file) {
		GError *error = NULL;

		if (priv->tls_cert)
			g_object_unref (priv->tls_cert);
		priv->tls_cert = g_tls_certificate_new_from_files (priv->ssl_cert_file, priv->ssl_key_file, &error);
		if (!priv->tls_cert) {
			g_warning ("Could not read TLS certificate from '%s': %s",
				   priv->ssl_cert_file, error->message);
			g_error_free (error);
			g_object_unref (server);
			return NULL;
		}
	}

	if (priv->legacy_port != -1)
		legacy_port_set = TRUE;
	else {
		legacy_port_set = FALSE;
		priv->legacy_port = 0;
	}

	if (legacy_port_set || priv->legacy_iface) {
		if (!soup_server_ensure_listening (SOUP_SERVER (server))) {
			g_object_unref (server);
			return NULL;
		}
	} else {
		/* If neither port nor iface was specified, then
		 * either: (a) the caller is planning to use the new
		 * listen APIs, so we don't have to do anything now,
		 * or (b) the caller is using the legacy APIs but
		 * wants the default values for interface and port
		 * (address 0.0.0.0, port 0), in which case a later
		 * call to soup_server_ensure_listening() will set it
		 * up just-in-time; we don't have to worry about it
		 * failing in that case, because it can't (unless you
		 * have no IPv4 addresses configured [even localhost],
		 * or there are already listeners on all 65,535 ports.
		 * We assume neither of these will happen.)
		 */
	}

	return server;
}

/* priv->http_aliases and priv->https_aliases are stored as arrays of
 * *interned* strings, so we can't just use g_strdupv() to set them.
 */
static void
set_aliases (char ***variable, char **value)
{
	int len, i;

	if (*variable)
		g_free (*variable);

	if (!value) {
		*variable = NULL;
		return;
	}

	len = g_strv_length (value);
	*variable = g_new (char *, len + 1);
	for (i = 0; i < len; i++)
		(*variable)[i] = (char *)g_intern_string (value[i]);
	(*variable)[i] = NULL;
}

static void
soup_server_set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	const char *header;

	switch (prop_id) {
	case PROP_PORT:
		if (g_value_get_uint (value) != 0)
			priv->legacy_port = g_value_get_uint (value);
		break;
	case PROP_INTERFACE:
		if (priv->legacy_iface)
			g_object_unref (priv->legacy_iface);
		priv->legacy_iface = g_value_get_object (value);
		if (priv->legacy_iface)
			g_object_ref (priv->legacy_iface);
		break;
	case PROP_SSL_CERT_FILE:
		g_free (priv->ssl_cert_file);
		priv->ssl_cert_file = g_value_dup_string (value);
		break;
	case PROP_SSL_KEY_FILE:
		g_free (priv->ssl_key_file);
		priv->ssl_key_file = g_value_dup_string (value);
		break;
	case PROP_TLS_CERTIFICATE:
		if (priv->tls_cert)
			g_object_unref (priv->tls_cert);
		priv->tls_cert = g_value_dup_object (value);
		break;
	case PROP_ASYNC_CONTEXT:
		priv->async_context = g_value_get_pointer (value);
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
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
	case PROP_HTTP_ALIASES:
		set_aliases (&priv->http_aliases, g_value_get_boxed (value));
		break;
	case PROP_HTTPS_ALIASES:
		set_aliases (&priv->https_aliases, g_value_get_boxed (value));
		break;
	case PROP_ADD_WEBSOCKET_EXTENSION:
		soup_server_add_websocket_extension (server, g_value_get_gtype (value));
		break;
	case PROP_REMOVE_WEBSOCKET_EXTENSION:
		soup_server_remove_websocket_extension (server, g_value_get_gtype (value));
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
	case PROP_PORT:
		soup_server_ensure_listening (server);
		g_value_set_uint (value, priv->legacy_port > 0 ? priv->legacy_port : 0);
		break;
	case PROP_INTERFACE:
		soup_server_ensure_listening (server);
		g_value_set_object (value, priv->legacy_iface);
		break;
	case PROP_SSL_CERT_FILE:
		g_value_set_string (value, priv->ssl_cert_file);
		break;
	case PROP_SSL_KEY_FILE:
		g_value_set_string (value, priv->ssl_key_file);
		break;
	case PROP_TLS_CERTIFICATE:
		g_value_set_object (value, priv->tls_cert);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	case PROP_RAW_PATHS:
		g_value_set_boolean (value, priv->raw_paths);
		break;
	case PROP_SERVER_HEADER:
		g_value_set_string (value, priv->server_header);
		break;
	case PROP_HTTP_ALIASES:
		g_value_set_boxed (value, priv->http_aliases);
		break;
	case PROP_HTTPS_ALIASES:
		g_value_set_boxed (value, priv->https_aliases);
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
	object_class->constructor = soup_server_constructor;
	object_class->dispose = soup_server_dispose;
	object_class->finalize = soup_server_finalize;
	object_class->set_property = soup_server_set_property;
	object_class->get_property = soup_server_get_property;

	/* signals */

	/**
	 * SoupServer::request-started:
	 * @server: the server
	 * @message: the new message
	 * @client: the client context
	 *
	 * Emitted when the server has started reading a new request.
	 * @message will be completely blank; not even the
	 * Request-Line will have been read yet. About the only thing
	 * you can usefully do with it is connect to its signals.
	 *
	 * If the request is read successfully, this will eventually
	 * be followed by a #SoupServer::request_read signal. If a
	 * response is then sent, the request processing will end with
	 * a #SoupServer::request_finished signal. If a network error
	 * occurs, the processing will instead end with
	 * #SoupServer::request_aborted.
	 **/
	signals[REQUEST_STARTED] =
		g_signal_new ("request-started",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_started),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2, 
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_CLIENT_CONTEXT);

	/**
	 * SoupServer::request-read:
	 * @server: the server
	 * @message: the message
	 * @client: the client context
	 *
	 * Emitted when the server has successfully read a request.
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
			      G_TYPE_NONE, 2,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_CLIENT_CONTEXT);

	/**
	 * SoupServer::request-finished:
	 * @server: the server
	 * @message: the message
	 * @client: the client context
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
			      G_TYPE_NONE, 2,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_CLIENT_CONTEXT);

	/**
	 * SoupServer::request-aborted:
	 * @server: the server
	 * @message: the message
	 * @client: the client context
	 *
	 * Emitted when processing has failed for a message; this
	 * could mean either that it could not be read (if
	 * #SoupServer::request_read has not been emitted for it yet),
	 * or that the response could not be written back (if
	 * #SoupServer::request_read has been emitted but
	 * #SoupServer::request_finished has not been).
	 *
	 * @message is in an undefined state when this signal is
	 * emitted; the signal exists primarily to allow the server to
	 * free any state that it may have allocated in
	 * #SoupServer::request_started.
	 **/
	signals[REQUEST_ABORTED] =
		g_signal_new ("request-aborted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_aborted),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      SOUP_TYPE_MESSAGE,
			      SOUP_TYPE_CLIENT_CONTEXT);

	/* properties */
	/**
	 * SoupServer:port:
	 *
	 * The port the server is listening on, if you are using the
	 * old #SoupServer API. (This will not be set if you use
	 * soup_server_listen(), etc.)
	 *
	 * Deprecated: #SoupServers can listen on multiple interfaces
	 * at once now. Use soup_server_listen(), etc, to listen on a
	 * port, and soup_server_get_uris() to see what ports are
	 * being listened on.
	 */
	/**
	 * SOUP_SERVER_PORT:
	 *
	 * Alias for the deprecated #SoupServer:port property, qv.
	 *
	 * Deprecated: #SoupServers can listen on multiple interfaces
	 * at once now. Use soup_server_listen(), etc, to listen on a
	 * port, and soup_server_get_uris() to see what ports are
	 * being listened on.
	 **/
	g_object_class_install_property (
		object_class, PROP_PORT,
		g_param_spec_uint (SOUP_SERVER_PORT,
				   "Port",
				   "Port to listen on (Deprecated)",
				   0, 65536, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_CONSTRUCT_ONLY |
				   G_PARAM_STATIC_STRINGS |
				   G_PARAM_DEPRECATED));
	/**
	 * SoupServer:interface:
	 *
	 * The address of the network interface the server is
	 * listening on, if you are using the old #SoupServer API.
	 * (This will not be set if you use soup_server_listen(),
	 * etc.)
	 *
	 * Deprecated: #SoupServers can listen on multiple interfaces
	 * at once now. Use soup_server_listen(), etc, to listen on an
	 * interface, and soup_server_get_uris() to see what addresses
	 * are being listened on.
	 */
	/**
	 * SOUP_SERVER_INTERFACE:
	 *
	 * Alias for the #SoupServer:interface property, qv.
	 *
	 * Deprecated: #SoupServers can listen on multiple interfaces
	 * at once now. Use soup_server_listen(), etc, to listen on an
	 * interface, and soup_server_get_uris() to see what addresses
	 * are being listened on.
	 **/
	g_object_class_install_property (
		object_class, PROP_INTERFACE,
		g_param_spec_object (SOUP_SERVER_INTERFACE,
				     "Interface",
				     "Address of interface to listen on (Deprecated)",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS |
				     G_PARAM_DEPRECATED));
	/**
	 * SOUP_SERVER_SSL_CERT_FILE:
	 *
	 * Alias for the #SoupServer:ssl-cert-file property, qv.
	 *
	 * Deprecated: use #SoupServer:tls-certificate or
	 * soup_server_set_ssl_certificate().
	 */
	/**
	 * SoupServer:ssl-cert-file:
	 *
	 * Path to a file containing a PEM-encoded certificate.
	 *
	 * If you set this property and #SoupServer:ssl-key-file at
	 * construct time, then soup_server_new() will try to read the
	 * files; if it cannot, it will return %NULL, with no explicit
	 * indication of what went wrong (and logging a warning with
	 * newer versions of glib, since returning %NULL from a
	 * constructor is illegal).
	 *
	 * Deprecated: use #SoupServer:tls-certificate or
	 * soup_server_set_ssl_certificate().
	 */
	g_object_class_install_property (
		object_class, PROP_SSL_CERT_FILE,
		g_param_spec_string (SOUP_SERVER_SSL_CERT_FILE,
				     "TLS (aka SSL) certificate file",
				     "File containing server TLS (aka SSL) certificate",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SERVER_SSL_KEY_FILE:
	 *
	 * Alias for the #SoupServer:ssl-key-file property, qv.
	 *
	 * Deprecated: use #SoupServer:tls-certificate or
	 * soup_server_set_ssl_certificate().
	 */
	/**
	 * SoupServer:ssl-key-file:
	 *
	 * Path to a file containing a PEM-encoded private key. See
	 * #SoupServer:ssl-cert-file for more information about how this
	 * is used.
	 *
	 * Deprecated: use #SoupServer:tls-certificate or
	 * soup_server_set_ssl_certificate().
	 */
	g_object_class_install_property (
		object_class, PROP_SSL_KEY_FILE,
		g_param_spec_string (SOUP_SERVER_SSL_KEY_FILE,
				     "TLS (aka SSL) key file",
				     "File containing server TLS (aka SSL) key",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_CONSTRUCT_ONLY |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SOUP_SERVER_TLS_CERTIFICATE:
	 *
	 * Alias for the #SoupServer:tls-certificate property, qv.
	 *
	 * Since: 2.38
	 */
	/**
	 * SoupServer:tls-certificate:
	 *
	 * A #GTlsCertificate that has a #GTlsCertificate:private-key
	 * set. If this is set, then the server will be able to speak
	 * https in addition to (or instead of) plain http.
	 *
	 * Alternatively, you can call soup_server_set_ssl_cert_file()
	 * to have #SoupServer read in a a certificate from a file.
	 *
	 * Since: 2.38
	 */
	g_object_class_install_property (
		object_class, PROP_TLS_CERTIFICATE,
		g_param_spec_object (SOUP_SERVER_TLS_CERTIFICATE,
				     "TLS certificate",
				     "GTlsCertificate to use for https",
				     G_TYPE_TLS_CERTIFICATE,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
	/**
	 * SoupServer:async-context:
	 *
	 * The server's #GMainContext, if you are using the old API.
	 * Servers created using soup_server_listen() will listen on
	 * the #GMainContext that was the thread-default context at
	 * the time soup_server_listen() was called.
	 *
	 * Deprecated: The new API uses the thread-default #GMainContext
	 * rather than having an explicitly-specified one.
	 */
	/**
	 * SOUP_SERVER_ASYNC_CONTEXT:
	 *
	 * Alias for the deprecated #SoupServer:async-context
	 * property, qv.
	 *
	 * Deprecated: The new API uses the thread-default #GMainContext
	 * rather than having an explicitly-specified one.
	 **/
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_SERVER_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "The GMainContext to dispatch async I/O in",
				      G_PARAM_READWRITE |
				      G_PARAM_CONSTRUCT_ONLY |
				      G_PARAM_STATIC_STRINGS |
				      G_PARAM_DEPRECATED));
	/**
	 * SOUP_SERVER_RAW_PATHS:
	 *
	 * Alias for the #SoupServer:raw-paths property. (If %TRUE,
	 * percent-encoding in the Request-URI path will not be
	 * automatically decoded.)
	 **/
	g_object_class_install_property (
		object_class, PROP_RAW_PATHS,
		g_param_spec_boolean (SOUP_SERVER_RAW_PATHS,
				      "Raw paths",
				      "If %TRUE, percent-encoding in the Request-URI path will not be automatically decoded.",
				      FALSE,
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	/**
	 * SoupServer:server-header:
	 *
	 * If non-%NULL, the value to use for the "Server" header on
	 * #SoupMessage<!-- -->s processed by this server.
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
	 * As with #SoupSession:user_agent, if you set a
	 * #SoupServer:server_header property that has trailing whitespace,
	 * #SoupServer will append its own product token (eg,
	 * "<literal>libsoup/2.3.2</literal>") to the end of the
	 * header for you.
	 **/
	/**
	 * SOUP_SERVER_SERVER_HEADER:
	 *
	 * Alias for the #SoupServer:server-header property, qv.
	 **/
	g_object_class_install_property (
		object_class, PROP_SERVER_HEADER,
		g_param_spec_string (SOUP_SERVER_SERVER_HEADER,
				     "Server header",
				     "Server header",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));

	/**
	 * SoupServer:http-aliases:
	 *
	 * A %NULL-terminated array of URI schemes that should be
	 * considered to be aliases for "http". Eg, if this included
	 * <literal>"dav"</literal>, than a URI of
	 * <literal>dav://example.com/path</literal> would be treated
	 * identically to <literal>http://example.com/path</literal>.
	 * In particular, this is needed in cases where a client
	 * sends requests with absolute URIs, where those URIs do
	 * not use "http:".
	 *
	 * The default value is an array containing the single element
	 * <literal>"*"</literal>, a special value which means that
	 * any scheme except "https" is considered to be an alias for
	 * "http".
	 *
	 * See also #SoupServer:https-aliases.
	 *
	 * Since: 2.44
	 */
	/**
	 * SOUP_SERVER_HTTP_ALIASES:
	 *
	 * Alias for the #SoupServer:http-aliases property, qv.
	 *
	 * Since: 2.44
	 */
	g_object_class_install_property (
		object_class, PROP_HTTP_ALIASES,
		g_param_spec_boxed (SOUP_SERVER_HTTP_ALIASES,
				    "http aliases",
				    "URI schemes that are considered aliases for 'http'",
				    G_TYPE_STRV,
				    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
	/**
	 * SoupServer:https-aliases:
	 *
	 * A comma-delimited list of URI schemes that should be
	 * considered to be aliases for "https". See
	 * #SoupServer:http-aliases for more information.
	 *
	 * The default value is %NULL, meaning that no URI schemes
	 * are considered aliases for "https".
	 *
	 * Since: 2.44
	 */
	/**
	 * SOUP_SERVER_HTTPS_ALIASES:
	 *
	 * Alias for the #SoupServer:https-aliases property, qv.
	 *
	 * Since: 2.44
	 **/
	g_object_class_install_property (
		object_class, PROP_HTTPS_ALIASES,
		g_param_spec_boxed (SOUP_SERVER_HTTPS_ALIASES,
				    "https aliases",
				    "URI schemes that are considered aliases for 'https'",
				    G_TYPE_STRV,
				    G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

        /**
         * SoupServer:add-websocket-extension: (skip)
         *
         * Add support for #SoupWebsocketExtension of the given type.
         * (Shortcut for calling soup_server_add_websocket_extension().)
         *
         * Since: 2.68
         **/
        /**
         * SOUP_SERVER_ADD_WEBSOCKET_EXTENSION: (skip)
         *
         * Alias for the #SoupServer:add-websocket-extension property, qv.
         *
         * Since: 2.68
         **/
        g_object_class_install_property (
                object_class, PROP_ADD_WEBSOCKET_EXTENSION,
                g_param_spec_gtype (SOUP_SERVER_ADD_WEBSOCKET_EXTENSION,
                                    "Add support for a WebSocket extension",
                                    "Add support for a WebSocket extension of the given type",
                                    SOUP_TYPE_WEBSOCKET_EXTENSION,
                                    G_PARAM_WRITABLE | G_PARAM_STATIC_STRINGS));
        /**
         * SoupServer:remove-websocket-extension: (skip)
         *
         * Remove support for #SoupWebsocketExtension of the given type. (Shortcut for
         * calling soup_server_remove_websocket_extension().)
         *
         * Since: 2.68
         **/
        /**
         * SOUP_SERVER_REMOVE_WEBSOCKET_EXTENSION: (skip)
         *
         * Alias for the #SoupServer:remove-websocket-extension property, qv.
         *
         * Since: 2.68
         **/
        g_object_class_install_property (
                object_class, PROP_REMOVE_WEBSOCKET_EXTENSION,
                g_param_spec_gtype (SOUP_SERVER_REMOVE_WEBSOCKET_EXTENSION,
                                    "Remove support for a WebSocket extension",
                                    "Remove support for a WebSocket extension of the given type",
                                    SOUP_TYPE_WEBSOCKET_EXTENSION,
                                    G_PARAM_WRITABLE | G_PARAM_STATIC_STRINGS));
}

/**
 * soup_server_new:
 * @optname1: name of first property to set
 * @...: value of @optname1, followed by additional property/value pairs
 *
 * Creates a new #SoupServer. This is exactly equivalent to calling
 * g_object_new() and specifying %SOUP_TYPE_SERVER as the type.
 *
 * Return value: (nullable): a new #SoupServer. If you are using
 * certain legacy properties, this may also return %NULL if an error
 * occurs.
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
 * soup_server_get_port:
 * @server: a #SoupServer
 *
 * Gets the TCP port that @server is listening on, if you are using
 * the old API.
 *
 * Return value: the port @server is listening on.
 *
 * Deprecated: If you are using soup_server_listen(), etc, then use
 * soup_server_get_uris() to get a list of all listening addresses.
 **/
guint
soup_server_get_port (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);
	priv = soup_server_get_instance_private (server);

	soup_server_ensure_listening (server);
	g_return_val_if_fail (priv->legacy_iface != NULL, 0);

	return priv->legacy_port;
}

/**
 * soup_server_set_ssl_cert_file:
 * @server: a #SoupServer
 * @ssl_cert_file: path to a file containing a PEM-encoded SSL/TLS
 *   certificate.
 * @ssl_key_file: path to a file containing a PEM-encoded private key.
 * @error: return location for a #GError
 *
 * Sets @server up to do https, using the SSL/TLS certificate
 * specified by @ssl_cert_file and @ssl_key_file (which may point to
 * the same file).
 *
 * Alternatively, you can set the #SoupServer:tls-certificate property
 * at construction time, if you already have a #GTlsCertificate.
 *
 * Return value: success or failure.
 *
 * Since: 2.48
 */
gboolean
soup_server_set_ssl_cert_file  (SoupServer  *server,
				const char  *ssl_cert_file,
				const char  *ssl_key_file,
				GError     **error)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	priv = soup_server_get_instance_private (server);

	if (priv->tls_cert)
		g_object_unref (priv->tls_cert);

	g_free (priv->ssl_cert_file);
	priv->ssl_cert_file = g_strdup (ssl_cert_file);

	g_free (priv->ssl_key_file);
	priv->ssl_key_file = g_strdup (ssl_key_file);

	priv->tls_cert = g_tls_certificate_new_from_files (priv->ssl_cert_file,
							   priv->ssl_key_file,
							   error);
	return priv->tls_cert != NULL;
}

/**
 * soup_server_is_https:
 * @server: a #SoupServer
 *
 * Checks whether @server is capable of https.
 *
 * In order for a server to run https, you must call
 * soup_server_set_ssl_cert_file(), or set the
 * #SoupServer:tls-certificate property, to provide it with a
 * certificate to use.
 *
 * If you are using the deprecated single-listener APIs, then a return
 * value of %TRUE indicates that the #SoupServer serves https
 * exclusively. If you are using soup_server_listen(), etc, then a
 * %TRUE return value merely indicates that the server is
 * <emphasis>able</emphasis> to do https, regardless of whether it
 * actually currently is or not. Use soup_server_get_uris() to see if
 * it currently has any https listeners.
 *
 * Return value: %TRUE if @server is configured to serve https.
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
 * soup_server_get_listener:
 * @server: a #SoupServer
 *
 * Gets @server's listening socket, if you are using the old API.
 *
 * You should treat this socket as read-only; writing to it or
 * modifiying it may cause @server to malfunction.
 *
 * Return value: (transfer none): the listening socket.
 *
 * Deprecated: If you are using soup_server_listen(), etc, then use
 * soup_server_get_listeners() to get a list of all listening sockets,
 * but note that that function returns #GSockets, not #SoupSockets.
 **/
SoupSocket *
soup_server_get_listener (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = soup_server_get_instance_private (server);

	soup_server_ensure_listening (server);
	g_return_val_if_fail (priv->legacy_iface != NULL, NULL);

	return priv->listeners ? priv->listeners->data : NULL;
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
 * (Beware that in contrast to the old soup_server_get_listener(), this
 * function returns #GSockets, not #SoupSockets.)
 *
 * Return value: (transfer container) (element-type Gio.Socket): a
 * list of listening sockets.
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
		listeners = g_slist_prepend (listeners, soup_socket_get_gsocket (iter->data));

	/* priv->listeners has the sockets in reverse order from how
	 * they were added, so listeners now has them back in the
	 * original order.
	 */
	return listeners;
}

static void start_request (SoupServer *, SoupClientContext *);
static void socket_disconnected (SoupSocket *sock, SoupClientContext *client);

static SoupClientContext *
soup_client_context_new (SoupServer *server, SoupSocket *sock)
{
	SoupClientContext *client = g_slice_new0 (SoupClientContext);

	client->server = server;
	client->sock = g_object_ref (sock);
	client->gsock = soup_socket_get_gsocket (sock);
	if (client->gsock)
		g_object_ref (client->gsock);
	g_signal_connect (sock, "disconnected",
			  G_CALLBACK (socket_disconnected), client);
	client->ref_count = 1;

	return client;
}

static void
soup_client_context_cleanup (SoupClientContext *client)
{
	g_clear_object (&client->auth_domain);
	g_clear_pointer (&client->auth_user, g_free);
	g_clear_object (&client->remote_addr);
	g_clear_object (&client->local_addr);

	client->msg = NULL;
}

static SoupClientContext *
soup_client_context_ref (SoupClientContext *client)
{
	g_atomic_int_inc (&client->ref_count);
	return client;
}

static void
soup_client_context_unref (SoupClientContext *client)
{
	if (!g_atomic_int_dec_and_test (&client->ref_count))
		return;

	soup_client_context_cleanup (client);

	g_signal_handlers_disconnect_by_func (client->sock, socket_disconnected, client);
	g_object_unref (client->sock);
	g_clear_object (&client->gsock);
	g_clear_pointer (&client->remote_ip, g_free);
	g_slice_free (SoupClientContext, client);
}

static void
request_finished (SoupMessage *msg, SoupMessageIOCompletion completion, gpointer user_data)
{
	SoupClientContext *client = user_data;
	SoupServer *server = client->server;
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupSocket *sock = client->sock;
	gboolean failed;

	if (completion == SOUP_MESSAGE_IO_STOLEN) {
		soup_client_context_unref (client);
		g_object_unref (msg);
		return;
	}

	/* Complete the message, assuming it actually really started. */
	if (msg->method) {
		soup_message_finished (msg);

		failed = (completion == SOUP_MESSAGE_IO_INTERRUPTED ||
			  msg->status_code == SOUP_STATUS_IO_ERROR);
		g_signal_emit (server,
			       failed ? signals[REQUEST_ABORTED] : signals[REQUEST_FINISHED],
			       0, msg, client);
	}

	if (completion == SOUP_MESSAGE_IO_COMPLETE &&
	    soup_socket_is_connected (sock) &&
	    soup_message_is_keepalive (msg) &&
	    priv->listeners) {
		start_request (server, client);
	} else {
		soup_socket_disconnect (client->sock);
		soup_client_context_unref (client);
	}
	g_object_unref (msg);
}

/* "" was never documented as meaning the same thing as "/", but it
 * effectively was. We have to special case it now or otherwise it
 * would match "*" too.
 */
#define NORMALIZED_PATH(path) ((path) && *(path) ? (path) : "/")

static SoupServerHandler *
get_handler (SoupServer *server, SoupMessage *msg)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupURI *uri;

	uri = soup_message_get_uri (msg);
	return soup_path_map_lookup (priv->handlers, NORMALIZED_PATH (uri->path));
}

static void
call_handler (SoupServer *server, SoupServerHandler *handler,
	      SoupClientContext *client, SoupMessage *msg,
	      gboolean early)
{
	GHashTable *form_data_set;
	SoupURI *uri;

	if (early && !handler->early_callback)
		return;
	else if (!early && !handler->callback)
		return;

	if (msg->status_code != 0)
		return;

	uri = soup_message_get_uri (msg);
	if (uri->query)
		form_data_set = soup_form_decode (uri->query);
	else
		form_data_set = NULL;

	if (early) {
		(*handler->early_callback) (server, msg,
					    uri->path, form_data_set,
					    client, handler->early_user_data);
	} else {
		(*handler->callback) (server, msg,
				      uri->path, form_data_set,
				      client, handler->user_data);
	}

	if (form_data_set)
		g_hash_table_unref (form_data_set);
}

static void
got_headers (SoupMessage *msg, SoupClientContext *client)
{
	SoupServer *server = client->server;
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupServerHandler *handler;
	SoupURI *uri;
	SoupDate *date;
	char *date_string;
	SoupAuthDomain *domain;
	GSList *iter;
	gboolean rejected = FALSE;
	char *auth_user;

	/* Add required response headers */
	date = soup_date_new_from_now (0);
	date_string = soup_date_to_string (date, SOUP_DATE_HTTP);
	soup_message_headers_replace (msg->response_headers, "Date",
				      date_string);
	g_free (date_string);
	soup_date_free (date);

	if (msg->status_code != 0)
		return;

	uri = soup_message_get_uri (msg);
	if ((soup_socket_is_ssl (client->sock) && !soup_uri_is_https (uri, priv->https_aliases)) ||
	    (!soup_socket_is_ssl (client->sock) && !soup_uri_is_http (uri, priv->http_aliases))) {
		soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
		return;
	}

	if (!priv->raw_paths) {
		char *decoded_path;

		decoded_path = soup_uri_decode (uri->path);

		if (strstr (decoded_path, "/../") ||
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
			soup_message_set_status (msg, SOUP_STATUS_BAD_REQUEST);
			return;
		}

		soup_uri_set_path (uri, decoded_path);
		g_free (decoded_path);
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
				client->auth_domain = g_object_ref (domain);
				client->auth_user = auth_user;
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
		call_handler (server, handler, client, msg, TRUE);
}

static void
complete_websocket_upgrade (SoupMessage *msg, gpointer user_data)
{
	SoupClientContext *client = user_data;
	SoupServer *server = client->server;
	SoupURI *uri = soup_message_get_uri (msg);
	SoupServerHandler *handler;
	GIOStream *stream;
	SoupWebsocketConnection *conn;

	handler = get_handler (server, msg);
	if (!handler || !handler->websocket_callback)
		return;

	soup_client_context_ref (client);
	stream = soup_client_context_steal_connection (client);
	conn = soup_websocket_connection_new_with_extensions (stream, uri,
							      SOUP_WEBSOCKET_CONNECTION_SERVER,
							      soup_message_headers_get_one (msg->request_headers, "Origin"),
							      soup_message_headers_get_one (msg->response_headers, "Sec-WebSocket-Protocol"),
							      handler->websocket_extensions);
	handler->websocket_extensions = NULL;
	g_object_unref (stream);
	soup_client_context_unref (client);

	(*handler->websocket_callback) (server, conn, uri->path, client,
					handler->websocket_user_data);
	g_object_unref (conn);
	soup_client_context_unref (client);
}

static void
got_body (SoupMessage *msg, SoupClientContext *client)
{
	SoupServer *server = client->server;
	SoupServerHandler *handler;

	g_signal_emit (server, signals[REQUEST_READ], 0, msg, client);

	if (msg->status_code != 0)
		return;

	handler = get_handler (server, msg);
	if (!handler) {
		soup_message_set_status (msg, SOUP_STATUS_NOT_FOUND);
		return;
	}

	call_handler (server, handler, client, msg, FALSE);
	if (msg->status_code != 0)
		return;

	if (handler->websocket_callback) {
		SoupServerPrivate *priv;

		priv = soup_server_get_instance_private (server);
		if (soup_websocket_server_process_handshake_with_extensions (msg,
									     handler->websocket_origin,
									     handler->websocket_protocols,
									     priv->websocket_extension_types,
									     &handler->websocket_extensions)) {
			g_signal_connect (msg, "wrote-informational",
					  G_CALLBACK (complete_websocket_upgrade),
					  soup_client_context_ref (client));
		}
	}
}

static void
start_request (SoupServer *server, SoupClientContext *client)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupMessage *msg;

	soup_client_context_cleanup (client);

	/* Listen for another request on this connection */
	msg = g_object_new (SOUP_TYPE_MESSAGE,
			    SOUP_MESSAGE_SERVER_SIDE, TRUE,
			    NULL);
	client->msg = msg;

	if (priv->server_header) {
		soup_message_headers_append (msg->response_headers, "Server",
					     priv->server_header);
	}

	g_signal_connect (msg, "got_headers", G_CALLBACK (got_headers), client);
	g_signal_connect (msg, "got_body", G_CALLBACK (got_body), client);

	g_signal_emit (server, signals[REQUEST_STARTED], 0,
		       msg, client);

	soup_message_read_request (msg, client->sock,
				   priv->legacy_iface == NULL,
				   request_finished, client);
}

static void
socket_disconnected (SoupSocket *sock, SoupClientContext *client)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (client->server);

	priv->clients = g_slist_remove (priv->clients, client);

	if (client->msg) {
		soup_message_set_status (client->msg, SOUP_STATUS_IO_ERROR);
		soup_message_io_finished (client->msg);
	}
}

static void
soup_server_accept_socket (SoupServer *server,
			   SoupSocket *sock)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	SoupClientContext *client;

	client = soup_client_context_new (server, sock);
	priv->clients = g_slist_prepend (priv->clients, client);
	start_request (server, client);
}

/**
 * soup_server_accept_iostream:
 * @server: a #SoupServer
 * @stream: a #GIOStream
 * @local_addr: (allow-none): the local #GSocketAddress associated with the @stream
 * @remote_addr: (allow-none): the remote #GSocketAddress associated with the @stream
 * @error: return location for a #GError
 *
 * Add a new client stream to the @server.
 *
 * Return value: %TRUE on success, %FALSE if the stream could not be
 * accepted or any other error occurred (in which case @error will be
 * set).
 *
 * Since: 2.50
 **/
gboolean
soup_server_accept_iostream   (SoupServer     *server,
			       GIOStream      *stream,
			       GSocketAddress *local_addr,
			       GSocketAddress *remote_addr,
			       GError        **error)
{
	SoupSocket *sock;
	SoupAddress *local = NULL, *remote = NULL;

	if (local_addr)
		local = soup_address_new_from_gsockaddr (local_addr);
	if (remote_addr)
		remote = soup_address_new_from_gsockaddr (remote_addr);

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, error,
			       "iostream", stream,
			       "local-address", local,
			       "remote-address", remote,
			       NULL);

	g_clear_object (&local);
	g_clear_object (&remote);

	if (!sock)
		return FALSE;

	soup_server_accept_socket (server, sock);
	g_object_unref (sock);

	return TRUE;
}

static void
new_connection (SoupSocket *listener, SoupSocket *sock, gpointer user_data)
{
	SoupServer *server = user_data;

	soup_server_accept_socket (server, sock);
}

/**
 * soup_server_run_async:
 * @server: a #SoupServer
 *
 * Starts @server, if you are using the old API, causing it to listen
 * for and process incoming connections.
 *
 * The server runs in @server's #GMainContext. It will not actually
 * perform any processing unless the appropriate main loop is running.
 * In the simple case where you did not set the server's
 * %SOUP_SERVER_ASYNC_CONTEXT property, this means the server will run
 * whenever the glib main loop is running.
 *
 * Deprecated: When using soup_server_listen(), etc, the server will
 * always listen for connections, and will process them whenever the
 * thread-default #GMainContext is running.
 **/
void
soup_server_run_async (SoupServer *server)
{
	SoupServerPrivate *priv;
	SoupSocket *listener;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	soup_server_ensure_listening (server);

	g_return_if_fail (priv->legacy_iface != NULL);

	if (!priv->listeners) {
		if (priv->loop) {
			g_main_loop_unref (priv->loop);
			priv->loop = NULL;
		}
		return;
	}

	listener = priv->listeners->data;
	g_signal_connect (listener, "new_connection",
			  G_CALLBACK (new_connection), server);

	return;
}

/**
 * soup_server_run:
 * @server: a #SoupServer
 *
 * Starts @server, if you are using the old API, causing it to listen
 * for and process incoming connections. Unlike
 * soup_server_run_async(), this creates a #GMainLoop and runs it, and
 * it will not return until someone calls soup_server_quit() to stop
 * the server.
 *
 * Deprecated: When using soup_server_listen(), etc, the server will
 * always listen for connections, and will process them whenever the
 * thread-default #GMainContext is running.
 **/
void
soup_server_run (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	if (!priv->loop) {
		priv->loop = g_main_loop_new (priv->async_context, TRUE);
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		soup_server_run_async (server);
		G_GNUC_END_IGNORE_DEPRECATIONS;
	}

	if (priv->loop)
		g_main_loop_run (priv->loop);
}

/**
 * soup_server_quit:
 * @server: a #SoupServer
 *
 * Stops processing for @server, if you are using the old API. Call
 * this to clean up after soup_server_run_async(), or to terminate a
 * call to soup_server_run().
 *
 * Note that messages currently in progress will continue to be
 * handled, if the main loop associated with the server is resumed or
 * kept running.
 *
 * @server is still in a working state after this call; you can start
 * and stop a server as many times as you want.
 *
 * Deprecated: When using soup_server_listen(), etc, the server will
 * always listen for connections, and will process them whenever the
 * thread-default #GMainContext is running.
 **/
void
soup_server_quit (SoupServer *server)
{
	SoupServerPrivate *priv;
	SoupSocket *listener;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);
	g_return_if_fail (priv->legacy_iface != NULL);
	g_return_if_fail (priv->listeners != NULL);

	listener = priv->listeners->data;
	g_signal_handlers_disconnect_by_func (listener,
					      G_CALLBACK (new_connection),
					      server);
	if (priv->loop)
		g_main_loop_quit (priv->loop);
}

/**
 * soup_server_disconnect:
 * @server: a #SoupServer
 *
 * Closes and frees @server's listening sockets. If you are using the
 * old #SoupServer APIs, this also includes the effect of
 * soup_server_quit().
 *
 * Note that if there are currently requests in progress on @server,
 * that they will continue to be processed if @server's #GMainContext
 * is still running.
 *
 * You can call soup_server_listen(), etc, after calling this function
 * if you want to start listening again.
 **/
void
soup_server_disconnect (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *listeners, *clients, *iter;
	SoupSocket *listener;
	SoupClientContext *client;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = soup_server_get_instance_private (server);

	if (priv->legacy_iface) {
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		soup_server_quit (server);
		G_GNUC_END_IGNORE_DEPRECATIONS;
	}

	clients = priv->clients;
	priv->clients = NULL;
	listeners = priv->listeners;
	priv->listeners = NULL;

	for (iter = clients; iter; iter = iter->next) {
		client = iter->data;
		soup_socket_disconnect (client->sock);
	}
	g_slist_free (clients);

	for (iter = listeners; iter; iter = iter->next) {
		listener = iter->data;
		soup_socket_disconnect (listener);
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
 * Options to pass to soup_server_listen(), etc.
 *
 * %SOUP_SERVER_LISTEN_IPV4_ONLY and %SOUP_SERVER_LISTEN_IPV6_ONLY
 * only make sense with soup_server_listen_all() and
 * soup_server_listen_local(), not plain soup_server_listen() (which
 * simply listens on whatever kind of socket you give it). And you
 * cannot specify both of them in a single call.
 *
 * Since: 2.48
 */

static gboolean
soup_server_listen_internal (SoupServer *server, SoupSocket *listener,
			     SoupServerListenOptions options,
			     GError **error)
{
	SoupServerPrivate *priv = soup_server_get_instance_private (server);
	gboolean is_listening;

	if (options & SOUP_SERVER_LISTEN_HTTPS) {
		if (!priv->tls_cert) {
			g_set_error_literal (error,
					     G_IO_ERROR,
					     G_IO_ERROR_INVALID_ARGUMENT,
					     _("Can’t create a TLS server without a TLS certificate"));
			return FALSE;
		}

		g_object_set (G_OBJECT (listener),
			      SOUP_SOCKET_SSL_CREDENTIALS, priv->tls_cert,
			      NULL);
	}

	g_object_get (G_OBJECT (listener),
		      SOUP_SOCKET_IS_SERVER, &is_listening,
		      NULL);
	if (!is_listening) {
		if (!soup_socket_listen_full (listener, error)) {
			SoupAddress *saddr = soup_socket_get_local_address (listener);

			g_prefix_error (error,
					_("Could not listen on address %s, port %d: "),
					soup_address_get_physical (saddr),
					soup_address_get_port (saddr));
			return FALSE;
		}
	}

	g_signal_connect (listener, "new_connection",
			  G_CALLBACK (new_connection), server);

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
 * This attempts to set up @server to listen for connections on
 * @address.
 *
 * If @options includes %SOUP_SERVER_LISTEN_HTTPS, and @server has
 * been configured for TLS, then @server will listen for https
 * connections on this port. Otherwise it will listen for plain http.
 *
 * You may call this method (along with the other "listen" methods)
 * any number of times on a server, if you want to listen on multiple
 * ports, or set up both http and https service.
 *
 * After calling this method, @server will begin accepting and
 * processing connections as soon as the appropriate #GMainContext is
 * run.
 *
 * Note that #SoupServer never makes use of dual IPv4/IPv6 sockets; if
 * @address is an IPv6 address, it will only accept IPv6 connections.
 * You must configure IPv4 listening separately.
 *
 * Return value: %TRUE on success, %FALSE if @address could not be
 * bound or any other error occurred (in which case @error will be
 * set).
 *
 * Since: 2.48
 **/
gboolean
soup_server_listen (SoupServer *server, GSocketAddress *address,
		    SoupServerListenOptions options,
		    GError **error)
{
	SoupServerPrivate *priv;
	SoupSocket *listener;
	SoupAddress *saddr;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) &&
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	priv = soup_server_get_instance_private (server);
	g_return_val_if_fail (priv->disposed == FALSE, FALSE);

	saddr = soup_address_new_from_gsockaddr (address);
	listener = soup_socket_new (SOUP_SOCKET_LOCAL_ADDRESS, saddr,
				    SOUP_SOCKET_USE_THREAD_CONTEXT, TRUE,
				    SOUP_SOCKET_IPV6_ONLY, TRUE,
				    NULL);

	success = soup_server_listen_internal (server, listener, options, error);
	g_object_unref (listener);
	g_object_unref (saddr);

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
	SoupSocket *v4sock;
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
		v4port = soup_address_get_port (soup_socket_get_local_address (v4sock));
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

	if (v4sock && g_error_matches (my_error, G_IO_ERROR,
#if GLIB_CHECK_VERSION (2, 41, 0)
				       G_IO_ERROR_NOT_SUPPORTED
#else
				       G_IO_ERROR_FAILED
#endif
				       )) {
		/* No IPv6 support, but IPV6_ONLY wasn't specified, so just
		 * ignore the failure.
		 */
		g_error_free (my_error);
		return TRUE;
	}

	if (v4sock) {
		priv->listeners = g_slist_remove (priv->listeners, v4sock);
		soup_socket_disconnect (v4sock);
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
 * This attempts to set up @server to listen for connections on all
 * interfaces on the system. (That is, it listens on the addresses
 * <literal>0.0.0.0</literal> and/or <literal>::</literal>, depending
 * on whether @options includes %SOUP_SERVER_LISTEN_IPV4_ONLY,
 * %SOUP_SERVER_LISTEN_IPV6_ONLY, or neither.) If @port is specified,
 * @server will listen on that port. If it is 0, @server will find an
 * unused port to listen on. (In that case, you can use
 * soup_server_get_uris() to find out what port it ended up choosing.)
 *
 * See soup_server_listen() for more details.
 *
 * Return value: %TRUE on success, %FALSE if @port could not be bound
 * or any other error occurred (in which case @error will be set).
 *
 * Since: 2.48
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
 * This attempts to set up @server to listen for connections on
 * "localhost" (that is, <literal>127.0.0.1</literal> and/or
 * <literal>::1</literal>, depending on whether @options includes
 * %SOUP_SERVER_LISTEN_IPV4_ONLY, %SOUP_SERVER_LISTEN_IPV6_ONLY, or
 * neither). If @port is specified, @server will listen on that port.
 * If it is 0, @server will find an unused port to listen on. (In that
 * case, you can use soup_server_get_uris() to find out what port it
 * ended up choosing.)
 *
 * See soup_server_listen() for more details.
 *
 * Return value: %TRUE on success, %FALSE if @port could not be bound
 * or any other error occurred (in which case @error will be set).
 *
 * Since: 2.48
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
 * This attempts to set up @server to listen for connections on
 * @socket.
 *
 * See soup_server_listen() for more details.
 *
 * Return value: %TRUE on success, %FALSE if an error occurred (in
 * which case @error will be set).
 *
 * Since: 2.48
 **/
gboolean
soup_server_listen_socket (SoupServer *server, GSocket *socket,
			   SoupServerListenOptions options,
			   GError **error)
{
	SoupServerPrivate *priv;
	SoupSocket *listener;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (G_IS_SOCKET (socket), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) &&
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	priv = soup_server_get_instance_private (server);
	g_return_val_if_fail (priv->disposed == FALSE, FALSE);

	listener = g_initable_new (SOUP_TYPE_SOCKET, NULL, error,
				   SOUP_SOCKET_GSOCKET, socket,
				   SOUP_SOCKET_USE_THREAD_CONTEXT, TRUE,
				   SOUP_SOCKET_IPV6_ONLY, TRUE,
				   NULL);
	if (!listener)
		return FALSE;

	success = soup_server_listen_internal (server, listener, options, error);
	g_object_unref (listener);

	return success;
}

/**
 * soup_server_listen_fd:
 * @server: a #SoupServer
 * @fd: the file descriptor of a listening socket
 * @options: listening options for this server
 * @error: return location for a #GError
 *
 * This attempts to set up @server to listen for connections on
 * @fd.
 *
 * See soup_server_listen() for more details.
 *
 * Note that @server will close @fd when you free it or call
 * soup_server_disconnect().
 *
 * Return value: %TRUE on success, %FALSE if an error occurred (in
 * which case @error will be set).
 *
 * Since: 2.48
 **/
gboolean
soup_server_listen_fd (SoupServer *server, int fd,
		       SoupServerListenOptions options,
		       GError **error)
{
	SoupServerPrivate *priv;
	SoupSocket *listener;
	gboolean success;

	g_return_val_if_fail (SOUP_IS_SERVER (server), FALSE);
	g_return_val_if_fail (!(options & SOUP_SERVER_LISTEN_IPV4_ONLY) &&
			      !(options & SOUP_SERVER_LISTEN_IPV6_ONLY), FALSE);

	priv = soup_server_get_instance_private (server);
	g_return_val_if_fail (priv->disposed == FALSE, FALSE);

	listener = g_initable_new (SOUP_TYPE_SOCKET, NULL, error,
				   SOUP_SOCKET_FD, fd,
				   SOUP_SOCKET_USE_THREAD_CONTEXT, TRUE,
				   SOUP_SOCKET_IPV6_ONLY, TRUE,
				   NULL);
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
 * listening on. These will contain IP addresses, not hostnames, and
 * will also indicate whether the given listener is http or https.
 *
 * Note that if you used soup_server_listen_all(), the returned URIs
 * will use the addresses <literal>0.0.0.0</literal> and
 * <literal>::</literal>, rather than actually returning separate URIs
 * for each interface on the system.
 *
 * Return value: (transfer full) (element-type Soup.URI): a list of
 * #SoupURIs, which you must free when you are done with it.
 *
 * Since: 2.48
 */
GSList *
soup_server_get_uris (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *uris, *l;
	SoupSocket *listener;
	SoupAddress *addr;
	SoupURI *uri;
	gpointer creds;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = soup_server_get_instance_private (server);

	for (l = priv->listeners, uris = NULL; l; l = l->next) {
		listener = l->data;
		addr = soup_socket_get_local_address (listener);
		g_object_get (G_OBJECT (listener), SOUP_SOCKET_SSL_CREDENTIALS, &creds, NULL);

		uri = soup_uri_new (NULL);
		soup_uri_set_scheme (uri, creds ? "https" : "http");
		soup_uri_set_host (uri, soup_address_get_physical (addr));
		soup_uri_set_port (uri, soup_address_get_port (addr));
		soup_uri_set_path (uri, "/");

		uris = g_slist_prepend (uris, uri);
	}

	return uris;
}

/**
 * soup_server_get_async_context:
 * @server: a #SoupServer
 *
 * Gets @server's async_context, if you are using the old API. (With
 * the new API, the server runs in the thread's thread-default
 * #GMainContext, regardless of what this method returns.)
 *
 * This does not add a ref to the context, so you will need to ref it
 * yourself if you want it to outlive its server.
 *
 * Return value: (nullable) (transfer none): @server's #GMainContext,
 * which may be %NULL
 *
 * Deprecated: If you are using soup_server_listen(), etc, then
 * the server listens on the thread-default #GMainContext, and this
 * property is ignored.
 **/
GMainContext *
soup_server_get_async_context (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = soup_server_get_instance_private (server);

	return priv->async_context;
}

/**
 * SoupClientContext:
 *
 * A #SoupClientContext provides additional information about the
 * client making a particular request. In particular, you can use
 * soup_client_context_get_auth_domain() and
 * soup_client_context_get_auth_user() to determine if HTTP
 * authentication was used successfully.
 *
 * soup_client_context_get_remote_address() and/or
 * soup_client_context_get_host() can be used to get information for
 * logging or debugging purposes. soup_client_context_get_gsocket() may
 * also be of use in some situations (eg, tracking when multiple
 * requests are made on the same connection).
 **/
G_DEFINE_BOXED_TYPE (SoupClientContext, soup_client_context, soup_client_context_ref, soup_client_context_unref)

/**
 * soup_client_context_get_socket:
 * @client: a #SoupClientContext
 *
 * Retrieves the #SoupSocket that @client is associated with.
 *
 * If you are using this method to observe when multiple requests are
 * made on the same persistent HTTP connection (eg, as the ntlm-test
 * test program does), you will need to pay attention to socket
 * destruction as well (either by using weak references, or by
 * connecting to the #SoupSocket::disconnected signal), so that you do
 * not get fooled when the allocator reuses the memory address of a
 * previously-destroyed socket to represent a new socket.
 *
 * Return value: (transfer none): the #SoupSocket that @client is
 * associated with.
 *
 * Deprecated: use soup_client_context_get_gsocket(), which returns
 * a #GSocket.
 **/
SoupSocket *
soup_client_context_get_socket (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	return client->sock;
}

/**
 * soup_client_context_get_gsocket:
 * @client: a #SoupClientContext
 *
 * Retrieves the #GSocket that @client is associated with.
 *
 * If you are using this method to observe when multiple requests are
 * made on the same persistent HTTP connection (eg, as the ntlm-test
 * test program does), you will need to pay attention to socket
 * destruction as well (eg, by using weak references), so that you do
 * not get fooled when the allocator reuses the memory address of a
 * previously-destroyed socket to represent a new socket.
 *
 * Return value: (nullable) (transfer none): the #GSocket that @client is
 * associated with, %NULL if you used soup_server_accept_iostream().
 *
 * Since: 2.48
 **/
GSocket *
soup_client_context_get_gsocket (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	return client->gsock;
}

/**
 * soup_client_context_get_address:
 * @client: a #SoupClientContext
 *
 * Retrieves the #SoupAddress associated with the remote end
 * of a connection.
 *
 * Return value: (nullable) (transfer none): the #SoupAddress
 * associated with the remote end of a connection, it may be
 * %NULL if you used soup_server_accept_iostream().
 *
 * Deprecated: Use soup_client_context_get_remote_address(), which returns
 * a #GSocketAddress.
 **/
SoupAddress *
soup_client_context_get_address (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	return soup_socket_get_remote_address (client->sock);
}

/**
 * soup_client_context_get_remote_address:
 * @client: a #SoupClientContext
 *
 * Retrieves the #GSocketAddress associated with the remote end
 * of a connection.
 *
 * Return value: (nullable) (transfer none): the #GSocketAddress
 * associated with the remote end of a connection, it may be
 * %NULL if you used soup_server_accept_iostream().
 *
 * Since: 2.48
 **/
GSocketAddress *
soup_client_context_get_remote_address (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	if (client->remote_addr)
		return client->remote_addr;

	client->remote_addr = client->gsock ?
		g_socket_get_remote_address (client->gsock, NULL) :
		soup_address_get_gsockaddr (soup_socket_get_remote_address (client->sock));

	return client->remote_addr;
}

/**
 * soup_client_context_get_local_address:
 * @client: a #SoupClientContext
 *
 * Retrieves the #GSocketAddress associated with the local end
 * of a connection.
 *
 * Return value: (nullable) (transfer none): the #GSocketAddress
 * associated with the local end of a connection, it may be
 * %NULL if you used soup_server_accept_iostream().
 *
 * Since: 2.48
 **/
GSocketAddress *
soup_client_context_get_local_address (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	if (client->local_addr)
		return client->local_addr;

	client->local_addr = client->gsock ?
		g_socket_get_local_address (client->gsock, NULL) :
		soup_address_get_gsockaddr (soup_socket_get_local_address (client->sock));

	return client->local_addr;
}

/**
 * soup_client_context_get_host:
 * @client: a #SoupClientContext
 *
 * Retrieves the IP address associated with the remote end of a
 * connection.
 *
 * Return value: (nullable): the IP address associated with the remote
 * end of a connection, it may be %NULL if you used
 * soup_server_accept_iostream().
 **/
const char *
soup_client_context_get_host (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	if (client->remote_ip)
		return client->remote_ip;

	if (client->gsock) {
		GSocketAddress *addr = soup_client_context_get_remote_address (client);
		GInetAddress *iaddr;

		if (!addr || !G_IS_INET_SOCKET_ADDRESS (addr))
			return NULL;
		iaddr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
		client->remote_ip = g_inet_address_to_string (iaddr);
	} else {
		SoupAddress *addr;

		G_GNUC_BEGIN_IGNORE_DEPRECATIONS;
		addr = soup_client_context_get_address (client);
		G_GNUC_END_IGNORE_DEPRECATIONS;
		client->remote_ip = g_strdup (soup_address_get_physical (addr));
	}

	return client->remote_ip;
}

/**
 * soup_client_context_get_auth_domain:
 * @client: a #SoupClientContext
 *
 * Checks whether the request associated with @client has been
 * authenticated, and if so returns the #SoupAuthDomain that
 * authenticated it.
 *
 * Return value: (transfer none) (nullable): a #SoupAuthDomain, or
 * %NULL if the request was not authenticated.
 **/
SoupAuthDomain *
soup_client_context_get_auth_domain (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	return client->auth_domain;
}

/**
 * soup_client_context_get_auth_user:
 * @client: a #SoupClientContext
 *
 * Checks whether the request associated with @client has been
 * authenticated, and if so returns the username that the client
 * authenticated as.
 *
 * Return value: (nullable): the authenticated-as user, or %NULL if
 * the request was not authenticated.
 **/
const char *
soup_client_context_get_auth_user (SoupClientContext *client)
{
	g_return_val_if_fail (client != NULL, NULL);

	return client->auth_user;
}

/**
 * soup_client_context_steal_connection:
 * @client: a #SoupClientContext
 *
 * "Steals" the HTTP connection associated with @client from its
 * #SoupServer. This happens immediately, regardless of the current
 * state of the connection; if the response to the current
 * #SoupMessage has not yet finished being sent, then it will be
 * discarded; you can steal the connection from a
 * #SoupMessage:wrote-informational or #SoupMessage:wrote-body signal
 * handler if you need to wait for part or all of the response to be
 * sent.
 *
 * Note that when calling this function from C, @client will most
 * likely be freed as a side effect.
 *
 * Return value: (transfer full): the #GIOStream formerly associated
 *   with @client (or %NULL if @client was no longer associated with a
 *   connection). No guarantees are made about what kind of #GIOStream
 *   is returned.
 *
 * Since: 2.50
 **/
GIOStream *
soup_client_context_steal_connection (SoupClientContext *client)
{
	GIOStream *stream;

	g_return_val_if_fail (client != NULL, NULL);

	soup_client_context_ref (client);

	stream = soup_message_io_steal (client->msg);
	if (stream) {
		g_object_set_data_full (G_OBJECT (stream), "GSocket",
					soup_socket_steal_gsocket (client->sock),
					g_object_unref);
	}

	socket_disconnected (client->sock, client);
	soup_client_context_unref (client);

	return stream;
}


/**
 * SoupServerCallback:
 * @server: the #SoupServer
 * @msg: the message being processed
 * @path: the path component of @msg's Request-URI
 * @query: (element-type utf8 utf8) (allow-none): the parsed query
 *   component of @msg's Request-URI
 * @client: additional contextual information about the client
 * @user_data: the data passed to soup_server_add_handler() or
 *   soup_server_add_early_handler().
 *
 * A callback used to handle requests to a #SoupServer.
 *
 * @path and @query contain the likewise-named components of the
 * Request-URI, subject to certain assumptions. By default,
 * #SoupServer decodes all percent-encoding in the URI path, such that
 * "/foo%<!-- -->2Fbar" is treated the same as "/foo/bar". If your
 * server is serving resources in some non-POSIX-filesystem namespace,
 * you may want to distinguish those as two distinct paths. In that
 * case, you can set the %SOUP_SERVER_RAW_PATHS property when creating
 * the #SoupServer, and it will leave those characters undecoded. (You
 * may want to call soup_uri_normalize() to decode any percent-encoded
 * characters that you aren't handling specially.)
 *
 * @query contains the query component of the Request-URI parsed
 * according to the rules for HTML form handling. Although this is the
 * only commonly-used query string format in HTTP, there is nothing
 * that actually requires that HTTP URIs use that format; if your
 * server needs to use some other format, you can just ignore @query,
 * and call soup_message_get_uri() and parse the URI's query field
 * yourself.
 *
 * See soup_server_add_handler() and soup_server_add_early_handler()
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
 * @path: (allow-none): the toplevel path for the handler
 * @callback: callback to invoke for requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds a handler to @server for requests under @path. If @path is
 * %NULL or "/", then this will be the default handler for all
 * requests that don't have a more specific handler. (Note though that
 * if you want to handle requests to the special "*" URI, you must
 * explicitly register a handler for "*"; the default handler will not
 * be used for that case.)
 *
 * For requests under @path (that have not already been assigned a
 * status code by a #SoupAuthDomain, an early #SoupServerHandler, or a
 * signal handler), @callback will be invoked after receiving the
 * request body; the message's #SoupMessage:method,
 * #SoupMessage:request-headers, and #SoupMessage:request-body fields
 * will be filled in.
 *
 * After determining what to do with the request, the callback must at
 * a minimum call soup_message_set_status() (or
 * soup_message_set_status_full()) on the message to set the response
 * status code. Additionally, it may set response headers and/or fill
 * in the response body.
 *
 * If the callback cannot fully fill in the response before returning
 * (eg, if it needs to wait for information from a database, or
 * another network server), it should call soup_server_pause_message()
 * to tell @server to not send the response right away. When the
 * response is ready, call soup_server_unpause_message() to cause it
 * to be sent.
 *
 * To send the response body a bit at a time using "chunked" encoding,
 * first call soup_message_headers_set_encoding() to set
 * %SOUP_ENCODING_CHUNKED on the #SoupMessage:response-headers. Then call
 * soup_message_body_append() (or soup_message_body_append_buffer())
 * to append each chunk as it becomes ready, and
 * soup_server_unpause_message() to make sure it's running. (The
 * server will automatically pause the message if it is using chunked
 * encoding but no more chunks are available.) When you are done, call
 * soup_message_body_complete() to indicate that no more chunks are
 * coming.
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
 * @path: (allow-none): the toplevel path for the handler
 * @callback: callback to invoke for requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds an "early" handler to @server for requests under @path. Note
 * that "normal" and "early" handlers are matched up together, so if
 * you add a normal handler for "/foo" and an early handler for
 * "/foo/bar", then a request to "/foo/bar" (or any path below it)
 * will run only the early handler. (But if you add both handlers at
 * the same path, then both will get run.)
 *
 * For requests under @path (that have not already been assigned a
 * status code by a #SoupAuthDomain or a signal handler), @callback
 * will be invoked after receiving the request headers, but before
 * receiving the request body; the message's #SoupMessage:method and
 * #SoupMessage:request-headers fields will be filled in.
 *
 * Early handlers are generally used for processing requests with
 * request bodies in a streaming fashion. If you determine that the
 * request will contain a message body, normally you would call
 * soup_message_body_set_accumulate() on the message's
 * #SoupMessage:request-body to turn off request-body accumulation,
 * and connect to the message's #SoupMessage::got-chunk signal to
 * process each chunk as it comes in.
 *
 * To complete the message processing after the full message body has
 * been read, you can either also connect to #SoupMessage::got-body,
 * or else you can register a non-early handler for @path as well. As
 * long as you have not set the #SoupMessage:status-code by the time
 * #SoupMessage::got-body is emitted, the non-early handler will be
 * run as well.
 *
 * Since: 2.50
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
 * @client: additional contextual information about the client
 * @user_data: the data passed to @soup_server_add_handler
 *
 * A callback used to handle WebSocket requests to a #SoupServer. The
 * callback will be invoked after sending the handshake response back
 * to the client (and is only invoked if the handshake was
 * successful).
 *
 * @path contains the path of the Request-URI, subject to the same
 * rules as #SoupServerCallback (qv).
 **/

/**
 * soup_server_add_websocket_handler:
 * @server: a #SoupServer
 * @path: (allow-none): the toplevel path for the handler
 * @origin: (allow-none): the origin of the connection
 * @protocols: (allow-none) (array zero-terminated=1): the protocols
 *   supported by this handler
 * @callback: callback to invoke for successful WebSocket requests under @path
 * @user_data: data for @callback
 * @destroy: destroy notifier to free @user_data
 *
 * Adds a WebSocket handler to @server for requests under @path. (If
 * @path is %NULL or "/", then this will be the default handler for
 * all requests that don't have a more specific handler.)
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
 * whatever checks are needed (possibly calling
 * soup_server_check_websocket_handshake() one or more times), and
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
 * Adds an authentication domain to @server. Each auth domain will
 * have the chance to require authentication for each request that
 * comes in; normally auth domains will require authentication for
 * requests on certain paths that they have been set up to watch, or
 * that meet other criteria set by the caller. If an auth domain
 * determines that a request requires authentication (and the request
 * doesn't contain authentication), @server will automatically reject
 * the request with an appropriate status (401 Unauthorized or 407
 * Proxy Authentication Required). If the request used the
 * "100-continue" Expectation, @server will reject it before the
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
 * @msg: a #SoupMessage associated with @server.
 *
 * Pauses I/O on @msg. This can be used when you need to return from
 * the server handler without having the full response ready yet. Use
 * soup_server_unpause_message() to resume I/O.
 *
 * This must only be called on #SoupMessages which were created by the
 * #SoupServer and are currently doing I/O, such as those passed into a
 * #SoupServerCallback or emitted in a #SoupServer::request-read signal.
 **/
void
soup_server_pause_message (SoupServer *server,
			   SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	soup_message_io_pause (msg);
}

/**
 * soup_server_unpause_message:
 * @server: a #SoupServer
 * @msg: a #SoupMessage associated with @server.
 *
 * Resumes I/O on @msg. Use this to resume after calling
 * soup_server_pause_message(), or after adding a new chunk to a
 * chunked response.
 *
 * I/O won't actually resume until you return to the main loop.
 *
 * This must only be called on #SoupMessages which were created by the
 * #SoupServer and are currently doing I/O, such as those passed into a
 * #SoupServerCallback or emitted in a #SoupServer::request-read signal.
 **/
void
soup_server_unpause_message (SoupServer *server,
			     SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	soup_message_io_unpause (msg);
}

/**
 * soup_server_add_websocket_extension:
 * @server: a #SoupServer
 * @extension_type: a #GType
 *
 * Add support for a WebSocket extension of the given @extension_type.
 * When a WebSocket client requests an extension of @extension_type,
 * a new #SoupWebsocketExtension of type @extension_type will be created
 * to handle the request.
 *
 * You can also add support for a WebSocket extension to the server at
 * construct time by using the %SOUP_SERVER_ADD_WEBSOCKET_EXTENSION property.
 * Note that #SoupWebsocketExtensionDeflate is supported by default, use
 * soup_server_remove_websocket_extension() if you want to disable it.
 *
 * Since: 2.68
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
 * @extension_type) from @server. You can also remove extensions enabled by default
 * from the server at construct time by using the %SOUP_SERVER_REMOVE_WEBSOCKET_EXTENSION
 * property.
 *
 * Since: 2.68
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
