/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.c: Asynchronous HTTP server
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

/*
 * FIXME: Split into SoupServerTCP and SoupServerCGI subclasses
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "soup-server.h"
#include "soup-address.h"
#include "soup-headers.h"
#include "soup-message-private.h"
#include "soup-marshal.h"
#include "soup-path-map.h" 
#include "soup-server-auth.h"
#include "soup-socket.h"
#include "soup-ssl.h"

G_DEFINE_TYPE (SoupServer, soup_server, G_TYPE_OBJECT)

enum {
	REQUEST_STARTED,
	REQUEST_READ,
	REQUEST_FINISHED,
	REQUEST_ABORTED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	char                   *path;

	SoupServerAuthContext  *auth_ctx;

	SoupServerCallbackFn    callback;
	GDestroyNotify          destroy;
	gpointer                user_data;
} SoupServerHandler;

typedef struct {
	SoupAddress       *interface;
	guint              port;

	char              *ssl_cert_file, *ssl_key_file;
	SoupSSLCredentials *ssl_creds;

	GMainLoop         *loop;

	SoupSocket        *listen_sock;
	GSList            *client_socks;

	SoupPathMap       *handlers;
	SoupServerHandler *default_handler;
	
	GMainContext      *async_context;
} SoupServerPrivate;
#define SOUP_SERVER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_SERVER, SoupServerPrivate))

enum {
	PROP_0,

	PROP_PORT,
	PROP_INTERFACE,
	PROP_SSL_CERT_FILE,
	PROP_SSL_KEY_FILE,
	PROP_ASYNC_CONTEXT,

	LAST_PROP
};

static GObject *constructor (GType                  type,
			     guint                  n_construct_properties,
			     GObjectConstructParam *construct_properties);
static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
free_handler (SoupServerHandler *hand)
{
	if (hand->auth_ctx) {
		g_free ((char *) hand->auth_ctx->basic_info.realm);
		g_free ((char *) hand->auth_ctx->digest_info.realm);
		g_free (hand->auth_ctx);
	}

	g_free (hand->path);
	g_free (hand);
}

static void
soup_server_init (SoupServer *server)
{
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (server);

	priv->handlers = soup_path_map_new ((GDestroyNotify)free_handler);
}

static void
finalize (GObject *object)
{
	SoupServer *server = SOUP_SERVER (object);
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (server);

	if (priv->interface)
		g_object_unref (priv->interface);

	g_free (priv->ssl_cert_file);
	g_free (priv->ssl_key_file);
	if (priv->ssl_creds)
		soup_ssl_free_server_credentials (priv->ssl_creds);

	if (priv->listen_sock)
		g_object_unref (priv->listen_sock);

	while (priv->client_socks) {
		SoupSocket *sock = priv->client_socks->data;

		soup_socket_disconnect (sock);
		priv->client_socks =
			g_slist_remove (priv->client_socks, sock);
	}

	if (priv->default_handler)
		free_handler (priv->default_handler);
	soup_path_map_free (priv->handlers);

	if (priv->loop)
		g_main_loop_unref (priv->loop);
	if (priv->async_context)
		g_main_context_unref (priv->async_context);

	G_OBJECT_CLASS (soup_server_parent_class)->finalize (object);
}

static void
soup_server_class_init (SoupServerClass *server_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (server_class);

	g_type_class_add_private (server_class, sizeof (SoupServerPrivate));

	/* virtual method override */
	object_class->constructor = constructor;
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */

	/**
	 * SoupServer::request-started
	 * @server: the server
	 * @connection: an (opaque) connection ID
	 * @message: the new message
	 *
	 * Emitted when the server has started reading a new request.
	 * @message will be completely blank; not even the
	 * Request-Line will have been read yet. About the only thing
	 * you can usefully do with it is connect to its signals.
	 *
	 * If the request is read successfully, this will eventually
	 * be followed by a #request-read signal. If a response is
	 * then sent, the request processing will end with a
	 * #request-finished signal. If a network error occurs, the
	 * processing will instead end with #request-aborted.
	 **/
	signals[REQUEST_STARTED] =
		g_signal_new ("request-started",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_started),
			      NULL, NULL,
			      soup_marshal_NONE__POINTER_OBJECT,
			      G_TYPE_NONE, 2,
			      G_TYPE_POINTER,
			      SOUP_TYPE_MESSAGE);

	/**
	 * SoupServer::request-read
	 * @server: the server
	 * @connection: an (opaque) connection ID
	 * @message: the message
	 *
	 * Emitted when the server has successfully read a request.
	 * @message will have all of its request-side information
	 * filled in. This signal is emitted before any handlers are
	 * called for the message, and if it sets the message's
	 * #status_code, then normal handler processing will be
	 * skipped.
	 **/
	signals[REQUEST_READ] =
		g_signal_new ("request-read",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_read),
			      NULL, NULL,
			      soup_marshal_NONE__POINTER_OBJECT,
			      G_TYPE_NONE, 2,
			      G_TYPE_POINTER,
			      SOUP_TYPE_MESSAGE);

	/**
	 * SoupServer::request-finished
	 * @server: the server
	 * @connection: an (opaque) connection ID
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
			      soup_marshal_NONE__POINTER_OBJECT,
			      G_TYPE_NONE, 2,
			      G_TYPE_POINTER,
			      SOUP_TYPE_MESSAGE);

	/**
	 * SoupServer::request-aborted
	 * @server: the server
	 * @connection: an (opaque) connection ID
	 * @message: the message
	 *
	 * Emitted when processing has failed for a message; this
	 * could mean either that it could not be read (if
	 * #request-read has not been emitted for it yet), or that the
	 * response could not be written back (if #request-read has
	 * been emitted but #request-finished has not been).
	 *
	 * @message is in an undefined state when this signal is
	 * emitted; the signal exists primarily to allow the server to
	 * free any state that it may have allocated in
	 * #request-started.
	 **/
	signals[REQUEST_ABORTED] =
		g_signal_new ("request-aborted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupServerClass, request_aborted),
			      NULL, NULL,
			      soup_marshal_NONE__POINTER_OBJECT,
			      G_TYPE_NONE, 2,
			      G_TYPE_POINTER,
			      SOUP_TYPE_MESSAGE);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_PORT,
		g_param_spec_uint (SOUP_SERVER_PORT,
				   "Port",
				   "Port to listen on",
				   0, 65536, 0,
				   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_INTERFACE,
		g_param_spec_object (SOUP_SERVER_INTERFACE,
				     "Interface",
				     "Address of interface to listen on",
				     SOUP_TYPE_ADDRESS,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_CERT_FILE,
		g_param_spec_string (SOUP_SERVER_SSL_CERT_FILE,
				     "SSL certificate file",
				     "File containing server SSL certificate",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_SSL_KEY_FILE,
		g_param_spec_string (SOUP_SERVER_SSL_KEY_FILE,
				     "SSL key file",
				     "File containing server SSL key",
				     NULL,
				     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property (
		object_class, PROP_ASYNC_CONTEXT,
		g_param_spec_pointer (SOUP_SERVER_ASYNC_CONTEXT,
				      "Async GMainContext",
				      "The GMainContext to dispatch async I/O in",
				      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

static GObject *
constructor (GType                  type,
	     guint                  n_construct_properties,
	     GObjectConstructParam *construct_properties)
{
	GObject *server;
	SoupServerPrivate *priv;

	server = G_OBJECT_CLASS (soup_server_parent_class)->constructor (
		type, n_construct_properties, construct_properties);
	if (!server)
		return NULL;
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (!priv->interface) {
		priv->interface =
			soup_address_new_any (SOUP_ADDRESS_FAMILY_IPV4,
					      priv->port);
	}

	if (priv->ssl_cert_file && priv->ssl_key_file) {
		priv->ssl_creds = soup_ssl_get_server_credentials (
			priv->ssl_cert_file,
			priv->ssl_key_file);
		if (!priv->ssl_creds) {
			g_object_unref (server);
			return NULL;
		}
	}

	priv->listen_sock =
		soup_socket_new (SOUP_SOCKET_LOCAL_ADDRESS, priv->interface,
				 SOUP_SOCKET_SSL_CREDENTIALS, priv->ssl_creds,
				 SOUP_SOCKET_ASYNC_CONTEXT, priv->async_context,
				 NULL);
	if (!soup_socket_listen (priv->listen_sock)) {
		g_object_unref (server);
		return NULL;
	}

	/* Re-resolve the interface address, in particular in case
	 * the passed-in address had SOUP_ADDRESS_ANY_PORT.
	 */
	g_object_unref (priv->interface);
	priv->interface = soup_socket_get_local_address (priv->listen_sock);
	g_object_ref (priv->interface);
	priv->port = soup_address_get_port (priv->interface);

	return server;
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PORT:
		priv->port = g_value_get_uint (value);
		break;
	case PROP_INTERFACE:
		if (priv->interface)
			g_object_unref (priv->interface);
		priv->interface = g_value_get_object (value);
		if (priv->interface)
			g_object_ref (priv->interface);
		break;
	case PROP_SSL_CERT_FILE:
		priv->ssl_cert_file =
			g_strdup (g_value_get_string (value));
		break;
	case PROP_SSL_KEY_FILE:
		priv->ssl_key_file =
			g_strdup (g_value_get_string (value));
		break;
	case PROP_ASYNC_CONTEXT:
		priv->async_context = g_value_get_pointer (value);
		if (priv->async_context)
			g_main_context_ref (priv->async_context);
		break;
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PORT:
		g_value_set_uint (value, priv->port);
		break;
	case PROP_INTERFACE:
		g_value_set_object (value, priv->interface);
		break;
	case PROP_SSL_CERT_FILE:
		g_value_set_string (value, priv->ssl_cert_file);
		break;
	case PROP_SSL_KEY_FILE:
		g_value_set_string (value, priv->ssl_key_file);
		break;
	case PROP_ASYNC_CONTEXT:
		g_value_set_pointer (value, priv->async_context ? g_main_context_ref (priv->async_context) : NULL);
		break;
	default:
		break;
	}
}

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

guint
soup_server_get_port (SoupServer *server)
{
	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);

	return SOUP_SERVER_GET_PRIVATE (server)->port;
}

gboolean
soup_server_is_https (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	return (priv->ssl_cert_file && priv->ssl_key_file);
}

SoupSocket *
soup_server_get_listener (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	return priv->listen_sock;
}

static void start_request (SoupServer *, SoupSocket *);

static void
request_finished (SoupMessage *msg, gpointer sock)
{
	SoupServer *server = g_object_get_data (sock, "SoupServer");

	g_signal_emit (server,
		       msg->status_code == SOUP_STATUS_IO_ERROR ?
		       signals[REQUEST_ABORTED] : signals[REQUEST_FINISHED],
		       0, sock, msg);

	if (soup_socket_is_connected (sock) && soup_message_is_keepalive (msg)) {
		/* Start a new request */
		start_request (server, sock);
	} else
		soup_socket_disconnect (sock);
	g_object_unref (msg);
	g_object_unref (sock);
}

static inline void
set_response_error (SoupMessage *req, guint code, char *phrase, char *body)
{
	if (phrase)
		soup_message_set_status_full (req, code, phrase);
	else
		soup_message_set_status (req, code);

	soup_message_body_append (req->response_body,
				  body, body ? strlen (body) : 0,
				  SOUP_MEMORY_STATIC);
}

static SoupServerHandler *
soup_server_get_handler (SoupServer *server, const char *path)
{
	SoupServerPrivate *priv;
	SoupServerHandler *hand;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (path) {
		hand = soup_path_map_lookup (priv->handlers, path);
		if (hand)
			return hand;
	}
	return priv->default_handler;
}

static void
check_auth (SoupMessage *req, SoupSocket *sock)
{
	SoupServer *server;
	SoupServerHandler *hand;
	SoupServerAuthContext *auth_ctx;
	const char *auth_hdr;
	SoupServerAuth *auth = NULL;
	const char *handler_path;

	server = g_object_get_data (G_OBJECT (sock), "SoupServer");

	handler_path = soup_message_get_uri (req)->path;

	hand = soup_server_get_handler (server, handler_path);
	if (!hand || !hand->auth_ctx)
		return;

	auth_ctx = hand->auth_ctx;
	auth_hdr = soup_message_headers_find (req->request_headers,
					      "Authorization");
	auth = soup_server_auth_new (auth_ctx, auth_hdr, req);
	g_object_set_data_full (G_OBJECT (req), "SoupServerAuth", auth,
				(GDestroyNotify)soup_server_auth_free);

	if (!auth_ctx->callback (auth_ctx, auth, req, auth_ctx->user_data)) {
		soup_server_auth_context_challenge (auth_ctx, req,
						    "WWW-Authenticate");
		if (!req->status_code)
			set_response_error (req, SOUP_STATUS_UNAUTHORIZED, NULL, NULL);
	}
}

static void
call_handler (SoupMessage *req, SoupSocket *sock)
{
	SoupServer *server;
	SoupServerHandler *hand;
	const char *handler_path;

	if (req->status_code != 0)
		return;

	server = g_object_get_data (G_OBJECT (sock), "SoupServer");

	handler_path = soup_message_get_uri (req)->path;

	hand = soup_server_get_handler (server, handler_path);
	if (!hand) {
		set_response_error (req, SOUP_STATUS_NOT_FOUND, NULL, NULL);
		return;
	}

	if (hand->callback) {
		const SoupURI *uri = soup_message_get_uri (req);
		SoupServerContext ctx;

		ctx.msg       = req;
		ctx.path      = uri->path;
		ctx.auth      = g_object_get_data (G_OBJECT (req), "SoupServerAuth");
		ctx.server    = server;
		ctx.sock      = sock;

		/* Call method handler */
		(*hand->callback) (&ctx, req, hand->user_data);
	}
}

static void
start_request (SoupServer *server, SoupSocket *server_sock)
{
	SoupMessage *msg;

	/* Listen for another request on this connection */
	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
        soup_message_headers_set_encoding (msg->response_headers,
                                           SOUP_ENCODING_CONTENT_LENGTH);

	g_signal_connect (msg, "got_headers", G_CALLBACK (check_auth), server_sock);
	g_signal_connect (msg, "got_body", G_CALLBACK (call_handler), server_sock);
	g_signal_connect (msg, "finished", G_CALLBACK (request_finished), server_sock);

	g_signal_emit (server, signals[REQUEST_STARTED], 0,
		       server_sock, msg);

	g_object_ref (server_sock);
	soup_message_read_request (msg, server_sock);
}

static void
socket_disconnected (SoupSocket *sock, SoupServer *server)
{
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (server);

	priv->client_socks = g_slist_remove (priv->client_socks, sock);
	g_signal_handlers_disconnect_by_func (sock, socket_disconnected, server);
	g_object_unref (sock);
}

static void
new_connection (SoupSocket *listner, SoupSocket *sock, gpointer user_data)
{
	SoupServer *server = user_data;
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (server);

	g_object_ref (sock);
	g_object_set_data (G_OBJECT (sock), "SoupServer", server);
	priv->client_socks = g_slist_prepend (priv->client_socks, sock);
	g_signal_connect (sock, "disconnected",
			  G_CALLBACK (socket_disconnected), server);
	start_request (server, sock);
}

void
soup_server_run_async (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (!priv->listen_sock) {
		if (priv->loop) {
			g_main_loop_unref (priv->loop);
			priv->loop = NULL;
		}
		return;
	}

	g_signal_connect (priv->listen_sock, "new_connection",
			  G_CALLBACK (new_connection), server);
	g_object_ref (server);

	return;

}

void
soup_server_run (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (!priv->loop) {
		priv->loop = g_main_loop_new (priv->async_context, TRUE);
		soup_server_run_async (server);
	}

	if (priv->loop)
		g_main_loop_run (priv->loop);
}

void
soup_server_quit (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = SOUP_SERVER_GET_PRIVATE (server);

	g_signal_handlers_disconnect_by_func (priv->listen_sock,
					      G_CALLBACK (new_connection),
					      server);
	if (priv->loop)
		g_main_loop_quit (priv->loop);

	g_object_unref (server);
}

/**
 * soup_server_get_async_context:
 * @server: a #SoupServer
 *
 * Gets @server's async_context. This does not add a ref to the
 * context, so you will need to ref it yourself if you want it to
 * outlive its server.
 *
 * Return value: @server's #GMainContext, which may be %NULL
 **/
GMainContext *
soup_server_get_async_context (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	return priv->async_context;
}

SoupAddress *
soup_server_context_get_client_address (SoupServerContext *context)
{
	g_return_val_if_fail (context != NULL, NULL);

	return soup_socket_get_remote_address (context->sock);
}

const char *
soup_server_context_get_client_host (SoupServerContext *context)
{
	SoupAddress *address;

	address = soup_server_context_get_client_address (context);
	return soup_address_get_physical (address);
}

static SoupServerAuthContext *
auth_context_copy (SoupServerAuthContext *auth_ctx)
{
	SoupServerAuthContext *new_auth_ctx = NULL;

	new_auth_ctx = g_new0 (SoupServerAuthContext, 1);

	new_auth_ctx->types = auth_ctx->types;
	new_auth_ctx->callback = auth_ctx->callback;
	new_auth_ctx->user_data = auth_ctx->user_data;

	new_auth_ctx->basic_info.realm =
		g_strdup (auth_ctx->basic_info.realm);

	new_auth_ctx->digest_info.realm =
		g_strdup (auth_ctx->digest_info.realm);
	new_auth_ctx->digest_info.allow_algorithms =
		auth_ctx->digest_info.allow_algorithms;
	new_auth_ctx->digest_info.force_integrity =
		auth_ctx->digest_info.force_integrity;

	return new_auth_ctx;
}

void
soup_server_add_handler (SoupServer            *server,
			 const char            *path,
			 SoupServerAuthContext *auth_ctx,
			 SoupServerCallbackFn   callback,
			 GDestroyNotify         destroy,
			 gpointer               user_data)
{
	SoupServerPrivate *priv;
	SoupServerHandler *hand;
	SoupServerAuthContext *new_auth_ctx = NULL;

	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (callback != NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (auth_ctx)
		new_auth_ctx = auth_context_copy (auth_ctx);

	hand = g_new0 (SoupServerHandler, 1);
	hand->path       = g_strdup (path);
	hand->auth_ctx   = new_auth_ctx;
	hand->callback   = callback;
	hand->destroy    = destroy;
	hand->user_data  = user_data;

	soup_server_remove_handler (server, path);
	if (path)
		soup_path_map_add (priv->handlers, path, hand);
	else
		priv->default_handler = hand;
}

static void
unregister_handler (SoupServerHandler *handler)
{
	if (handler->destroy)
		handler->destroy (handler->user_data);
}

void
soup_server_remove_handler (SoupServer *server, const char *path)
{
	SoupServerPrivate *priv;
	SoupServerHandler *hand;

	g_return_if_fail (SOUP_IS_SERVER (server));
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (!path) {
		if (priv->default_handler) {
			unregister_handler (priv->default_handler);
			free_handler (priv->default_handler);
			priv->default_handler = NULL;
		}
		return;
	}

	hand = soup_path_map_lookup (priv->handlers, path);
	if (hand && !strcmp (path, hand->path)) {
		unregister_handler (hand);
		soup_path_map_remove (priv->handlers, path);
	}
}

/**
 * soup_server_pause_message:
 * @server: a #SoupServer
 * @msg: a #SoupMessage associated with @server.
 *
 * Pauses I/O on @msg. This can be used when you need to return from
 * the server handler without having the full response ready yet. Use
 * soup_server_unpause_message() to resume I/O.
 **/
void
soup_server_pause_message (SoupServer *server,
			   SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	soup_message_io_unpause (msg);
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
 **/
void
soup_server_unpause_message (SoupServer *server,
			     SoupMessage *msg)
{
	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	soup_message_io_unpause (msg);
}

