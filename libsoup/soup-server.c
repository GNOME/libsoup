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
#include "soup-server-auth.h"
#include "soup-server-message.h"
#include "soup-socket.h"
#include "soup-ssl.h"

G_DEFINE_TYPE (SoupServer, soup_server, G_TYPE_OBJECT)

typedef struct {
	SoupAddress       *interface;
	guint              port;

	char              *ssl_cert_file, *ssl_key_file;
	gpointer           ssl_creds;

	GMainLoop         *loop;

	SoupSocket        *listen_sock;
	GSList            *client_socks;

	GHashTable        *handlers; /* KEY: path, VALUE: SoupServerHandler */
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

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_server_init (SoupServer *server)
{
	SoupServerPrivate *priv = SOUP_SERVER_GET_PRIVATE (server);

	priv->handlers = g_hash_table_new (g_str_hash, g_str_equal);
}

static void
free_handler (SoupServer *server, SoupServerHandler *hand)
{
	if (hand->unregister)
		(*hand->unregister) (server, hand, hand->user_data);

	if (hand->auth_ctx) {
		g_free ((char *) hand->auth_ctx->basic_info.realm);
		g_free ((char *) hand->auth_ctx->digest_info.realm);
		g_free (hand->auth_ctx);
	}

	g_free (hand->path);
	g_free (hand);
}

static void
free_handler_foreach (gpointer key, gpointer hand, gpointer server)
{
	free_handler (server, hand);
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
		free_handler (server, priv->default_handler);

	g_hash_table_foreach (priv->handlers, free_handler_foreach, server);
	g_hash_table_destroy (priv->handlers);

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
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

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
	SoupServerPrivate *priv;
	va_list ap;

	va_start (ap, optname1);
	server = (SoupServer *)g_object_new_valist (SOUP_TYPE_SERVER,
						    optname1, ap);
	va_end (ap);

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
		soup_socket_new (SOUP_SOCKET_SSL_CREDENTIALS, priv->ssl_creds,
				 SOUP_SOCKET_ASYNC_CONTEXT, priv->async_context,
				 NULL);
	if (!soup_socket_listen (priv->listen_sock, priv->interface)) {
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

guint
soup_server_get_port (SoupServer *server)
{
	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);

	return SOUP_SERVER_GET_PRIVATE (server)->port;
}

SoupProtocol
soup_server_get_protocol (SoupServer *server)
{
	SoupServerPrivate *priv;

	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (priv->ssl_cert_file && priv->ssl_key_file)
		return SOUP_PROTOCOL_HTTPS;
	else
		return SOUP_PROTOCOL_HTTP;
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
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (msg);

	if (soup_socket_is_connected (sock) && soup_message_is_keepalive (msg)) {
		/* Start a new request */
		start_request (soup_server_message_get_server (smsg), sock);
	} else
		soup_socket_disconnect (sock);
	g_object_unref (msg);
}

static inline void
set_response_error (SoupMessage *req, guint code, char *phrase, char *body)
{
	if (phrase)
		soup_message_set_status_full (req, code, phrase);
	else
		soup_message_set_status (req, code);

	req->response.owner = SOUP_BUFFER_STATIC;
	req->response.body = body;
	req->response.length = body ? strlen (req->response.body) : 0;
}


static void
call_handler (SoupMessage *req, SoupSocket *sock)
{
	SoupServer *server;
	SoupServerHandler *hand;
	SoupServerAuth *auth = NULL;
	const char *handler_path;

	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (req));

	server = soup_server_message_get_server (SOUP_SERVER_MESSAGE (req));
	handler_path = soup_message_get_uri (req)->path;

	hand = soup_server_get_handler (server, handler_path);
	if (!hand) {
		set_response_error (req, SOUP_STATUS_NOT_FOUND, NULL, NULL);
		return;
	}

	if (hand->auth_ctx) {
		SoupServerAuthContext *auth_ctx = hand->auth_ctx;
		const GSList *auth_hdrs;

		auth_hdrs = soup_message_get_header_list (req->request_headers,
							  "Authorization");
		auth = soup_server_auth_new (auth_ctx, auth_hdrs, req);

		if (auth_ctx->callback) {
			gboolean ret = FALSE;

			ret = (*auth_ctx->callback) (auth_ctx,
						     auth,
						     req,
						     auth_ctx->user_data);
			if (!ret) {
				soup_server_auth_context_challenge (
					auth_ctx,
					req,
					"WWW-Authenticate");

				if (!req->status_code)
					soup_message_set_status (
						req,
						SOUP_STATUS_UNAUTHORIZED);

				return;
			}
		} else if (req->status_code) {
			soup_server_auth_context_challenge (
				auth_ctx,
				req,
				"WWW-Authenticate");
			return;
		}
	}

	if (hand->callback) {
		const SoupUri *uri = soup_message_get_uri (req);
		SoupServerContext ctx;

		ctx.msg       = req;
		ctx.path      = uri->path;
		ctx.method_id = soup_method_get_id (req->method);
		ctx.auth      = auth;
		ctx.server    = server;
		ctx.handler   = hand;
		ctx.sock      = sock;

		/* Call method handler */
		(*hand->callback) (&ctx, req, hand->user_data);
	}

	if (auth)
		soup_server_auth_free (auth);
}

static void
start_request (SoupServer *server, SoupSocket *server_sock)
{
	SoupMessage *msg;

	/* Listen for another request on this connection */
	msg = (SoupMessage *)soup_server_message_new (server);

	g_signal_connect (msg, "got_body", G_CALLBACK (call_handler), server_sock);
	g_signal_connect (msg, "finished", G_CALLBACK (request_finished), server_sock);

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

	if (priv->loop)
		g_main_loop_quit (priv->loop);

	g_object_unref (server);
}

static void
append_handler (gpointer key, gpointer value, gpointer user_data)
{
	GSList **ret = user_data;

	*ret = g_slist_prepend (*ret, value);
}

GSList *
soup_server_list_handlers (SoupServer *server)
{
	SoupServerPrivate *priv;
	GSList *ret = NULL;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	g_hash_table_foreach (priv->handlers, append_handler, &ret);

	return ret;
}

SoupServerHandler *
soup_server_get_handler (SoupServer *server, const char *path)
{
	SoupServerPrivate *priv;
	char *mypath, *dir;
	SoupServerHandler *hand = NULL;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);
	priv = SOUP_SERVER_GET_PRIVATE (server);

	if (!path || !priv->handlers)
		return priv->default_handler;

	mypath = g_strdup (path);

	dir = strchr (mypath, '?');
	if (dir) *dir = '\0';

	dir = mypath;

	do {
		hand = g_hash_table_lookup (priv->handlers, mypath);
		if (hand) {
			g_free (mypath);
			return hand;
		}

		dir = strrchr (mypath, '/');
		if (dir) *dir = '\0';
	} while (dir);

	g_free (mypath);

	return priv->default_handler;
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
			 SoupServerUnregisterFn unregister,
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
	hand->unregister = unregister;
	hand->user_data  = user_data;

	if (path) {
		soup_server_remove_handler (server, path);
		g_hash_table_insert (priv->handlers, hand->path, hand);
	} else {
		soup_server_remove_handler (server, NULL);
		priv->default_handler = hand;
	}
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
			free_handler (server, priv->default_handler);
			priv->default_handler = NULL;
		}
		return;
	}

	hand = g_hash_table_lookup (priv->handlers, path);
	if (hand) {
		g_hash_table_remove (priv->handlers, path);
		free_handler (server, hand);
	}
}
