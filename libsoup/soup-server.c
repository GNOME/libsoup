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
#include "soup-private.h"
#include "soup-message-private.h"
#include "soup-server-auth.h"
#include "soup-server-message.h"
#include "soup-socket.h"

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

struct SoupServerPrivate {
	SoupProtocol       proto;
	guint              port;

	GMainLoop         *loop;

	SoupSocket        *listen_sock;
	GSList            *client_socks;

	GHashTable        *handlers; /* KEY: path, VALUE: SoupServerHandler */
	SoupServerHandler *default_handler;
};

static void
init (GObject *object)
{
	SoupServer *server = SOUP_SERVER (object);

	server->priv = g_new0 (SoupServerPrivate, 1);
	server->priv->handlers = g_hash_table_new (g_str_hash, g_str_equal);
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

	if (server->priv->listen_sock)
		g_object_unref (server->priv->listen_sock);

	while (server->priv->client_socks) {
		SoupSocket *sock = server->priv->client_socks->data;

		soup_socket_disconnect (sock);
		server->priv->client_socks =
			g_slist_remove (server->priv->client_socks, sock);
	}

	if (server->priv->default_handler)
		free_handler (server, server->priv->default_handler);

	g_hash_table_foreach (server->priv->handlers,
			      free_handler_foreach, server);
	g_hash_table_destroy (server->priv->handlers);

	if (server->priv->loop)
		g_main_loop_unref (server->priv->loop);

	g_free (server->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
}

SOUP_MAKE_TYPE (soup_server, SoupServer, class_init, init, PARENT_TYPE)


static SoupServer *
new_server (SoupAddress *address, SoupProtocol proto)
{
	SoupServer *server;
	SoupSocket *sock = NULL;

	g_return_val_if_fail (address, NULL);

	sock = soup_socket_server_new (address,
				       proto == SOUP_PROTOCOL_HTTPS,
				       NULL, NULL);
	if (!sock)
		return NULL;
	address = soup_socket_get_local_address (sock);

	server = g_object_new (SOUP_TYPE_SERVER, NULL);
	server->priv->port = soup_address_get_port (address);
	server->priv->proto = proto;
	server->priv->listen_sock = sock;

	return server;
}

SoupServer *
soup_server_new (SoupProtocol proto, guint port)
{
	return new_server (soup_address_new_any (SOUP_ADDRESS_FAMILY_IPV4, port), proto);
}

SoupServer *
soup_server_new_with_host (const char *host, SoupProtocol proto, guint port)
{
	SoupAddress *address;

	address = soup_address_new (host, port);
	if (!address)
		return NULL;

	return new_server (address, proto);
}

guint
soup_server_get_port (SoupServer *server)
{
	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);

	return server->priv->port;
}

SoupProtocol
soup_server_get_protocol (SoupServer *server)
{
	g_return_val_if_fail (SOUP_IS_SERVER (server), 0);

	return server->priv->proto;
}

static void start_request (SoupServer *, SoupSocket *);

static void
error_cb (SoupMessage *msg, gpointer user_data)
{
	g_object_unref (msg);
}

static void
write_done_cb (SoupMessage *msg, gpointer user_data)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (msg);

	if (soup_message_is_keepalive (msg)) {
		/* Start a new request */
		start_request (soup_server_message_get_server (smsg),
			       soup_message_get_socket (msg));
	}
	g_object_unref (msg);
}

static void
write_header (gpointer name, gpointer value, gpointer headers)
{
	g_string_append_printf (headers, "%s: %s\r\n",
				(char *)name, (char *)value);
}

static void
get_response_header_cb (SoupMessage *msg, GString *headers,
			gpointer user_data)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (msg);
	SoupTransferEncoding encoding =
		soup_server_message_get_encoding (smsg);

	if (!soup_server_message_is_started (smsg)) {
		soup_message_write_pause (msg);
		return;
	}

	g_string_append_printf (headers, "HTTP/1.1 %d %s\r\n",
				msg->errorcode, msg->errorphrase);

	if (encoding == SOUP_TRANSFER_CONTENT_LENGTH) {
		g_string_append_printf (headers, "Content-Length: %d\r\n",
					msg->response.length);
	} else if (encoding == SOUP_TRANSFER_CHUNKED)
		g_string_append (headers, "Transfer-Encoding: chunked\r\n");

	soup_message_foreach_header (msg->response_headers,
				     write_header, headers);

	g_string_append (headers, "\r\n");
}

static inline void
set_response_error (SoupMessage *req, guint code, char *phrase, char *body)
{
	if (phrase)
		soup_message_set_error_full (req, code, phrase);
	else
		soup_message_set_error (req, code);

	req->response.owner = SOUP_BUFFER_STATIC;
	req->response.body = body;
	req->response.length = body ? strlen (req->response.body) : 0;
}

static void
issue_bad_request (SoupMessage *msg)
{
	soup_message_read_cancel (msg);

	soup_message_add_header (msg->response_headers,
				 "Connection", "close");
	soup_server_message_finish (SOUP_SERVER_MESSAGE (msg));

	soup_message_write_simple (msg, &msg->response,
				   get_response_header_cb, NULL,
				   write_done_cb, error_cb, NULL);
}

static SoupKnownErrorCode
parse_headers_cb (SoupMessage *msg, char *headers, guint headers_len,
		  SoupTransferEncoding *encoding, guint *content_len,
		  gpointer user_data)
{
	SoupContext *ctx;
	char *req_path = NULL, *url;
	const char *length, *enc, *req_host;
	SoupServer *server;

	if (!soup_headers_parse_request (headers, headers_len,
					 msg->request_headers,
					 (char **) &msg->method,
					 &req_path,
					 &msg->priv->http_version))
		return SOUP_ERROR_BAD_REQUEST;

	/* Handle request body encoding */
	length = soup_message_get_header (msg->request_headers,
					  "Content-Length");
	enc = soup_message_get_header (msg->request_headers,
				       "Transfer-Encoding");

	if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			*encoding = SOUP_TRANSFER_CHUNKED;
		else {
			g_warning ("Unknown encoding type in HTTP request.");
			g_free (req_path);
			return SOUP_ERROR_NOT_IMPLEMENTED;
		}
	} else if (length) {
		int len;
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		len = atoi (length);
		if (len < 0) {
			g_free (req_path);
			return SOUP_ERROR_BAD_REQUEST;
		}
		*content_len = len;
	} else {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = 0;
	}

	/* Generate correct context for request */
	server = soup_server_message_get_server (SOUP_SERVER_MESSAGE (msg));
	req_host = soup_message_get_header (msg->request_headers, "Host");

	if (*req_path != '/') {
		/* Check for absolute URI */
		SoupUri *absolute;

		absolute = soup_uri_new (req_path);
		if (absolute) {
			url = g_strdup (req_path);
			soup_uri_free (absolute);
		} else {
			g_free (req_path);
			return SOUP_ERROR_BAD_REQUEST;
		}
	} else if (req_host) {
		url = g_strdup_printf ("%s://%s:%d%s",
				       server->priv->proto == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       req_host, server->priv->port,
				       req_path);
	} else if (msg->priv->http_version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupSocket *sock = soup_message_get_socket (msg);
		SoupAddress *addr = soup_socket_get_local_address (sock);
		const char *host = soup_address_get_physical (addr);

		url = g_strdup_printf ("%s://%s:%d%s",
				       server->priv->proto == SOUP_PROTOCOL_HTTPS ? "https" : "http",
				       host, server->priv->port,
				       req_path);
	} else {
		g_free (req_path);
		return SOUP_ERROR_BAD_REQUEST;
	}

	ctx = soup_context_get (url);
	g_free (url);
	g_free (req_path);

	if (!ctx)
		return SOUP_ERROR_BAD_REQUEST;

	soup_message_set_context (msg, ctx);
	g_object_unref (ctx);

	return SOUP_ERROR_OK;
}

static void
call_handler (SoupMessage *req)
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
		set_response_error (req, SOUP_ERROR_NOT_FOUND, NULL, NULL);
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

				if (!req->errorcode)
					soup_message_set_error (
						req,
						SOUP_ERROR_UNAUTHORIZED);

				return;
			}
		} else if (req->errorcode) {
			soup_server_auth_context_challenge (
				auth_ctx,
				req,
				"WWW-Authenticate");
			return;
		}
	}

	if (hand->callback) {
		const SoupUri *uri = soup_message_get_uri (req);

		SoupServerContext serverctx = {
			req,
			uri->path,
			soup_method_get_id (req->method),
			auth,
			server,
			hand
		};

		/* Call method handler */
		(*hand->callback) (&serverctx, req, hand->user_data);
	}

	if (auth)
		soup_server_auth_free (auth);
}

static gboolean
get_chunk_cb (SoupMessage *msg, SoupDataBuffer *out_next, gpointer user_data)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (msg);
	SoupDataBuffer *next;

	next = soup_server_message_get_chunk (smsg);
	if (next) {
		out_next->owner = next->owner;
		out_next->body = next->body;
		out_next->length = next->length;
		g_free (next);

		return TRUE;
	}

	if (!soup_server_message_is_finished (smsg))
		soup_message_write_pause (msg);
	return FALSE;
}

static void
read_done_cb (SoupMessage *req, gpointer user_data)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (req);
	SoupTransferEncoding encoding;

	if (req->errorcode && !SOUP_ERROR_IS_SUCCESSFUL (req->errorcode)) {
		issue_bad_request (req);
		return;
	}

	call_handler (req);

	encoding = soup_server_message_get_encoding (smsg);
	if (encoding == SOUP_TRANSFER_CONTENT_LENGTH) {
		soup_message_write_simple (req, &req->response,
					   get_response_header_cb, NULL,
					   write_done_cb, error_cb, NULL);
		soup_server_message_start (smsg);
	} else {
		soup_message_write (req, encoding,
				    get_response_header_cb, get_chunk_cb, NULL,
				    write_done_cb, error_cb, NULL);
	}

	return;
}

static void
start_request (SoupServer *server, SoupSocket *server_sock)
{
	SoupMessage *msg;

	/* Listen for another request on this connection */
	msg = (SoupMessage *)soup_server_message_new (server, server_sock);
	soup_message_read (msg, &msg->request, parse_headers_cb,
			   NULL, NULL, read_done_cb, error_cb, NULL);
}

static void
socket_disconnected (SoupSocket *sock, SoupServer *server)
{
	server->priv->client_socks =
		g_slist_remove (server->priv->client_socks, sock);
	g_signal_handlers_disconnect_by_func (sock, socket_disconnected, server);
	g_object_unref (sock);
}

static void
new_connection (SoupSocket *listner, SoupSocket *sock, gpointer user_data)
{
	SoupServer *server = user_data;

	g_object_ref (sock);
	server->priv->client_socks =
		g_slist_prepend (server->priv->client_socks, sock);
	g_signal_connect (sock, "disconnected",
			  G_CALLBACK (socket_disconnected), server);
	start_request (server, sock);
}

void
soup_server_run_async (SoupServer *server)
{
	g_return_if_fail (SOUP_IS_SERVER (server));

	if (!server->priv->listen_sock) {
		if (server->priv->loop) {
			g_main_loop_unref (server->priv->loop);
			server->priv->loop = NULL;
		}
		return;
	}

	g_signal_connect (server->priv->listen_sock, "new_connection",
			  G_CALLBACK (new_connection), server);
	g_object_ref (server);

	return;

}

void
soup_server_run (SoupServer *server)
{
	g_return_if_fail (SOUP_IS_SERVER (server));

	if (!server->priv->loop) {
		server->priv->loop = g_main_loop_new (NULL, TRUE);
		soup_server_run_async (server);
	}

	if (server->priv->loop)
		g_main_loop_run (server->priv->loop);
}

void
soup_server_quit (SoupServer *server)
{
	g_return_if_fail (SOUP_IS_SERVER (server));

	g_main_loop_quit (server->priv->loop);
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
	GSList *ret = NULL;

	g_hash_table_foreach (server->priv->handlers, append_handler, &ret);

	return ret;
}

SoupServerHandler *
soup_server_get_handler (SoupServer *server, const char *path)
{
	char *mypath, *dir;
	SoupServerHandler *hand = NULL;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);

	if (!path || !server->priv->handlers)
		return server->priv->default_handler;

	mypath = g_strdup (path);

	dir = strchr (mypath, '?');
	if (dir) *dir = '\0';

	dir = mypath;

	do {
		hand = g_hash_table_lookup (server->priv->handlers, mypath);
		if (hand) {
			g_free (mypath);
			return hand;
		}

		dir = strrchr (mypath, '/');
		if (dir) *dir = '\0';
	} while (dir);

	g_free (mypath);

	return server->priv->default_handler;
}

SoupAddress *
soup_server_context_get_client_address (SoupServerContext *context)
{
	SoupSocket *socket;

	g_return_val_if_fail (context != NULL, NULL);

	socket = soup_message_get_socket (context->msg);
	return soup_socket_get_remote_address (socket);
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
	SoupServerHandler *hand;
	SoupServerAuthContext *new_auth_ctx = NULL;

	g_return_if_fail (SOUP_IS_SERVER (server));
	g_return_if_fail (callback != NULL);

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
		g_hash_table_insert (server->priv->handlers, hand->path, hand);
	} else {
		soup_server_remove_handler (server, NULL);
		server->priv->default_handler = hand;
	}
}

void
soup_server_remove_handler (SoupServer *server, const char *path)
{
	SoupServerHandler *hand;

	g_return_if_fail (SOUP_IS_SERVER (server));

	if (!path) {
		if (server->priv->default_handler) {
			free_handler (server, server->priv->default_handler);
			server->priv->default_handler = NULL;
		}
		return;
	}

	hand = g_hash_table_lookup (server->priv->handlers, path);
	if (hand) {
		g_hash_table_remove (server->priv->handlers, path);
		free_handler (server, hand);
	}
}
