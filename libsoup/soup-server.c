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

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "soup-server.h"
#include "soup-headers.h"
#include "soup-private.h"
#include "soup-ssl.h"
#include "soup-transfer.h"

#define PARENT_TYPE G_TYPE_OBJECT
static GObjectClass *parent_class;

struct SoupServerPrivate {
	SoupProtocol       proto;
	guint              port;

	GMainLoop         *loop;

	SoupSocket        *listen_sock;

	GHashTable        *handlers; /* KEY: path, VALUE: SoupServerHandler */
	SoupServerHandler *default_handler;
};

struct SoupServerMessage {
	SoupMessage *msg;
	GSList      *chunks;           /* CONTAINS: SoupDataBuffer* */
	gboolean     started;
	gboolean     finished;
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

static void
free_chunk (gpointer chunk, gpointer notused)
{
	SoupDataBuffer *buf = chunk;

	if (buf->owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (buf->body);

	g_free (buf);
}

typedef struct {
	SoupServer *server;
	SoupSocket *server_sock;
} ServerConnectData;

static gboolean start_another_request (GIOChannel    *server_chan,
				       GIOCondition   condition, 
				       gpointer       user_data);

static gboolean
check_close_connection (SoupMessage *msg)
{
	const char *connection_hdr;
	gboolean close_connection;

	connection_hdr = soup_message_get_header (msg->request_headers,
						  "Connection");

	if (msg->priv->http_version == SOUP_HTTP_1_0) {
		if (connection_hdr && g_strcasecmp (connection_hdr,
						    "keep-alive") == 0)
			close_connection = FALSE;
		else
			close_connection = TRUE;
	}
	else {
		if (connection_hdr && g_strcasecmp (connection_hdr,
						    "close") == 0)
			close_connection = TRUE;
		else
			close_connection = FALSE;
	}

	return close_connection;
} /* check_close_connection */

static void
destroy_message (SoupMessage *msg)
{
	SoupServer *server = msg->priv->server;
	SoupSocket *server_sock = msg->priv->server_sock;
	SoupServerMessage *server_msg = msg->priv->server_msg;

	if (server_sock) {
		GIOChannel *chan;

		chan = soup_socket_get_iochannel (server_sock);

		/*
		 * Close the socket if we're using HTTP/1.0 and
		 * "Connection: keep-alive" isn't specified, or if we're
		 * using HTTP/1.1 and "Connection: close" was specified.
		 */
		if (check_close_connection (msg)) {
			g_io_channel_close (chan);
			g_object_unref (server_sock);
		}
		else {
			/*
			 * Listen for another request on this connection
			 */
			ServerConnectData *data;

			data = g_new0 (ServerConnectData, 1);
			data->server = msg->priv->server;
			data->server_sock = server_sock;

			g_io_add_watch (chan,
					G_IO_IN|G_IO_PRI|
					G_IO_ERR|G_IO_HUP|G_IO_NVAL,
					start_another_request,
					data);
		}
	}

	if (server_msg) {
		g_slist_foreach (server_msg->chunks, free_chunk, NULL);
		g_slist_free (server_msg->chunks);
		g_free (server_msg);
	}

	g_object_unref (server);

	g_free ((char *) msg->method);
	soup_message_free (msg);
}

static void 
error_cb (gboolean body_started, gpointer user_data)
{
	SoupMessage *msg = user_data;

	destroy_message (msg);
}

static void
write_done_cb (gpointer user_data)
{
	SoupMessage *msg = user_data;

	soup_transfer_write_unref (msg->priv->write_tag);
	msg->priv->write_tag = 0;
	destroy_message (msg);
}

static void
write_header (char *key, char *value, GString *ret)
{
	g_string_sprintfa (ret, "%s: %s\r\n", key, value);
}

static GString *
get_response_header (SoupMessage          *req, 
		     gboolean              status_line, 
		     SoupTransferEncoding  encoding)
{
	GString *ret = g_string_new (NULL);

	if (status_line)
		g_string_sprintfa (ret, 
				   "HTTP/1.1 %d %s\r\n", 
				   req->errorcode, 
				   req->errorphrase);
	else
		g_string_sprintfa (ret, 
				   "Status: %d %s\r\n", 
				   req->errorcode, 
				   req->errorphrase);

	if (encoding == SOUP_TRANSFER_CONTENT_LENGTH)
		g_string_sprintfa (ret, 
				   "Content-Length: %d\r\n",  
				   req->response.length);
	else if (encoding == SOUP_TRANSFER_CHUNKED)
		g_string_append (ret, "Transfer-Encoding: chunked\r\n");

	soup_message_foreach_header (req->response_headers,
				     (GHFunc) write_header,
				     ret);

	g_string_append (ret, "\r\n");

	return ret;
}

static inline void
set_response_error (SoupMessage    *req,
		    guint           code,
		    char           *phrase,
		    char           *body)
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
	GString *header;
	GIOChannel *channel;

	set_response_error (msg, SOUP_ERROR_BAD_REQUEST, NULL, NULL);

	header = get_response_header (msg, 
				      FALSE,
				      SOUP_TRANSFER_CONTENT_LENGTH);

	channel = soup_socket_get_iochannel (msg->priv->server_sock);
	msg->priv->write_tag =
		soup_transfer_write_simple (channel,
					    header,
					    &msg->response,
					    write_done_cb,
					    error_cb,
					    msg);
}

static void
read_headers_cb (const GString        *headers,
		 SoupTransferEncoding *encoding,
		 gint                 *content_len,
		 gpointer              user_data)
{
	SoupMessage *msg = user_data;
	SoupContext *ctx;
	char *req_path = NULL;

	if (!soup_headers_parse_request (headers->str, 
					 headers->len, 
					 msg->request_headers, 
					 (char **) &msg->method, 
					 &req_path,
					 &msg->priv->http_version))
		goto THROW_MALFORMED_HEADER;

	/* 
	 * Handle request body encoding 
	 */
	{
		const char *length, *enc;

		/* Handle Content-Length or Chunked encoding */
		length = soup_message_get_header (msg->request_headers, 
						  "Content-Length");
		enc = soup_message_get_header (msg->request_headers, 
					       "Transfer-Encoding");

		if (enc) {
			if (g_strcasecmp (enc, "chunked") == 0)
				*encoding = SOUP_TRANSFER_CHUNKED;
			else {
				g_warning ("Unknown encoding type in HTTP "
					   "request.");
				goto THROW_MALFORMED_HEADER;
			}
		} else if (length) {
			*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
			*content_len = atoi (length);
			if (*content_len < 0) 
				goto THROW_MALFORMED_HEADER;
		} else {
			*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
			*content_len = 0;
		}
	}

	/* 
	 * Generate correct context for request 
	 */
	{
		char *url = NULL;
		const char *req_host = NULL;
		SoupServer *server = msg->priv->server;

		req_host = soup_message_get_header (msg->request_headers, 
						    "Host");

		if (*req_path != '/') {
			/*
			 * Check for absolute URI
			 */
			SoupUri *absolute;

			absolute = soup_uri_new (req_path);
			if (absolute) {
				url = g_strdup (req_path);
				soup_uri_free (absolute);
			} else 
				goto THROW_MALFORMED_HEADER;
		} else if (req_host) {
			url = 
				g_strdup_printf (
					"%s%s:%d%s",
					server->priv->proto == SOUP_PROTOCOL_HTTPS ?
					        "https://" :
					        "http://",
					req_host, 
					server->priv->port,
					req_path);
		} else {
			/* 
			 * No Host header, no AbsoluteUri
			 */
			SoupSocket *server_sock = msg->priv->server_sock;
			SoupAddress *addr = soup_socket_get_local_address (server_sock);
			const char *host = soup_address_get_physical (addr);

			url = 
				g_strdup_printf (
					"%s%s:%d%s",
					server->priv->proto == 
					        SOUP_PROTOCOL_HTTPS ?
						         "https://" :
						         "http://",
					host ? host : "localhost",
					server->priv->port,
					req_path);
		}

		ctx = soup_context_get (url);
		g_free (url);

		if (!ctx) goto THROW_MALFORMED_HEADER;

		soup_message_set_context (msg, ctx);
		g_object_unref (ctx);
	}

	g_free (req_path);

	return;

 THROW_MALFORMED_HEADER:
	g_free (req_path);

	issue_bad_request(msg);
}

static void
call_handler (SoupMessage          *req,
	      const SoupDataBuffer *req_data,
	      const char           *handler_path)
{
	SoupServer *server = req->priv->server;
	SoupServerHandler *hand;
	SoupServerAuth *auth = NULL;

	g_return_if_fail (req != NULL);

	req->request.owner = req_data->owner;
	req->request.length = req_data->length;
	req->request.body = req_data->body;

	req->status = SOUP_STATUS_FINISHED;

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
		const SoupUri *uri = soup_context_get_uri (req->context);

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

static void
get_header_cb (GString  **out_hdr,
	       gpointer   user_data)
{
	SoupMessage *msg = user_data;
	SoupServerMessage *server_msg = msg->priv->server_msg;
	SoupTransferEncoding encoding;

	if (server_msg && server_msg->started) {
		if (msg->priv->http_version == SOUP_HTTP_1_0)
			encoding = SOUP_TRANSFER_UNKNOWN;
		else
			encoding = SOUP_TRANSFER_CHUNKED;
		
		*out_hdr = get_response_header (msg, TRUE, encoding);
	} else
		soup_transfer_write_pause (msg->priv->write_tag);
}

static SoupTransferDone
get_chunk_cb (SoupDataBuffer *out_next, gpointer user_data)
{
	SoupMessage *msg = user_data;
	SoupServerMessage *server_msg = msg->priv->server_msg;

	if (server_msg->chunks) {
		SoupDataBuffer *next = server_msg->chunks->data;

		out_next->owner = next->owner;
		out_next->body = next->body;
		out_next->length = next->length;

		server_msg->chunks = g_slist_remove (server_msg->chunks, next);

		/*
		 * Caller will free the response body, so just free the
		 * SoupDataBuffer struct.
		 */
		g_free (next);

		return SOUP_TRANSFER_CONTINUE;
	} 
	else if (server_msg->finished) {
		return SOUP_TRANSFER_END;
	} 
	else {
		soup_transfer_write_pause (msg->priv->write_tag);
		return SOUP_TRANSFER_CONTINUE;
	}
}

static void
read_done_cb (const SoupDataBuffer *data,
	      gpointer              user_data)
{
	SoupMessage *req = user_data;
	SoupSocket *server_sock = req->priv->server_sock;
	GIOChannel *channel;

	soup_transfer_read_unref (req->priv->read_tag);
	req->priv->read_tag = 0;

	call_handler (req, data, soup_context_get_uri (req->context)->path);

	channel = soup_socket_get_iochannel (server_sock);

	if (req->priv->server_msg) {
		SoupTransferEncoding encoding;

		if (req->priv->http_version == SOUP_HTTP_1_0)
			encoding = SOUP_TRANSFER_UNKNOWN;
		else
			encoding = SOUP_TRANSFER_CHUNKED;

		req->priv->write_tag = 
			soup_transfer_write (channel,
					     encoding,
					     get_header_cb,
					     get_chunk_cb,
					     write_done_cb,
					     error_cb,
					     req);

		/*
		 * Pause write until soup_server_message_start()
		 */
		if (!req->priv->server_msg->started)
			soup_transfer_write_pause (req->priv->write_tag);
	} else {
		GString *header;
		header = get_response_header (req, 
					      TRUE, 
					      SOUP_TRANSFER_CONTENT_LENGTH);
		req->priv->write_tag = 
			soup_transfer_write_simple (channel,
						    header,
						    &req->response,
						    write_done_cb,
						    error_cb,
						    req);
	}

	return;
}

static SoupMessage *
message_new (SoupServer *server)
{
	SoupMessage *msg;

	/*
	 * Create an empty message to hold request state.
	 */
	msg = soup_message_new (NULL, NULL);
	if (msg) {
		msg->method = NULL;
		msg->priv->server = server;
		g_object_ref (server);
	}

	return msg;
}

static gboolean
start_another_request (GIOChannel    *server_chan,
		       GIOCondition   condition, 
		       gpointer       user_data)
{
	ServerConnectData *data = user_data;
	SoupMessage *msg;
	int fd, cnt;

	fd = g_io_channel_unix_get_fd (server_chan);

	if (!(condition & G_IO_IN) || 
	    ioctl (fd, FIONREAD, &cnt) < 0 ||
	    cnt <= 0)
		g_object_unref (data->server_sock);
	else {
		msg = message_new (data->server);
		if (!msg) {
			g_warning ("Unable to create new incoming message\n");
			g_object_unref (data->server_sock);
		} else {
			msg->priv->server_sock = data->server_sock;
			msg->priv->read_tag = 
				soup_transfer_read (server_chan,
						    FALSE,
						    read_headers_cb,
						    NULL,
						    read_done_cb,
						    error_cb,
						    msg);
		}
	}

	g_free (data);
	return FALSE;
}

static void
new_connection (SoupSocket *listner, SoupSocket *sock, gpointer user_data)
{
	SoupServer *server = user_data;
	SoupMessage *msg;

	msg = message_new (server);
	if (!msg) {
		g_warning ("Unable to create new incoming message\n");
		return;
	}

	msg->priv->server_sock = g_object_ref (sock);
	msg->priv->read_tag = 
		soup_transfer_read (soup_socket_get_iochannel (sock),
				    FALSE,
				    read_headers_cb,
				    NULL,
				    read_done_cb,
				    error_cb,
				    msg);
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

	socket = context->msg->priv->server_sock;
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
