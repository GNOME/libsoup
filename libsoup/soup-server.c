/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

/*
 * FIXME: Split into soup-server-cgi.[ch] and soup-server-dyn.[ch]
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

extern char **environ;

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

#include "soup-server.h"
#include "soup-headers.h"
#include "soup-private.h"
#include "soup-ssl.h"
#include "soup-transfer.h"

#define SOUP_PROTOCOL_CGI 0xff

struct _SoupServerMessage {
	SoupMessage *msg;
	GSList      *chunks;           /* CONTAINS: SoupDataBuffer* */
	gboolean     started;
	gboolean     finished;
};

static SoupServer *
new_server (SoupAddress *address, SoupProtocol proto, guint port)
{
	SoupServer *serv;
	SoupSocket *sock = NULL;
	GIOChannel *read_chan = NULL, *write_chan = NULL;

	g_return_val_if_fail (address, NULL);

	if (proto == SOUP_PROTOCOL_CGI) {
		read_chan = g_io_channel_unix_new (STDIN_FILENO);
		if (!read_chan)
			return NULL;

		write_chan = g_io_channel_unix_new (STDOUT_FILENO);
		if (!write_chan) {
			g_io_channel_unref (read_chan);
			return NULL;
		}
	} else {
		sock = soup_socket_server_new (address, port);
		if (!sock)
			return NULL;

		port = soup_socket_get_port (sock);
	}

	serv = g_new0 (SoupServer, 1);
	serv->refcnt = 1;
	serv->port = port;
	serv->proto = proto;
	serv->listen_sock = sock;
	serv->cgi_read_chan = read_chan;
	serv->cgi_write_chan = write_chan;

	return serv;
}	

SoupServer *
soup_server_new (SoupProtocol proto, guint port)
{
	return new_server (soup_address_ipv4_any (), proto, port);
}

SoupServer *
soup_server_new_with_host (const char *host, SoupProtocol proto, guint port)
{
	SoupAddress *address;

	address = soup_address_new_sync (host);

	if (!address)
		return NULL;

	return new_server (address, proto, port);
}

SoupServer *
soup_server_cgi (void)
{
	static SoupServer *cgi = NULL;

	if (!cgi) 
		cgi = soup_server_new (SOUP_PROTOCOL_CGI, 0);

	return cgi;
}

static void 
free_handler (SoupServer *server, SoupServerHandler *hand)
{
	if (hand->unregister)
		(*hand->unregister) (server, hand, hand->user_data);

	if (hand->auth_ctx) {
		g_free ((gchar *) hand->auth_ctx->basic_info.realm);
		g_free ((gchar *) hand->auth_ctx->digest_info.realm);
		g_free (hand->auth_ctx);
	}

	g_free ((gchar *) hand->path);	
	g_free (hand);
}

static gboolean
free_handler_foreach (gchar *key, SoupServerHandler *hand, SoupServer *server)
{
	free_handler (server, hand);
	return TRUE;
}

void
soup_server_ref (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);

	++serv->refcnt;	
}

void
soup_server_unref (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);

	--serv->refcnt;

	if (serv->refcnt == 0) {
		if (serv->accept_tag)
			g_source_remove (serv->accept_tag);

		if (serv->listen_sock)
			soup_socket_unref (serv->listen_sock);

		if (serv->cgi_read_chan)
			g_io_channel_unref (serv->cgi_read_chan);

		if (serv->cgi_write_chan)
			g_io_channel_unref (serv->cgi_write_chan);

		if (serv->default_handler)
			free_handler (serv, serv->default_handler);

		g_hash_table_foreach_remove (serv->handlers, 
					     (GHRFunc) free_handler_foreach, 
					     serv);
		g_hash_table_destroy (serv->handlers);

		if (serv->loop)
			g_main_loop_unref (serv->loop);

		g_free (serv);
	}
}

gint
soup_server_get_port (SoupServer *serv)
{
	g_return_val_if_fail (serv != NULL, 0);
	return serv->port;
}

SoupProtocol
soup_server_get_protocol (SoupServer *serv)
{
	g_return_val_if_fail (serv != NULL, 0);
	return serv->proto;
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

static gboolean start_another_request (GIOChannel    *serv_chan,
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
close_connection (SoupMessage *msg)
{
	SoupSocket *server_sock = msg->priv->server_sock;

	if (server_sock) {
		GIOChannel *chan;

		chan = soup_socket_get_iochannel (server_sock);
		
		g_io_channel_close (chan);
		soup_socket_unref (server_sock);

		msg->priv->server_sock = NULL;
	}
}

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
			close_connection (msg);
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

		g_io_channel_unref (chan);
	}

	if (server_msg) {
		g_slist_foreach (server_msg->chunks, free_chunk, NULL);
		g_slist_free (server_msg->chunks);
		g_free (server_msg);
	}

	/*
	 * If CGI, service one message and quit 
	 */
	if (server->proto == SOUP_PROTOCOL_CGI)
		g_main_loop_quit (server->loop);

	soup_server_unref (server);

	g_free ((gchar *) msg->method);
	soup_message_free (msg);
}

static void 
error_cb (gboolean body_started, gpointer user_data)
{
	SoupMessage *msg = user_data;

	close_connection (msg);
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

static SoupTransferDone
read_headers_cgi (SoupMessage *msg,
		  gint        *content_len)
{
	SoupContext *ctx;

	/*
	 * Get request HTTP method
	 */
	(gchar *) msg->method = g_strdup (g_getenv ("REQUEST_METHOD"));

	/* 
	 * Get content length of request body
	 */
	{
		const gchar *length;
		length = g_getenv ("CONTENT_LENGTH");

		*content_len = length ? atoi (length) : 0;
	}

	/* 
	 * Determine request HTTP version
	 */
	{
		const gchar *proto;
		proto = g_getenv ("SERVER_PROTOCOL");
		if (proto) {
			if (!g_strcasecmp (proto, "HTTP/1.1"))
				msg->priv->http_version = SOUP_HTTP_1_1;
			else
				msg->priv->http_version = SOUP_HTTP_1_0;
		} else
			msg->priv->http_version = SOUP_HTTP_1_0;
	}

	/* 
	 * Generate correct context for request 
	 */
	{
		const gchar *host, *https;
		gchar *url;

		host = g_getenv ("HTTP_HOST");
		if (!host)
			host = g_getenv ("SERVER_ADDR");

		/*
		 * MS IIS sets $HTTPS to "off" if not using HTTPS
		 */
		https = g_getenv ("HTTPS");
		if (https && !g_strcasecmp (https, "OFF"))
			https = NULL;

		url = g_strconcat (https ? "https://" : "http://",
				   host,
				   ":",
				   g_getenv ("SERVER_PORT"),
				   g_getenv ("REQUEST_URI"),
				   NULL);

		ctx = soup_context_get (url);
		g_free (url);

		if (!ctx) goto THROW_MALFORMED_HEADER;

		soup_message_set_context (msg, ctx);
		soup_context_unref (ctx);
	}

	/*
	 * Load request headers from environment. Header environment variables
	 * are of the form "HTTP_<NAME>=<VALUE>"
	 */
	{
		gint iter;
		for (iter = 0; environ [iter]; iter++) {
			gchar *env = environ [iter];

			if (!strncmp (env, "HTTP_", 5)) {
				gchar *cpy, *iter;

				cpy = iter = g_strdup (env + 5);

				if (!cpy) 
					continue;

				/*
				 * Replace '_' with '-' in header names
				 */
				while (*iter && *iter != '=') {
					if (*iter == '_')
						*iter = '-';
					iter++;
				}

				if (*cpy && *iter) {
					/* 
					 * Skip '=' between key and value 
					 */
					*iter++ = '\0';

					soup_message_add_header (
						msg->request_headers,
						cpy,
						iter);
				}

				g_free (cpy);
			}
		}
	}

	return SOUP_TRANSFER_CONTINUE;

 THROW_MALFORMED_HEADER:
	destroy_message (msg);

	return SOUP_TRANSFER_END;
}

#define SOUP_SOCKADDR_IN(s) (*((struct sockaddr_in*) &s))

static gchar *
get_server_sockname (gint fd)
{
	struct sockaddr name;
	int namelen;
	gchar *host = NULL;
	guchar *p;

	if (getsockname (fd, &name, &namelen) == 0) {
		p = (guchar*) &(SOUP_SOCKADDR_IN(name).sin_addr);
		host = g_strdup_printf ("%d.%d.%d.%d",
					p [0],
					p [1],
					p [2],
					p [3]);
	}

	return host;
}

static void
write_header (gchar *key, gchar *value, GString *ret)
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
		    gchar          *phrase,
		    gchar          *body)
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

	g_io_channel_unref (channel);
} /* issue_bad_request */

static void
read_headers_cb (const GString        *headers,
		 SoupTransferEncoding *encoding,
		 gint                 *content_len,
		 gpointer              user_data)
{
	SoupMessage *msg = user_data;
	SoupContext *ctx;
	gchar *req_path = NULL;

	if (!soup_headers_parse_request (headers->str, 
					 headers->len, 
					 msg->request_headers, 
					 (gchar **) &msg->method, 
					 &req_path,
					 &msg->priv->http_version))
		goto THROW_MALFORMED_HEADER;

	/* 
	 * Handle request body encoding 
	 */
	{
		const gchar *length, *enc;

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
		gchar *url = NULL;
		const gchar *req_host = NULL;
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
					server->proto == SOUP_PROTOCOL_HTTPS ?
					        "https://" :
					        "http://",
					req_host, 
					server->port,
					req_path);
		} else {
			/* 
			 * No Host header, no AbsoluteUri
			 */
			SoupSocket *server_sock = msg->priv->server_sock;
			gchar *host;

			host = get_server_sockname (server_sock->sockfd);
			url = 
				g_strdup_printf (
					"%s%s:%d%s",
					server->proto == 
					        SOUP_PROTOCOL_HTTPS ?
						         "https://" :
						         "http://",
					host ? host : "localhost",
					server->port,
					req_path);
		}

		ctx = soup_context_get (url);
		g_free (url);

		if (!ctx) goto THROW_MALFORMED_HEADER;

		soup_message_set_context (msg, ctx);
		soup_context_unref (ctx);
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
	      const gchar          *handler_path)
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
		SoupServerContext servctx = {
			req,
			req->context->uri->path,
			soup_method_get_id (req->method),
			auth,
			server,
			hand
		};

		/* Call method handler */
		(*hand->callback) (&servctx, req, hand->user_data);
	}

	if (auth)
		soup_server_auth_free (auth);
}

static void
get_header_cgi_cb (GString  **out_hdr,
		   gpointer   user_data)
{
	SoupMessage *msg = user_data;
	SoupServerMessage *server_msg = msg->priv->server_msg;

	if (server_msg && server_msg->started)
		*out_hdr = get_response_header (msg, 
						FALSE, 
						SOUP_TRANSFER_UNKNOWN);
	else
		soup_transfer_write_pause (msg->priv->write_tag);
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
read_done_cgi_cb (const SoupDataBuffer *data,
		  gpointer              user_data)
{
	SoupMessage *req = user_data;
	SoupServer *server = req->priv->server;
	GIOChannel *channel;

	req->priv->read_tag = 0;

	call_handler (req, data, g_getenv ("PATH_INFO"));

	channel = server->cgi_write_chan;

	if (req->priv->server_msg) {
		req->priv->write_tag = 
			soup_transfer_write (channel,
					     SOUP_TRANSFER_UNKNOWN,
					     get_header_cgi_cb,
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
					      FALSE, 
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

	g_io_channel_unref (channel);

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
		soup_server_ref (server);
	}

	return msg;
}

static gboolean
start_another_request (GIOChannel    *serv_chan,
		       GIOCondition   condition, 
		       gpointer       user_data)
{
	ServerConnectData *data = user_data;
	SoupMessage *msg;
	int fd, cnt;

	fd = g_io_channel_unix_get_fd (serv_chan);

	if (!(condition & G_IO_IN) || 
	    ioctl (fd, FIONREAD, &cnt) < 0 ||
	    cnt <= 0)
		soup_socket_unref (data->server_sock);
	else {
		msg = message_new (data->server);
		if (!msg) {
			g_warning ("Unable to create new incoming message\n");
			soup_socket_unref (data->server_sock);
		} else {
			msg->priv->server_sock = data->server_sock;
			msg->priv->read_tag = 
				soup_transfer_read (serv_chan,
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

static gboolean 
conn_accept (GIOChannel    *serv_chan,
	     GIOCondition   condition, 
	     gpointer       user_data)
{
	SoupServer *server = user_data;
	SoupMessage *msg;
	GIOChannel *chan;
	SoupSocket *sock;

	sock = soup_socket_server_try_accept (server->listen_sock);
	if (!sock) return TRUE;

	msg = message_new (server);
	if (!msg) {
		g_warning ("Unable to create new incoming message\n");
		return TRUE;
	}

	chan = soup_socket_get_iochannel (sock);

	if (server->proto == SOUP_PROTOCOL_HTTPS)
		sock->iochannel = soup_ssl_get_server_iochannel (chan);

	msg->priv->server_sock = sock;
	msg->priv->read_tag = 
		soup_transfer_read (sock->iochannel,
				    FALSE,
				    read_headers_cb,
				    NULL,
				    read_done_cb,
				    error_cb,
				    msg);

	g_io_channel_unref (chan);

	return TRUE;
}

typedef struct {
	SoupMessage *msg;
	guint        content_len;
	GByteArray  *recv_buf;
} CgiReader;

static gboolean
cgi_read (GIOChannel    *serv_chan,
	  GIOCondition   condition, 
	  gpointer       user_data)
{
	CgiReader *reader = user_data;

	if (!(condition & G_IO_IN))
		goto DONE_READING;
	else {
		while (reader->recv_buf->len < reader->content_len) {
			guchar read_buf [RESPONSE_BLOCK_SIZE];
			gsize bytes_read;
			GIOError error;

			error = g_io_channel_read (serv_chan,
						   read_buf,
						   sizeof (read_buf),
						   &bytes_read);

			if (error == G_IO_ERROR_AGAIN)
				return TRUE;

			if (error != G_IO_ERROR_NONE)
				goto DONE_READING;

			if (bytes_read) 
				g_byte_array_append (reader->recv_buf, 
						     read_buf, 
						     bytes_read);
			else
				break;
		}
	}

 DONE_READING:
	if (reader->recv_buf->len == reader->content_len) {
		SoupDataBuffer buf;

		g_byte_array_append (reader->recv_buf, "\0", 1);

		buf.owner  = SOUP_BUFFER_SYSTEM_OWNED;
		buf.body   = reader->recv_buf->data;
		buf.length = reader->recv_buf->len;

		read_done_cgi_cb (&buf, reader->msg);
		
		g_byte_array_free (reader->recv_buf, FALSE);
	} else 
		g_byte_array_free (reader->recv_buf, TRUE);

	g_free (reader);		

	return FALSE;
}

void
soup_server_run_async (SoupServer *server)
{
	g_return_if_fail (server != NULL);

	if (server->proto == SOUP_PROTOCOL_CGI) {
		SoupMessage *msg;
		gint content_len = 0;

		msg = message_new (server);
		if (!msg) {
			g_warning ("Unable to create new incoming message\n");
			return;
		}

		if (read_headers_cgi (msg, &content_len) == SOUP_TRANSFER_END)
			goto START_ERROR;

		if (content_len > 0) {
			CgiReader *reader;

			reader = g_new0 (CgiReader, 1);
			reader->msg = msg;
			reader->content_len = content_len;
			reader->recv_buf = g_byte_array_new ();

			g_io_add_watch (server->cgi_read_chan,
					G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL,
					(GIOFunc) cgi_read, 
					reader);
		} else {
			SoupDataBuffer buf = {
				SOUP_BUFFER_STATIC,
				"",
				0
			};

			read_done_cgi_cb (&buf, msg);
		}
	} else {
		GIOChannel *chan;

		if (!server->listen_sock) 
			goto START_ERROR;

		/* 
		 * Listen for new connections (if not already)
		 */
		if (!server->accept_tag) {
			chan = soup_socket_get_iochannel (server->listen_sock);

			server->accept_tag = 
				g_io_add_watch (chan,
						G_IO_IN,
						(GIOFunc) conn_accept, 
						server);

			g_io_channel_unref (chan);
		}
	}

	soup_server_ref (server);

	return;

 START_ERROR:
	if (server->loop) {
		g_main_loop_unref (server->loop);
		server->loop = NULL;
	}
}

void
soup_server_run (SoupServer *server)
{
	g_return_if_fail (server != NULL);

	if (!server->loop) {
		server->loop = g_main_loop_new (NULL, TRUE);
		soup_server_run_async (server);
	}

	if (server->loop)
		g_main_loop_run (server->loop);
}

void 
soup_server_quit (SoupServer *server)
{
	g_return_if_fail (server != NULL);

	g_main_loop_quit (server->loop);
	soup_server_unref (server);
}

static void
append_handler (gpointer key, gpointer value, gpointer user_data)
{
	GSList **ret = user_data;

	*ret = g_slist_append (*ret, value);
}

GSList *
soup_server_list_handlers (SoupServer *server)
{
	GSList *ret = NULL;

	g_hash_table_foreach (server->handlers, append_handler, &ret);

	return ret;
}

SoupServerHandler *
soup_server_get_handler (SoupServer *server, const gchar *path)
{
	gchar *mypath, *dir;
	SoupServerHandler *hand = NULL;

	g_return_val_if_fail (server != NULL, NULL);

	if (!path || !server->handlers)
		return server->default_handler;

	mypath = g_strdup (path);

	dir = strchr (mypath, '?');
	if (dir) *dir = '\0';

	dir = mypath;

	do {
		hand = g_hash_table_lookup (server->handlers, mypath);
		if (hand) {
			g_free (mypath);
			return hand;
		}

		dir = strrchr (mypath, '/');
		if (dir) *dir = '\0';
	} while (dir);

	g_free (mypath);

	return server->default_handler;
}

SoupAddress *
soup_server_context_get_client_address (SoupServerContext *context)
{
	SoupSocket *socket;
	SoupAddress *address;

	g_return_val_if_fail (context != NULL, NULL);

	socket = context->msg->priv->server_sock;
	address = soup_socket_get_address (socket);

	return address;
}

gchar *
soup_server_context_get_client_host (SoupServerContext *context)
{
	gchar *host;
	SoupAddress *address;

	address = soup_server_context_get_client_address (context);
	host = g_strdup (soup_address_get_canonical_name (address));
	soup_address_unref (address);
	
	return host;
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
soup_server_register (SoupServer            *server,
		      const gchar           *path,
		      SoupServerAuthContext *auth_ctx,
		      SoupServerCallbackFn   callback,
		      SoupServerUnregisterFn unregister,
		      gpointer               user_data)
{
	SoupServerHandler *new_hand;
	SoupServerAuthContext *new_auth_ctx = NULL;

	g_return_if_fail (server != NULL);
	g_return_if_fail (callback != NULL);

	if (auth_ctx)
		new_auth_ctx = auth_context_copy (auth_ctx);

	new_hand = g_new0 (SoupServerHandler, 1);
	new_hand->path       = g_strdup (path);
	new_hand->auth_ctx   = new_auth_ctx;
	new_hand->callback   = callback;
	new_hand->unregister = unregister;
	new_hand->user_data  = user_data;

	if (path) {
		if (!server->handlers)
			server->handlers = g_hash_table_new (g_str_hash, 
							     g_str_equal);
		else 
			soup_server_unregister (server, new_hand->path);

		g_hash_table_insert (server->handlers, 
				     (gchar *) new_hand->path, 
				     new_hand);
	} else {
		soup_server_unregister (server, NULL);
		server->default_handler = new_hand;
	}
}

void  
soup_server_unregister (SoupServer *server, const gchar *path)
{
	SoupServerHandler *hand;

	g_return_if_fail (server != NULL);

	if (!path) {
		if (server->default_handler) {
			free_handler (server, server->default_handler);
			server->default_handler = NULL;
		}
		return;
	}

	if (!server->handlers) 
		return;

	hand = g_hash_table_lookup (server->handlers, path);
	if (hand) {
		g_hash_table_remove (server->handlers, path);
		free_handler (server, hand);
	}
}

SoupServerMessage *
soup_server_message_new (SoupMessage *src_msg)
{
	SoupServerMessage *ret;

	g_return_val_if_fail (src_msg != NULL, NULL);

	if (src_msg->priv->server_msg) 
		return src_msg->priv->server_msg;

	ret = g_new0 (SoupServerMessage, 1);
	ret->msg = src_msg;

	src_msg->priv->server_msg = ret;

	return ret;
}

void
soup_server_message_start (SoupServerMessage *serv_msg)
{
	g_return_if_fail (serv_msg != NULL);

	serv_msg->started = TRUE;

	soup_transfer_write_unpause (serv_msg->msg->priv->write_tag);
}

void
soup_server_message_add_data (SoupServerMessage *serv_msg,
			      SoupOwnership      owner,
			      gchar             *body,
			      gulong             length)
{
	SoupDataBuffer *buf;

	g_return_if_fail (serv_msg != NULL);
	g_return_if_fail (body != NULL);
	g_return_if_fail (length != 0);

	buf = g_new0 (SoupDataBuffer, 1);
	buf->length = length;

	if (owner == SOUP_BUFFER_USER_OWNED) {
		buf->body = g_memdup (body, length);
		buf->owner = SOUP_BUFFER_SYSTEM_OWNED;
	} else {
		buf->body = body;
		buf->owner = owner;
	}

	serv_msg->chunks = g_slist_append (serv_msg->chunks, buf);

	soup_transfer_write_unpause (serv_msg->msg->priv->write_tag);
}

void
soup_server_message_finish  (SoupServerMessage *serv_msg)
{
	g_return_if_fail (serv_msg != NULL);

	serv_msg->started = TRUE;
	serv_msg->finished = TRUE;

	soup_transfer_write_unpause (serv_msg->msg->priv->write_tag);
}

SoupMessage *
soup_server_message_get_source (SoupServerMessage *serv_msg)
{
	g_return_val_if_fail (serv_msg != NULL, NULL);
	return serv_msg->msg;
}
