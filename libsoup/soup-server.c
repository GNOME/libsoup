/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

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

SoupServer cgi_server = {
	SOUP_PROTOCOL_CGI
};

SoupServer httpd_server = {
	SOUP_PROTOCOL_HTTP
};

SoupServer httpd_ssl_server = {
	SOUP_PROTOCOL_HTTPS
};

SoupServer *SOUP_CGI_SERVER = &cgi_server;
SoupServer *SOUP_HTTPD_SERVER = &httpd_server;
SoupServer *SOUP_HTTPD_SSL_SERVER = &httpd_ssl_server;

SoupServer *
soup_server_new (SoupProtocol proto, guint port)
{
	SoupServer *serv;
	SoupSocket *sock = NULL;

	if (proto != SOUP_PROTOCOL_CGI) {
		sock = soup_socket_server_new (port);
		if (!sock) return NULL;
	}

	serv = g_new0 (SoupServer, 1);
	serv->port = soup_socket_get_port (sock);
	serv->proto = proto;
	serv->sock = sock;

	return serv;
}

static gboolean 
free_handler (char *path, SoupServerHandler *hand)
{
	g_free (hand->path);
	g_free (hand);

	return TRUE;
}

void
soup_server_free (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);

	if (serv->sock)
		soup_socket_unref (serv->sock);

	g_hash_table_foreach_remove (serv->handlers, 
				     (GHRFunc) free_handler, 
				     NULL);
	g_hash_table_destroy (serv->handlers);

	g_slist_free (serv->static_handlers);

	if (serv->accept_tag)
		g_source_remove (serv->accept_tag);

	g_main_destroy (serv->loop);

	g_free (serv);
}

gint
soup_server_get_port (SoupServer *serv)
{
	g_return_val_if_fail (serv != NULL, 0);
	return serv->port;
}

static inline void
destroy_message (SoupMessage *req)
{
	soup_socket_unref (req->priv->server_sock);

	g_free ((gchar *) req->method);

	if (req->priv->server->proto == SOUP_PROTOCOL_CGI)
		g_main_quit (req->priv->server->loop);

	soup_message_free (req);
}

static void 
error_cb (gboolean body_started, gpointer user_data)
{
	SoupMessage *req = user_data;

	destroy_message (req);
}

static void
write_done_cb (gpointer user_data)
{
	SoupMessage *req = user_data;

	req->priv->write_tag = 0;
	destroy_message (req);
}

static SoupTransferDone
read_headers_cb (const GString        *headers,
		 SoupTransferEncoding *encoding,
		 gint                 *content_len,
		 gpointer              user_data)
{
	SoupMessage *msg = user_data;
	SoupContext *ctx;
	gchar *req_path = NULL, *url;
	const gchar *connection, *length, *enc, *req_host = NULL;

	if (!soup_headers_parse_request (headers->str, 
					 headers->len, 
					 msg->request_headers, 
					 (gchar **) &msg->method, 
					 &req_path,
					 &msg->priv->http_version))
		goto THROW_MALFORMED_HEADER;

	/* Handle connection persistence */
	connection = soup_message_get_header (msg->request_headers, 
					      "Connection");

	/* FIXME: Make this work.
	if (connection && g_strcasecmp (connection, "close") == 0)
		soup_connection_set_keep_alive (req->connection, FALSE);
	*/

	/* Handle Content-Length or Chunked encoding */
	length = soup_message_get_header (msg->request_headers, 
					  "Content-Length");
	enc = soup_message_get_header (msg->request_headers, 
				       "Transfer-Encoding");

	if (length) {
		*encoding = SOUP_TRANSFER_CONTENT_LENGTH;
		*content_len = atoi (length);
		if (*content_len < 0) 
			goto THROW_MALFORMED_HEADER;
	} else if (enc) {
		if (g_strcasecmp (enc, "chunked") == 0)
			*encoding = SOUP_TRANSFER_CHUNKED;
		else {
			g_warning ("Unknown encoding type in HTTP request.");
			goto THROW_MALFORMED_HEADER;
		}
	}

	/* Generate correct context for request */
	req_host = soup_message_get_header (msg->request_headers, "Host");
	if (req_host) 
		url = g_strconcat ("http://", req_host, req_path, NULL);
	else 
		url = g_strdup (req_path);

	ctx = soup_context_get (url);
	g_free (url);

	/* No Host, no AbsoluteUri */
	if (!ctx) {
		/* FIXME: Get local socket host name */
		url = g_strconcat ("http://localhost/", req_path, NULL);
		ctx = soup_context_get (url);
		g_free (url);
	}

	if (!ctx) goto THROW_MALFORMED_HEADER;

	soup_message_set_context (msg, ctx);
	soup_context_unref (ctx);

	g_free (req_path);

	return SOUP_TRANSFER_CONTINUE;

 THROW_MALFORMED_HEADER:
	g_free (req_path);

	destroy_message (msg);

	return SOUP_TRANSFER_END;
}

static void
write_header (gchar *key, GSList *vals, SoupMessage *msg)
{
	while (vals) {
		g_string_sprintfa (msg->priv->req_header, 
				   "%s: %s\r\n", 
				   key, 
				   (gchar *) vals->data);
		vals = vals->next;
	}
}

static GString *
get_response_header (SoupMessage *req)
{
	GString *ret = g_string_new (NULL);

	g_string_sprintfa (ret, 
			   "HTTP/1.1 %d %s\r\n", 
			   req->errorcode, 
			   req->errorphrase);

	g_string_sprintfa (ret, 
			   "Content-Length: %d\r\n",  
			   req->response.length);

	g_hash_table_foreach (req->response_headers, 
			      (GHFunc) write_header,
			      req);

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
read_done_cb (const SoupDataBuffer *data,
	      gpointer              user_data)
{
	SoupMessage *req = user_data;
	SoupServerHandler *hand;
	GIOChannel *channel;
	const gchar *path;

	req->response.owner = data->owner;
	req->response.length = data->length;
	req->response.body = data->body;

	req->status = SOUP_STATUS_FINISHED;

	/* FIXME: Do this in soap handler 
	action = soup_message_get_header (req->request_headers, "SOAPAction");
	if (!action) {
		g_print ("No SOAPAction found in request.\n");
		set_response_error (
			req, 
			403, 
			"Missing SOAPAction", 
			"The required SOAPAction header was not supplied.");
		goto START_WRITE;
	}
	*/

	path = soup_context_get_uri (req->context)->path;

	hand = soup_server_get_handler (req->priv->server, path);
	if (!hand) {
		if (req->priv->server->default_handler.cb)
			hand = &req->priv->server->default_handler;
		else {
			set_response_error (req, 404, NULL, NULL);
			goto START_WRITE;
		}
	}

	/* Call method handler */
	if (hand->cb) (*hand->cb) (req, NULL, hand->user_data);

 START_WRITE:
	channel = soup_socket_get_iochannel (req->priv->server_sock);

	req->priv->req_header = get_response_header (req);
	req->priv->read_tag = 0;
	req->priv->write_tag = 
		soup_transfer_write (channel,
				     req->priv->req_header,
				     &req->response,
				     NULL,
				     write_done_cb,
				     error_cb,
				     req);

	g_io_channel_unref (channel);

	return;
}

static void 
conn_accept (GIOChannel    *chan,
	     GIOCondition   condition, 
	     SoupServer    *serv)
{
	GIOChannel *channel;
	SoupSocket *sock;
	SoupContext *ctx;
	SoupMessage *msg;
	SoupUri uri = { 
		serv->proto,
		NULL, 
		NULL, 
		NULL, 
		"localhost", 
		serv->port, 
		"/",
		NULL,
		NULL 
	};

	sock = soup_socket_server_try_accept (serv->sock);
	if (!sock) return;
	
	channel = soup_socket_get_iochannel (sock);

	/* 
	 * Create a fake context until the request is read 
	 * and we can generate a valid one.
	 */
	ctx = soup_context_from_uri (&uri);
	msg = soup_message_new (ctx, NULL);

	msg->priv->server = serv;
	msg->priv->server_sock = sock;

	chan = soup_socket_get_iochannel (sock);

	if (serv->proto == SOUP_PROTOCOL_HTTPS) 
		chan = soup_ssl_get_iochannel (chan);

	msg->priv->read_tag = 
		soup_transfer_read (
			chan,
			FALSE,
			read_headers_cb,
			NULL,
			read_done_cb,
			error_cb,
			msg);

	g_io_channel_unref (chan);
}

void
soup_server_run_async (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);
	g_return_if_fail (serv->port >= 0);

	if (!serv->sock) {
		serv->sock = soup_socket_server_new (serv->port);
		if (!serv->sock) goto START_ERROR;
	}

	if (!serv->accept_tag) 
		serv->accept_tag = 
			g_io_add_watch (soup_socket_get_iochannel (serv->sock),
					G_IO_IN,
					(GIOFunc) conn_accept, 
					serv);

	return;

 START_ERROR:
	if (serv->loop) {
		g_main_destroy (serv->loop);
		serv->loop = NULL;
	}
	return;
}

void
soup_server_run (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);
	g_return_if_fail (serv->port >= 0);

	serv->loop = g_main_new (TRUE);

	soup_server_run_async (serv);

	if (serv->loop)
		g_main_run (serv->loop);
}

void 
soup_server_quit (SoupServer *serv)
{
	g_return_if_fail (serv != NULL);

	g_main_quit (serv->loop);
}

void 
soup_server_add_list (SoupServer        *serv,
		      SoupServerHandler *list)
{
	g_return_if_fail (serv != NULL);

	serv->static_handlers = g_slist_prepend (serv->static_handlers, list);
}

SoupServerHandler *
soup_server_get_handler (SoupServer *serv, const gchar *path)
{
	GSList *iter;
	gchar *mypath, *dir;
	SoupServerHandler *hand = NULL;

	g_return_val_if_fail (serv != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	if (!serv->handlers) return NULL;

	mypath = g_strdup (path);

	dir = strchr (mypath, '?');
	if (dir) *dir = '\0';

	dir = mypath;

	do {
		hand = g_hash_table_lookup (serv->handlers, mypath);
		if (hand) {
			g_free (mypath);
			return hand;
		}

		for (iter = serv->static_handlers; iter; iter = iter->next) {
			hand = iter->data;
			while (hand && hand->path) {
				if (!strcmp (hand->path, mypath)) {
					g_free (mypath);
					return hand;
				}
				hand++;
			}
		}

		dir = strrchr (mypath, '/');
		if (dir) *dir = '\0';
	} while (dir);

	g_free (mypath);
	return NULL;
}

void  
soup_server_register (SoupServer           *serv,
		      const gchar          *path, 
		      guint                 auth_types,
		      SoupServerCallbackFn  cb,
		      gpointer              user_data)
{
	SoupServerHandler *hand;

	g_return_if_fail (serv != NULL);
	g_return_if_fail (path != NULL);

	hand = g_new0 (SoupServerHandler, 1);
	hand->path = g_strdup (path);
	hand->auth_types = auth_types;
	hand->cb = cb;
	hand->user_data = user_data;

	if (!serv->handlers)
		serv->handlers = g_hash_table_new (g_str_hash, g_str_equal);
	else 
		soup_server_unregister (serv, path);

	g_hash_table_insert (serv->handlers, hand->path, hand);
}

void  
soup_server_unregister (SoupServer *serv, const gchar *path)
{
	SoupServerHandler *hand;

	g_return_if_fail (serv != NULL);
	g_return_if_fail (path != NULL);

	if (!serv->handlers) return;

	hand = g_hash_table_lookup (serv->handlers, path);
	if (hand) {
		g_hash_table_remove (serv->handlers, path);

		g_free (hand->path);
		g_free (hand);
	}
}

void  
soup_server_register_default (SoupServer           *serv,
			      guint                 auth_types,
			      SoupServerCallbackFn  cb,
			      gpointer              user_data)
{
	g_return_if_fail (serv != NULL);

	serv->default_handler.auth_types = auth_types;
	serv->default_handler.cb = cb;
	serv->default_handler.user_data = user_data;
}
