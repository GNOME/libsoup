/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#include "soup-queue.h"
#include "soup-auth.h"
#include "soup-connection.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-context.h"
#include "soup-headers.h"
#include "soup-misc.h"
#include "soup-private.h"
#include "soup-socket.h"

static GSList *soup_active_requests = NULL, *soup_active_request_next = NULL;

static guint soup_queue_idle_tag = 0;

static void
soup_debug_print_a_header (gchar *key, gchar *val, gpointer not_used)
{
	g_print ("\tKEY: \"%s\", VALUE: \"%s\"\n", key, val);
}

void 
soup_debug_print_headers (SoupMessage *req)
{
	g_print ("Request Headers:\n");
	soup_message_foreach_header (req->request_headers,
				     (GHFunc) soup_debug_print_a_header,
				     NULL);

	g_print ("Response Headers:\n");
	soup_message_foreach_header (req->response_headers,
				     (GHFunc) soup_debug_print_a_header,
				     NULL);
}

static void 
soup_queue_error_cb (SoupMessage *req, gpointer user_data)
{
	SoupConnection *conn = soup_message_get_connection (req);
	const SoupUri *uri;
	gboolean conn_is_new;

	conn_is_new = soup_connection_is_new (conn);
	soup_message_disconnect (req);

	switch (req->priv->status) {
	case SOUP_MESSAGE_STATUS_IDLE:
	case SOUP_MESSAGE_STATUS_QUEUED:
	case SOUP_MESSAGE_STATUS_FINISHED:
		break;

	case SOUP_MESSAGE_STATUS_CONNECTING:
		soup_message_set_error (req, SOUP_ERROR_CANT_CONNECT);
		soup_message_issue_callback (req);
		break;

	case SOUP_MESSAGE_STATUS_WRITING_HEADERS:
	case SOUP_MESSAGE_STATUS_READING_HEADERS:
		uri = soup_message_get_uri (req);

		if (uri->protocol == SOUP_PROTOCOL_HTTPS) {
			/* FIXME: what does this really do? */

			/*
			 * This can happen if the SSL handshake fails
			 * for some reason (untrustable signatures,
			 * etc.)
			 */
			if (req->priv->retries >= 3) {
				soup_message_set_error (req, SOUP_ERROR_SSL_FAILED);
				soup_message_issue_callback (req);
			} else {
				req->priv->retries++;
				soup_message_requeue (req);
			}
		} else if (conn_is_new) {
			soup_message_set_error (req, SOUP_ERROR_CANT_CONNECT);
			soup_message_issue_callback (req);
		} else {
			/* Must have timed out. Try a new connection */
			soup_message_requeue (req);
		}
		break;

	default:
		soup_message_set_error (req, SOUP_ERROR_IO);
		soup_message_issue_callback (req);
		break;
	}
}

static void
soup_queue_read_headers_cb (SoupMessage *req, gpointer user_data)
{
	soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY);
}

static void
soup_queue_read_chunk_cb (SoupMessage *req, SoupDataBuffer *chunk,
			  gpointer user_data)
{
	/* FIXME? */
	memcpy (&req->response, chunk, sizeof (req->response));

	soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK);
}

static void
soup_queue_read_done_cb (SoupMessage *req, gpointer user_data)
{
	SoupConnection *conn = soup_message_get_connection (req);

	if (soup_message_is_keepalive (req) && conn)
		soup_connection_mark_old (conn);
	else
		soup_message_disconnect (req);

	if (req->errorclass == SOUP_ERROR_CLASS_INFORMATIONAL) {
		soup_message_read_response (req, 
					    soup_queue_read_headers_cb,
					    soup_queue_read_chunk_cb,
					    soup_queue_read_done_cb,
					    soup_queue_error_cb,
					    NULL);
	} else
		req->priv->status = SOUP_MESSAGE_STATUS_FINISHED;

	soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
}

static void 
soup_queue_write_done_cb (SoupMessage *req, gpointer user_data)
{
	soup_message_read_response (req, soup_queue_read_headers_cb,
				    soup_queue_read_chunk_cb,
				    soup_queue_read_done_cb,
				    soup_queue_error_cb,
				    NULL);
}

static void
start_request (SoupContext *ctx, SoupMessage *req)
{
	SoupSocket *sock;

	sock = soup_message_get_socket (req);
	if (!sock) {	/* FIXME */
		SoupProtocol proto;
		gchar *phrase;

		proto = soup_context_get_uri (ctx)->protocol;

		if (proto == SOUP_PROTOCOL_HTTPS)
			phrase = "Unable to create secure data channel";
		else
			phrase = "Unable to create data channel";

		if (ctx != req->priv->context)
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_CANT_CONNECT_PROXY,
				phrase);
		else 
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_CANT_CONNECT,
				phrase);

		soup_message_issue_callback (req);
		return;
	}

	soup_message_write_request (req, soup_get_proxy () != NULL,
				    soup_queue_write_done_cb,
				    soup_queue_error_cb,
				    NULL);
}

static void
proxy_https_connect_cb (SoupMessage *msg, gpointer user_data)
{
	gboolean *ret = user_data;

	if (!SOUP_MESSAGE_IS_ERROR (msg)) {
		soup_socket_start_ssl (soup_message_get_socket (msg));
		*ret = TRUE;
	}
}

static gboolean
proxy_https_connect (SoupContext    *proxy, 
		     SoupConnection *conn, 
		     SoupContext    *dest_ctx)
{
	SoupProtocol proxy_proto;
	SoupMessage *connect_msg;
	gboolean ret = FALSE;

	proxy_proto = soup_context_get_uri (proxy)->protocol;

	if (proxy_proto != SOUP_PROTOCOL_HTTP && 
	    proxy_proto != SOUP_PROTOCOL_HTTPS) 
		return FALSE;

	connect_msg = soup_message_new_from_uri (SOUP_METHOD_CONNECT,
						 soup_context_get_uri (dest_ctx));
	soup_message_set_connection (connect_msg, conn);
	soup_message_add_handler (connect_msg, 
				  SOUP_HANDLER_POST_BODY,
				  proxy_https_connect_cb,
				  &ret);
	soup_message_send (connect_msg);
	g_object_unref (connect_msg);

	return ret;
}

static gboolean
proxy_connect (SoupContext *ctx, SoupMessage *req, SoupConnection *conn)
{
	SoupProtocol proto, dest_proto;

	/* 
	 * Only attempt proxy connect if the connection's context is different
	 * from the requested context, and if the connection is new 
	 */
	if (ctx == req->priv->context || !soup_connection_is_new (conn))
		return FALSE;

	proto = soup_context_get_uri (ctx)->protocol;
	dest_proto = soup_context_get_uri (req->priv->context)->protocol;
	
	/* Handle HTTPS tunnel setup via proxy CONNECT request. */
	if (dest_proto == SOUP_PROTOCOL_HTTPS) {
		/* Syncronously send CONNECT request */
		if (!proxy_https_connect (ctx, conn, req->priv->context)) {
			soup_message_set_error_full (
				req, 
				SOUP_ERROR_CANT_CONNECT_PROXY,
				"Unable to create secure data "
				"tunnel through proxy");
			soup_message_issue_callback (req);
			return TRUE;
		}
	}

	return FALSE;
}

void
soup_queue_connect_cb (SoupContext          *ctx,
		       SoupKnownErrorCode    err,
		       SoupConnection       *conn,
		       gpointer              user_data)
{
	SoupMessage *req = user_data;

	req->priv->connect_tag = NULL;
	soup_message_set_connection (req, conn);

	switch (err) {
	case SOUP_ERROR_OK:
		/* 
		 * NOTE: proxy_connect will either set an error or call us 
		 * again after proxy negotiation.
		 */
		if (proxy_connect (ctx, req, conn))
			return;

		start_request (ctx, req);
		break;

	case SOUP_ERROR_CANT_RESOLVE:
		if (ctx == req->priv->context)
			soup_message_set_error (req, SOUP_ERROR_CANT_RESOLVE);
		else
			soup_message_set_error (req, SOUP_ERROR_CANT_RESOLVE_PROXY);
		soup_message_issue_callback (req);
		break;

	default:
		if (ctx == req->priv->context)
			soup_message_set_error (req, SOUP_ERROR_CANT_CONNECT);
		else
			soup_message_set_error (req, SOUP_ERROR_CANT_CONNECT_PROXY);
		soup_message_issue_callback (req);
		break;
	}

	return;
}

void
soup_queue_add_request (SoupMessage *req)
{
	soup_active_requests = g_slist_prepend (soup_active_requests, req);
}

void
soup_queue_remove_request (SoupMessage *req)
{
	if (soup_active_request_next && soup_active_request_next->data == req)
		soup_queue_next_request ();
	soup_active_requests = g_slist_remove (soup_active_requests, req);
}

SoupMessage *
soup_queue_first_request (void)
{
	if (!soup_active_requests)
		return NULL;

	soup_active_request_next = soup_active_requests->next;
	return soup_active_requests->data;
}

SoupMessage *
soup_queue_next_request (void)
{
	SoupMessage *ret;

	if (!soup_active_request_next)
		return NULL;
	ret = soup_active_request_next->data;
	soup_active_request_next = soup_active_request_next->next;
	return ret;
}

static gboolean
request_in_progress (SoupMessage *req)
{
	if (!soup_active_requests)
		return FALSE;

	return g_slist_index (soup_active_requests, req) != -1;
}

static gboolean 
soup_idle_handle_new_requests (gpointer unused)
{
	SoupMessage *req = soup_queue_first_request ();
	SoupConnection *conn;

	for (; req; req = soup_queue_next_request ()) {
		SoupContext *ctx, *proxy;

		if (req->priv->status != SOUP_MESSAGE_STATUS_QUEUED)
			continue;

		proxy = soup_get_proxy ();
		ctx = proxy ? proxy : req->priv->context;

		req->priv->status = SOUP_MESSAGE_STATUS_CONNECTING;

		conn = soup_message_get_connection (req);
		if (conn && soup_connection_is_connected (conn))
			start_request (ctx, req);
		else {
			gpointer connect_tag;

			connect_tag = 
				soup_context_get_connection (
					ctx, 
					soup_queue_connect_cb, 
					req);

			if (connect_tag && request_in_progress (req))
				req->priv->connect_tag = connect_tag;
		}
	}

	soup_queue_idle_tag = 0;
	return FALSE;
}

static void
soup_queue_initialize (void)
{
	if (!soup_initialized)
		soup_load_config (NULL);

	if (!soup_queue_idle_tag)
		soup_queue_idle_tag = 
			g_idle_add (soup_idle_handle_new_requests, NULL);
}

void 
soup_queue_message (SoupMessage *req)
{
	g_return_if_fail (SOUP_IS_MESSAGE (req));

	req->priv->status = SOUP_MESSAGE_STATUS_QUEUED;
	soup_queue_add_request (req);
	soup_queue_initialize ();
}

/**
 * soup_queue_shutdown:
 * 
 * Shut down the message queue by calling soup_message_cancel() on all
 * active requests and then closing all open connections.
 */
void 
soup_queue_shutdown (void)
{
	SoupMessage *req;

	soup_initialized = FALSE;

	if (soup_queue_idle_tag) {
		g_source_remove (soup_queue_idle_tag);
		soup_queue_idle_tag = 0;
	}

	req = soup_queue_first_request ();
	for (; req; req = soup_queue_next_request ())
		soup_message_cancel (req);

	soup_connection_purge_idle ();
}
