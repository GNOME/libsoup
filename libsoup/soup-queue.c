/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <config.h>
#include <glib.h>
#include <gnet/gnet.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "soup-queue.h"
#include "soup-context.h"
#include "soup-private.h"

guint connection_count = 0;

GList *active_requests = NULL;

static guint max_connections = 4;

static guint soup_queue_idle_tag = 0;

static SoupContext *proxy_context;

static gboolean 
soup_queue_read_async (GIOChannel* iochannel, 
		       GIOCondition condition, 
		       SoupRequest *req)
{
	guint bytes_read;
	GIOError error;

	if (!req->response.body) {
		req->response.body = g_malloc (RESPONSE_BLOCK_SIZE);
		req->response.length = RESPONSE_BLOCK_SIZE;
	} else if (req->priv->read_len == req->response.length) {
		req->response.length += RESPONSE_BLOCK_SIZE;
		req->response.body = g_realloc (req->response.body, 
						 req->response.length);
	}

	error = g_io_channel_read (iochannel, 
				   &req->response.body[req->priv->read_len], 
				   req->response.length - req->priv->read_len,
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;
	
	if (error != G_IO_ERROR_NONE) {
		soup_request_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	if (bytes_read == 0) {
		req->status = SOUP_STATUS_FINISHED;
		soup_request_issue_callback (req, SOUP_ERROR_NONE);
		return FALSE;
	}
	
	req->priv->read_len += bytes_read;

	return TRUE;
}

static gboolean 
soup_queue_write_async (GIOChannel* iochannel, 
			GIOCondition condition, 
			SoupRequest *req)
{
	guint bytes_written;
	GIOError error;

	error = g_io_channel_write (iochannel, 
				    &req->request.body[req->priv->write_len], 
				    req->request.length - req->priv->write_len,
				    &bytes_written);

	if (error == G_IO_ERROR_AGAIN)
		return TRUE;
	
	if (error != G_IO_ERROR_NONE) {
		soup_request_issue_callback (req, SOUP_ERROR_IO);
		return FALSE;
	}

	req->priv->write_len += bytes_written;

	if (req->priv->write_len == req->request.length) {
		req->status = SOUP_STATUS_READING_RESPONSE;
		req->priv->read_tag = 
			g_io_add_watch (iochannel, 
					G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL, 
					(GIOFunc) soup_queue_read_async, 
					req);
		return FALSE;
	}

	return TRUE;
}

static void 
soup_setup_socket (GIOChannel *channel)
{
#ifdef TCP_NODELAY
	{
		int on, fd;
		on = 1;
		fd = g_io_channel_unix_get_fd (channel);
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}
#endif
}

static void
soup_queue_connect (SoupContext          *ctx,
		    SoupConnectErrorCode  err,
		    GTcpSocket           *socket,
		    gpointer              user_data)
{
	SoupRequest *req = user_data;
	GIOChannel *channel;

	switch (err) {
	case SOUP_CONNECT_ERROR_NONE:
		channel = gnet_tcp_socket_get_iochannel (socket);
		
		soup_setup_socket (channel);

		req->status = SOUP_STATUS_SENDING_REQUEST;
		req->priv->socket = socket;
		req->priv->write_tag = 
			g_io_add_watch (channel, 
					G_IO_OUT|G_IO_ERR|G_IO_HUP|G_IO_NVAL, 
					(GIOFunc) soup_queue_write_async, 
					req);
		break;
	case SOUP_CONNECT_ERROR_ADDR_RESOLVE:
	case SOUP_CONNECT_ERROR_NETWORK:
		soup_request_issue_callback (req, SOUP_ERROR_CANT_CONNECT);
		connection_count--;
		break;
	}
}

static gboolean 
soup_idle_handle_new_requests (gpointer unused)
{
        GList *iter;
	gboolean work_to_do = FALSE;

	if (connection_count >= max_connections)
		return TRUE;
	
	for (iter = active_requests; iter; iter = iter->next) {
		SoupRequest *req = iter->data;

		if (connection_count >= max_connections)
			return TRUE;

		if (req->status != SOUP_STATUS_QUEUED)
			continue;

		if (req->priv->socket) {
			GTcpSocket *sock = req->priv->socket;
			GIOChannel *channel;
			channel = gnet_tcp_socket_get_iochannel (sock);

			req->status = SOUP_STATUS_SENDING_REQUEST;
			req->priv->write_tag = g_io_add_watch (
			        channel, 
				G_IO_OUT|G_IO_ERR|G_IO_HUP|G_IO_NVAL, 
				(GIOFunc) soup_queue_write_async, 
			        req);
		} else {
			SoupContext *ctx;
			ctx = proxy_context ? proxy_context : req->context;
			connection_count++;

			req->status = SOUP_STATUS_CONNECTING;
			soup_context_get_connection (ctx, 
						     soup_queue_connect, 
						     req);
		}

		work_to_do = TRUE;
	}

	if (!work_to_do) {
		soup_queue_idle_tag = 0;
		return FALSE;
	}

	return TRUE;
}

void 
soup_queue_request (SoupRequest    *req,
		    SoupCallbackFn  callback, 
		    gpointer        user_data)
{
	if (!soup_queue_idle_tag)
		soup_queue_idle_tag = 
			g_idle_add (soup_idle_handle_new_requests, NULL);

	if (req->response.body && 
	    req->response.owner == SOUP_BUFFER_SYSTEM_OWNED) {
		g_free (req->response.body);
		req->response.body = NULL;
		req->response.length = 0;
	}

	req->priv->callback = callback;
	req->priv->user_data = user_data;
	req->status = SOUP_STATUS_QUEUED;

	active_requests = g_list_append (active_requests, req);
}

void 
soup_queue_shutdown ()
{
        GList *iter;

	g_source_remove (soup_queue_idle_tag);
	soup_queue_idle_tag = 0;

	for (iter = active_requests; iter; iter = iter->next)
		soup_request_cancel (iter->data);
}

void         
soup_queue_set_proxy (SoupContext *context)
{
	if (proxy_context)
		soup_context_free (proxy_context);

	proxy_context = context;
}

SoupContext *
soup_queue_get_proxy ()
{
	return proxy_context;
}

