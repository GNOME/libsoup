/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <glib.h>
#include <string.h>

#include "soup-socks.h"
#include "soup-context.h"
#include "soup-socket.h"
#include "soup-private.h"

typedef struct {
	SoupConnection        *src_conn;
	
	enum {
		SOCKS_4_DEST_ADDR_LOOKUP,
		SOCKS_4_SEND_DEST_ADDR,
		SOCKS_4_VERIFY_SUCCESS,

		SOCKS_5_SEND_INIT,
		SOCKS_5_VERIFY_INIT,
		SOCKS_5_SEND_AUTH,
		SOCKS_5_VERIFY_AUTH,
		SOCKS_5_SEND_DEST_ADDR,
		SOCKS_5_VERIFY_SUCCESS	
	} phase;

	SoupAddress           *dest_addr;
	SoupContext           *dest_ctx;
	SoupConnectCallbackFn  cb;
	gpointer               user_data;
} SoupSocksData;

static inline void
WSTRING (char *buf, gint *len, gchar *str)
{
	gint l = strlen (str);
	buf [(*len)++] = (guchar) l;
	strncpy (&buf [*len], str, l);
	*len += l;
}

static inline void
WSHORT (char *buf, gint *len, gushort port)
{
	buf [(*len)++] = (((gushort) htons (port)) >> 8);
	buf [(*len)++] = (((gushort) htons (port)) & 0xff);
}

static gboolean
soup_socks_write (GIOChannel* iochannel, 
		  GIOCondition condition, 
		  SoupSocksData *sd)
{
	const SoupUri *dest_uri, *proxy_uri;
	SoupContext *proxy_ctx;

	gboolean finished = FALSE;
	guchar buf[128];
	gint len = 0;
	guint bytes_written;
	GIOError error;

	dest_uri = soup_context_get_uri (sd->dest_ctx);
	proxy_ctx = soup_connection_get_context (sd->src_conn);
	proxy_uri = soup_context_get_uri (proxy_ctx);

	switch (sd->phase) {
	case SOCKS_4_SEND_DEST_ADDR: 
		buf[len++] = 0x04;
		buf[len++] = 0x01;
		WSHORT (buf, &len, (gushort) dest_uri->port);
		memcpy (&buf [len], 
			&((struct sockaddr_in *) &sd->dest_addr->sa)->sin_addr,
			4);
		len += 4;
		buf[8] = 0x00;
		len = 9;
		
		sd->phase = SOCKS_4_VERIFY_SUCCESS;
		finished = TRUE;
		break;

	case SOCKS_5_SEND_INIT:
		if (proxy_uri->user) {
			buf[0] = 0x05;
			buf[1] = 0x02;
			buf[2] = 0x00;
			buf[3] = 0x02;
			len = 4;
		} else {
			buf[0] = 0x05;
			buf[1] = 0x01;
			buf[2] = 0x00;
			len = 3;
		}
		sd->phase = SOCKS_5_VERIFY_INIT;
		break;

	case SOCKS_5_SEND_AUTH:
		buf[len++] = 0x01;
		WSTRING (buf, &len, proxy_uri->user);
		WSTRING (buf, &len, proxy_uri->passwd);
		sd->phase = SOCKS_5_VERIFY_AUTH;
		break;

	case SOCKS_5_SEND_DEST_ADDR:
		buf[len++] = 0x05;
		buf[len++] = 0x01;
		buf[len++] = 0x00;
		buf[len++] = 0x03;
		WSTRING (buf, &len, dest_uri->host);
		WSHORT (buf, &len, (gushort) dest_uri->port);
		sd->phase = SOCKS_5_VERIFY_SUCCESS;
		finished = TRUE;
		break;

	default:
		break;
	}

	error = g_io_channel_write (iochannel, buf, len, &bytes_written);
	
	if (error == G_IO_ERROR_AGAIN) return TRUE;
	if (error != G_IO_ERROR_NONE) goto CONNECT_ERROR;

	return !finished;

 CONNECT_ERROR:
	(*sd->cb) (sd->dest_ctx, 
		   SOUP_CONNECT_ERROR_NETWORK, 
		   NULL, 
		   sd->user_data);
	return FALSE;
}

static gboolean
soup_socks_read (GIOChannel* iochannel, 
		 GIOCondition condition, 
		 SoupSocksData *sd)
{
	guchar buf[128];
	gint  len = 0;
	guint bytes_read;
	GIOError error;

	error = g_io_channel_read (iochannel, buf, len, &bytes_read);

	if (error == G_IO_ERROR_AGAIN) return TRUE;
	if (error != G_IO_ERROR_NONE) goto CONNECT_ERROR;

	switch (sd->phase) {
	case SOCKS_4_VERIFY_SUCCESS:
		if (bytes_read < 4 || buf[1] != 90) 
			goto CONNECT_ERROR;

		goto CONNECT_OK;

	case SOCKS_5_VERIFY_INIT:
		if (bytes_read < 2 || buf [0] != 0x05 || buf [1] == 0xff)
			goto CONNECT_ERROR;

		if (buf [1] == 0x02) 
			sd->phase = SOCKS_5_SEND_AUTH;
		else 
			sd->phase = SOCKS_5_SEND_DEST_ADDR;
		break;

	case SOCKS_5_VERIFY_AUTH:
		if (bytes_read < 2 || buf [0] != 0x01 || buf [1] != 0x00)
			goto CONNECT_ERROR;

		sd->phase = SOCKS_5_SEND_DEST_ADDR;
		break;

	case SOCKS_5_VERIFY_SUCCESS:
		if (bytes_read < 10 || buf[0] != 0x05 || buf[1] != 0x00) 
			goto CONNECT_ERROR;

		goto CONNECT_OK;

	default:
		break;
	}

	return TRUE;

 CONNECT_OK:
	(*sd->cb) (sd->dest_ctx, 
		   SOUP_CONNECT_ERROR_NONE, 
		   sd->src_conn, 
		   sd->user_data);
	g_free (sd);
	return FALSE;

 CONNECT_ERROR:
	(*sd->cb) (sd->dest_ctx, 
		   SOUP_CONNECT_ERROR_NETWORK, 
		   NULL, 
		   sd->user_data);
	g_free (sd);
	return FALSE;
}

static void
soup_lookup_dest_addr_cb (SoupAddress*         inetaddr, 
			  SoupAddressStatus    status, 
			  gpointer             data)
{
	SoupSocksData *sd = data;
	GIOChannel *channel;

	if (status != SOUP_ADDRESS_STATUS_OK) {
		(*sd->cb) (sd->dest_ctx, 
			   SOUP_CONNECT_ERROR_ADDR_RESOLVE, 
			   NULL, 
			   sd->user_data); 
		g_free (sd);
		return;
	}

	sd->dest_addr = inetaddr;
	sd->phase = SOCKS_4_SEND_DEST_ADDR;
	channel = soup_connection_get_iochannel (sd->src_conn);

	g_io_add_watch (channel, G_IO_OUT, (GIOFunc) soup_socks_write, sd);
	g_io_add_watch (channel, G_IO_IN, (GIOFunc) soup_socks_read, sd);
}

void
soup_connect_socks_proxy (SoupConnection        *conn, 
			  SoupContext           *dest_ctx, 
			  SoupConnectCallbackFn  cb,
			  gpointer               user_data)
{
	SoupSocksData *sd = NULL;
	SoupContext *proxy_ctx;
	const SoupUri *dest_uri;
	GIOChannel *channel;

	if (!soup_connection_is_new (conn)) goto CONNECT_SUCCESS;
	
	proxy_ctx = soup_connection_get_context (conn);
	dest_uri = soup_context_get_uri (dest_ctx);

	sd = g_new0 (SoupSocksData, 1);
	sd->src_conn = conn;
	sd->dest_ctx = dest_ctx;
	sd->cb = cb;
	sd->user_data = user_data;
	
	switch (soup_context_get_uri (proxy_ctx)->protocol) {
	case SOUP_PROTOCOL_SOCKS4:
		soup_address_new (dest_uri->host, 
				  dest_uri->port, 
				  soup_lookup_dest_addr_cb,
				  sd);
		sd->phase = SOCKS_4_DEST_ADDR_LOOKUP;
		break;

	case SOUP_PROTOCOL_SOCKS5:
		channel = soup_connection_get_iochannel (conn);
		g_io_add_watch (channel, 
				G_IO_OUT, 
				(GIOFunc) soup_socks_write, 
				sd);
		g_io_add_watch (channel, 
				G_IO_IN, 
				(GIOFunc) soup_socks_read, 
				sd);
		sd->phase = SOCKS_5_SEND_INIT;
		break;

	default:
		goto CONNECT_SUCCESS;
	}

	return;
	
 CONNECT_SUCCESS:
	(*cb) (dest_ctx, SOUP_CONNECT_ERROR_NONE, conn, user_data); 
	g_free (sd);
}
