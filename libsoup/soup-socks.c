/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
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

static void
socks_data_free (SoupSocksData *sd)
{
	if (sd->dest_ctx)
		soup_context_unref (sd->dest_ctx);

	if (sd->dest_addr)
		g_object_unref (sd->dest_addr);

	while (g_source_remove_by_user_data (sd))
		continue;

	g_free (sd);
}

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
	gushort np = htons (port);

	memcpy (&buf [*len], &np, sizeof (np));
	*len += sizeof (np);
}

static gboolean
soup_socks_write (GIOChannel* iochannel, 
		  GIOCondition condition, 
		  SoupSocksData *sd)
{
	const SoupUri *dest_uri, *proxy_uri;
	SoupContext *proxy_ctx;
	struct sockaddr *sa;
	gboolean finished = FALSE;
	guchar buf[128];
	gint len = 0, sa_len;
	gsize bytes_written;
	GIOError error;

	dest_uri = soup_context_get_uri (sd->dest_ctx);

	proxy_ctx = soup_connection_get_context (sd->src_conn);
	proxy_uri = soup_context_get_uri (proxy_ctx);
	soup_context_unref (proxy_ctx);

	switch (sd->phase) {
	case SOCKS_4_SEND_DEST_ADDR: 
		/* FIXME: This won't work if dest_addr isn't IPv4 */

		buf[len++] = 0x04;
		buf[len++] = 0x01;
		WSHORT (buf, &len, (gushort) dest_uri->port);
		soup_address_make_sockaddr (sd->dest_addr, dest_uri->port,
					    &sa, &sa_len);
		memcpy (&buf [len], 
			&((struct sockaddr_in *) sa)->sin_addr,
			4);
		g_free (sa);
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
		return TRUE;
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
	socks_data_free (sd);
	return FALSE;
}

static gboolean
soup_socks_read (GIOChannel* iochannel, 
		 GIOCondition condition, 
		 SoupSocksData *sd)
{
	guchar buf[128];
	gsize bytes_read;
	GIOError error;

	error = g_io_channel_read (iochannel, buf, sizeof (buf), &bytes_read);

	if (error == G_IO_ERROR_AGAIN) return TRUE;
	if (error != G_IO_ERROR_NONE || bytes_read == 0) goto CONNECT_ERROR;

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
	socks_data_free (sd);
	return FALSE;

 CONNECT_ERROR:
	(*sd->cb) (sd->dest_ctx, 
		   SOUP_CONNECT_ERROR_NETWORK, 
		   NULL, 
		   sd->user_data);
	socks_data_free (sd);
	return FALSE;
}

static gboolean
soup_socks_error (GIOChannel* iochannel, 
		  GIOCondition condition, 
		  SoupSocksData *sd)
{
	(*sd->cb) (sd->dest_ctx, 
		   SOUP_CONNECT_ERROR_NETWORK, 
		   NULL, 
		   sd->user_data);

	socks_data_free (sd);
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
	g_io_add_watch (channel, 
			G_IO_ERR | G_IO_HUP | G_IO_NVAL, 
			(GIOFunc) soup_socks_error, 
			sd);		
	g_io_channel_unref (channel);
}

void
soup_connect_socks_proxy (SoupConnection        *conn, 
			  SoupContext           *dest_ctx, 
			  SoupConnectCallbackFn  cb,
			  gpointer               user_data)
{
	SoupSocksData *sd = NULL;
	SoupContext *proxy_ctx;
	const SoupUri *dest_uri, *proxy_uri;
	GIOChannel *channel;

	if (!soup_connection_is_new (conn)) goto CONNECT_SUCCESS;
	
	soup_context_ref (dest_ctx);
	dest_uri = soup_context_get_uri (dest_ctx);

	proxy_ctx = soup_connection_get_context (conn);
	proxy_uri = soup_context_get_uri (proxy_ctx);
	soup_context_unref (proxy_ctx);

	sd = g_new0 (SoupSocksData, 1);
	sd->src_conn = conn;
	sd->dest_ctx = dest_ctx;
	sd->cb = cb;
	sd->user_data = user_data;
	
	if (proxy_uri->protocol == SOUP_PROTOCOL_SOCKS4) {
		soup_address_new (dest_uri->host, 
				  soup_lookup_dest_addr_cb,
				  sd);
		sd->phase = SOCKS_4_DEST_ADDR_LOOKUP;
	} else if (proxy_uri->protocol == SOUP_PROTOCOL_SOCKS5) {
		channel = soup_connection_get_iochannel (conn);
		g_io_add_watch (channel, 
				G_IO_OUT, 
				(GIOFunc) soup_socks_write, 
				sd);
		g_io_add_watch (channel, 
				G_IO_IN, 
				(GIOFunc) soup_socks_read, 
				sd);
		g_io_add_watch (channel, 
				G_IO_ERR | G_IO_HUP | G_IO_NVAL, 
				(GIOFunc) soup_socks_error, 
				sd);		
		g_io_channel_unref (channel);

		sd->phase = SOCKS_5_SEND_INIT;
	} else
		goto CONNECT_SUCCESS;

	return;
	
 CONNECT_SUCCESS:
	(*cb) (dest_ctx, SOUP_CONNECT_ERROR_NONE, conn, user_data); 
	g_free (sd);
}
