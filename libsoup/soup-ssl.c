/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include "soup-ssl.h"
#include <config.h>
#include <gnet/gnet.h>

#if defined HAVE_OPENSSL_SSL_H && defined HAVE_LIBSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

static GIOError soup_ssl_read      (GIOChannel   *channel,
				    gchar        *buf,
				    guint         count,
				    guint        *bytes_written);

static GIOError soup_ssl_write     (GIOChannel   *channel,
				    gchar        *buf,
				    guint         count,
				    guint        *bytes_written);

static GIOError soup_ssl_seek      (GIOChannel   *channel,
				    gint          offset,
				    GSeekType     type);

static void     soup_ssl_close     (GIOChannel   *channel);

static void     soup_ssl_free      (GIOChannel   *channel);

static guint    soup_ssl_add_watch (GIOChannel     *channel,
				    gint            priority,
				    GIOCondition    condition,
				    GIOFunc         func,
				    gpointer        user_data,
				    GDestroyNotify  notify);

GIOFuncs soup_ssl_channel_funcs = {
	soup_ssl_read,
	soup_ssl_write,
	soup_ssl_seek,
	soup_ssl_close,
	soup_ssl_add_watch,
	soup_ssl_free,
};

typedef struct {
	GIOChannel   channel;
	gint         fd;
	GIOChannel  *real_sock;
	SSL         *ssl;
} SoupSSLChannel;

static SSL_CTX *ssl_context = NULL;

static void 
soup_ssl_init (void)
{
	SSLeay_add_ssl_algorithms ();
	SSL_load_error_strings ();

	ssl_context = SSL_CTX_new (SSLv23_client_method ());
	if (!ssl_context) {
		g_warning ("Unable to initialize SSL Library.");
		return;
	}
	
	SSL_CTX_set_default_verify_paths (ssl_context);
}

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	SoupSSLChannel *chan;
	GIOChannel *gchan;
	int bits, alg_bits, err, sockfd;
	SSL *ssl;
	X509 *cert;

        g_return_val_if_fail (sock != NULL, NULL);

	if (!ssl_context) soup_ssl_init ();
	if (!ssl_context) goto THROW_CREATE_ERROR;
	
	sockfd = g_io_channel_unix_get_fd (sock);
	if (!sockfd) goto THROW_CREATE_ERROR;

	ssl = SSL_new (ssl_context);
	if (!ssl) {
		g_warning ("SSL object creation failure.");
		goto THROW_CREATE_ERROR;
	}

	err = SSL_set_fd (ssl, sockfd);
	if (err == 0) {
		g_warning ("Unable to set SSL file descriptor.");
		goto THROW_CREATE_ERROR;
	}

	SSL_connect (ssl);
	if (err == 0) {
		g_warning ("Secure connection could not be established.");
		goto THROW_CREATE_ERROR;
	}

	bits = SSL_get_cipher_bits (ssl, &alg_bits);
	if (bits == 0) {
		g_warning ("Server requested unsecure tranfer."); 
		goto THROW_CREATE_ERROR;
	}

	cert = SSL_get_peer_certificate (ssl);
	if (!cert) {
		g_warning ("Server certificate unavailable");
		goto THROW_CREATE_ERROR;
	}
	X509_free (cert);

	chan = g_new0 (SoupSSLChannel, 1);
	chan->fd = sockfd;
	chan->real_sock = sock;
	chan->ssl = ssl;
	g_io_channel_ref (sock);

	gchan = (GIOChannel *) chan;
	gchan->funcs = &soup_ssl_channel_funcs;
	g_io_channel_init (gchan);

	return gchan;

 THROW_CREATE_ERROR:
	return NULL;
}

static GIOError
soup_ssl_read (GIOChannel   *channel,
	       gchar        *buf,
	       guint         count,
	       guint        *bytes_read)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	gint result;

	result = SSL_read (chan->ssl, buf, count);

	if (result < 0) {
		*bytes_read = 0;
		switch (errno) {
		case EINVAL:
			return G_IO_ERROR_INVAL;
		case EAGAIN:
		case EINTR:
			return G_IO_ERROR_AGAIN;
		default:
			return G_IO_ERROR_UNKNOWN;
		}
	} else {
		*bytes_read = result;
		return G_IO_ERROR_NONE;
	}
}

static GIOError
soup_ssl_write (GIOChannel   *channel,
		gchar        *buf,
		guint         count,
		guint        *bytes_written)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	gint result;

	result = SSL_write (chan->ssl, buf, count);

	if (result < 0) {
		*bytes_written = 0;
		switch (errno) {
		case EINVAL:
			return G_IO_ERROR_INVAL;
		case EAGAIN:
		case EINTR:
			return G_IO_ERROR_AGAIN;
		default:
			return G_IO_ERROR_UNKNOWN;
		}
	} else {
		*bytes_written = result;
		return G_IO_ERROR_NONE;
	}
}

static GIOError
soup_ssl_seek (GIOChannel *channel, gint offset, GSeekType type)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	return g_io_channel_seek (chan->real_sock, offset, type);
}

static void
soup_ssl_close (GIOChannel   *channel)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	g_io_channel_close (chan->real_sock);
}

static void
soup_ssl_free (GIOChannel   *channel)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	g_io_channel_unref (chan->real_sock);
	SSL_free (chan->ssl);
	g_free (chan);
}

typedef struct {
	GIOFunc         func;
	gpointer        user_data;
} SoupSSLReadData;

static gboolean 
soup_ssl_read_cb (GIOChannel   *channel, 
		  GIOCondition  condition, 
		  gpointer      user_data)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	SoupSSLReadData *data = user_data;

	if (condition & G_IO_IN) {
		if (//SSL_pending (chan->ssl) && 
		    !(*data->func) (channel, condition, data->user_data)) {
			g_free (data);
			return FALSE;
		}
		return TRUE;
	} else return (*data->func) (channel, condition, data->user_data);
}

static guint
soup_ssl_add_watch (GIOChannel     *channel,
		    gint            priority,
		    GIOCondition    condition,
		    GIOFunc         func,
		    gpointer        user_data,
		    GDestroyNotify  notify)
{
	SoupSSLChannel *chan = (SoupSSLChannel *) channel;
	if (condition & G_IO_IN) {
		SoupSSLReadData *data = g_new0 (SoupSSLReadData, 1);
		data->func = func;
		data->user_data = user_data;

		return chan->real_sock->funcs->io_add_watch (channel, 
							     priority, 
							     condition,
							     soup_ssl_read_cb,
							     data,
							     notify);
	} else return chan->real_sock->funcs->io_add_watch (channel, 
							    priority, 
							    condition,
							    func,
							    user_data,
							    notify);
}

#else /* HAVE_OPENSSL_SSL_H */

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	g_warning ("SSL Not Supported.");
	return NULL;
}

#endif /* HAVE_OPENSSL_SSL_H */
