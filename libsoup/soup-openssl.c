/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-openssl.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H

#include <unistd.h>
#include <glib.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "soup-openssl.h"

static gboolean server_mode = FALSE;

typedef struct {
	GIOChannel   channel;
	gint         fd;
	GIOChannel  *real_sock;
	SSL         *ssl;
} SoupOpenSSLChannel;

static void
soup_openssl_free (GIOChannel *channel)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;
	g_io_channel_unref (chan->real_sock);
	SSL_free (chan->ssl);
	g_free (chan);
}

static GIOStatus
soup_openssl_read (GIOChannel   *channel,
		   gchar        *buf,
		   gsize         count,
		   gsize        *bytes_read,
		   GError      **err)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;
	gint result;

	result = SSL_read (chan->ssl, buf, count);

	if (result < 0) {
		/* This occurs when a re-handshake is required */
		*bytes_read = 0;
		if (SSL_get_error (chan->ssl, result) == SSL_ERROR_WANT_READ)
		  	return G_IO_STATUS_AGAIN;
		switch (errno) {
		case EINVAL:
#if 0
			return G_IO_ERROR_INVAL;
#else
			return G_IO_STATUS_ERROR;
#endif
		case EAGAIN:
		case EINTR:
			return G_IO_STATUS_AGAIN;
		default:
			return G_IO_STATUS_ERROR;
		}
	} else {
		*bytes_read = result;
		return G_IO_STATUS_NORMAL;
	}
}

static GIOStatus
soup_openssl_write (GIOChannel   *channel,
		    const gchar  *buf,
		    gsize         count,
		    gsize        *bytes_written,
		    GError      **err)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;
	gint result;

	result = SSL_write (chan->ssl, buf, count);

	if (result < 0) {
		*bytes_written = 0;
		if (SSL_get_error (chan->ssl, result) == SSL_ERROR_WANT_WRITE)
			return G_IO_STATUS_AGAIN;
		switch (errno) {
		case EINVAL:
#if 0
			return G_IO_ERROR_INVAL;
#else
			return G_IO_STATUS_ERROR;
#endif
		case EAGAIN:
		case EINTR:
			return G_IO_STATUS_AGAIN;
		default:
			return G_IO_STATUS_ERROR;
		}
	} else {
		*bytes_written = result;

		return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
	}
}

static GIOStatus
soup_openssl_seek (GIOChannel  *channel,
		   gint64       offset,
		   GSeekType    type,
		   GError     **err)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;
	GIOError e;

	e = g_io_channel_seek (chan->real_sock, offset, type);

	if (e != G_IO_ERROR_NONE)
		return G_IO_STATUS_ERROR;
	else
		return G_IO_STATUS_NORMAL;
}

static GIOStatus
soup_openssl_close (GIOChannel  *channel,
		    GError     **err)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;
	SSL_shutdown (chan->ssl);
	g_io_channel_close (chan->real_sock);

	return G_IO_STATUS_NORMAL;
}

typedef struct {
	GSource       source;
	GPollFD       pollfd;
	GIOChannel   *channel;
	GIOCondition  condition;
} SoupOpenSSLWatch;

static gboolean
soup_openssl_prepare (GSource *source,
		      gint    *timeout)
{
	SoupOpenSSLWatch *watch = (SoupOpenSSLWatch *) source;
	GIOCondition buffer_condition = g_io_channel_get_buffer_condition (
		watch->channel);

	*timeout = -1;

	/* Only return TRUE here if _all_ bits in watch->condition will be set
	 */
	return ((watch->condition & buffer_condition) == watch->condition);
}

static gboolean
soup_openssl_check (GSource *source)
{
	SoupOpenSSLWatch *watch = (SoupOpenSSLWatch *) source;
	GIOCondition buffer_condition = g_io_channel_get_buffer_condition (
		watch->channel);
	GIOCondition poll_condition = watch->pollfd.revents;

	return ((poll_condition | buffer_condition) & watch->condition);
}

static gboolean
soup_openssl_dispatch (GSource     *source,
		       GSourceFunc  callback,
		       gpointer     user_data)
{
	GIOFunc func = (GIOFunc) callback;
	SoupOpenSSLWatch *watch = (SoupOpenSSLWatch *) source;
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) watch->channel;
	GIOCondition buffer_condition = g_io_channel_get_buffer_condition (
		watch->channel);
	GIOCondition cond;

	if (!func) {
		g_warning ("IO watch dispatched without callback\n"
			   "You must call g_source_connect().");
		return FALSE;
	}
	
	cond = (watch->pollfd.revents | buffer_condition) & watch->condition;

	if (cond & G_IO_IN) {
		do {
			if (!(*func) (watch->channel, cond, user_data))
			return FALSE;
		} while (SSL_pending (chan->ssl));

		return TRUE;
	} else
		return (*func) (watch->channel, cond, user_data);
}

static void
soup_openssl_finalize (GSource *source)
{
	SoupOpenSSLWatch *watch = (SoupOpenSSLWatch *) source;

	g_io_channel_unref (watch->channel);
}

/* All of these functions were basically cut-and-pasted from glib */
GSourceFuncs soup_openssl_watch_funcs = {
	soup_openssl_prepare,
	soup_openssl_check,
	soup_openssl_dispatch,
	soup_openssl_finalize
};

static GSource *
soup_openssl_create_watch (GIOChannel   *channel,
			   GIOCondition  condition)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;

	if (condition & G_IO_IN) {
		GSource *source;
		SoupOpenSSLWatch *watch;

		source = g_source_new (&soup_openssl_watch_funcs,
				       sizeof (SoupOpenSSLWatch));
		watch = (SoupOpenSSLWatch *) source;

		watch->channel = channel;
		g_io_channel_ref (channel);

		watch->condition = condition;
		
		watch->pollfd.fd = chan->fd;
		watch->pollfd.events = condition;

		g_source_add_poll (source, &watch->pollfd);

		return source;
	}
	else {
		return chan->real_sock->funcs->io_create_watch (channel,
								condition);
	}
}

static GIOStatus
soup_openssl_set_flags (GIOChannel  *channel,
			GIOFlags     flags,
			GError     **err)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;

	return chan->real_sock->funcs->io_set_flags (channel, flags, err);
}	

static GIOFlags
soup_openssl_get_flags (GIOChannel *channel)
{
	SoupOpenSSLChannel *chan = (SoupOpenSSLChannel *) channel;

	return chan->real_sock->funcs->io_get_flags (channel);
}

GIOFuncs soup_openssl_channel_funcs = {
	soup_openssl_read,
	soup_openssl_write,
	soup_openssl_seek,
	soup_openssl_close,
	soup_openssl_create_watch,
	soup_openssl_free,
	soup_openssl_set_flags,
	soup_openssl_get_flags
};

static SSL_CTX *ssl_context = NULL;

#if SSL_LIBRARY_VERSION >= 0x00905100
#  define CHECK_OPENSSL_SEEDED RAND_status()
#  define CHECK_OPENSSL_SEEDED_FINAL RAND_status()
#else
#  define CHECK_OPENSSL_SEEDED FALSE
#  define CHECK_OPENSSL_SEEDED_FINAL TRUE
#endif

static gboolean
soup_openssl_seed (void) 
{
	pid_t pid;
	struct timeval tv;
	guchar stack [1024], *heap;

	if (!CHECK_OPENSSL_SEEDED) {
		/* Seed with pid */
		pid = getpid ();
		RAND_seed ((guchar *) &pid, sizeof (pid_t));

		/* Seed with current time */
		if (gettimeofday (&tv, NULL) == 0)
			RAND_seed ((guchar *) &tv, sizeof (struct timeval));

		/* Seed with untouched stack (1024) */
		RAND_seed (stack, sizeof (stack));

		/* Quit now if we are adequately seeded */
		if (CHECK_OPENSSL_SEEDED) 
			return TRUE;

		/* Seed with untouched heap (1024) */
		heap = g_malloc (1024);
		if (heap) 
			RAND_seed (heap, 1024);
		g_free (heap);

		return CHECK_OPENSSL_SEEDED_FINAL;
	} else
		return TRUE;
}

GIOChannel *
soup_openssl_get_iochannel (GIOChannel *sock)
{
	SoupOpenSSLChannel *chan;
	GIOChannel *gchan;
	int bits, alg_bits, err, sockfd;
	SSL *ssl;
	X509 *cert;
	gchar *ccert_file, *ckey_file;

        g_return_val_if_fail (sock != NULL, NULL);

	if (!ssl_context && !soup_openssl_init (server_mode)) 
		goto THROW_CREATE_ERROR;

	if (!soup_openssl_seed ())
		g_warning ("SSL random number seed failed.");
	
	sockfd = g_io_channel_unix_get_fd (sock);
	if (!sockfd) 
		goto THROW_CREATE_ERROR;

	ssl = SSL_new (ssl_context);
	if (!ssl) {
		g_warning ("SSL object creation failure.");
		goto THROW_CREATE_ERROR;
	}

	ccert_file = getenv ("HTTPS_CERT_FILE");
	ckey_file = getenv ("HTTPS_KEY_FILE");

	if (ccert_file) {
		if (!ckey_file) {
			g_warning ("SSL key file not specified.");
			goto THROW_CREATE_ERROR;
		}

		if (!SSL_use_RSAPrivateKey_file (ssl, ckey_file, SSL_FILETYPE_PEM)) {
			g_warning ("Unable to use private key file.");
			ERR_print_errors_fp(stderr);
			goto THROW_CREATE_ERROR;
		}

		if (!SSL_use_certificate_file (ssl, ccert_file, SSL_FILETYPE_PEM)) {
			g_warning ("Unable to use certificate file.");
			goto THROW_CREATE_ERROR;
		}

		if (!SSL_check_private_key (ssl)) {
			g_warning ("Can't verify correct private key.");
			goto THROW_CREATE_ERROR;
		}
	} else if (ckey_file) {
		g_warning ("SSL certificate file not specified.");
	}

	err = SSL_set_fd (ssl, sockfd);
	if (err == 0) {
		g_warning ("Unable to set SSL file descriptor.");
		goto THROW_CREATE_ERROR;
	}

	do {
		fd_set ssl_fdset;

		if (server_mode)
			err = SSL_accept (ssl);
		else
			err = SSL_connect (ssl);

		err = SSL_get_error (ssl, err);

		if (err == SSL_ERROR_WANT_READ) {
			FD_ZERO (&ssl_fdset);
			FD_SET (sockfd, &ssl_fdset);
			select (sockfd + 1, &ssl_fdset, NULL, NULL, NULL);
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			FD_ZERO (&ssl_fdset);
			FD_SET (sockfd, &ssl_fdset);
			select (sockfd + 1, NULL, &ssl_fdset, NULL, NULL);
		}
		else if (err != SSL_ERROR_NONE) {
			g_warning ("Could not establish secure connection.");
			goto THROW_CREATE_ERROR;
		}
	} while (err != SSL_ERROR_NONE);

	bits = SSL_get_cipher_bits (ssl, &alg_bits);
	if (bits == 0) {
		g_warning ("Server requested unsecure tranfer."); 
		goto THROW_CREATE_ERROR;
	}

	if (!server_mode) {
		cert = SSL_get_peer_certificate (ssl);
		if (!cert) {
			g_warning ("Server certificate unavailable");
			goto THROW_CREATE_ERROR;
		}
		else
			X509_free (cert);
	}

	chan = g_new0 (SoupOpenSSLChannel, 1);
	chan->fd = sockfd;
	chan->real_sock = sock;
	chan->ssl = ssl;
	g_io_channel_ref (sock);

	gchan = (GIOChannel *) chan;
	gchan->funcs = &soup_openssl_channel_funcs;
	g_io_channel_init (gchan);

	return gchan;

 THROW_CREATE_ERROR:
	return NULL;
}

static int
verify_cb (int verified, X509_STORE_CTX *x509_ctx)
{
	if (!verified)
		g_warning ("Unable to verify server's CA");

	return verified;
}

gboolean
soup_openssl_init (gboolean server)
{
	static gchar *ssl_ca_file = NULL;
	static gchar *ssl_ca_dir  = NULL;

	SSL_library_init ();
	SSL_load_error_strings ();

	server_mode = server;

	if (server_mode)
		ssl_context = SSL_CTX_new (SSLv23_server_method ());
	else
		ssl_context = SSL_CTX_new (SSLv23_client_method ());

	if (!ssl_context) {
		g_warning ("Unable to initialize OpenSSL library");
		return FALSE;
	}

	ssl_ca_file = getenv ("HTTPS_CA_FILE");
	ssl_ca_dir  = getenv ("HTTPS_CA_DIR");
	
	SSL_CTX_set_default_verify_paths (ssl_context);

	if (ssl_ca_file || ssl_ca_dir) {
		SSL_CTX_load_verify_locations (ssl_context, 
					       ssl_ca_file, 
					       ssl_ca_dir);
		SSL_CTX_set_verify (ssl_context, SSL_VERIFY_PEER, verify_cb);
	}

	return TRUE;
}

void 
soup_openssl_set_security_policy (SoupSecurityPolicy policy)
{
	switch (policy) {
	case SOUP_SECURITY_DOMESTIC:
		break;
	case SOUP_SECURITY_EXPORT:
		break;
	case SOUP_SECURITY_FRANCE:
		break;
	}
}

#endif /*HAVE_OPENSSL_SSL_H*/
