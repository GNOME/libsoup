/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-gnutls.c
 *
 * Authors:
 *      Ian Peters <itp@ximian.com>
 *
 * Copyright (C) 2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_SSL

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <gnutls/gnutls.h>

#include "soup-ssl.h"
#include "soup-misc.h"

gboolean soup_ssl_supported = TRUE;

#define DH_BITS 1024

typedef struct {
	gnutls_certificate_credentials cred;
	gboolean have_ca_file;
} SoupGNUTLSCred;

typedef struct {
	GIOChannel channel;
	int fd;
	GIOChannel *real_sock;
	gnutls_session session;
	SoupGNUTLSCred *cred;
	char *hostname;
	gboolean established;
	SoupSSLType type;
} SoupGNUTLSChannel;

static gboolean
verify_certificate (gnutls_session session, const char *hostname)
{
	int status;

	status = gnutls_certificate_verify_peers (session);

	if (status == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		g_warning ("No certificate was sent.");
		return FALSE;
	}

	if (status & GNUTLS_CERT_INVALID ||
	    status & GNUTLS_CERT_NOT_TRUSTED ||
	    status & GNUTLS_CERT_REVOKED)
	{
		g_warning ("The certificate is not trusted.");
		return FALSE;
	}

	if (gnutls_certificate_expiration_time_peers (session) < time (0)) {
		g_warning ("The certificate has expired.");
		return FALSE;
	}

	if (gnutls_certificate_activation_time_peers (session) > time (0)) {
		g_warning ("The certificate is not yet activated.");
		return FALSE;
	}

	if (gnutls_certificate_type_get (session) == GNUTLS_CRT_X509) {
		const gnutls_datum* cert_list;
		int cert_list_size;
		gnutls_x509_crt cert;

		if (gnutls_x509_crt_init (&cert) < 0) {
			g_warning ("Error initializing certificate.");
			return FALSE;
		}
      
		cert_list = gnutls_certificate_get_peers (
			session, &cert_list_size);

		if (cert_list == NULL) {
			g_warning ("No certificate was found.");
			return FALSE;
		}

		if (gnutls_x509_crt_import (cert, &cert_list[0],
					    GNUTLS_X509_FMT_DER) < 0) {
			g_warning ("The certificate could not be parsed.");
			return FALSE;
		}

		if (!gnutls_x509_crt_check_hostname (cert, hostname)) {
			g_warning ("The certificate does not match hostname.");
			return FALSE;
		}
	}
   
	return TRUE;
}

static GIOStatus
do_handshake (SoupGNUTLSChannel *chan, GError **err)
{
	int result;

	result = gnutls_handshake (chan->session);

	if (result == GNUTLS_E_AGAIN ||
	    result == GNUTLS_E_INTERRUPTED)
		return G_IO_STATUS_AGAIN;

	if (result < 0) {
		g_set_error (err, G_IO_CHANNEL_ERROR,
			     G_IO_CHANNEL_ERROR_FAILED,
			     "Unable to handshake");
		return G_IO_STATUS_ERROR;
	}

	if (chan->type == SOUP_SSL_TYPE_CLIENT &&
	    chan->cred->have_ca_file) {
		if (!verify_certificate (chan->session, chan->hostname)) {
			g_set_error (err, G_IO_CHANNEL_ERROR,
				     G_IO_CHANNEL_ERROR_FAILED,
				     "Unable to verify certificate");
			return G_IO_STATUS_ERROR;
		}
	}

	return G_IO_STATUS_NORMAL;
}

static GIOStatus
soup_gnutls_read (GIOChannel   *channel,
		  gchar        *buf,
		  gsize         count,
		  gsize        *bytes_read,
		  GError      **err)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;
	gint result;

	*bytes_read = 0;

	if (!chan->established) {
		result = do_handshake (chan, err);

		if (result == G_IO_STATUS_AGAIN ||
		    result == G_IO_STATUS_ERROR)
			return result;

		chan->established = TRUE;
	}

	result = gnutls_record_recv (chan->session, buf, count);

	if (result == GNUTLS_E_REHANDSHAKE) {
		chan->established = FALSE;
		return G_IO_STATUS_AGAIN;
	}

	if (result < 0) {
		if ((result == GNUTLS_E_INTERRUPTED) ||
		    (result == GNUTLS_E_AGAIN))
			return G_IO_STATUS_AGAIN;
		g_set_error (err, G_IO_CHANNEL_ERROR,
			     G_IO_CHANNEL_ERROR_FAILED,
			     "Received corrupted data");
		return G_IO_STATUS_ERROR;
	} else {
		*bytes_read = result;

		return G_IO_STATUS_NORMAL;
	}
}

static GIOStatus
soup_gnutls_write (GIOChannel   *channel,
		   const gchar  *buf,
		   gsize         count,
		   gsize        *bytes_written,
		   GError      **err)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;
	gint result;

	*bytes_written = 0;

	if (!chan->established) {
		result = do_handshake (chan, err);

		if (result == G_IO_STATUS_AGAIN ||
		    result == G_IO_STATUS_ERROR)
			return result;

		chan->established = TRUE;
	}

	result = gnutls_record_send (chan->session, buf, count);

	if (result == GNUTLS_E_REHANDSHAKE) {
		chan->established = FALSE;
		return G_IO_STATUS_AGAIN;
	}

	if (result < 0) {
		if ((result == GNUTLS_E_INTERRUPTED) ||
		    (result == GNUTLS_E_AGAIN))
			return G_IO_STATUS_AGAIN;
		g_set_error (err, G_IO_CHANNEL_ERROR,
			     G_IO_CHANNEL_ERROR_FAILED,
			     "Received corrupted data");
		return G_IO_STATUS_ERROR;
	} else {
		*bytes_written = result;

		return (result > 0) ? G_IO_STATUS_NORMAL : G_IO_STATUS_EOF;
	}
}

static GIOStatus
soup_gnutls_seek (GIOChannel  *channel,
		  gint64       offset,
		  GSeekType    type,
		  GError     **err)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;

	return chan->real_sock->funcs->io_seek (channel, offset, type, err);
}

static GIOStatus
soup_gnutls_close (GIOChannel  *channel,
		   GError     **err)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;

	if (chan->established) {
		int ret;

		do {
			ret = gnutls_bye (chan->session, GNUTLS_SHUT_WR);
		} while (ret == GNUTLS_E_INTERRUPTED);
	}

	return chan->real_sock->funcs->io_close (channel, err);
}

static GSource *
soup_gnutls_create_watch (GIOChannel   *channel,
			  GIOCondition  condition)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;

	return chan->real_sock->funcs->io_create_watch (channel,
							condition);
}

static void
soup_gnutls_free (GIOChannel *channel)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;
	g_io_channel_unref (chan->real_sock);
	gnutls_deinit (chan->session);
	g_free (chan);
}

static GIOStatus
soup_gnutls_set_flags (GIOChannel  *channel,
		       GIOFlags     flags,
		       GError     **err)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;

	return chan->real_sock->funcs->io_set_flags (channel, flags, err);
}

static GIOFlags
soup_gnutls_get_flags (GIOChannel *channel)
{
	SoupGNUTLSChannel *chan = (SoupGNUTLSChannel *) channel;

	return chan->real_sock->funcs->io_get_flags (channel);
}

GIOFuncs soup_gnutls_channel_funcs = {
	soup_gnutls_read,
	soup_gnutls_write,
	soup_gnutls_seek,
	soup_gnutls_close,
	soup_gnutls_create_watch,
	soup_gnutls_free,
	soup_gnutls_set_flags,
	soup_gnutls_get_flags
};

static gnutls_dh_params dh_params = NULL;

static gboolean
init_dh_params (void)
{
	if (gnutls_dh_params_init (&dh_params) != 0)
		goto THROW_CREATE_ERROR;

	if (gnutls_dh_params_generate2 (dh_params, DH_BITS) != 0)
		goto THROW_CREATE_ERROR;

	return TRUE;

THROW_CREATE_ERROR:
	if (dh_params) {
		gnutls_dh_params_deinit (dh_params);
		dh_params = NULL;
	}

	return FALSE;
}

GIOChannel *
soup_ssl_wrap_iochannel (GIOChannel *sock, SoupSSLType type,
			 const char *hostname, gpointer cred_pointer)
{
	SoupGNUTLSChannel *chan = NULL;
	GIOChannel *gchan = NULL;
	gnutls_session session = NULL;
	SoupGNUTLSCred *cred = cred_pointer;
	int sockfd;
	int ret;

	g_return_val_if_fail (sock != NULL, NULL);
	g_return_val_if_fail (cred_pointer != NULL, NULL);

	sockfd = g_io_channel_unix_get_fd (sock);
	if (!sockfd) {
		g_warning ("Failed to get channel fd.");
		goto THROW_CREATE_ERROR;
	}

	chan = g_new0 (SoupGNUTLSChannel, 1);

	ret = gnutls_init (&session,
			   (type == SOUP_SSL_TYPE_CLIENT) ? GNUTLS_CLIENT : GNUTLS_SERVER);
	if (ret)
		goto THROW_CREATE_ERROR;

	if (gnutls_set_default_priority (session) != 0)
		goto THROW_CREATE_ERROR;

	if (gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,
				    cred->cred) != 0)
		goto THROW_CREATE_ERROR;

	if (type == SOUP_SSL_TYPE_SERVER)
		gnutls_dh_set_prime_bits (session, DH_BITS);

	gnutls_transport_set_ptr (session, GINT_TO_POINTER (sockfd));

	chan->fd = sockfd;
	chan->real_sock = sock;
	chan->session = session;
	chan->cred = cred;
	chan->hostname = g_strdup (hostname);
	chan->type = type;
	g_io_channel_ref (sock);

	gchan = (GIOChannel *) chan;
	gchan->funcs = &soup_gnutls_channel_funcs;
	g_io_channel_init (gchan);
	g_io_channel_set_close_on_unref (gchan, TRUE);
	gchan->is_readable = gchan->is_writeable = TRUE;
	gchan->use_buffer = FALSE;

	return gchan;

 THROW_CREATE_ERROR:
	if (session)
		gnutls_deinit (session);
	return NULL;
}

gpointer
soup_ssl_get_client_credentials (const char *ca_file)
{
	SoupGNUTLSCred *cred;
	int status;

	gnutls_global_init ();

	cred = g_new0 (SoupGNUTLSCred, 1);
	gnutls_certificate_allocate_credentials (&cred->cred);

	if (ca_file) {
		cred->have_ca_file = TRUE;
		status = gnutls_certificate_set_x509_trust_file (
			cred->cred, ca_file, GNUTLS_X509_FMT_PEM);
		if (status < 0) {
			g_warning ("Failed to set SSL trust file (%s).",
				   ca_file);
			/* Since we set have_ca_file though, this just
			 * means that no certs will validate, so we're
			 * ok securitywise if we just return these
			 * creds to the caller.
			 */
		}
	}

	return cred;
}

void
soup_ssl_free_client_credentials (gpointer client_creds)
{
	SoupGNUTLSCred *cred = client_creds;

	gnutls_certificate_free_credentials (cred->cred);
	g_free (cred);
}

gpointer
soup_ssl_get_server_credentials (const char *cert_file, const char *key_file)
{
	SoupGNUTLSCred *cred;

	gnutls_global_init ();
	if (!dh_params) {
		if (!init_dh_params ())
			return NULL;
	}

	cred = g_new0 (SoupGNUTLSCred, 1);
	gnutls_certificate_allocate_credentials (&cred->cred);

	if (gnutls_certificate_set_x509_key_file (cred->cred,
						  cert_file, key_file,
						  GNUTLS_X509_FMT_PEM) != 0) {
		g_warning ("Failed to set SSL certificate and key files "
			   "(%s, %s).", cert_file, key_file);
		soup_ssl_free_server_credentials (cred);
		return NULL;
	}

	gnutls_certificate_set_dh_params (cred->cred, dh_params);
	return cred;
}

void
soup_ssl_free_server_credentials (gpointer server_creds)
{
	SoupGNUTLSCred *cred = server_creds;

	gnutls_certificate_free_credentials (cred->cred);
	g_free (cred);
}

#endif /* HAVE_SSL */
