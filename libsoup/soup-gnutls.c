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

#ifdef HAVE_GNUTLS_GNUTLS_H

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <gnutls/gnutls.h>

#include "soup-gnutls.h"

#define DH_BITS 1024

typedef struct {
	gnutls_certificate_credentials cred;
	guint ref_count;
} SoupGNUTLSCred;

static void
soup_gnutls_cred_ref (SoupGNUTLSCred *cred)
{
	cred->ref_count++;
}

static void
soup_gnutls_cred_unref (SoupGNUTLSCred *cred)
{
	cred->ref_count--;
	if (!cred->ref_count) {
		gnutls_certificate_free_credentials (cred->cred);
		g_free (cred);
	}
}

static SoupGNUTLSCred *client_cred = NULL;
static char *ca_file = NULL;
static SoupGNUTLSCred *server_cred = NULL;

typedef struct {
	GIOChannel channel;
	gint fd;
	GIOChannel *real_sock;
	gnutls_session session;
	SoupGNUTLSCred *cred;
	gboolean established;
	SoupSSLType type;
} SoupGNUTLSChannel;

static gboolean
verify_certificate (gnutls_session session, const char* hostname)
{
	int status;

	if (!soup_get_ssl_ca_file ())
		return TRUE;

	status = gnutls_certificate_verify_peers (session);

	if (status == GNUTLS_E_NO_CERTIFICATE_FOUND) {
		g_warning ("No certificate was sent.");
		return FALSE;
	}

	if (status & GNUTLS_CERT_INVALID ||
	    status & GNUTLS_CERT_NOT_TRUSTED ||
	    status & GNUTLS_CERT_CORRUPTED ||
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
      
		cert_list = gnutls_certificate_get_peers (
			session, &cert_list_size);
		if (cert_list == NULL) {
			g_warning ("No certificate was found.");
			return FALSE;
		}
#if 0
                /* Due to the Soup design, we don't have enough
		 * information to check the certificate vs. the
		 * hostname at this point.  This should really be
		 * fixed, but I don't think we intend to keep Soup
		 * around long enough to make it worthwhile. */
		if (!gnutls_x509_check_certificates_hostname(
			    &cert_list[0], hostname))
		{
			g_warning ("The certificate does not match hostname.");
			return FALSE;
		}
#endif
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

	if (chan->type == SOUP_SSL_TYPE_CLIENT)
		if (!verify_certificate (chan->session, NULL)) {
			g_set_error (err, G_IO_CHANNEL_ERROR,
				     G_IO_CHANNEL_ERROR_FAILED,
				     "Unable to verify certificate");
			return G_IO_STATUS_ERROR;
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
			ret = gnutls_bye (chan->session, GNUTLS_SHUT_RDWR);
		} while (ret == GNUTLS_E_INTERRUPTED ||
			 ret == GNUTLS_E_AGAIN);
	}

#if 0
	/* gnutls_bye closes the fd itself, so we shouldn't do this.
	 * All of this GIOChannel abuse makes me a little sick. */
	return chan->real_sock->funcs->io_close (channel, err);
#else
	return TRUE;
#endif
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
	soup_gnutls_cred_unref (chan->cred);
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
	gnutls_datum prime, generator;

	if (gnutls_dh_params_init (&dh_params) != 0)
		goto THROW_CREATE_ERROR;

	if (gnutls_dh_params_generate (&prime, &generator, DH_BITS) != 0)
		goto THROW_CREATE_ERROR;

	if (gnutls_dh_params_set (dh_params, prime, generator, DH_BITS) != 0)
		goto THROW_CREATE_ERROR;

	free (prime.data);
	free (generator.data);

	return TRUE;

    THROW_CREATE_ERROR:
	if (dh_params) {
		gnutls_dh_params_deinit (dh_params);
		dh_params = NULL;
	}
	if (prime.data)
		free (prime.data);
	if (generator.data)
		free (generator.data);
	return FALSE;
}

static SoupGNUTLSCred *
get_credentials (SoupSSLType type)
{
	gnutls_certificate_credentials cred;
	SoupGNUTLSCred *scred;

	gnutls_certificate_allocate_credentials (&cred);

	if (type == SOUP_SSL_TYPE_CLIENT) {
		if (soup_get_ssl_ca_file ())
			if (gnutls_certificate_set_x509_trust_file (
				    cred, soup_get_ssl_ca_file (),
				    GNUTLS_X509_FMT_PEM) < 0)
			{
				g_warning ("Failed to set SSL trust file "
					   "(%s).", soup_get_ssl_ca_file ());
				goto THROW_CREATE_ERROR;
			}

		if (soup_get_ssl_ca_dir ())
			g_warning ("CA directory not supported.");
	} else {
		const char *cert_file, *key_file;

		soup_get_ssl_cert_files (&cert_file, &key_file);

		if (cert_file) {
			if (!key_file) {
				g_warning ("SSL certificate file specified "
					   "without key file.");
				goto THROW_CREATE_ERROR;
			}

			if (gnutls_certificate_set_x509_key_file (
				    cred, cert_file, key_file,
				    GNUTLS_X509_FMT_PEM) != 0)
			{
				g_warning ("Failed to set SSL certificate "
					   "and key files (%s, %s).",
					   cert_file, key_file);
				goto THROW_CREATE_ERROR;
			}
		} else if (key_file) {
			g_warning ("SSL key file specified without "
				   "certificate file.");
			goto THROW_CREATE_ERROR;
		}
	
		if (!dh_params)
			if (!init_dh_params ())
				goto THROW_CREATE_ERROR;

		gnutls_certificate_set_dh_params (cred, dh_params);
	}

	scred = g_new0 (SoupGNUTLSCred, 1);
	scred->cred = cred;
	scred->ref_count = 1;

	return scred;

    THROW_CREATE_ERROR:
	gnutls_certificate_free_credentials (cred);
	return NULL;
}

GIOChannel *
soup_gnutls_get_iochannel (GIOChannel *sock, SoupSSLType type)
{
	static gboolean initialized = FALSE;
	SoupGNUTLSChannel *chan = NULL;
	GIOChannel *gchan = NULL;
	gnutls_session session = NULL;
	SoupGNUTLSCred *cred;
	int sockfd;
	int ret;

	g_return_val_if_fail (sock != NULL, NULL);

	if (!initialized) {
		gnutls_global_init ();
		initialized = TRUE;
	}

	sockfd = g_io_channel_unix_get_fd (sock);
	if (!sockfd) {
		g_warning ("Failed to get channel fd.");
		goto THROW_CREATE_ERROR;
	}

	chan = g_new0 (SoupGNUTLSChannel, 1);

	if (type == SOUP_SSL_TYPE_CLIENT) {
		const char *new_ca_file = soup_get_ssl_ca_file ();

		if ((new_ca_file && !ca_file) ||
		    (ca_file && !new_ca_file) ||
		    (ca_file && strcmp (ca_file, new_ca_file)))
		{
			if (client_cred)
				soup_gnutls_cred_unref (client_cred);
			client_cred = NULL;
			g_free (ca_file);
			ca_file = g_strdup (new_ca_file);
		}

		if (!client_cred)
			client_cred = get_credentials (type);
		if (!client_cred)
			goto THROW_CREATE_ERROR;

		cred = client_cred;

		ret = gnutls_init (&session, GNUTLS_CLIENT);
	} else {
		if (!server_cred)
			server_cred = get_credentials (type);
		if (!server_cred)
			goto THROW_CREATE_ERROR;

		cred = server_cred;

		ret = gnutls_init (&session, GNUTLS_SERVER);
	}
	if (ret)
		goto THROW_CREATE_ERROR;

	if (gnutls_set_default_priority (session) != 0)
		goto THROW_CREATE_ERROR;

	if (gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,
				    cred->cred) != 0)
		goto THROW_CREATE_ERROR;
	soup_gnutls_cred_ref (cred);

	if (type == SOUP_SSL_TYPE_SERVER) {
		gnutls_certificate_server_set_request (
			session, GNUTLS_CERT_REQUEST);

		gnutls_dh_set_prime_bits (session, DH_BITS);
	}

	gnutls_transport_set_ptr (session, sockfd);

	chan->fd = sockfd;
	chan->real_sock = sock;
	chan->session = session;
	chan->cred = cred;
	chan->type = type;
	g_io_channel_ref (sock);

	gchan = (GIOChannel *) chan;
	gchan->funcs = &soup_gnutls_channel_funcs;
	g_io_channel_init (gchan);
	g_io_channel_set_close_on_unref (gchan, TRUE);

	return gchan;

 THROW_CREATE_ERROR:
	if (session)
		gnutls_deinit (session);
	return NULL;
}

void
soup_gnutls_set_security_policy (SoupSecurityPolicy policy)
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

#endif /* HAVE_GNUTLS_GNUTLS_H */
