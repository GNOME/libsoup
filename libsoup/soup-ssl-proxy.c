/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#include <config.h>
#include <gmodule.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "soup-misc.h"
#include "soup-private.h"

#ifdef HAVE_SECURITY_SSL_H
#include "soup-nss.h"
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include "soup-openssl.h"
#endif

static gint ssl_library = 0; /* -1 = fail,
				 0 = first time, 
				 1 = nss, 
				 2 = openssl */
static SoupSecurityPolicy ssl_security_level = SOUP_SECURITY_DOMESTIC;

static GMainLoop *loop;

static void 
soup_ssl_proxy_set_security_policy (SoupSecurityPolicy policy)
{
	ssl_security_level = policy;

	switch (ssl_library) {
	case -1:
	case 0:
		break;
#ifdef HAVE_SECURITY_SSL_H
	case 1:
		soup_nss_set_security_policy (policy);
		break;
#endif
#ifdef HAVE_OPENSSL_SSL_H
	case 2:
		soup_openssl_set_security_policy (policy);
		break;
#endif
	}
}

static void 
soup_ssl_proxy_init (void)
{
	ssl_library = -1;

	if (!g_module_supported ()) return;

#ifdef HAVE_SECURITY_SSL_H
	if (ssl_library == -1) ssl_library = soup_nss_init () ? 1 : -1;
#endif

#ifdef HAVE_OPENSSL_SSL_H
	if (ssl_library == -1) ssl_library = soup_openssl_init () ? 2 : -1;
#endif

	if (ssl_library == -1) return;

	soup_ssl_proxy_set_security_policy (ssl_security_level);
}

static GIOChannel *
soup_ssl_proxy_get_iochannel (GIOChannel *sock)
{
	switch (ssl_library) {
	case -1:
		g_warning ("SSL Not Supported.");
		return NULL;
	case 0:
	default:
		soup_ssl_proxy_init ();
		return soup_ssl_proxy_get_iochannel (sock);
#ifdef HAVE_SECURITY_SSL_H
	case 1:
		return soup_nss_get_iochannel (sock);
#endif
#ifdef HAVE_OPENSSL_SSL_H
	case 2:
		return soup_openssl_get_iochannel (sock);
#endif
	}
}

static gboolean 
soup_ssl_proxy_readwrite (GIOChannel   *iochannel, 
			  GIOCondition  condition, 
			  GIOChannel   *dest)
{
	gchar read_buf [RESPONSE_BLOCK_SIZE];
	gint bytes_read = 0, bytes_written = 0, write_total = 0;
	GIOError error;

	if (condition & (G_IO_HUP | G_IO_ERR)) goto FINISH;

	error = g_io_channel_read (iochannel,
				   read_buf,
				   sizeof (read_buf),
				   &bytes_read);

	if (error == G_IO_ERROR_AGAIN) return TRUE;

	if (error != G_IO_ERROR_NONE || bytes_read == 0) goto FINISH;

	while (write_total != bytes_read) {
		error = g_io_channel_write (dest, 
					    &read_buf [write_total], 
					    bytes_read - write_total, 
					    &bytes_written);

		if (error != G_IO_ERROR_NONE || errno != 0) goto FINISH;

		write_total += bytes_written;
	}

	return TRUE;

 FINISH:
	g_main_quit (loop);
	return FALSE;
}

int
main (int argc, char** argv) 
{
	gchar *env;
	GIOChannel *read_chan, *write_chan, *sock_chan;
	int sockfd, secpol, flags;

	loop = g_main_new (FALSE);

	env = getenv ("SOCKFD");
	if (!env) g_error ("SOCKFD environment not set.");
	sockfd = atoi (env);

	env = getenv ("SECURITY_POLICY");
	if (!env) g_error ("SECURITY_POLICY environment not set.");
	secpol = atoi (env);

	soup_ssl_proxy_set_security_policy (secpol);

	read_chan = g_io_channel_unix_new (STDIN_FILENO);
	write_chan = g_io_channel_unix_new (STDOUT_FILENO);

	/* Block on socket write */
	flags = fcntl(sockfd, F_GETFL, 0);
	fcntl (sockfd, F_SETFL, flags & ~O_NONBLOCK);

	/* Don't block on STDIN read */
	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl (STDIN_FILENO, F_SETFL, flags & O_NONBLOCK);

	sock_chan = g_io_channel_unix_new (sockfd);
	sock_chan = soup_ssl_proxy_get_iochannel (sock_chan);

	g_io_add_watch (read_chan, 
			G_IO_IN | G_IO_HUP | G_IO_ERR, 
			(GIOFunc) soup_ssl_proxy_readwrite,
			sock_chan);

	g_io_add_watch (sock_chan, 
			G_IO_IN | G_IO_HUP | G_IO_ERR, 
			(GIOFunc) soup_ssl_proxy_readwrite,
			write_chan);

	g_main_run (loop);

	exit (0);
}
