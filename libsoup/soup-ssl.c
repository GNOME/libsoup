/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001-2002, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include "soup-ssl.h"
#include "soup-nss.h"
#include "soup-misc.h"

#ifdef HAVE_NSS

GIOChannel *
soup_ssl_get_iochannel_real (GIOChannel *sock, SoupSSLType type)
{
	g_return_val_if_fail (sock != NULL, NULL);

	return soup_nss_get_iochannel (sock, type);
}

#else /* HAVE_NSS */

typedef struct {
	int ppid;
	GIOChannel *real_sock;
} SoupSSLInfo;

static gboolean
soup_ssl_hup_waitpid (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	SoupSSLInfo *ssl_info = user_data;

	waitpid (ssl_info->ppid, NULL, 0);
	
	/*
	 * FIXME: The refcounting for these iochannels is totally
	 * broken.  If we have this unref below, it causes crashes
	 * when using HTTPS with a proxy.  Sigh.  It's better to
	 * just leak.
	 */
	/* g_io_channel_unref (ssl_info->real_sock); */
	g_free (ssl_info);

	return FALSE;
}

static GIOChannel *
soup_ssl_get_iochannel_real (GIOChannel *sock, SoupSSLType type)
{
	GIOChannel *new_chan;
	int sock_fd;
	int pid;
	int pair[2], flags;
	const char *cert_file, *key_file;
	SoupSSLInfo *ssl_info;

	g_return_val_if_fail (sock != NULL, NULL);

	if (!(sock_fd = g_io_channel_unix_get_fd (sock))) goto ERROR_ARGS;
	flags = fcntl(sock_fd, F_GETFD, 0);
	fcntl (sock_fd, F_SETFD, flags & ~FD_CLOEXEC);

	if (socketpair (PF_UNIX, SOCK_STREAM, 0, pair) != 0) goto ERROR_ARGS;

	fflush (stdin);
	fflush (stdout);

	pid = fork ();

	switch (pid) {
	case -1:
		goto ERROR;
	case 0:
		close (pair [1]);

		dup2 (pair [0], STDIN_FILENO);
		dup2 (pair [0], STDOUT_FILENO);

		close (pair [0]);

		putenv (g_strdup_printf ("SOCKFD=%d", sock_fd));
		putenv (g_strdup_printf ("SECURITY_POLICY=%d",
					 soup_get_security_policy ()));

		if (type == SOUP_SSL_TYPE_SERVER)
			putenv ("IS_SERVER=1");

		if (soup_get_ssl_ca_file ()) {
			putenv (g_strdup_printf ("HTTPS_CA_FILE=%s",
						 soup_get_ssl_ca_file ()));
		}

		if (soup_get_ssl_ca_dir ()) {
			putenv (g_strdup_printf ("HTTPS_CA_DIR=%s",
						 soup_get_ssl_ca_dir ()));
		}

		soup_get_ssl_cert_files (&cert_file, &key_file);

		if (cert_file) {
			putenv (g_strdup_printf ("HTTPS_CERT_FILE=%s",
						 cert_file));
		}
		
		if (key_file) {
			putenv (g_strdup_printf ("HTTPS_KEY_FILE=%s",
						 key_file));
		}

		execl (LIBEXECDIR G_DIR_SEPARATOR_S SSL_PROXY_NAME,
		       LIBEXECDIR G_DIR_SEPARATOR_S SSL_PROXY_NAME,
		       NULL);

		execlp (SSL_PROXY_NAME, SSL_PROXY_NAME, NULL);

		g_error ("Error executing SSL Proxy\n");
	}

	close (pair [0]);

	flags = fcntl(pair [1], F_GETFL, 0);
	fcntl (pair [1], F_SETFL, flags | O_NONBLOCK);

	ssl_info = g_new0 (SoupSSLInfo, 1);
	ssl_info->ppid = pid;
	ssl_info->real_sock = sock;

	new_chan = g_io_channel_unix_new (pair [1]);
	g_io_channel_set_close_on_unref (new_chan, TRUE);
	g_io_add_watch (new_chan, G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			soup_ssl_hup_waitpid, ssl_info);

	return new_chan;

 ERROR:
	close (pair [0]);
	close (pair [1]);
 ERROR_ARGS:
	g_io_channel_unref (sock);
	return NULL;
}

#endif /* HAVE_NSS */

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	return soup_ssl_get_iochannel_real (sock, SOUP_SSL_TYPE_CLIENT);
}

GIOChannel *
soup_ssl_get_server_iochannel (GIOChannel *sock)
{
	return soup_ssl_get_iochannel_real (sock, SOUP_SSL_TYPE_SERVER);
}
