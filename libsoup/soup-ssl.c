/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#include "soup-ssl.h"
#include "soup-nss.h"
#include "soup-misc.h"

#ifdef SOUP_WIN32

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	return NULL;
}

#else /* SOUP_WIN32 */
#ifdef HAVE_NSS

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	g_return_val_if_fail (sock != NULL, NULL);

	return soup_nss_get_iochannel (sock);
}

#else /* HAVE_NSS */

static gboolean
soup_ssl_hup_waitpid (GIOChannel *source, GIOCondition condition, gpointer ppid)
{
	waitpid (GPOINTER_TO_INT (ppid), NULL, 0);

	return FALSE;
}

GIOChannel *
soup_ssl_get_iochannel (GIOChannel *sock)
{
	GIOChannel *new_chan;
	int sock_fd;
	int pid;
	int pair[2], flags;

	g_return_val_if_fail (sock != NULL, NULL);

	g_io_channel_ref (sock);

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

		execl (BINDIR G_DIR_SEPARATOR_S SSL_PROXY_NAME,
		       BINDIR G_DIR_SEPARATOR_S SSL_PROXY_NAME,
		       NULL);

		execlp (SSL_PROXY_NAME, SSL_PROXY_NAME, NULL);

		g_error ("Error executing SSL Proxy\n");
	}

	close (pair [0]);

	flags = fcntl(pair [1], F_GETFL, 0);
	fcntl (pair [1], F_SETFL, flags | O_NONBLOCK);

	new_chan = g_io_channel_unix_new (pair [1]);
	g_io_add_watch (new_chan, G_IO_HUP,
			soup_ssl_hup_waitpid, GINT_TO_POINTER (pid));

	/* FIXME: Why is this needed?? */
	g_io_channel_ref (new_chan);
	return new_chan;

 ERROR:
	close (pair [0]);
	close (pair [1]);
 ERROR_ARGS:
	g_io_channel_unref (sock);
	return NULL;
}

#endif /* HAVE_NSS */
#endif /* SOUP_WIN32 */
