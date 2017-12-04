/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 * Copyright 2012 Nokia Corporation
 */

#include "test-utils.h"
#include "libsoup/soup-socket-private.h"

#include <fcntl.h>
#include <gio/gnetworking.h>

#ifdef G_OS_WIN32
#include <io.h>
#endif

static void
do_unconnected_socket_test (void)
{
	SoupAddress *localhost;
	SoupSocket *sock;
	SoupSocket *client;
	SoupAddress *addr;
	guint res;
	struct sockaddr_in in_localhost;

	g_test_bug ("673083");

	in_localhost.sin_family = AF_INET;
	in_localhost.sin_port = 0;
	in_localhost.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	localhost = soup_address_new_from_sockaddr (
		(struct sockaddr *) &in_localhost, sizeof (in_localhost));
	g_assert_true (localhost != NULL);
	res = soup_address_resolve_sync (localhost, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_OK);

	sock = soup_socket_new (SOUP_SOCKET_LOCAL_ADDRESS, localhost,
				NULL);
	g_assert_true (sock != NULL);

	addr = soup_socket_get_local_address (sock);
	g_assert_true (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), ==, 0);

	/* fails with ENOTCONN */
	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*socket not connected*");
	addr = soup_socket_get_remote_address (sock);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	res = soup_socket_listen (sock);
	g_assert_true (res);

	addr = soup_socket_get_local_address (sock);
	g_assert_true (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), >, 0);

	client = soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS,
				  soup_socket_get_local_address (sock),
				  NULL);
	res = soup_socket_connect_sync (client, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_OK);
	addr = soup_socket_get_local_address (client);
	g_assert_true (addr != NULL);
	addr = soup_socket_get_remote_address (client);
	g_assert_true (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), >, 0);
	g_object_unref (client);

	client = soup_socket_new (SOUP_SOCKET_REMOTE_ADDRESS,
				  soup_socket_get_local_address (sock),
				  NULL);
	/* save it for later */

	/* listening socket fails with ENOTCONN */
	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       /* We can't check the error message since it comes from
				* libc and is locale-dependent.
				*/
			       "*");
	addr = soup_socket_get_remote_address (sock);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	soup_socket_disconnect (sock);

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       /* This error message comes from soup-socket.c though */
			       "*socket not connected*");
	addr = soup_socket_get_remote_address (sock);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	/* has never been connected */
	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*socket not connected*");
	addr = soup_socket_get_local_address (client);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	res = soup_socket_connect_sync (client, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_CANT_CONNECT);

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*socket not connected*");
	addr = soup_socket_get_local_address (client);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	g_object_unref (localhost);
	g_object_unref (client);
	g_object_unref (sock);
}

static void
do_socket_from_fd_client_test (void)
{
	SoupServer *server;
	SoupURI *uri;
	GSocket *gsock;
	SoupSocket *sock;
	SoupAddress *local, *remote;
	GSocketAddress *gaddr;
	gboolean is_server;
	GError *error = NULL;

	server = soup_test_server_new (SOUP_TEST_SERVER_DEFAULT);
	uri = soup_test_server_get_uri (server, "http", "127.0.0.1");

	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);

	gaddr = g_inet_socket_address_new_from_string ("127.0.0.1", uri->port);
	g_socket_connect (gsock, gaddr, NULL, &error);
	g_object_unref (gaddr);
	g_assert_no_error (error);
	g_assert_true (g_socket_is_connected (gsock));

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
			       SOUP_SOCKET_FD, g_socket_get_fd (gsock),
			       NULL);
	g_assert_no_error (error);
	g_assert_nonnull (sock);

	g_object_get (G_OBJECT (sock),
		      SOUP_SOCKET_LOCAL_ADDRESS, &local,
		      SOUP_SOCKET_REMOTE_ADDRESS, &remote,
		      SOUP_SOCKET_IS_SERVER, &is_server,
		      NULL);
	g_assert_cmpint (soup_socket_get_fd (sock), ==, g_socket_get_fd (gsock));
	g_assert_false (is_server);
	g_assert_true (soup_socket_is_connected (sock));

	g_assert_cmpstr (soup_address_get_physical (local), ==, "127.0.0.1");
	g_assert_cmpint (soup_address_get_port (local), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
	g_assert_cmpstr (soup_address_get_physical (remote), ==, "127.0.0.1");
	g_assert_cmpint (soup_address_get_port (remote), ==, uri->port);

	g_object_unref (local);
	g_object_unref (remote);
	g_object_unref (gaddr);

	g_object_unref (sock);
	g_object_unref (gsock);

	soup_test_server_quit_unref (server);
	soup_uri_free (uri);
}

static void
do_socket_from_fd_server_test (void)
{
	GSocket *gsock;
	SoupSocket *sock;
	SoupAddress *local;
	GSocketAddress *gaddr;
	gboolean is_server;
	GError *error = NULL;

	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);

	gaddr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_socket_bind (gsock, gaddr, TRUE, &error);
	g_object_unref (gaddr);
	g_assert_no_error (error);
	g_socket_listen (gsock, &error);
	g_assert_no_error (error);
	g_assert_false (g_socket_is_connected (gsock));

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
			       SOUP_SOCKET_GSOCKET, gsock,
			       NULL);
	g_assert_no_error (error);
	g_assert_nonnull (sock);

	g_object_get (G_OBJECT (sock),
		      SOUP_SOCKET_LOCAL_ADDRESS, &local,
		      SOUP_SOCKET_IS_SERVER, &is_server,
		      NULL);
	g_assert_cmpint (soup_socket_get_fd (sock), ==, g_socket_get_fd (gsock));
	g_assert_true (is_server);
	g_assert_true (soup_socket_is_connected (sock));

	g_assert_cmpstr (soup_address_get_physical (local), ==, "127.0.0.1");
	g_assert_cmpint (soup_address_get_port (local), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
	g_object_unref (local);
	g_object_unref (gaddr);

	g_object_unref (sock);

	/* Closing the SoupSocket should have closed the GSocket */
	g_assert_true (g_socket_is_closed (gsock));

	g_object_unref (gsock);
}

static void
do_socket_from_fd_bad_test (void)
{
	GSocket *gsock, *gsock2, *gsockcli;
	SoupSocket *sock, *sock2;
	SoupAddress *local, *remote;
	GSocketAddress *gaddr;
	gboolean is_server;
	int fd;
	GError *error = NULL;

	/* Importing a non-socket fd gives an error */
	fd = open (g_test_get_filename (G_TEST_DIST, "test-cert.pem", NULL), O_RDONLY);
	g_assert_cmpint (fd, !=, -1);

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
			       SOUP_SOCKET_FD, fd,
			       NULL);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_clear_error (&error);
	g_assert_null (sock);
	close (fd);

	/* Importing an unconnected socket gives an error */
	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);
	g_assert_false (g_socket_is_connected (gsock));

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
			       SOUP_SOCKET_FD, g_socket_get_fd (gsock),
			       NULL);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_clear_error (&error);
	g_assert_null (sock);
	g_object_unref (gsock);

	/* Importing a non-listening server-side socket works, but
	 * gives the wrong answer for soup_socket_is_server().
	 */
	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);

	gaddr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);
	g_socket_bind (gsock, gaddr, TRUE, &error);
	g_object_unref (gaddr);
	g_assert_no_error (error);
	g_socket_listen (gsock, &error);
	g_assert_no_error (error);
	g_assert_false (g_socket_is_connected (gsock));

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);

	gsockcli = g_socket_new (G_SOCKET_FAMILY_IPV4,
				 G_SOCKET_TYPE_STREAM,
				 G_SOCKET_PROTOCOL_DEFAULT,
				 &error);
	g_assert_no_error (error);

	g_socket_connect (gsockcli, gaddr, NULL, &error);
	g_assert_no_error (error);
	g_assert_true (g_socket_is_connected (gsockcli));
	
	gsock2 = g_socket_accept (gsock, NULL, &error);
	g_assert_no_error (error);
	g_assert_nonnull (gsock2);

	sock2 = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
				SOUP_SOCKET_GSOCKET, gsock2,
				NULL);
	g_assert_no_error (error);
	g_assert_nonnull (sock2);

	g_object_get (G_OBJECT (sock2),
		      SOUP_SOCKET_LOCAL_ADDRESS, &local,
		      SOUP_SOCKET_REMOTE_ADDRESS, &remote,
		      SOUP_SOCKET_IS_SERVER, &is_server,
		      NULL);
	g_assert_cmpint (soup_socket_get_fd (sock2), ==, g_socket_get_fd (gsock2));
	g_assert_true (soup_socket_is_connected (sock2));
	/* This is wrong, but can't be helped. */
	g_assert_false (is_server);

	g_assert_cmpstr (soup_address_get_physical (local), ==, "127.0.0.1");
	g_assert_cmpint (soup_address_get_port (local), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
	g_object_unref (gaddr);

	gaddr = g_socket_get_local_address (gsockcli, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (soup_address_get_physical (remote), ==, "127.0.0.1");
	g_assert_cmpint (soup_address_get_port (remote), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
	g_object_unref (gaddr);

	g_object_unref (local);
	g_object_unref (remote);

	g_object_unref (sock2);

	g_object_unref (gsock);
	g_object_unref (gsock2);
	g_object_unref (gsockcli);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/sockets/unconnected", do_unconnected_socket_test);
	g_test_add_func ("/sockets/from-fd/client", do_socket_from_fd_client_test);
	g_test_add_func ("/sockets/from-fd/server", do_socket_from_fd_server_test);
	g_test_add_func ("/sockets/from-fd/bad", do_socket_from_fd_bad_test);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
