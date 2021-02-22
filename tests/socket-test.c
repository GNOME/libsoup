/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 * Copyright 2012 Nokia Corporation
 */

#include "test-utils.h"
#include "libsoup/server/soup-socket.h"

#include <fcntl.h>
#include <gio/gnetworking.h>

#ifdef G_OS_WIN32
#include <io.h>
#endif

static void
assert_host_equals (GInetSocketAddress *addr, const char *host)
{
        char *addr_host = g_inet_address_to_string (g_inet_socket_address_get_address (addr));
        g_assert_cmpstr (addr_host, ==, host);
        g_free (addr_host);
}

static void
do_unconnected_socket_test (void)
{
	GInetSocketAddress *addr;
        GSocketAddress *localhost;
	SoupSocket *sock;
	GSocketClient *client;
	GSocketConnectable *remote_connectable;
	GSocketConnection *conn;
	GSocket *client_socket;
	guint res;

	g_test_bug ("673083");

        localhost = g_inet_socket_address_new_from_string ("127.0.0.1", 0);

	sock = soup_socket_new ("local-address", localhost,
				NULL);
	g_assert_true (sock != NULL);

	addr = soup_socket_get_local_address (sock);
	g_assert_true (addr != NULL);
	assert_host_equals (addr, "127.0.0.1");
	g_assert_cmpuint (g_inet_socket_address_get_port (addr), ==, 0);

	/* fails with ENOTCONN */
	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
			       "*socket not connected*");
	addr = soup_socket_get_remote_address (sock);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	res = soup_socket_listen (sock, NULL);
	g_assert_true (res);

	addr = soup_socket_get_local_address (sock);
	g_assert_true (addr != NULL);
	assert_host_equals (addr, "127.0.0.1");
	g_assert_cmpuint (g_inet_socket_address_get_port (addr), >, 0);

	client = g_socket_client_new ();
	remote_connectable = G_SOCKET_CONNECTABLE (soup_socket_get_local_address (sock));
	conn = g_socket_client_connect (client, remote_connectable, NULL, NULL);
	g_assert_true (conn != NULL);
	client_socket = g_socket_connection_get_socket (conn);
	g_assert_true (client_socket != NULL);
	addr = G_INET_SOCKET_ADDRESS (g_socket_get_local_address (client_socket, NULL));
	g_assert_true (addr != NULL);
	g_object_unref (addr);
	addr = G_INET_SOCKET_ADDRESS (g_socket_get_remote_address (client_socket, NULL));
	g_assert_true (addr != NULL);
	assert_host_equals (addr, "127.0.0.1");
	g_assert_cmpuint (g_inet_socket_address_get_port (addr), >, 0);
	g_object_unref (addr);
	g_object_unref (conn);
	g_object_unref (client);

	client = g_socket_client_new ();
	remote_connectable = G_SOCKET_CONNECTABLE (soup_socket_get_local_address (sock));
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

	conn = g_socket_client_connect (client, remote_connectable, NULL, NULL);
	g_assert_false (conn != NULL);

	g_object_unref (localhost);
	g_object_unref (client);
	g_object_unref (sock);
}

static int
socket_get_fd (SoupSocket *socket)
{
        return g_socket_get_fd (soup_socket_get_gsocket (socket));
}

static void
do_socket_from_fd_server_test (void)
{
	GSocket *gsock;
	SoupSocket *sock;
	GInetSocketAddress *local;
	GSocketAddress *gaddr;
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
			       "gsocket", gsock,
			       NULL);
	g_assert_no_error (error);
	g_assert_nonnull (sock);

	g_object_get (G_OBJECT (sock),
		      "local-address", &local,
		      NULL);
	g_assert_cmpint (socket_get_fd (sock), ==, g_socket_get_fd (gsock));
	g_assert_true (soup_socket_is_connected (sock));

	assert_host_equals (local, "127.0.0.1");
	g_assert_cmpint (g_inet_socket_address_get_port (local), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
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
	GInetSocketAddress *local, *remote;
	GSocketAddress *gaddr;
	GError *error = NULL;

	/* Importing an unconnected socket gives an error */
	gsock = g_socket_new (G_SOCKET_FAMILY_IPV4,
			      G_SOCKET_TYPE_STREAM,
			      G_SOCKET_PROTOCOL_DEFAULT,
			      &error);
	g_assert_no_error (error);
	g_assert_false (g_socket_is_connected (gsock));

	sock = g_initable_new (SOUP_TYPE_SOCKET, NULL, &error,
			       "gsocket", gsock,
			       NULL);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_FAILED);
	g_clear_error (&error);
	g_assert_null (sock);
	g_object_unref (gsock);

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
				"gsocket", gsock2,
				NULL);
	g_assert_no_error (error);
	g_assert_nonnull (sock2);

	g_object_get (G_OBJECT (sock2),
		      "local-address", &local,
		      "remote-address", &remote,
		      NULL);
	g_assert_cmpint (socket_get_fd (sock2), ==, g_socket_get_fd (gsock2));
	g_assert_true (soup_socket_is_connected (sock2));

	assert_host_equals (local, "127.0.0.1");
	g_assert_cmpint (g_inet_socket_address_get_port (local), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
	g_object_unref (gaddr);

	gaddr = g_socket_get_local_address (gsockcli, &error);
	g_assert_no_error (error);
	assert_host_equals (remote, "127.0.0.1");
	g_assert_cmpint (g_inet_socket_address_get_port (remote), ==, g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (gaddr)));
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
	g_test_add_func ("/sockets/from-fd/server", do_socket_from_fd_server_test);
	g_test_add_func ("/sockets/from-fd/bad", do_socket_from_fd_bad_test);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
