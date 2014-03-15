/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 * Copyright 2012 Nokia Corporation
 */

#include "test-utils.h"

#include <gio/gnetworking.h>

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
			       "*endpoint is not connected*");
	addr = soup_socket_get_remote_address (sock);
	g_test_assert_expected_messages ();
	g_assert_null (addr);

	soup_socket_disconnect (sock);

	g_test_expect_message ("libsoup", G_LOG_LEVEL_WARNING,
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

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/sockets/unconnected", do_unconnected_socket_test);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
