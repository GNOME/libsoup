/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 * Copyright 2012 Nokia Corporation
 */

#include <libsoup/soup.h>

#include <string.h>

#include "test-utils.h"

static void
do_unconnected_socket_test (void)
{
	SoupAddress *localhost;
	SoupSocket *sock;
	SoupSocket *client;
	SoupAddress *addr;
	guint res;
	struct sockaddr_in in_localhost;

	in_localhost.sin_family = AF_INET;
	in_localhost.sin_port = 0;
	in_localhost.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	localhost = soup_address_new_from_sockaddr (
		(struct sockaddr *) &in_localhost, sizeof (in_localhost));
	g_assert (localhost != NULL);
	res = soup_address_resolve_sync (localhost, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_OK);

	sock = soup_socket_new (
		SOUP_SOCKET_LOCAL_ADDRESS, localhost,
		NULL);
	g_assert (sock != NULL);

	addr = soup_socket_get_local_address (sock);
	g_assert (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), ==, 0);

	/* fails with ENOTCONN */
	expect_warning++;
	addr = soup_socket_get_remote_address (sock);
	g_assert (addr == NULL);

	res = soup_socket_listen (sock);
	g_assert_cmpuint (res, ==, TRUE);

	addr = soup_socket_get_local_address (sock);
	g_assert (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), >, 0);

	client = soup_socket_new (
		SOUP_SOCKET_REMOTE_ADDRESS,
			soup_socket_get_local_address (sock),
		NULL);
	res = soup_socket_connect_sync (client, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_OK);
	addr = soup_socket_get_local_address (client);
	g_assert (addr != NULL);
	addr = soup_socket_get_remote_address (client);
	g_assert (addr != NULL);
	g_assert_cmpstr (soup_address_get_physical (addr), ==, "127.0.0.1");
	g_assert_cmpuint (soup_address_get_port (addr), >, 0);
	g_object_unref (client);

	client = soup_socket_new (
		SOUP_SOCKET_REMOTE_ADDRESS,
			soup_socket_get_local_address (sock),
		NULL);
	/* save it for later */

	/* listening socket fails with ENOTCONN */
	expect_warning++;
	addr = soup_socket_get_remote_address (sock);
	g_assert (addr == NULL);

	soup_socket_disconnect (sock);

	expect_warning++;
	addr = soup_socket_get_remote_address (sock);
	g_assert (addr == NULL);

	/* has never been connected */
	expect_warning++;
	addr = soup_socket_get_local_address (client);
	g_assert (addr == NULL);

	res = soup_socket_connect_sync (client, NULL);
	g_assert_cmpuint (res, ==, SOUP_STATUS_CANT_CONNECT);

	expect_warning++;
	addr = soup_socket_get_local_address (client);
	g_assert (addr == NULL);

	g_object_unref (localhost);
	g_object_unref (client);
	g_object_unref (sock);
}

int
main (int argc, char **argv)
{
	test_init (argc, argv, NULL);

	do_unconnected_socket_test ();

	test_cleanup ();
	return errors != 0;
}
