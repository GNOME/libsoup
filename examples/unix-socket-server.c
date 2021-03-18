/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Canonical Ltd.
 */

#include <libsoup/soup.h>
#include <glib/gstdio.h>

#include <gio/gunixsocketaddress.h>

#define SOCKET_PATH "/tmp/libsoup-unix-server"

static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg,
                 const char        *path,
                 GHashTable        *query,
                 gpointer           data)
{
        const char *method;

        method = soup_server_message_get_method (msg);
        if (method != SOUP_METHOD_GET) {
                soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
                return;
        }

        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_server_message_set_response (msg, "text/plain",
                                          SOUP_MEMORY_STATIC, "Hello World!", 12);
}

int
main (int argc, char **argv)
{
	GSocket *listen_socket;
	GSocketAddress *listen_address;
	SoupServer *server;
	GMainLoop *loop;
	GError *error = NULL;

	/* Remove an existing socket */
	g_unlink (SOCKET_PATH);

	/* Create a server that uses a unix socket */
	listen_socket = g_socket_new (G_SOCKET_FAMILY_UNIX,
				      G_SOCKET_TYPE_STREAM,
				      G_SOCKET_PROTOCOL_DEFAULT,
				      &error);
	if (listen_socket == NULL) {
		g_printerr ("Unable to create unix socket: %s\n", error->message);
		return 1;
	}
	listen_address = g_unix_socket_address_new (SOCKET_PATH);
	if (!g_socket_bind (listen_socket, listen_address, TRUE, &error)) {
		g_printerr ("Unable to bind unix socket to %s: %s\n", SOCKET_PATH, error->message);
		return 1;
	}
	g_object_unref (listen_address);
	if (!g_socket_listen (listen_socket, &error)) {
		g_printerr ("Unable to listen on unix socket: %s\n", error->message);
		return 1;
	}
	server = soup_server_new ("server-header", "unix-socket-server", NULL);
        soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	if (!soup_server_listen_socket (server, listen_socket, 0, &error)) {
		g_printerr ("Unable to listen on unix socket: %s\n", error->message);
		return 1;
	}
	g_object_unref (listen_socket);

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);

	g_object_unref (server);

	return 0;
}
