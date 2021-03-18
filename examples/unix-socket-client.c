/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Canonical Ltd.
 */

#include <libsoup/soup.h>

#include <gio/gunixsocketaddress.h>

int
main (int argc, char **argv)
{
	SoupSession *session;
	GSocketAddress *address;
	SoupMessage *msg;
	GBytes *body;
	const char *content_type;
	char *text;
	GError *error = NULL;

	/* Create a session that uses a unix socket */
	address = g_unix_socket_address_new ("/tmp/libsoup-unix-server");
	session = soup_session_new_with_options ("remote-connectable", address, NULL);
	g_object_unref (address);

	/* Do a GET across the unix socket */
	msg = soup_message_new (SOUP_METHOD_GET, "http://locahost");
	body = soup_session_send_and_read (session, msg, NULL, &error);
	if (body == NULL) {
		g_printerr ("Failed to contact HTTP server: %s\n", error->message);
		return 1;
	}
	content_type = soup_message_headers_get_one (soup_message_get_response_headers (msg), "Content-Type");
	if (g_strcmp0 (content_type, "text/plain") != 0) {
		g_printerr ("Server returned unexpected content-type: %s\n", content_type);
		return 1;
	}
	text = g_strndup (g_bytes_get_data (body, NULL), g_bytes_get_size (body));
	g_printerr ("%s\n", text);

	g_object_unref (msg);
	g_bytes_unref (body);
	g_object_unref (session);

	return 0;
}
