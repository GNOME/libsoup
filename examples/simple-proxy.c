/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#include <stdlib.h>
#include <string.h>

#include <libsoup/soup.h>

/* WARNING: this is really really really not especially compliant with
 * RFC 2616. But it does work for basic stuff.
 */

static SoupSession *session;
static SoupServer *server;

typedef struct {
	GIOStream *iostream;
	GInputStream *istream;
	GOutputStream *ostream;

	gssize nread, nwrote;
	guchar *buffer;
} TunnelEnd;

typedef struct {
	SoupServer *self;
	SoupMessage *msg;
	SoupClientContext *context;
	GCancellable *cancellable;

	TunnelEnd client, server;
} Tunnel;

#define BUFSIZE 8192

static void tunnel_read_cb (GObject      *object,
			    GAsyncResult *result,
			    gpointer      user_data);

static void
tunnel_close (Tunnel *tunnel)
{
	if (tunnel->cancellable) {
		g_cancellable_cancel (tunnel->cancellable);
		g_object_unref (tunnel->cancellable);
	}

	if (tunnel->client.iostream) {
		g_io_stream_close (tunnel->client.iostream, NULL, NULL);
		g_object_unref (tunnel->client.iostream);
	}
	if (tunnel->server.iostream) {
		g_io_stream_close (tunnel->server.iostream, NULL, NULL);
		g_object_unref (tunnel->server.iostream);
	}

	g_free (tunnel->client.buffer);
	g_free (tunnel->server.buffer);

	g_object_unref (tunnel->self);
	g_object_unref (tunnel->msg);

	g_free (tunnel);
}

static void
tunnel_wrote_cb (GObject      *object,
		 GAsyncResult *result,
		 gpointer      user_data)
{
	Tunnel *tunnel = user_data;
	TunnelEnd *write_end, *read_end;
	GError *error = NULL;
	gssize nwrote;

	nwrote = g_output_stream_write_finish (G_OUTPUT_STREAM (object), result, &error);
	if (nwrote <= 0) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			g_error_free (error);
			return;
		} else if (error) {
			g_print ("Tunnel write failed: %s\n", error->message);
			g_error_free (error);
		}
		tunnel_close (tunnel);
		return;
	}

	if (object == (GObject *)tunnel->client.ostream) {
		write_end = &tunnel->client;
		read_end = &tunnel->server;
	} else {
		write_end = &tunnel->server;
		read_end = &tunnel->client;
	}

	write_end->nwrote += nwrote;
	if (write_end->nwrote < read_end->nread) {
		g_output_stream_write_async (write_end->ostream,
					     read_end->buffer + write_end->nwrote,
					     read_end->nread - write_end->nwrote,
					     G_PRIORITY_DEFAULT, tunnel->cancellable,
					     tunnel_wrote_cb, tunnel);
	} else {
		g_input_stream_read_async (read_end->istream,
					   read_end->buffer, BUFSIZE,
					   G_PRIORITY_DEFAULT, tunnel->cancellable,
					   tunnel_read_cb, tunnel);
	}
}

static void
tunnel_read_cb (GObject      *object,
		GAsyncResult *result,
		gpointer      user_data)
{
	Tunnel *tunnel = user_data;
	TunnelEnd *read_end, *write_end;
	GError *error = NULL;
	gssize nread;

	nread = g_input_stream_read_finish (G_INPUT_STREAM (object), result, &error);
	if (nread <= 0) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			g_error_free (error);
			return;
		} else if (error) {
			g_print ("Tunnel read failed: %s\n", error->message);
			g_error_free (error);
		}
		tunnel_close (tunnel);
		return;
	}

	if (object == (GObject *)tunnel->client.istream) {
		read_end = &tunnel->client;
		write_end = &tunnel->server;
	} else {
		read_end = &tunnel->server;
		write_end = &tunnel->client;
	}

	read_end->nread = nread;
	write_end->nwrote = 0;
	g_output_stream_write_async (write_end->ostream,
				     read_end->buffer, read_end->nread,
				     G_PRIORITY_DEFAULT, tunnel->cancellable,
				     tunnel_wrote_cb, tunnel);
}

static void
start_tunnel (SoupMessage *msg, gpointer user_data)
{
	Tunnel *tunnel = user_data;

	tunnel->client.iostream = soup_client_context_steal_connection (tunnel->context);
	tunnel->client.istream = g_io_stream_get_input_stream (tunnel->client.iostream);
	tunnel->client.ostream = g_io_stream_get_output_stream (tunnel->client.iostream);

	tunnel->client.buffer = g_malloc (BUFSIZE);
	tunnel->server.buffer = g_malloc (BUFSIZE);

	tunnel->cancellable = g_cancellable_new ();

	g_input_stream_read_async (tunnel->client.istream,
				   tunnel->client.buffer, BUFSIZE,
				   G_PRIORITY_DEFAULT, tunnel->cancellable,
				   tunnel_read_cb, tunnel);
	g_input_stream_read_async (tunnel->server.istream,
				   tunnel->server.buffer, BUFSIZE,
				   G_PRIORITY_DEFAULT, tunnel->cancellable,
				   tunnel_read_cb, tunnel);
}


static void
tunnel_connected_cb (GObject      *object,
		     GAsyncResult *result,
		     gpointer      user_data)
{
	Tunnel *tunnel = user_data;
	GError *error = NULL;

	tunnel->server.iostream = (GIOStream *)
		g_socket_client_connect_to_host_finish (G_SOCKET_CLIENT (object), result, &error);
	if (!tunnel->server.iostream) {
		soup_message_set_status (tunnel->msg, SOUP_STATUS_BAD_GATEWAY);
		soup_message_set_response (tunnel->msg, "text/plain",
					   SOUP_MEMORY_COPY,
					   error->message, strlen (error->message));
		g_error_free (error);
		soup_server_unpause_message (tunnel->self, tunnel->msg);
		tunnel_close (tunnel);
		return;
	}

	tunnel->server.istream = g_io_stream_get_input_stream (tunnel->server.iostream);
	tunnel->server.ostream = g_io_stream_get_output_stream (tunnel->server.iostream);

	soup_message_set_status (tunnel->msg, SOUP_STATUS_OK);
	soup_server_unpause_message (tunnel->self, tunnel->msg);
	g_signal_connect (tunnel->msg, "finished",
			  G_CALLBACK (start_tunnel), tunnel);
}

static void
try_tunnel (SoupServer *server, SoupMessage *msg, SoupClientContext *context)
{
	Tunnel *tunnel;
	SoupURI *dest_uri;
	GSocketClient *sclient;

	soup_server_pause_message (server, msg);

	tunnel = g_new0 (Tunnel, 1);
	tunnel->self = g_object_ref (server);
	tunnel->msg = g_object_ref (msg);
	tunnel->context = context;

	dest_uri = soup_message_get_uri (msg);
	sclient = g_socket_client_new ();
	g_socket_client_connect_to_host_async (sclient, dest_uri->host, dest_uri->port,
					       NULL, tunnel_connected_cb, tunnel);
	g_object_unref (sclient);
}

static void
copy_header (const char *name, const char *value, gpointer dest_headers)
{
	soup_message_headers_append (dest_headers, name, value);
}

static void
send_headers (SoupMessage *from, SoupMessage *to)
{
	g_print ("[%p] HTTP/1.%d %d %s\n", to,
		 soup_message_get_http_version (from),
		 from->status_code, from->reason_phrase);

	soup_message_set_status_full (to, from->status_code,
				      from->reason_phrase);
	soup_message_headers_foreach (from->response_headers, copy_header,
				      to->response_headers);
	soup_message_headers_remove (to->response_headers, "Content-Length");
	soup_server_unpause_message (server, to);
}

static void
send_chunk (SoupMessage *from, SoupBuffer *chunk, SoupMessage *to)
{
	g_print ("[%p]   writing chunk of %lu bytes\n", to,
		 (unsigned long)chunk->length);

	soup_message_body_append_buffer (to->response_body, chunk);
	soup_server_unpause_message (server, to);
}

static void
client_msg_failed (SoupMessage *msg, gpointer msg2)
{
	soup_session_cancel_message (session, msg2, SOUP_STATUS_IO_ERROR);
}

static void
finish_msg (SoupSession *session, SoupMessage *msg2, gpointer data)
{
	SoupMessage *msg = data;

	g_print ("[%p]   done\n\n", msg);
	g_signal_handlers_disconnect_by_func (msg, client_msg_failed, msg2);

	soup_message_body_complete (msg->response_body);
	soup_server_unpause_message (server, msg);
	g_object_unref (msg);
}

static void
server_callback (SoupServer *server, SoupMessage *msg,
		 const char *path, GHashTable *query,
		 SoupClientContext *context, gpointer data)
{
	SoupMessage *msg2;
	char *uristr;

	uristr = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
	g_print ("[%p] %s %s HTTP/1.%d\n", msg, msg->method, uristr,
		 soup_message_get_http_version (msg));

	if (msg->method == SOUP_METHOD_CONNECT) {
		try_tunnel (server, msg, context);
		return;
	}

        msg2 = soup_message_new (msg->method, uristr);
	soup_message_headers_foreach (msg->request_headers, copy_header,
				      msg2->request_headers);
	soup_message_headers_remove (msg2->request_headers, "Host");
	soup_message_headers_remove (msg2->request_headers, "Connection");

	if (msg->request_body->length) {
		SoupBuffer *request = soup_message_body_flatten (msg->request_body);
		soup_message_body_append_buffer (msg2->request_body, request);
		soup_buffer_free (request);
	}
	soup_message_headers_set_encoding (msg->response_headers,
					   SOUP_ENCODING_CHUNKED);

	g_signal_connect (msg2, "got_headers",
			  G_CALLBACK (send_headers), msg);
	g_signal_connect (msg2, "got_chunk",
			  G_CALLBACK (send_chunk), msg);

	g_signal_connect (msg, "finished", G_CALLBACK (client_msg_failed), msg2);

	soup_session_queue_message (session, msg2, finish_msg, msg);

	g_object_ref (msg);
	soup_server_pause_message (server, msg);
}

static gboolean
auth_callback (SoupAuthDomain *auth_domain, SoupMessage *msg,
	       const char *username, const char *password, gpointer data)
{
	return !strcmp (username, "user") && !strcmp (password, "password");
}

static void
quit (int sig)
{
	/* Exit cleanly on ^C in case we're valgrinding. */
	exit (0);
}

static int port;
static gboolean require_auth;

static GOptionEntry entries[] = {
	{ "auth-domain", 'a', 0,
	  G_OPTION_ARG_NONE, &require_auth,
	  "Require authentication", NULL },
	{ "port", 'p', 0,
	  G_OPTION_ARG_INT, &port,
	  "Port to listen on", NULL },
	{ NULL }
};

int
main (int argc, char **argv)
{
	GOptionContext *opts;
	GMainLoop *loop;
	GSList *uris, *u;
	char *str;
	GError *error = NULL;

	opts = g_option_context_new (NULL);
	g_option_context_add_main_entries (opts, entries, NULL);
	if (!g_option_context_parse (opts, &argc, &argv, &error)) {
		g_printerr ("Could not parse arguments: %s\n",
			    error->message);
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}

	if (argc != 1) {
		g_printerr ("%s",
			    g_option_context_get_help (opts, TRUE, NULL));
		exit (1);
	}
	g_option_context_free (opts);

	signal (SIGINT, quit);

	server = g_object_new (SOUP_TYPE_SERVER, NULL);
	soup_server_add_handler (server, NULL,
				 server_callback, NULL, NULL);
	if (require_auth) {
		SoupAuthDomain *auth_domain;

		auth_domain = soup_auth_domain_basic_new (
			SOUP_AUTH_DOMAIN_REALM, "simple-proxy",
			SOUP_AUTH_DOMAIN_PROXY, TRUE,
			SOUP_AUTH_DOMAIN_BASIC_AUTH_CALLBACK, auth_callback,
			NULL);
		soup_server_add_auth_domain (server, auth_domain);
		g_object_unref (auth_domain);
	}

	soup_server_listen_all (server, port, 0, &error);
	if (error) {
		g_printerr ("Unable to create server: %s\n", error->message);
		exit (1);
	}

	uris = soup_server_get_uris (server);
	for (u = uris; u; u = u->next) {
		str = soup_uri_to_string (u->data, FALSE);
		g_print ("Listening on %s\n", str);
		g_free (str);
		soup_uri_free (u->data);
	}
	g_slist_free (uris);

	session = soup_session_new ();

	g_print ("\nWaiting for requests...\n");

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
