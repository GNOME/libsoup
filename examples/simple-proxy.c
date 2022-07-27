/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
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
	SoupServerMessage *msg;
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

	tunnel->client.iostream = soup_server_message_steal_connection (tunnel->msg);
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
                soup_server_message_set_status (tunnel->msg, SOUP_STATUS_BAD_GATEWAY, NULL);
		soup_server_message_set_response (tunnel->msg, "text/plain",
					          SOUP_MEMORY_COPY,
					          error->message, strlen (error->message));
		g_error_free (error);
		soup_server_message_unpause (tunnel->msg);
		tunnel_close (tunnel);
		return;
	}

	tunnel->server.istream = g_io_stream_get_input_stream (tunnel->server.iostream);
	tunnel->server.ostream = g_io_stream_get_output_stream (tunnel->server.iostream);

	soup_server_message_set_status (tunnel->msg, SOUP_STATUS_OK, NULL);
	soup_server_message_unpause (tunnel->msg);
	g_signal_connect (tunnel->msg, "finished",
			  G_CALLBACK (start_tunnel), tunnel);
}

static void
try_tunnel (SoupServer *server, SoupServerMessage *msg)
{
	Tunnel *tunnel;
	GUri *dest_uri;
	GSocketClient *sclient;

	soup_server_message_pause (msg);

	tunnel = g_new0 (Tunnel, 1);
	tunnel->self = g_object_ref (server);
	tunnel->msg = g_object_ref (msg);

	dest_uri = soup_server_message_get_uri (msg);
	sclient = g_socket_client_new ();
	g_socket_client_connect_to_host_async (sclient, g_uri_get_host (dest_uri), g_uri_get_port (dest_uri),
					       NULL, tunnel_connected_cb, tunnel);
	g_object_unref (sclient);
}

static void
copy_header (const char *name, const char *value, gpointer dest_headers)
{
	soup_message_headers_append (dest_headers, name, value);
}

static void
send_headers (SoupMessage *from, SoupServerMessage *to)
{
	g_print ("[%p] HTTP/1.%d %d %s\n", to,
		 soup_message_get_http_version (from),
		 soup_message_get_status (from), soup_message_get_reason_phrase (from));

        soup_server_message_set_status (to, soup_message_get_status (from), soup_message_get_reason_phrase (from));
	soup_message_headers_foreach (soup_message_get_response_headers (from), copy_header,
				      soup_server_message_get_response_headers (to));
	soup_message_headers_remove (soup_server_message_get_response_headers (to), "Content-Length");
	soup_server_message_unpause (to);
}

static void
client_msg_failed (SoupServerMessage *msg, gpointer user_data)
{
        g_print ("[%p]   cancelled\n\n", msg);
        g_cancellable_cancel (G_CANCELLABLE (user_data));
}

static void
stream_read (GObject *source, GAsyncResult *result, gpointer user_data)
{
        GInputStream *stream = G_INPUT_STREAM (source);
        SoupServerMessage *server_msg = SOUP_SERVER_MESSAGE (user_data);
        GError *error = NULL;
        GBytes *bytes = g_input_stream_read_bytes_finish (stream, result, &error);

        if (error) {
                g_print ("[%p]  failed to read body: %s\n\n", server_msg, error->message);
                soup_server_message_set_status (server_msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
                soup_server_message_unpause (server_msg);
                g_error_free (error);
                return;
        }

        if (g_bytes_get_size (bytes) == 0) {
                g_print ("[%p]   done\n\n", server_msg);
                GCancellable *client_cancellable = g_object_get_data (G_OBJECT (server_msg), "cancellable");
                g_assert (client_cancellable);
                g_signal_handlers_disconnect_by_func (server_msg, client_msg_failed, client_cancellable);

                soup_message_body_complete (soup_server_message_get_response_body (server_msg));
                soup_server_message_unpause (server_msg);
                g_object_unref (server_msg);
                return;
        }

	g_print ("[%p]   writing chunk of %lu bytes\n", server_msg,
		 (unsigned long)g_bytes_get_size (bytes));

        SoupMessageBody *body = soup_server_message_get_response_body (server_msg);
        soup_message_body_append_bytes (body, bytes);
        soup_server_message_unpause (server_msg);

        g_bytes_unref (bytes);

        g_input_stream_read_bytes_async (stream, BUFSIZE, G_PRIORITY_DEFAULT, NULL,
                                         stream_read, server_msg);
}

static void
client_message_sent (GObject *source, GAsyncResult *result, gpointer user_data)
{
        SoupSession *session = SOUP_SESSION (source);
        SoupServerMessage *server_msg = SOUP_SERVER_MESSAGE (user_data);
        GError *error = NULL;
        GInputStream *in_stream = soup_session_send_finish (session, result, &error);

        if (error) {
                g_print ("[%p]  failed to read body: %s\n\n", server_msg, error->message);
                soup_server_message_set_status (server_msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
                soup_server_message_unpause (server_msg);
                g_error_free (error);
                return;
        }

        g_input_stream_read_bytes_async (in_stream, BUFSIZE, G_PRIORITY_DEFAULT, NULL,
                                         stream_read, server_msg);
}

static void
server_callback (SoupServer *server, SoupServerMessage *msg,
		 const char *path, GHashTable *query,
		 gpointer data)
{
	SoupMessage *client_msg;
	char *uristr;

	uristr = g_uri_to_string (soup_server_message_get_uri (msg));
	g_print ("[%p] %s %s HTTP/1.%d\n", msg,
                 soup_server_message_get_method (msg), uristr,
		 soup_server_message_get_http_version (msg));

	if (soup_server_message_get_method (msg) == SOUP_METHOD_CONNECT) {
		try_tunnel (server, msg);
                g_free (uristr);
		return;
	}

        // Copy the servers message to a new client message
        client_msg = soup_message_new (soup_server_message_get_method (msg), uristr);
        g_assert (client_msg && SOUP_IS_MESSAGE (client_msg));
        SoupMessageHeaders *client_msg_headers = soup_message_get_request_headers (client_msg);
        SoupMessageHeaders *server_msg_headers = soup_server_message_get_request_headers (msg);
	soup_message_headers_foreach (server_msg_headers, copy_header, client_msg_headers);
	soup_message_headers_remove (client_msg_headers, "Host");
	soup_message_headers_remove (client_msg_headers, "Connection");

        g_free (uristr);

	if (soup_server_message_get_request_body (msg)->length) {
		GBytes *request = soup_message_body_flatten (soup_server_message_get_request_body (msg));
                const char *content_type = soup_message_headers_get_content_type (server_msg_headers, NULL);
                g_print ("[%p] Directly copying data of type %s\n", msg, content_type);
		soup_message_set_request_body_from_bytes (client_msg, content_type, request);
		g_bytes_unref (request);
	}
	soup_message_headers_set_encoding (soup_server_message_get_response_headers (msg),
					   SOUP_ENCODING_CHUNKED);

	g_signal_connect (client_msg, "got_headers", G_CALLBACK (send_headers), msg);

        GCancellable *client_cancellable = g_cancellable_new ();
	g_signal_connect (msg, "finished", G_CALLBACK (client_msg_failed), client_cancellable);
        g_object_set_data_full (G_OBJECT (msg), "cancellable", client_cancellable, g_object_unref);

        soup_session_send_async (session, client_msg, G_PRIORITY_DEFAULT, client_cancellable,
                                 client_message_sent, msg);

        g_object_unref (client_msg);

        // Keep the server message alive until the client one is finished
	g_object_ref (msg);
	soup_server_message_pause (msg);
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
			"realm", "simple-proxy",
			"proxy", TRUE,
			"auth-callback", auth_callback,
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
		str = g_uri_to_string (u->data);
		g_print ("Listening on %s\n", str);
		g_free (str);
		g_uri_unref (u->data);
	}
	g_slist_free (uris);

	session = soup_session_new ();

	g_print ("\nWaiting for requests...\n");

	loop = g_main_loop_new (NULL, TRUE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	return 0;
}
