/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2007-2012 Red Hat, Inc.
 */

#include "test-utils.h"
#include "soup-message-private.h"
#include "soup-uri-utils-private.h"
#include "soup-server-private.h"
#include "soup-misc.h"

#include <gio/gnetworking.h>

typedef struct {
	SoupServer *server;
	GUri *base_uri, *ssl_base_uri;
	GSList *handlers;
} ServerData;

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *method;

	soup_message_headers_append (soup_server_message_get_response_headers (msg),
				     "X-Handled-By", "server_callback");

	if (!strcmp (path, "*")) {
		soup_test_assert (FALSE, "default server_callback got request for '*'");
		soup_server_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return;
	}

	method = soup_server_message_get_method (msg);
	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_POST) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_STATIC, "index", 5);
}

static void
server_setup_nohandler (ServerData *sd, gconstpointer test_data)
{
	sd->server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	sd->base_uri = soup_test_server_get_uri (sd->server, "http", NULL);
	if (tls_available)
		sd->ssl_base_uri = soup_test_server_get_uri (sd->server, "https", NULL);
}

static void
server_add_handler (ServerData         *sd,
		    const char         *path,
		    SoupServerCallback  callback,
		    gpointer            user_data,
		    GDestroyNotify      destroy)
{
	soup_server_add_handler (sd->server, path, callback, user_data, destroy);
	sd->handlers = g_slist_prepend (sd->handlers, g_strdup (path));
}

static void
server_add_early_handler (ServerData         *sd,
			  const char         *path,
			  SoupServerCallback  callback,
			  gpointer            user_data,
			  GDestroyNotify      destroy)
{
	soup_server_add_early_handler (sd->server, path, callback, user_data, destroy);
	sd->handlers = g_slist_prepend (sd->handlers, g_strdup (path));
}

static void
server_setup (ServerData *sd, gconstpointer test_data)
{
	server_setup_nohandler (sd, test_data);
	server_add_handler (sd, NULL, server_callback, NULL, NULL);
}

static void
server_teardown (ServerData *sd, gconstpointer test_data)
{
	GSList *iter;

	for (iter = sd->handlers; iter; iter = iter->next)
		soup_server_remove_handler (sd->server, iter->data);
	g_slist_free_full (sd->handlers, g_free);

	g_clear_pointer (&sd->server, soup_test_server_quit_unref);
	g_clear_pointer (&sd->base_uri, g_uri_unref);
	g_clear_pointer (&sd->ssl_base_uri, g_uri_unref);
}

static void
server_star_callback (SoupServer        *server,
		      SoupServerMessage *msg,
		      const char        *path,
		      GHashTable        *query,
		      gpointer           data)
{
	soup_message_headers_append (soup_server_message_get_response_headers (msg),
				     "X-Handled-By", "star_callback");

	if (strcmp (path, "*") != 0) {
		soup_test_assert (FALSE, "server_star_callback got request for '%s'", path);
		soup_server_message_set_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR, NULL);
		return;
	}

	if (soup_server_message_get_method (msg) != SOUP_METHOD_OPTIONS) {
		soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

/* Server handlers for "*" work but are separate from handlers for
 * all other URIs. #590751
 */
static void
do_star_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;

	g_test_bug ("590751");

	session = soup_test_session_new (NULL);

	debug_printf (1, "  Testing with no handler\n");
	msg = soup_message_new_options_ping (sd->base_uri);
        g_assert_true (soup_message_get_is_options_ping (msg));
	soup_test_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_NOT_FOUND);
	soup_test_assert_handled_by (msg, NULL);
	g_object_unref (msg);

	server_add_handler (sd, "*", server_star_callback, NULL, NULL);

	debug_printf (1, "  Testing with handler\n");
        msg = soup_message_new_from_uri ("GET", sd->base_uri);
        g_assert_false (soup_message_get_is_options_ping (msg));
        soup_message_set_is_options_ping (msg, TRUE);
        g_assert_true (soup_message_get_is_options_ping (msg));
	soup_test_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	soup_test_assert_handled_by (msg, "star_callback");
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
do_dot_dot_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;

	g_test_bug ("667635");

	session = soup_test_session_new (NULL);

	uri = g_uri_parse_relative (sd->base_uri, "/..%2ftest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "/%2e%2e%2ftest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

#ifdef G_OS_WIN32
	uri = g_uri_parse_relative (sd->base_uri, "\\..%5Ctest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "\\../test", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "%5C..%2ftest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "/..\\test", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "%2f..%5Ctest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "\\%2e%2e%5ctest", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	uri = g_uri_parse_relative (sd->base_uri, "\\..%%35%63..%%35%63test", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);
#endif

	soup_test_session_abort_unref (session);
}

static void
do_invalid_percent_encoding_paths_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;

	g_test_bug ("https://gitlab.gnome.org/GNOME/libsoup/-/issues/262");

	session = soup_test_session_new (NULL);

	uri = g_uri_parse_relative (sd->base_uri, "/TestString1%00%0aTestString2", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_BAD_REQUEST);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
ipv6_server_callback (SoupServer        *server,
		      SoupServerMessage *msg,
		      const char        *path,
		      GHashTable        *query,
		      gpointer           data)
{
	const char *host;
	GSocketAddress *addr;
	char expected_host[128];

	addr = soup_server_message_get_local_address (msg);
	g_snprintf (expected_host, sizeof (expected_host),
		    "[::1]:%d",
		    g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (addr)));

	host = soup_message_headers_get_one (soup_server_message_get_request_headers (msg), "Host");
	g_assert_cmpstr (host, ==, expected_host);

	if (g_test_failed ())
		soup_server_message_set_status (msg, SOUP_STATUS_BAD_REQUEST, NULL);
	else
		soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

static void
do_ipv6_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	GError *error = NULL;

	g_test_bug ("666399");

        SOUP_TEST_SKIP_IF_NO_IPV6;

	sd->server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	server_add_handler (sd, NULL, ipv6_server_callback, NULL, NULL);

	soup_server_listen_local (sd->server, 0, SOUP_SERVER_LISTEN_IPV6_ONLY, &error);
        g_assert_no_error (error);

	sd->base_uri = soup_test_server_get_uri (sd->server, "http", "::1");

	session = soup_test_session_new (NULL);

	debug_printf (1, "  HTTP/1.1\n");
	msg = soup_message_new_from_uri ("GET", sd->base_uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);

	debug_printf (1, "  HTTP/1.0\n");
	msg = soup_message_new_from_uri ("GET", sd->base_uri);
	soup_message_set_http_version (msg, SOUP_HTTP_1_0);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);
}

static void
multi_server_callback (SoupServer        *server,
		       SoupServerMessage *msg,
		       const char        *path,
		       GHashTable        *query,
		       gpointer           data)
{
	GSocketAddress *addr;
	GInetSocketAddress *iaddr;
	GUri *uri;
	char *uristr, *addrstr;

	addr = soup_server_message_get_local_address (msg);
	iaddr = G_INET_SOCKET_ADDRESS (addr);

	uri = soup_server_message_get_uri (msg);
	uristr = g_uri_to_string (uri);

	addrstr = g_inet_address_to_string (g_inet_socket_address_get_address (iaddr));
	g_assert_cmpstr (addrstr, ==, g_uri_get_host (uri));
	g_free (addrstr);

	g_assert_cmpint (g_inet_socket_address_get_port (iaddr), ==, g_uri_get_port (uri));

	/* FIXME ssl */

	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_TAKE, uristr, strlen (uristr));
	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
}

static void
do_multi_test (ServerData *sd, GUri *uri1, GUri *uri2)
{
	char *uristr;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;

	server_add_handler (sd, NULL, multi_server_callback, NULL, NULL);

	session = soup_test_session_new (NULL);

	uristr = g_uri_to_string (uri1);
	msg = soup_message_new ("GET", uristr);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpmem (uristr, strlen (uristr), g_bytes_get_data (body, NULL), g_bytes_get_size (body));
	g_bytes_unref (body);
	g_object_unref (msg);
	g_free (uristr);

	uristr = g_uri_to_string (uri2);
	msg = soup_message_new ("GET", uristr);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpmem (uristr, strlen (uristr), g_bytes_get_data (body, NULL), g_bytes_get_size (body));
	g_bytes_unref (body);
	g_object_unref (msg);
	g_free (uristr);

	soup_test_session_abort_unref (session);

	g_uri_unref (uri1);
	g_uri_unref (uri2);
}

static void
do_multi_port_test (ServerData *sd, gconstpointer test_data)
{
	GSList *uris;
	GUri *uri1, *uri2;
	GError *error = NULL;

	sd->server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (sd->server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}
	if (!soup_server_listen_local (sd->server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (sd->server);
	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpint (g_uri_get_port (uri1), !=, g_uri_get_port (uri2));

	do_multi_test (sd, uri1, uri2);
}

static void
do_multi_scheme_test (ServerData *sd, gconstpointer test_data)
{
	GSList *uris;
	GUri *uri1, *uri2;
	GError *error = NULL;

	SOUP_TEST_SKIP_IF_NO_TLS;

	sd->server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (sd->server, 0, SOUP_SERVER_LISTEN_IPV4_ONLY, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}
	if (!soup_server_listen_local (sd->server, 0,
				       SOUP_SERVER_LISTEN_IPV4_ONLY | SOUP_SERVER_LISTEN_HTTPS,
				       &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (sd->server);
	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpstr (g_uri_get_scheme (uri1), !=, g_uri_get_scheme (uri2));

	do_multi_test (sd, uri1, uri2);
}

static void
do_multi_family_test (ServerData *sd, gconstpointer test_data)
{
	GSList *uris;
	GUri *uri1, *uri2;
	GError *error = NULL;

        SOUP_TEST_SKIP_IF_NO_IPV6;

	sd->server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);

	if (!soup_server_listen_local (sd->server, 0, 0, &error)) {
		g_assert_no_error (error);
		g_error_free (error);
		return;
	}

	uris = soup_server_get_uris (sd->server);
	g_assert_cmpint (g_slist_length (uris), ==, 2);
	uri1 = uris->data;
	uri2 = uris->next->data;
	g_slist_free (uris);

	g_assert_cmpstr (g_uri_get_host (uri1), !=, g_uri_get_host (uri2));
	g_assert_cmpint (g_uri_get_port (uri1), ==, g_uri_get_port (uri2));

	do_multi_test (sd, uri1, uri2);
}

static void
do_gsocket_import_test (void)
{
	GSocket *gsock;
	GSocketAddress *gaddr;
	SoupServer *server;
	GSList *listeners;
	GUri *uri;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
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

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);
	g_object_unref (gaddr);

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 0);
	g_slist_free (listeners);

	soup_server_listen_socket (server, gsock, 0, &error);
	g_assert_no_error (error);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	uri = soup_test_server_get_uri (server, "http", "127.0.0.1");
	g_assert_nonnull (uri);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);

	g_uri_unref (uri);
	soup_test_server_quit_unref (server);

	g_assert_false (g_socket_is_connected (gsock));
	g_object_unref (gsock);
}

static void
do_fd_import_test (void)
{
	GSocket *gsock;
	GSocketAddress *gaddr;
	SoupServer *server;
	GSList *listeners;
	GUri *uri;
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	int type;
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

	gaddr = g_socket_get_local_address (gsock, &error);
	g_assert_no_error (error);
	g_object_unref (gaddr);

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);

	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 0);
	g_slist_free (listeners);

	soup_server_listen_socket (server, gsock, 0, &error);
	g_assert_no_error (error);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	uri = soup_test_server_get_uri (server, "http", "127.0.0.1");
	g_assert_nonnull (uri);
	listeners = soup_server_get_listeners (server);
	g_assert_cmpint (g_slist_length (listeners), ==, 1);
	g_slist_free (listeners);

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_bytes_unref (body);
	g_object_unref (msg);

	soup_test_session_abort_unref (session);

	g_uri_unref (uri);
	soup_test_server_quit_unref (server);

	/* @server should have closed our socket, note the specific error isn't reliable */
	g_socket_get_option (gsock, SOL_SOCKET, SO_TYPE, &type, &error);
	g_assert_nonnull (error);
	g_clear_error (&error);
	g_object_unref (gsock);
}

typedef struct
{
	GIOStream parent;
	GInputStream *input_stream;
	GOutputStream *output_stream;
} GTestIOStream;

typedef struct
{
	GIOStreamClass parent_class;
} GTestIOStreamClass;

static GType g_test_io_stream_get_type (void);
G_DEFINE_TYPE (GTestIOStream, g_test_io_stream, G_TYPE_IO_STREAM);


static GInputStream *
get_input_stream (GIOStream *io_stream)
{
	GTestIOStream *self =  (GTestIOStream *) io_stream;

	return self->input_stream;
}

static GOutputStream *
get_output_stream (GIOStream *io_stream)
{
	GTestIOStream *self =  (GTestIOStream *) io_stream;

	return self->output_stream;
}

static void
finalize (GObject *object)
{
	GTestIOStream *self = (GTestIOStream *) object;

	if (self->input_stream != NULL)
		g_object_unref (self->input_stream);

	if (self->output_stream != NULL)
		g_object_unref (self->output_stream);

	G_OBJECT_CLASS (g_test_io_stream_parent_class)->finalize (object);
}

static void
g_test_io_stream_class_init (GTestIOStreamClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GIOStreamClass *io_class = G_IO_STREAM_CLASS (klass);

	object_class->finalize = finalize;

	io_class->get_input_stream = get_input_stream;
	io_class->get_output_stream = get_output_stream;
}

static void
g_test_io_stream_init (GTestIOStream *self)
{
}

static GIOStream *
g_test_io_stream_new (GInputStream *input, GOutputStream *output)
{
	GTestIOStream *self;

	self = g_object_new (g_test_io_stream_get_type (), NULL);
	self->input_stream = g_object_ref (input);
	self->output_stream = g_object_ref (output);

	return G_IO_STREAM (self);
}

static void
mem_server_callback (SoupServer        *server,
		     SoupServerMessage *msg,
		     const char        *path,
		     GHashTable        *query,
		     gpointer           data)
{
	GSocketAddress *addr;
	GSocket *sock;
	const char *host;

	addr = soup_server_message_get_local_address (msg);
	g_assert_nonnull (addr);

	addr = soup_server_message_get_remote_address (msg);
	g_assert_nonnull (addr);

	sock = soup_server_message_get_socket (msg);
	g_assert_null (sock);

	host = soup_server_message_get_remote_host (msg);
	g_assert_cmpstr (host, ==, "127.0.0.1");

	server_callback (server, msg, path, query, data);
}

static void
do_iostream_accept_test (void)
{
	GError *error = NULL;
	SoupServer *server;
	GInputStream *input;
	GOutputStream *output;
	GIOStream *stream;
	GSocketAddress *addr;
	const char req[] = "GET / HTTP/1.0\r\n\r\n";
	gchar *reply;
	gsize reply_size;

	server = soup_test_server_new (SOUP_TEST_SERVER_NO_DEFAULT_LISTENER);
	soup_server_add_handler (server, NULL, mem_server_callback, NULL, NULL);

	input = g_memory_input_stream_new_from_data (req, sizeof(req), NULL);
	output = g_memory_output_stream_new_resizable ();
	stream = g_test_io_stream_new (input, output);

	addr = g_inet_socket_address_new_from_string ("127.0.0.1", 0);

	soup_server_accept_iostream (server, stream, addr, addr, &error);
	g_assert_no_error (error);

	soup_test_server_quit_unref (server);

	reply = g_memory_output_stream_get_data (G_MEMORY_OUTPUT_STREAM (output));
	reply_size = g_memory_output_stream_get_data_size (G_MEMORY_OUTPUT_STREAM (output));
	g_assert_true (reply_size > 0);
	g_assert_true (g_str_has_prefix (reply, "HTTP/1.0 200 OK"));

	g_clear_object (&addr);
	g_clear_object (&stream);
	g_clear_object (&input);
	g_clear_object (&output);
	g_clear_error (&error);
}

typedef struct {
	SoupServerMessage *smsg;
	gboolean handler_called;
	gboolean paused;
} UnhandledServerData;

static gboolean
idle_unpause_message (gpointer user_data)
{
	UnhandledServerData *usd = user_data;

	soup_server_message_unpause (usd->smsg);
	return FALSE;
}

static void
unhandled_server_callback (SoupServer        *server,
			   SoupServerMessage *msg,
			   const char        *path,
			   GHashTable        *query,
			   gpointer           data)
{
	UnhandledServerData *usd = data;

	usd->handler_called = TRUE;

	if (soup_message_headers_get_one (soup_server_message_get_request_headers (msg), "X-Test-Server-Pause")) {
		usd->paused = TRUE;
		usd->smsg = msg;
		soup_server_message_pause (msg);
                soup_add_completion (g_main_context_get_thread_default (),
                                     idle_unpause_message, usd);
	}
}

static void
do_fail_404_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	UnhandledServerData usd;

	usd.handler_called = usd.paused = FALSE;

	server_add_handler (sd, "/not-a-match", unhandled_server_callback, &usd, NULL);

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", sd->base_uri);
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_NOT_FOUND);
	g_bytes_unref (body);
	g_object_unref (msg);

	g_assert_false (usd.handler_called);
	g_assert_false (usd.paused);

	soup_test_session_abort_unref (session);
}

static void
do_fail_500_test (ServerData *sd, gconstpointer pause)
{
	SoupSession *session;
	SoupMessage *msg;
	GBytes *body;
	UnhandledServerData usd;

	usd.handler_called = usd.paused = FALSE;

	server_add_handler (sd, NULL, unhandled_server_callback, &usd, NULL);

	session = soup_test_session_new (NULL);
	msg = soup_message_new_from_uri ("GET", sd->base_uri);
	if (pause)
		soup_message_headers_append (soup_message_get_request_headers (msg), "X-Test-Server-Pause", "true");
	body = soup_test_session_async_send (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
	g_bytes_unref (body);
	g_object_unref (msg);

	g_assert_true (usd.handler_called);
	if (pause)
		g_assert_true (usd.paused);
	else
		g_assert_false (usd.paused);

	soup_test_session_abort_unref (session);
}

static void
stream_got_chunk (SoupServerMessage *msg,
		  GBytes            *chunk,
		  gpointer           user_data)
{
	GChecksum *checksum = user_data;

	g_checksum_update (checksum, g_bytes_get_data (chunk, NULL), g_bytes_get_size (chunk));
}

static void
stream_got_body (SoupServerMessage *msg,
		 gpointer           user_data)
{
	GChecksum *checksum = user_data;
	const char *md5 = g_checksum_get_string (checksum);

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain", SOUP_MEMORY_COPY,
					  md5, strlen (md5));
	g_checksum_free (checksum);
}

static void
early_stream_callback (SoupServer        *server,
		       SoupServerMessage *msg,
		       const char        *path,
		       GHashTable        *query,
		       gpointer           data)
{
	GChecksum *checksum;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_POST) {
		soup_server_message_set_status (msg, SOUP_STATUS_METHOD_NOT_ALLOWED, NULL);
		return;
	}

	checksum = g_checksum_new (G_CHECKSUM_MD5);
	g_signal_connect (msg, "got-chunk",
			  G_CALLBACK (stream_got_chunk), checksum);
	g_signal_connect (msg, "got-body",
			  G_CALLBACK (stream_got_body), checksum);

	soup_message_body_set_accumulate (soup_server_message_get_request_body (msg), TRUE);
}

static void
do_early_stream_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GBytes *index, *body;
	char *md5;

	server_add_early_handler (sd, NULL, early_stream_callback, NULL, NULL);

	session = soup_test_session_new (NULL);

	msg = soup_message_new_from_uri ("POST", sd->base_uri);

	index = soup_test_get_index ();
	soup_message_set_request_body_from_bytes (msg, "text/plain", index);
	body = soup_session_send_and_read (session, msg, NULL, NULL);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);

	md5 = g_compute_checksum_for_bytes (G_CHECKSUM_MD5, index);
	g_assert_cmpmem (md5, strlen (md5), g_bytes_get_data (body, NULL), g_bytes_get_size (body));
	g_free (md5);

	g_bytes_unref (body);
	g_object_unref (msg);
	soup_test_session_abort_unref (session);
}

static void
early_respond_callback (SoupServer        *server,
			SoupServerMessage *msg,
			const char        *path,
			GHashTable        *query,
			gpointer           data)
{
	if (!strcmp (path, "/"))
		soup_server_message_set_status (msg, SOUP_STATUS_FORBIDDEN, NULL);
}

static void
do_early_respond_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri2;
	GBytes *body;

	server_add_early_handler (sd, NULL, early_respond_callback, NULL, NULL);

	session = soup_test_session_new (NULL);

	/* The early handler will intercept, and the normal handler will be skipped */
	msg = soup_message_new_from_uri ("GET", sd->base_uri);
	soup_test_session_send_message (session, msg);
	soup_test_assert_message_status (msg, SOUP_STATUS_FORBIDDEN);
	g_object_unref (msg);

	/* The early handler will ignore this one */
	uri2 = g_uri_parse_relative (sd->base_uri, "/subdir", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri2);
	body = soup_session_send_and_read (session, msg, NULL, NULL);
	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	g_assert_cmpmem ("index", sizeof ("index") - 1, g_bytes_get_data (body, NULL), g_bytes_get_size (body));
	g_bytes_unref (body);
	g_object_unref (msg);
	g_uri_unref (uri2);

	soup_test_session_abort_unref (session);
}

static void
early_multi_callback (SoupServer        *server,
		      SoupServerMessage *msg,
		      const char        *path,
		      GHashTable        *query,
		      gpointer           data)
{
	soup_message_headers_append (soup_server_message_get_response_headers (msg), "X-Early", "yes");
}

static void
do_early_multi_test (ServerData *sd, gconstpointer test_data)
{
	SoupSession *session;
	SoupMessage *msg;
	GUri *uri;
	GBytes *body;
	struct {
		const char *path;
		gboolean expect_normal, expect_early;
	} multi_tests[] = {
		{ "/", FALSE, FALSE },
		{ "/normal", TRUE, FALSE },
		{ "/normal/subdir", TRUE, FALSE },
		{ "/normal/early", FALSE, TRUE },
		{ "/normal/early/subdir", FALSE, TRUE },
		{ "/early", FALSE, TRUE },
		{ "/early/subdir", FALSE, TRUE },
		{ "/early/normal", TRUE, FALSE },
		{ "/early/normal/subdir", TRUE, FALSE },
		{ "/both", TRUE, TRUE },
		{ "/both/subdir", TRUE, TRUE }
	};
	int i;
	const char *header;

	server_add_handler (sd, "/normal", server_callback, NULL, NULL);
	server_add_early_handler (sd, "/normal/early", early_multi_callback, NULL, NULL);
	server_add_early_handler (sd, "/early", early_multi_callback, NULL, NULL);
	server_add_handler (sd, "/early/normal", server_callback, NULL, NULL);
	server_add_handler (sd, "/both", server_callback, NULL, NULL);
	server_add_early_handler (sd, "/both", early_multi_callback, NULL, NULL);

	session = soup_test_session_new (NULL);

	for (i = 0; i < G_N_ELEMENTS (multi_tests); i++) {
		uri = g_uri_parse_relative (sd->base_uri, multi_tests[i].path, SOUP_HTTP_URI_FLAGS, NULL);
		msg = soup_message_new_from_uri ("GET", uri);
		g_uri_unref (uri);

		body = soup_session_send_and_read (session, msg, NULL, NULL);

		/* The normal handler sets status to OK. The early handler doesn't
		 * touch status, meaning that if it runs and the normal handler doesn't,
		 * then SoupServer will set the status to INTERNAL_SERVER_ERROR
		 * (since a handler ran, but didn't set the status). If neither handler
		 * runs then SoupServer will set the status to NOT_FOUND.
		 */
		if (multi_tests[i].expect_normal)
			soup_test_assert_message_status (msg, SOUP_STATUS_OK);
		else if (multi_tests[i].expect_early)
			soup_test_assert_message_status (msg, SOUP_STATUS_INTERNAL_SERVER_ERROR);
		else
			soup_test_assert_message_status (msg, SOUP_STATUS_NOT_FOUND);

		header = soup_message_headers_get_one (soup_message_get_response_headers (msg), "X-Early");
		if (multi_tests[i].expect_early)
			g_assert_cmpstr (header, ==, "yes");
		else
			g_assert_cmpstr (header, ==, NULL);
		if (multi_tests[i].expect_normal)
			g_assert_cmpmem ("index", sizeof ("index") - 1, g_bytes_get_data (body, NULL), g_bytes_get_size (body));
		else
			g_assert_cmpint (g_bytes_get_size (body), ==, 0);

		g_bytes_unref (body);
		g_object_unref (msg);
	}

	soup_test_session_abort_unref (session);
}

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

	g_clear_object (&tunnel->self);
	g_clear_object (&tunnel->msg);

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
			debug_printf (1, "Tunnel write failed: %s\n", error->message);
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
			debug_printf (1, "Tunnel read failed: %s\n", error->message);
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
start_tunnel (SoupServerMessage *msg,
	      gpointer           user_data)
{
	Tunnel *tunnel = user_data;

	tunnel->client.iostream = soup_server_message_steal_connection (msg);
	tunnel->client.istream = g_io_stream_get_input_stream (tunnel->client.iostream);
	tunnel->client.ostream = g_io_stream_get_output_stream (tunnel->client.iostream);
	g_clear_object (&tunnel->self);
	g_clear_object (&tunnel->msg);

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
	g_signal_connect (tunnel->msg, "wrote-body",
			  G_CALLBACK (start_tunnel), tunnel);
}

static void
proxy_server_callback (SoupServer        *server,
		       SoupServerMessage *msg,
		       const char        *path,
		       GHashTable        *query,
		       gpointer           data)
{
	GSocketClient *sclient;
	GUri *dest_uri;
	Tunnel *tunnel;

	if (soup_server_message_get_method (msg) != SOUP_METHOD_CONNECT) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

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
do_steal_connect_test (ServerData *sd, gconstpointer test_data)
{
	SoupServer *proxy;
	SoupSession *session;
	SoupMessage *msg;
	GUri *proxy_uri;
	char *proxy_uri_str;
	GProxyResolver *resolver;

	SOUP_TEST_SKIP_IF_NO_TLS;

	proxy = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
        proxy_uri = soup_test_server_get_uri (proxy, "http", "127.0.0.1");
	proxy_uri_str = g_uri_to_string (proxy_uri);
	soup_server_add_handler (proxy, NULL, proxy_server_callback, NULL, NULL);

	resolver = g_simple_proxy_resolver_new (proxy_uri_str, NULL);
	session = soup_test_session_new ("proxy-resolver", resolver,
					 NULL);
	msg = soup_message_new_from_uri ("GET", sd->ssl_base_uri);
	soup_test_session_send_message (session, msg);

	soup_test_assert_message_status (msg, SOUP_STATUS_OK);
	soup_test_assert_handled_by (msg, "server_callback");

	g_object_unref (msg);
	soup_test_session_abort_unref (session);

	soup_test_server_quit_unref (proxy);
	g_object_unref (resolver);
	g_uri_unref (proxy_uri);
	g_free (proxy_uri_str);
}

static void
do_idle_connection_closed_test (ServerData *sd, gconstpointer test_data)
{
        SoupSession *session;
        SoupMessage *msg;
        GBytes *body;
        GError *error = NULL;
        GSList *clients;

        soup_server_set_http2_enabled (sd->server, tls_available);

        session = soup_test_session_new (NULL);

        msg = soup_message_new_from_uri ("GET", sd->base_uri);
        body = soup_session_send_and_read (session, msg, NULL, &error);
        g_assert_no_error (error);
        g_bytes_unref (body);
        g_object_unref (msg);

        clients = soup_server_get_clients (sd->server);
        g_assert_cmpuint (g_slist_length (clients), ==, 1);

        if (tls_available) {
                msg = soup_message_new_from_uri ("GET", sd->ssl_base_uri);
                body = soup_session_send_and_read (session, msg, NULL, &error);
                g_assert_no_error (error);
                g_bytes_unref (body);
                g_object_unref (msg);

                clients = soup_server_get_clients (sd->server);
                g_assert_cmpuint (g_slist_length (clients), ==, 2);
        }

        soup_test_session_abort_unref (session);

        while (soup_server_get_clients (sd->server))
                g_main_context_iteration (NULL, FALSE);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add ("/server/OPTIONS *", ServerData, NULL,
		    server_setup, do_star_test, server_teardown);
	g_test_add ("/server/..-in-path", ServerData, NULL,
		    server_setup, do_dot_dot_test, server_teardown);
	g_test_add ("/server/invalid-percent-encoding-paths", ServerData, NULL,
		    server_setup, do_invalid_percent_encoding_paths_test, server_teardown);
	g_test_add ("/server/ipv6", ServerData, NULL,
		    NULL, do_ipv6_test, server_teardown);
        g_test_add ("/server/idle-connection-closed", ServerData, NULL,
                    server_setup, do_idle_connection_closed_test, server_teardown);
	g_test_add ("/server/multi/port", ServerData, NULL,
		    NULL, do_multi_port_test, server_teardown);
	g_test_add ("/server/multi/scheme", ServerData, NULL,
		    NULL, do_multi_scheme_test, server_teardown);
	g_test_add ("/server/multi/family", ServerData, NULL,
		    NULL, do_multi_family_test, server_teardown);
	g_test_add_func ("/server/import/gsocket", do_gsocket_import_test);
	g_test_add_func ("/server/import/fd", do_fd_import_test);
	g_test_add_func ("/server/accept/iostream", do_iostream_accept_test);
	g_test_add ("/server/fail/404", ServerData, NULL,
		    server_setup_nohandler, do_fail_404_test, server_teardown);
	g_test_add ("/server/fail/500", ServerData, GINT_TO_POINTER (FALSE),
		    server_setup_nohandler, do_fail_500_test, server_teardown);
	g_test_add ("/server/fail/500-pause", ServerData, GINT_TO_POINTER (TRUE),
		    server_setup_nohandler, do_fail_500_test, server_teardown);
	g_test_add ("/server/early/stream", ServerData, NULL,
		    server_setup_nohandler, do_early_stream_test, server_teardown);
	g_test_add ("/server/early/respond", ServerData, NULL,
		    server_setup, do_early_respond_test, server_teardown);
	g_test_add ("/server/early/multi", ServerData, NULL,
		    server_setup_nohandler, do_early_multi_test, server_teardown);
	g_test_add ("/server/steal/CONNECT", ServerData, NULL,
		    server_setup, do_steal_connect_test, server_teardown);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
