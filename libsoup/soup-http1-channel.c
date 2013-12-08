/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-http1-channel.c
 *
 * Copyright 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib/gi18n-lib.h>

#include "soup-http1-channel.h"
#include "soup.h"
#include "soup-body-input-stream.h"
#include "soup-body-output-stream.h"
#include "soup-filter-input-stream.h"
#include "soup-socket-private.h"

G_DEFINE_TYPE (SoupHTTP1Channel, soup_http1_channel, SOUP_TYPE_HTTP_CHANNEL)

typedef struct {
	SoupSocket *server_sock;

	SoupFilterInputStream *istream;
	GPollableInputStream *poll_istream;
	GOutputStream *ostream;
	GPollableOutputStream *poll_ostream;

	GString *input_headers, *output_headers;
	gboolean headers_read;
	gsize headers_nwritten;

	SoupEncoding input_encoding, output_encoding;
	goffset input_length, output_length;

} SoupHTTP1ChannelPrivate;
#define SOUP_HTTP1_CHANNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_HTTP1_CHANNEL, SoupHTTP1ChannelPrivate))

static void
soup_http1_channel_init (SoupHTTP1Channel *channel)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	priv->input_headers = g_string_new (NULL);
	priv->output_headers = g_string_new (NULL);
}

#define READ_BUFFER_SIZE 8192

static gboolean
read_headers (SoupHTTPChannel *channel,
	      gboolean blocking,
	      GCancellable *cancellable,
	      GError **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	gssize nread, old_len;
	gboolean got_lf;

	if (priv->headers_read) {
		/* restart */
		g_string_truncate (priv->input_headers, 0);
		priv->headers_read = FALSE;
	}

	while (1) {
		old_len = priv->input_headers->len;
		g_string_set_size (priv->input_headers, old_len + READ_BUFFER_SIZE);
		nread = soup_filter_input_stream_read_line (priv->istream,
							    priv->input_headers->str + old_len,
							    READ_BUFFER_SIZE,
							    blocking,
							    &got_lf,
							    cancellable, error);
		priv->input_headers->len = old_len + MAX (nread, 0);

		if (nread < 0)
			return FALSE;
		else if (nread == 0) {
			g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
					     _("Connection terminated unexpectedly"));
			return FALSE;
		}

		if (got_lf) {
			if (nread == 1 && old_len >= 2 &&
			    !strncmp (priv->input_headers->str +
				      priv->input_headers->len - 2,
				      "\n\n", 2))
				break;
			else if (nread == 2 && old_len >= 3 &&
				 !strncmp (priv->input_headers->str +
					   priv->input_headers->len - 3,
					   "\n\r\n", 3))
				break;
		}
	}

	/* We need to "rewind" priv->input_headers back one line.
	 * That SHOULD be two characters (CR LF), but if the
	 * web server was stupid, it might only be one.
	 */
	if (priv->input_headers->len < 3 ||
	    priv->input_headers->str[priv->input_headers->len - 2] == '\n')
		priv->input_headers->len--;
	else
		priv->input_headers->len -= 2;
	priv->input_headers->str[priv->input_headers->len] = '\0';

	priv->headers_read = TRUE;
	return TRUE;
}

static gboolean
soup_http1_channel_read_request_headers (SoupHTTPChannel      *channel,
					 gboolean              blocking,
					 GCancellable         *cancellable,
					 GError              **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	SoupMessage *msg = soup_http_channel_get_message (channel);
	guint status;
	char *req_method, *req_path, *uri_string;
	const char *req_host;
	SoupHTTPVersion version;
	SoupURI *uri;

	if (!read_headers (channel, blocking, cancellable, error))
		return FALSE;

	status = soup_headers_parse_request (priv->input_headers->str,
					     priv->input_headers->len,
					     msg->request_headers,
					     &req_method, &req_path, &version);

	if (status != SOUP_STATUS_OK) {
	failed:
		g_set_error_literal (error, SOUP_HTTP_ERROR, status,
				     _("Could not parse HTTP request"));
		return FALSE;
	}

	g_object_set (msg,
		      SOUP_MESSAGE_METHOD, req_method,
		      SOUP_MESSAGE_HTTP_VERSION, version,
		      NULL);
	g_free (req_method);

	/* Handle request body encoding */
	priv->input_encoding = soup_message_headers_get_encoding (msg->request_headers);
	if (priv->input_encoding == SOUP_ENCODING_UNRECOGNIZED) {
		g_free (req_path);
		if (soup_message_headers_get_list (msg->request_headers, "Transfer-Encoding"))
			status = SOUP_STATUS_NOT_IMPLEMENTED;
		else
			status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}
	if (priv->input_encoding == SOUP_ENCODING_CONTENT_LENGTH)
		priv->input_length = soup_message_headers_get_content_length (msg->request_headers);
	else
		priv->input_length = -1;

	/* Generate correct context for request */
	req_host = soup_message_headers_get_one (msg->request_headers, "Host");
	if (req_host && strchr (req_host, '/')) {
		g_free (req_path);
		status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}

	if (!strcmp (req_path, "*") && req_host) {
		/* Eg, "OPTIONS * HTTP/1.1" */
		uri_string = g_strdup_printf ("%s://%s",
					      soup_socket_is_ssl (priv->server_sock) ? "https" : "http",
					      req_host);
		uri = soup_uri_new (uri_string);
		if (uri)
			soup_uri_set_path (uri, "*");
		g_free (uri_string);
	} else if (*req_path != '/') {
		/* Must be an absolute URI */
		uri = soup_uri_new (req_path);
	} else if (req_host) {
		uri_string = g_strdup_printf ("%s://%s%s",
					      soup_socket_is_ssl (priv->server_sock) ? "https" : "http",
					      req_host, req_path);
		uri = soup_uri_new (uri_string);
		g_free (uri_string);
	} else if (version == SOUP_HTTP_1_0) {
		/* No Host header, no AbsoluteUri */
		SoupAddress *addr = soup_socket_get_local_address (priv->server_sock);

		uri = soup_uri_new (NULL);
		soup_uri_set_scheme (uri, soup_socket_is_ssl (priv->server_sock) ? "https" : "http");
		soup_uri_set_host (uri, soup_address_get_physical (addr));
		soup_uri_set_port (uri, soup_address_get_port (addr));
		soup_uri_set_path (uri, req_path);
	} else
		uri = NULL;

	g_free (req_path);

	if (!uri || !uri->host) {
		if (uri)
			soup_uri_free (uri);
		status = SOUP_STATUS_BAD_REQUEST;
		goto failed;
	}

	g_object_set (msg,
		      SOUP_MESSAGE_URI, uri,
		      NULL);
	soup_uri_free (uri);

	return TRUE;
}

static gboolean
soup_http1_channel_read_response_headers (SoupHTTPChannel      *channel,
					  gboolean              blocking,
					  GCancellable         *cancellable,
					  GError              **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	SoupMessage *msg = soup_http_channel_get_message (channel);
	SoupHTTPVersion version;
	guint status_code;
	char *reason_phrase;
	gboolean ok;

	if (!read_headers (channel, blocking, cancellable, error))
		return FALSE;

	ok = soup_headers_parse_response (priv->input_headers->str,
					  priv->input_headers->len,
					  msg->response_headers,
					  &version, &status_code, &reason_phrase);

	if (!ok) {
		g_set_error_literal (error, SOUP_HTTP_ERROR,
				     SOUP_STATUS_MALFORMED,
				     _("Could not parse HTTP response"));
		return FALSE;
	}

	g_object_set (msg,
		      SOUP_MESSAGE_STATUS_CODE, status_code,
		      SOUP_MESSAGE_REASON_PHRASE, reason_phrase,
		      SOUP_MESSAGE_HTTP_VERSION, MIN (version, soup_message_get_http_version (msg)),
		      NULL);

	if (msg->method == SOUP_METHOD_HEAD ||
	    status_code == SOUP_STATUS_NO_CONTENT ||
	    status_code == SOUP_STATUS_NOT_MODIFIED ||
	    SOUP_STATUS_IS_INFORMATIONAL (status_code) ||
	    (msg->method == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (status_code)))
		priv->input_encoding = SOUP_ENCODING_NONE;
	else {
		priv->input_encoding = soup_message_headers_get_encoding (msg->response_headers);

		if (priv->input_encoding == SOUP_ENCODING_UNRECOGNIZED) {
			g_set_error_literal (error, SOUP_HTTP_ERROR,
					     SOUP_STATUS_NOT_IMPLEMENTED,
					     _("Unrecognized HTTP encoding"));
			return FALSE;
		}
	}

	if (priv->input_encoding == SOUP_ENCODING_CONTENT_LENGTH) {
		const char *conn;

		priv->input_length = soup_message_headers_get_content_length (msg->response_headers);

		/* Some servers suck and send incorrect Content-Length
		 * values, so if the message isn't keepalive anyway, allow
		 * EOF termination.
		 */
		conn = soup_message_headers_get_one (msg->response_headers, "Connection");
		if (version == SOUP_HTTP_1_0 &&
		    (!conn || !soup_header_contains (conn, "Keep-Alive")))
			priv->input_encoding = SOUP_ENCODING_EOF;
		else if (version == SOUP_HTTP_1_1 && conn &&
			 soup_header_contains (conn, "close"))
			priv->input_encoding = SOUP_ENCODING_EOF;
	} else
		priv->input_length = -1;

	return TRUE;
}

static gboolean
write_headers (SoupHTTPChannel  *channel,
	       gboolean          blocking,
	       GCancellable     *cancellable,
	       GError          **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	gssize nwrote;

	while (priv->headers_nwritten < priv->output_headers->len) {
		nwrote = g_pollable_stream_write (priv->ostream,
						  priv->output_headers->str + priv->headers_nwritten,
						  priv->output_headers->len - priv->headers_nwritten,
						  blocking, cancellable, error);
		if (nwrote == -1)
			return FALSE;
		priv->headers_nwritten += nwrote;
	}
	return TRUE;
}

static void
finish_build_headers (SoupHTTPChannel    *channel,
		      SoupMessageHeaders *headers)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	SoupMessageHeadersIter iter;
	const char *name, *value;

	if (priv->output_encoding == SOUP_ENCODING_CONTENT_LENGTH)
		priv->output_length = soup_message_headers_get_content_length (headers);

	soup_message_headers_iter_init (&iter, headers);
	while (soup_message_headers_iter_next (&iter, &name, &value))
		g_string_append_printf (priv->output_headers, "%s: %s\r\n", name, value);
	g_string_append (priv->output_headers, "\r\n");
}

static void
build_request_headers (SoupHTTPChannel *channel)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	SoupMessage *msg = soup_http_channel_get_message (channel);
	SoupURI *request_uri = soup_message_get_uri (msg);
	char *uri_host;
	char *uri_string;

	g_string_truncate (priv->output_headers, 0);
	priv->headers_nwritten = 0;

	if (strchr (request_uri->host, ':'))
		uri_host = g_strdup_printf ("[%.*s]", (int) strcspn (request_uri->host, "%"), request_uri->host);
	else if (g_hostname_is_non_ascii (request_uri->host))
		uri_host = g_hostname_to_ascii (request_uri->host);
	else
		uri_host = request_uri->host;

	if (msg->method == SOUP_METHOD_CONNECT) {
		/* CONNECT URI is hostname:port for tunnel destination */
		uri_string = g_strdup_printf ("%s:%d", uri_host, request_uri->port);
	} else {
		/* Proxy expects full URI to destination. Otherwise
		 * just the path.
		 */
		if (soup_connection_is_via_proxy (soup_message_get_connection (msg))) {
			uri_string = soup_uri_to_string (request_uri, FALSE);
			if (request_uri->fragment) {
				/* Strip fragment */
				char *fragment = strchr (uri_string, '#');
				if (fragment)
					*fragment = '\0';
			}
		} else
			uri_string = soup_uri_to_string (request_uri, TRUE);
	}

	g_string_append_printf (priv->output_headers, "%s %s HTTP/1.%d\r\n",
				msg->method, uri_string,
				(soup_message_get_http_version (msg) == SOUP_HTTP_1_0) ? 0 : 1);

	if (!soup_message_headers_get_one (msg->request_headers, "Host")) {
		if (soup_uri_uses_default_port (request_uri)) {
			g_string_append_printf (priv->output_headers, "Host: %s\r\n",
						uri_host);
		} else {
			g_string_append_printf (priv->output_headers, "Host: %s:%d\r\n",
						uri_host, request_uri->port);
		}
	}
	g_free (uri_string);
	if (uri_host != request_uri->host)
		g_free (uri_host);

	priv->output_encoding = soup_message_headers_get_encoding (msg->request_headers);
	finish_build_headers (channel, msg->request_headers);
}

static void
build_response_headers (SoupHTTPChannel *channel)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	SoupMessage *msg = soup_http_channel_get_message (channel);
	SoupEncoding claimed_encoding;

	g_string_truncate (priv->output_headers, 0);
	priv->headers_nwritten = 0;

	g_string_append_printf (priv->output_headers, "HTTP/1.%c %d %s\r\n",
				(soup_message_get_http_version (msg) == SOUP_HTTP_1_0) ? '0' : '1',
				msg->status_code, msg->reason_phrase);

	claimed_encoding = soup_message_headers_get_encoding (msg->response_headers);
	if ((msg->method == SOUP_METHOD_HEAD ||
	     msg->status_code == SOUP_STATUS_NO_CONTENT ||
	     msg->status_code == SOUP_STATUS_NOT_MODIFIED ||
	     SOUP_STATUS_IS_INFORMATIONAL (msg->status_code)) ||
	    (msg->method == SOUP_METHOD_CONNECT &&
	     SOUP_STATUS_IS_SUCCESSFUL (msg->status_code)))
		priv->output_encoding = SOUP_ENCODING_NONE;
	else
		priv->output_encoding = claimed_encoding;

	finish_build_headers (channel, msg->response_headers);
}

static gboolean
soup_http1_channel_write_request_headers (SoupHTTPChannel  *channel,
					  gboolean          blocking,
					  GCancellable     *cancellable,
					  GError          **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	if (priv->headers_nwritten == priv->output_headers->len)
		build_request_headers (channel);
	return write_headers (channel, blocking, cancellable, error);
}

static gboolean
soup_http1_channel_write_response_headers (SoupHTTPChannel  *channel,
					   gboolean          blocking,
					   GCancellable     *cancellable,
					   GError          **error)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	if (priv->headers_nwritten == priv->output_headers->len)
		build_response_headers (channel);
	return write_headers (channel, blocking, cancellable, error);
}

static GInputStream *
soup_http1_channel_get_body_input_stream (SoupHTTPChannel *channel)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	GInputStream *istream;

	g_return_val_if_fail (priv->headers_read, NULL);

	istream = soup_body_input_stream_new (G_INPUT_STREAM (priv->istream),
					      priv->input_encoding,
					      priv->input_length);
	g_object_unref (priv->poll_istream);
	priv->poll_istream = g_object_ref (istream);

	return istream;
}

static GOutputStream *
soup_http1_channel_get_body_output_stream (SoupHTTPChannel *channel)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);
	GOutputStream *ostream;

	g_return_val_if_fail (priv->headers_nwritten != 0, NULL);

	ostream = soup_body_output_stream_new (priv->ostream,
					       priv->output_encoding,
					       priv->output_length);
	g_object_unref (priv->poll_ostream);
	priv->poll_ostream = g_object_ref (ostream);

	return ostream;
}

static GSource *
soup_http1_channel_create_oneshot_source (SoupHTTPChannel  *channel,
					  GIOCondition      cond,
					  GCancellable     *cancellable)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	if (cond == G_IO_IN)
		return g_pollable_input_stream_create_source (priv->poll_istream, cancellable);
	else if (cond == G_IO_OUT)
		return g_pollable_output_stream_create_source (priv->poll_ostream, cancellable);
	else
		g_assert_not_reached ();
}

static void
soup_http1_channel_dispose (GObject *object)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (object);

	g_clear_object (&priv->server_sock);
	g_clear_object (&priv->istream);
	g_clear_object (&priv->poll_istream);
	g_clear_object (&priv->ostream);
	g_clear_object (&priv->poll_ostream);

	G_OBJECT_CLASS (soup_http1_channel_parent_class)->dispose (object);
}

static void
soup_http1_channel_finalize (GObject *object)
{
	SoupHTTP1ChannelPrivate *priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (object);

	g_string_free (priv->input_headers, TRUE);
	g_string_free (priv->output_headers, TRUE);

	G_OBJECT_CLASS (soup_http1_channel_parent_class)->finalize (object);
}

static void
soup_http1_channel_class_init (SoupHTTP1ChannelClass *http1_channel_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (http1_channel_class);
	SoupHTTPChannelClass *channel_class = SOUP_HTTP_CHANNEL_CLASS (http1_channel_class);

	g_type_class_add_private (http1_channel_class, sizeof (SoupHTTP1ChannelPrivate));

	object_class->dispose = soup_http1_channel_dispose;
	object_class->finalize = soup_http1_channel_finalize;

	channel_class->read_request_headers = soup_http1_channel_read_request_headers;
	channel_class->read_response_headers = soup_http1_channel_read_response_headers;
	channel_class->write_request_headers = soup_http1_channel_write_request_headers;
	channel_class->write_response_headers = soup_http1_channel_write_response_headers;
	channel_class->get_body_input_stream = soup_http1_channel_get_body_input_stream;
	channel_class->get_body_output_stream = soup_http1_channel_get_body_output_stream;
	channel_class->create_oneshot_source = soup_http1_channel_create_oneshot_source;
}

SoupHTTPChannel *
soup_http1_channel_new_client (SoupMessage *msg)
{
	SoupHTTPChannel *channel;
	SoupHTTP1ChannelPrivate *priv;
	GIOStream *iostream;

	channel = g_object_new (SOUP_TYPE_HTTP1_CHANNEL,
				SOUP_HTTP_CHANNEL_MESSAGE, msg,
				SOUP_HTTP_CHANNEL_MODE, SOUP_HTTP_CHANNEL_CLIENT,
				NULL);
	priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	iostream = soup_socket_get_iostream (soup_connection_get_socket (soup_message_get_connection (msg)));
	priv->istream = g_object_ref (g_io_stream_get_input_stream (iostream));
	priv->poll_istream = g_object_ref (priv->istream);
	priv->ostream = g_object_ref (g_io_stream_get_output_stream (iostream));
	priv->poll_ostream = g_object_ref (priv->ostream);

	return channel;
}

SoupHTTPChannel *
soup_http1_channel_new_server (SoupMessage *msg,
			       SoupSocket *sock)
{
	SoupHTTPChannel *channel;
	SoupHTTP1ChannelPrivate *priv;
	GIOStream *iostream;

	channel = g_object_new (SOUP_TYPE_HTTP1_CHANNEL,
				SOUP_HTTP_CHANNEL_MESSAGE, msg,
				SOUP_HTTP_CHANNEL_MODE, SOUP_HTTP_CHANNEL_SERVER,
				NULL);
	priv = SOUP_HTTP1_CHANNEL_GET_PRIVATE (channel);

	priv->server_sock = g_object_ref (sock);

	iostream = soup_socket_get_iostream (sock);
	priv->istream = g_object_ref (g_io_stream_get_input_stream (iostream));
	priv->poll_istream = g_object_ref (priv->istream);
	priv->ostream = g_object_ref (g_io_stream_get_output_stream (iostream));
	priv->poll_ostream = g_object_ref (priv->ostream);

	return channel;
}
