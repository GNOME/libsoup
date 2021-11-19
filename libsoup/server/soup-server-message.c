/*
 * soup-server-message.c: HTTP server request/response
 *
 * Copyright (C) 2020 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-server-message.h"
#include "soup.h"
#include "soup-connection.h"
#include "soup-server-message-private.h"
#include "soup-message-headers-private.h"
#include "soup-socket.h"
#include "soup-uri-utils-private.h"

/**
 * SoupServerMessage:
 *
 * An HTTP server request and response pair.
 *
 * A SoupServerMessage represents an HTTP message that is being sent or
 * received on a [class@Server].
 *
 * [class@Server] will create `SoupServerMessage`s automatically for
 * incoming requests, which your application will receive via handlers.
 *
 * Note that libsoup's terminology here does not quite match the HTTP
 * specification: in RFC 2616, an "HTTP-message" is *either* a Request, *or* a
 * Response. In libsoup, a #SoupServerMessage combines both the request and the
 * response.
 **/

struct _SoupServerMessage {
        GObject             parent;

        SoupSocket         *sock;
        GSocket            *gsock;
        SoupAuthDomain     *auth_domain;
        char               *auth_user;

        GSocketAddress     *remote_addr;
        char               *remote_ip;
        GSocketAddress     *local_addr;

        const char         *method;
        SoupHTTPVersion     http_version;
        SoupHTTPVersion     orig_http_version;

        guint               status_code;
        char               *reason_phrase;

        GUri               *uri;

        SoupMessageBody    *request_body;
        SoupMessageHeaders *request_headers;

        SoupMessageBody    *response_body;
        SoupMessageHeaders *response_headers;

        SoupServerMessageIOData *io_data;

        gboolean                 options_ping;

        GTlsCertificate      *tls_peer_certificate;
        GTlsCertificateFlags  tls_peer_certificate_errors;
};

struct _SoupServerMessageClass {
        GObjectClass parent_class;
};

G_DEFINE_FINAL_TYPE (SoupServerMessage, soup_server_message, G_TYPE_OBJECT)

enum {
        WROTE_INFORMATIONAL,
        WROTE_HEADERS,
        WROTE_CHUNK,
        WROTE_BODY_DATA,
        WROTE_BODY,

        GOT_HEADERS,
        GOT_CHUNK,
        GOT_BODY,

        DISCONNECTED,
        FINISHED,

        ACCEPT_CERTIFICATE,

        LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_TLS_PEER_CERTIFICATE,
	PROP_TLS_PEER_CERTIFICATE_ERRORS,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

static void
soup_server_message_init (SoupServerMessage *msg)
{
        msg->request_body = soup_message_body_new ();
        msg->request_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
        msg->response_body = soup_message_body_new ();
        msg->response_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
        soup_message_headers_set_encoding (msg->response_headers, SOUP_ENCODING_CONTENT_LENGTH);
}

static void
soup_server_message_finalize (GObject *object)
{
        SoupServerMessage *msg = SOUP_SERVER_MESSAGE (object);

        soup_server_message_io_data_free (msg->io_data);

        g_clear_object (&msg->auth_domain);
        g_clear_pointer (&msg->auth_user, g_free);
        g_clear_object (&msg->remote_addr);
        g_clear_object (&msg->local_addr);

        if (msg->sock) {
                g_signal_handlers_disconnect_by_data (msg->sock, msg);
                g_object_unref (msg->sock);
        }
        g_clear_object (&msg->gsock);
        g_clear_pointer (&msg->remote_ip, g_free);

        g_clear_pointer (&msg->uri, g_uri_unref);
        g_free (msg->reason_phrase);

        soup_message_body_unref (msg->request_body);
        soup_message_headers_unref (msg->request_headers);
        soup_message_body_unref (msg->response_body);
        soup_message_headers_unref (msg->response_headers);

        G_OBJECT_CLASS (soup_server_message_parent_class)->finalize (object);
}

static void
soup_server_message_get_property (GObject *object, guint prop_id,
                                  GValue *value, GParamSpec *pspec)
{
	SoupServerMessage *msg = SOUP_SERVER_MESSAGE (object);

	switch (prop_id) {
	case PROP_TLS_PEER_CERTIFICATE:
		g_value_set_object (value, msg->tls_peer_certificate);
		break;
	case PROP_TLS_PEER_CERTIFICATE_ERRORS:
		g_value_set_flags (value, msg->tls_peer_certificate_errors);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_server_message_class_init (SoupServerMessageClass *klass)
{
        GObjectClass *object_class = G_OBJECT_CLASS (klass);

        object_class->finalize = soup_server_message_finalize;
        object_class->get_property = soup_server_message_get_property;

        /**
         * SoupServerMessage::wrote-informational:
         * @msg: the message
         *
         * Emitted immediately after writing a 1xx (Informational) response.
         */
        signals[WROTE_INFORMATIONAL] =
                g_signal_new ("wrote-informational",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::wrote-headers:
         * @msg: the message
         *
         * Emitted immediately after writing the response headers for a
         * message.
         */
        signals[WROTE_HEADERS] =
                g_signal_new ("wrote-headers",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::wrote-chunk:
         * @msg: the message
         *
         * Emitted immediately after writing a body chunk for a message.
         *
         * Note that this signal is not parallel to
         * [signal@ServerMessage::got-chunk]; it is emitted only when a complete
         * chunk (added with [method@MessageBody.append] or
         * [method@MessageBody.append_bytes] has been written. To get
         * more useful continuous progress information, use
         * [signal@ServerMessage::wrote-body-data].
         */
        signals[WROTE_CHUNK] =
                g_signal_new ("wrote-chunk",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::wrote-body-data:
         * @msg: the message
         * @chunk_size: the number of bytes written
         *
         * Emitted immediately after writing a portion of the message
         * body to the network.
         */
        signals[WROTE_BODY_DATA] =
                g_signal_new ("wrote-body-data",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 1,
                              G_TYPE_UINT);

        /**
         * SoupServerMessage::wrote-body:
         * @msg: the message
         *
         * Emitted immediately after writing the complete response body for a
         * message.
         */
        signals[WROTE_BODY] =
                g_signal_new ("wrote-body",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::got-headers:
         * @msg: the message
         *
         * Emitted after receiving the Request-Line and request headers.
         */
        signals[GOT_HEADERS] =
                g_signal_new ("got-headers",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::got-chunk:
         * @msg: the message
         * @chunk: the just-read chunk
         *
         * Emitted after receiving a chunk of a message body.
         *
         * Note that "chunk" in this context means any subpiece of the body, not
         * necessarily the specific HTTP 1.1 chunks sent by the other side.
         */
        signals[GOT_CHUNK] =
                g_signal_new ("got-chunk",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_FIRST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 1,
                              G_TYPE_BYTES);

        /**
         * SoupServerMessage::got-body:
         * @msg: the message
         *
         * Emitted after receiving the complete request body.
         */
        signals[GOT_BODY] =
                g_signal_new ("got-body",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::finished:
         * @msg: the message
         *
         * Emitted when all HTTP processing is finished for a message.
         * (After [signal@ServerMessage::wrote-body]).
         */
        signals[FINISHED] =
                g_signal_new ("finished",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

        /**
         * SoupServerMessage::disconnected:
         * @msg: the message
         *
         * Emitted when the @msg's socket is disconnected.
         */
        signals[DISCONNECTED] =
                g_signal_new ("disconnected",
                              G_OBJECT_CLASS_TYPE (object_class),
                              G_SIGNAL_RUN_LAST,
                              0,
                              NULL, NULL,
                              NULL,
                              G_TYPE_NONE, 0);

	/**
	 * SoupServerMessage::accept-certificate:
	 * @msg: the message
	 * @tls_peer_certificate: the peer's #GTlsCertificate
	 * @tls_peer_errors: the tls errors of @tls_certificate
	 *
	 * Emitted during the @msg's connection TLS handshake
	 * after client TLS certificate has been received.
	 * You can return %TRUE to accept @tls_certificate despite
	 * @tls_errors.
	 *
	 * Returns: %TRUE to accept the TLS certificate and stop other
	 *   handlers from being invoked, or %FALSE to propagate the
	 *   event further.
	 */
	signals[ACCEPT_CERTIFICATE] =
		g_signal_new ("accept-certificate",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0,
			      g_signal_accumulator_true_handled, NULL,
			      NULL,
			      G_TYPE_BOOLEAN, 2,
			      G_TYPE_TLS_CERTIFICATE,
			      G_TYPE_TLS_CERTIFICATE_FLAGS);

	/**
	 * SoupServerMessage:tls-peer-certificate:
	 *
	 * The peer's #GTlsCertificate associated with the message
	 *
	 * Since: 3.2
	 */
        properties[PROP_TLS_PEER_CERTIFICATE] =
		g_param_spec_object ("tls-peer-certificate",
				     "TLS Peer Certificate",
				     "The TLS peer certificate associated with the message",
				     G_TYPE_TLS_CERTIFICATE,
				     G_PARAM_READABLE |
				     G_PARAM_STATIC_STRINGS);

	/**
	 * SoupServerMessage:tls-peer-certificate-errors:
	 *
	 * The verification errors on #SoupServerMessage:tls-peer-certificate
	 *
	 * Since: 3.2
	 */
        properties[PROP_TLS_PEER_CERTIFICATE_ERRORS] =
		g_param_spec_flags ("tls-peer-certificate-errors",
				    "TLS Peer Certificate Errors",
				    "The verification errors on the message's TLS peer certificate",
				    G_TYPE_TLS_CERTIFICATE_FLAGS, 0,
				    G_PARAM_READABLE |
				    G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

static void
socket_disconnected (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[DISCONNECTED], 0);
}

static gboolean
socket_accept_certificate (SoupServerMessage    *msg,
                           GTlsCertificate      *tls_certificate,
                           GTlsCertificateFlags *tls_errors)
{
	gboolean accept = FALSE;

	g_signal_emit (msg, signals[ACCEPT_CERTIFICATE], 0,
		       tls_certificate, tls_errors, &accept);
	return accept;
}

static void
soup_server_message_set_tls_peer_certificate (SoupServerMessage   *msg,
                                              GTlsCertificate     *tls_certificate,
                                              GTlsCertificateFlags tls_errors)
{
        if (msg->tls_peer_certificate == tls_certificate && msg->tls_peer_certificate_errors == tls_errors)
                return;

        g_clear_object (&msg->tls_peer_certificate);
        msg->tls_peer_certificate = tls_certificate ? g_object_ref (tls_certificate) : NULL;
        msg->tls_peer_certificate_errors = tls_errors;
        g_object_notify_by_pspec (G_OBJECT (msg), properties[PROP_TLS_PEER_CERTIFICATE]);
        g_object_notify_by_pspec (G_OBJECT (msg), properties[PROP_TLS_PEER_CERTIFICATE_ERRORS]);
}

static void
re_emit_tls_certificate_changed (SoupServerMessage *msg,
                                 GParamSpec        *pspec,
                                 SoupSocket        *sock)
{
        soup_server_message_set_tls_peer_certificate (msg,
                                                      soup_socket_get_tls_certificate (sock),
                                                      soup_socket_get_tls_certificate_errors (sock));
}

SoupServerMessage *
soup_server_message_new (SoupSocket *sock)
{
        SoupServerMessage *msg;

        msg = g_object_new (SOUP_TYPE_SERVER_MESSAGE, NULL);
        msg->sock = g_object_ref (sock);
        msg->gsock = soup_socket_get_gsocket (sock);
        if (msg->gsock)
                g_object_ref (msg->gsock);

        g_signal_connect_object (sock, "disconnected",
                                 G_CALLBACK (socket_disconnected),
                                 msg, G_CONNECT_SWAPPED);
        g_signal_connect_object (sock, "accept-certificate",
                                 G_CALLBACK (socket_accept_certificate),
                                 msg, G_CONNECT_SWAPPED);
        g_signal_connect_object (sock, "notify::tls-certificate",
                                 G_CALLBACK (re_emit_tls_certificate_changed),
                                 msg, G_CONNECT_SWAPPED);

        return msg;
}

void
soup_server_message_set_uri (SoupServerMessage *msg,
                             GUri              *uri)
{
        if (msg->uri)
                g_uri_unref (msg->uri);
        msg->uri = soup_uri_copy_with_normalized_flags (uri);
}

SoupSocket *
soup_server_message_get_soup_socket (SoupServerMessage *msg)
{
        return msg->sock;
}

void
soup_server_message_set_auth (SoupServerMessage *msg,
                              SoupAuthDomain    *domain,
                              char              *user)
{
        if (msg->auth_domain)
                g_object_unref (msg->auth_domain);
        msg->auth_domain = domain;

        if (msg->auth_user)
                g_free (msg->auth_user);
        msg->auth_user = user;
}

gboolean
soup_server_message_is_keepalive (SoupServerMessage *msg)
{
        if (msg->status_code == SOUP_STATUS_OK && msg->method == SOUP_METHOD_CONNECT)
                return TRUE;

        /* Not persistent if the server sent a terminate-by-EOF response */
        if (soup_message_headers_get_encoding (msg->response_headers) == SOUP_ENCODING_EOF)
                return FALSE;

        if (msg->http_version == SOUP_HTTP_1_0) {
                /* In theory, HTTP/1.0 connections are only persistent
                 * if the client requests it, and the server agrees.
                 * But some servers do keep-alive even if the client
                 * doesn't request it. So ignore c_conn.
                 */

                if (!soup_message_headers_header_contains_common (msg->response_headers,
                                                                  SOUP_HEADER_CONNECTION,
                                                                  "Keep-Alive"))
                        return FALSE;
        } else {
                /* Normally persistent unless either side requested otherwise */
                if (soup_message_headers_header_contains_common (msg->request_headers,
                                                                 SOUP_HEADER_CONNECTION,
                                                                 "close") ||
                    soup_message_headers_header_contains_common (msg->response_headers,
                                                                 SOUP_HEADER_CONNECTION,
                                                                 "close"))
                        return FALSE;

                return TRUE;
        }

        return TRUE;
}

void
soup_server_message_set_io_data (SoupServerMessage       *msg,
                                 SoupServerMessageIOData *io)
{
        soup_server_message_io_data_free (msg->io_data);
        msg->io_data = io;
}

SoupServerMessageIOData *
soup_server_message_get_io_data (SoupServerMessage *msg)
{
        return msg->io_data;
}

void
soup_server_message_cleanup_response (SoupServerMessage *msg)
{
        soup_message_body_truncate (msg->response_body);
        soup_message_headers_clear (msg->response_headers);
        soup_message_headers_set_encoding (msg->response_headers,
                                           SOUP_ENCODING_CONTENT_LENGTH);
        msg->status_code = SOUP_STATUS_NONE;
        g_clear_pointer (&msg->reason_phrase, g_free);
        msg->http_version = msg->orig_http_version;
}

void
soup_server_message_wrote_informational (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[WROTE_INFORMATIONAL], 0);
}

void
soup_server_message_wrote_headers (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[WROTE_HEADERS], 0);
}

void
soup_server_message_wrote_chunk (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[WROTE_CHUNK], 0);
}

void
soup_server_message_wrote_body_data (SoupServerMessage *msg,
                                     gsize              chunk_size)
{
        g_signal_emit (msg, signals[WROTE_BODY_DATA], 0, chunk_size);
}

void
soup_server_message_wrote_body (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[WROTE_BODY], 0);
}

void
soup_server_message_got_headers (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[GOT_HEADERS], 0);
}

void
soup_server_message_got_chunk (SoupServerMessage *msg,
                               GBytes            *chunk)
{
        g_signal_emit (msg, signals[GOT_CHUNK], 0, chunk);
}

void
soup_server_message_got_body (SoupServerMessage *msg)
{
        if (soup_message_body_get_accumulate (msg->request_body))
                g_bytes_unref (soup_message_body_flatten (msg->request_body));
        g_signal_emit (msg, signals[GOT_BODY], 0);
}

void
soup_server_message_finished (SoupServerMessage *msg)
{
        g_signal_emit (msg, signals[FINISHED], 0);
}

/**
 * soup_server_message_get_request_headers:
 * @msg: a #SoupServerMessage
 *
 * Get the request headers of @msg.
 *
 * Returns: (transfer none): a #SoupMessageHeaders with the request headers.
 */
SoupMessageHeaders *
soup_server_message_get_request_headers (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->request_headers;
}

/**
 * soup_server_message_get_response_headers:
 * @msg: a #SoupServerMessage
 *
 * Get the response headers of @msg.
 *
 * Returns: (transfer none): a #SoupMessageHeaders with the response headers.
 */
SoupMessageHeaders *
soup_server_message_get_response_headers (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->response_headers;
}

/**
 * soup_server_message_get_request_body:
 * @msg: a #SoupServerMessage
 *
 * Get the request body of @msg.
 *
 * Returns: (transfer none): a #SoupMessageBody.
 */
SoupMessageBody *
soup_server_message_get_request_body (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->request_body;
}

/**
 * soup_server_message_get_response_body:
 * @msg: a #SoupServerMessage
 *
 * Get the response body of @msg.
 *
 * Returns: (transfer none): a #SoupMessageBody.
 */
SoupMessageBody *
soup_server_message_get_response_body (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->response_body;
}

/**
 * soup_server_message_get_method:
 * @msg: a #SoupServerMessage
 *
 * Get the HTTP method of @msg.
 *
 * Returns: the HTTP method.
 */
const char *
soup_server_message_get_method (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->method;
}

void
soup_server_message_set_method (SoupServerMessage *msg,
                                const char        *method)
{
        msg->method = g_intern_string (method);
}

void
soup_server_message_set_options_ping (SoupServerMessage *msg,
                                      gboolean           is_options_ping)
{
        msg->options_ping = is_options_ping;
}

/**
 * soup_server_message_is_options_ping:
 * @msg: a #SoupServerMessage
 *
 * Gets if @msg represents an OPTIONS message with the path `*`.
 * 
 * Returns: %TRUE if is an OPTIONS ping
 */
gboolean
soup_server_message_is_options_ping (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), FALSE);

        return msg->options_ping;
}

/**
 * soup_server_message_get_http_version:
 * @msg: a #SoupServerMessage
 *
 * Get the HTTP version of @msg.
 *
 * Returns: a #SoupHTTPVersion.
 */
SoupHTTPVersion
soup_server_message_get_http_version (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), SOUP_HTTP_1_1);

        return msg->http_version;
}

/**
 * soup_server_message_set_http_version:
 * @msg: a #SoupServerMessage
 * @version: a #SoupHTTPVersion
 *
 * Set the HTTP version of @msg.
 */
void
soup_server_message_set_http_version (SoupServerMessage *msg,
                                      SoupHTTPVersion    version)
{
        g_return_if_fail (SOUP_IS_SERVER_MESSAGE (msg));

        msg->http_version = version;
        if (msg->status_code == SOUP_STATUS_NONE)
                msg->orig_http_version = version;
}

/**
 * soup_server_message_get_reason_phrase:
 * @msg: a #SoupServerMessage:
 *
 * Get the HTTP reason phrase of @msg.
 *
 * Returns: (nullable): the reason phrase.
 */
const char *
soup_server_message_get_reason_phrase (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->reason_phrase;
}

/**
 * soup_server_message_get_status:
 * @msg: a #SoupServerMessage
 *
 * Get the HTTP status code of @msg.
 *
 * Returns: the HTTP status code.
 */
guint
soup_server_message_get_status (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), 0);

        return msg->status_code;
}

/**
 * soup_server_message_set_status:
 * @msg: a #SoupServerMessage
 * @status_code: an HTTP status code
 * @reason_phrase: (nullable): a reason phrase
 *
 * Sets @msg's status code to @status_code.
 *
 * If @status_code is a known value and @reason_phrase is %NULL, the
 * reason_phrase will be set automatically.
 **/
void
soup_server_message_set_status (SoupServerMessage *msg,
                                guint              status_code,
                                const char        *reason_phrase)
{
        g_return_if_fail (SOUP_IS_SERVER_MESSAGE (msg));
        g_return_if_fail (status_code != 0);

        g_free (msg->reason_phrase);

        msg->status_code = status_code;
        msg->reason_phrase = g_strdup (reason_phrase ? reason_phrase : soup_status_get_phrase (status_code));
}

/**
 * soup_server_message_get_uri:
 * @msg: a #SoupServerMessage
 *
 * Get @msg's URI.
 *
 * Returns: (transfer none): a #GUri
 */
GUri *
soup_server_message_get_uri (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->uri;
}

/**
 * soup_server_message_set_response:
 * @msg: the message
 * @content_type: (nullable): MIME Content-Type of the body
 * @resp_use: a #SoupMemoryUse describing how to handle @resp_body
 * @resp_body: (nullable) (array length=resp_length) (element-type guint8):
 *   a data buffer containing the body of the message response.
 * @resp_length: the byte length of @resp_body.
 *
 * Convenience function to set the response body of a #SoupServerMessage. If
 * @content_type is %NULL, the response body must be empty as well.
 */
void
soup_server_message_set_response (SoupServerMessage *msg,
                                  const char        *content_type,
                                  SoupMemoryUse      resp_use,
                                  const char        *resp_body,
                                  gsize              resp_length)
{
        g_return_if_fail (SOUP_IS_SERVER_MESSAGE (msg));
        g_return_if_fail (content_type != NULL || resp_length == 0);

        if (content_type) {
                g_warn_if_fail (strchr (content_type, '/') != NULL);

                soup_message_headers_replace_common (msg->response_headers,
                                                     SOUP_HEADER_CONTENT_TYPE,
                                                     content_type);
                soup_message_body_append (msg->response_body, resp_use,
                                          resp_body, resp_length);
        } else {
                soup_message_headers_remove_common (msg->response_headers,
                                                    SOUP_HEADER_CONTENT_TYPE);
                soup_message_body_truncate (msg->response_body);
        }
}

/**
 * soup_server_message_set_redirect:
 * @msg: a #SoupServerMessage
 * @status_code: a 3xx status code
 * @redirect_uri: the URI to redirect @msg to
 *
 * Sets @msg's status_code to @status_code and adds a Location header
 * pointing to @redirect_uri. Use this from a [class@Server] when you
 * want to redirect the client to another URI.
 *
 * @redirect_uri can be a relative URI, in which case it is
 * interpreted relative to @msg's current URI. In particular, if
 * @redirect_uri is just a path, it will replace the path
 * *and query* of @msg's URI.
 */
void
soup_server_message_set_redirect (SoupServerMessage *msg,
                                  guint              status_code,
                                  const char        *redirect_uri)
{
	GUri *location;
	char *location_str;

        g_return_if_fail (SOUP_IS_SERVER_MESSAGE (msg));

	location = g_uri_parse_relative (soup_server_message_get_uri (msg), redirect_uri, SOUP_HTTP_URI_FLAGS, NULL);
	g_return_if_fail (location != NULL);

	soup_server_message_set_status (msg, status_code, NULL);
	location_str = g_uri_to_string (location);
	soup_message_headers_replace_common (msg->response_headers, SOUP_HEADER_LOCATION,
                                             location_str);
	g_free (location_str);
	g_uri_unref (location);
}

/**
 * soup_server_message_get_socket:
 * @msg: a #SoupServerMessage
 *
 * Retrieves the [class@Gio.Socket] that @msg is associated with.
 *
 * If you are using this method to observe when multiple requests are
 * made on the same persistent HTTP connection (eg, as the ntlm-test
 * test program does), you will need to pay attention to socket
 * destruction as well (eg, by using weak references), so that you do
 * not get fooled when the allocator reuses the memory address of a
 * previously-destroyed socket to represent a new socket.
 *
 * Returns: (nullable) (transfer none): the #GSocket that @msg is
 *   associated with, %NULL if you used [method@Server.accept_iostream].
 */
GSocket *
soup_server_message_get_socket (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->gsock;
}

/**
 * soup_server_message_get_remote_address:
 * @msg: a #SoupServerMessage
 *
 * Retrieves the [class@Gio.SocketAddress] associated with the remote end
 * of a connection.
 *
 * Returns: (nullable) (transfer none): the #GSocketAddress
 *   associated with the remote end of a connection, it may be
 *   %NULL if you used [class@Server.accept_iostream].
 */
GSocketAddress *
soup_server_message_get_remote_address (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        if (msg->remote_addr)
                return msg->remote_addr;

        msg->remote_addr = msg->gsock ?
                g_socket_get_remote_address (msg->gsock, NULL) :
                G_SOCKET_ADDRESS (g_object_ref (soup_socket_get_remote_address (msg->sock)));

        return msg->remote_addr;
}

/**
 * soup_server_message_get_local_address:
 * @msg: a #SoupServerMessage
 *
 * Retrieves the [class@Gio.SocketAddress] associated with the local end
 * of a connection.
 *
 * Returns: (nullable) (transfer none): the #GSocketAddress
 *   associated with the local end of a connection, it may be
 *   %NULL if you used [method@Server.accept_iostream].
 */
GSocketAddress *
soup_server_message_get_local_address (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        if (msg->local_addr)
                return msg->local_addr;

        msg->local_addr = msg->gsock ?
                g_socket_get_local_address (msg->gsock, NULL) :
                G_SOCKET_ADDRESS (g_object_ref (soup_socket_get_local_address (msg->sock)));

        return msg->local_addr;
}

/**
 * soup_server_message_get_remote_host:
 * @msg: a #SoupServerMessage
 *
 * Retrieves the IP address associated with the remote end of a
 * connection.
 *
 * Returns: (nullable): the IP address associated with the remote
 *   end of a connection, it may be %NULL if you used
 *   [method@Server.accept_iostream].
 */
const char *
soup_server_message_get_remote_host (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        if (msg->remote_ip)
                return msg->remote_ip;

        if (msg->gsock) {
                GSocketAddress *addr = soup_server_message_get_remote_address (msg);
                GInetAddress *iaddr;

                if (!addr || !G_IS_INET_SOCKET_ADDRESS (addr))
                        return NULL;
                iaddr = g_inet_socket_address_get_address (G_INET_SOCKET_ADDRESS (addr));
                msg->remote_ip = g_inet_address_to_string (iaddr);
        } else {
                GInetSocketAddress *addr = G_INET_SOCKET_ADDRESS (soup_socket_get_remote_address (msg->sock));
                GInetAddress *inet_addr = g_inet_socket_address_get_address (addr);
                msg->remote_ip = g_inet_address_to_string (inet_addr);
        }

        return msg->remote_ip;
}

/**
 * soup_server_message_steal_connection:
 * @msg: a #SoupServerMessage
 *
 * "Steals" the HTTP connection associated with @msg from its #SoupServer. This
 * happens immediately, regardless of the current state of the connection; if
 * the response to @msg has not yet finished being sent, then it will be
 * discarded; you can steal the connection from a
 * [signal@ServerMessage::wrote-informational] or
 * [signal@ServerMessage::wrote-body] signal handler if you need to wait for
 * part or all of the response to be sent.
 *
 * Note that when calling this function from C, @msg will most
 * likely be freed as a side effect.
 *
 * Returns: (transfer full): the #GIOStream formerly associated
 *   with @msg (or %NULL if @msg was no longer associated with a
 *   connection). No guarantees are made about what kind of #GIOStream
 *   is returned.
 */
GIOStream *
soup_server_message_steal_connection (SoupServerMessage *msg)
{
        GIOStream *stream;

        g_object_ref (msg);
        stream = soup_server_message_io_steal (msg);
        if (stream) {
                g_object_set_data_full (G_OBJECT (stream), "GSocket",
                                        soup_socket_steal_gsocket (msg->sock),
                                        g_object_unref);
        }

        g_signal_handlers_disconnect_by_data (msg, msg->sock);

        socket_disconnected (msg);
        g_object_unref (msg);

        return stream;
}

/**
 * soup_server_message_get_tls_peer_certificate:
 * @msg: a #SoupMessage
 *
 * Gets the peer's #GTlsCertificate associated with @msg's connection.
 * Note that this is not set yet during the emission of
 * SoupServerMessage::accept-certificate signal.
 *
 * Returns: (transfer none) (nullable): @msg's TLS peer certificate,
 *    or %NULL if @msg's connection is not SSL.
 *
 * Since: 3.2
 */
GTlsCertificate *
soup_server_message_get_tls_peer_certificate (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), NULL);

        return msg->tls_peer_certificate;
}

/**
 * soup_server_message_get_tls_peer_certificate_errors:
 * @msg: a #SoupMessage
 *
 * Gets the errors associated with validating @msg's TLS peer certificate.
 * Note that this is not set yet during the emission of
 * SoupServerMessage::accept-certificate signal.
 *
 * Returns: a #GTlsCertificateFlags with @msg's TLS peer certificate errors.
 *
 * Since: 3.2
 */
GTlsCertificateFlags
soup_server_message_get_tls_peer_certificate_errors (SoupServerMessage *msg)
{
        g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (msg), 0);

        return msg->tls_peer_certificate_errors;
}
