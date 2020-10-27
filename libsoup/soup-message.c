/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: HTTP request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-message.h"
#include "soup.h"
#include "soup-connection.h"
#include "soup-message-private.h"

/**
 * SECTION:soup-message
 * @short_description: An HTTP request and response.
 * @see_also: #SoupMessageHeaders
 *
 * A #SoupMessage represents an HTTP message that is being sent or
 * received.
 *
 * You would create a #SoupMessage with soup_message_new() or
 * soup_message_new_from_uri(), set up its
 * fields appropriately, and send it.
 *
 * Note that libsoup's terminology here does not quite match the HTTP
 * specification: in RFC 2616, an "HTTP-message" is
 * <emphasis>either</emphasis> a Request, <emphasis>or</emphasis> a
 * Response. In libsoup, a #SoupMessage combines both the request and
 * the response.
 **/

/**
 * SoupMessage:
 * @method: the HTTP method
 * @status_code: the HTTP status code
 * @reason_phrase: the status phrase associated with @status_code
 * @request_headers: the request headers
 * @response_headers: the response headers
 *
 * Represents an HTTP message being sent or received.
 *
 * @status_code will normally be a #SoupStatus value, eg,
 * %SOUP_STATUS_OK, though of course it might actually be an unknown
 * status code. @reason_phrase is the actual text returned from the
 * server, which may or may not correspond to the "standard"
 * description of @status_code. At any rate, it is almost certainly
 * not localized, and not very descriptive even if it is in the user's
 * language; you should not use @reason_phrase in user-visible
 * messages. Rather, you should look at @status_code, and determine an
 * end-user-appropriate message based on that and on what you were
 * trying to do.
 */

G_DEFINE_TYPE_WITH_PRIVATE (SoupMessage, soup_message, G_TYPE_OBJECT)

enum {
	WROTE_HEADERS,
	WROTE_BODY_DATA,
	WROTE_BODY,

	GOT_INFORMATIONAL,
	GOT_HEADERS,
	GOT_BODY,
	CONTENT_SNIFFED,

	STARTING,
	RESTARTED,
	FINISHED,

	NETWORK_EVENT,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,

	PROP_METHOD,
	PROP_URI,
	PROP_HTTP_VERSION,
	PROP_FLAGS,
	PROP_STATUS_CODE,
	PROP_REASON_PHRASE,
	PROP_FIRST_PARTY,
	PROP_REQUEST_HEADERS,
	PROP_RESPONSE_HEADERS,
	PROP_TLS_CERTIFICATE,
	PROP_TLS_ERRORS,
	PROP_PRIORITY,
	PROP_SITE_FOR_COOKIES,
	PROP_IS_TOP_LEVEL_NAVIGATION,

	LAST_PROP
};

static void
soup_message_init (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	priv->http_version = priv->orig_http_version = SOUP_HTTP_1_1;
	priv->priority = SOUP_MESSAGE_PRIORITY_NORMAL;

	msg->request_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
	msg->response_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
}

static void
soup_message_finalize (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	soup_client_message_io_data_free (priv->io_data);

	g_clear_pointer (&priv->uri, soup_uri_free);
	g_clear_pointer (&priv->first_party, soup_uri_free);
	g_clear_pointer (&priv->site_for_cookies, soup_uri_free);

	g_clear_object (&priv->auth);
	g_clear_object (&priv->proxy_auth);

	g_clear_pointer (&priv->disabled_features, g_hash_table_destroy);

	g_clear_object (&priv->tls_certificate);

	soup_message_headers_free (msg->request_headers);
	soup_message_headers_free (msg->response_headers);
	g_clear_object (&msg->request_body_stream);

	g_free (msg->reason_phrase);

	G_OBJECT_CLASS (soup_message_parent_class)->finalize (object);
}

static void
soup_message_set_property (GObject *object, guint prop_id,
			   const GValue *value, GParamSpec *pspec)
{
	SoupMessage *msg = SOUP_MESSAGE (object);
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	switch (prop_id) {
	case PROP_METHOD:
		msg->method = g_intern_string (g_value_get_string (value));
		break;
	case PROP_URI:
		soup_message_set_uri (msg, g_value_get_boxed (value));
		break;
	case PROP_SITE_FOR_COOKIES:
		soup_message_set_site_for_cookies (msg, g_value_get_boxed (value));
		break;
	case PROP_IS_TOP_LEVEL_NAVIGATION:
		soup_message_set_is_top_level_navigation (msg, g_value_get_boolean (value));
		break;
	case PROP_HTTP_VERSION:
		soup_message_set_http_version (msg, g_value_get_enum (value));
		break;
	case PROP_FLAGS:
		soup_message_set_flags (msg, g_value_get_flags (value));
		break;
	case PROP_STATUS_CODE:
		soup_message_set_status (msg, g_value_get_uint (value));
		break;
	case PROP_REASON_PHRASE:
		soup_message_set_status_full (msg, msg->status_code,
					      g_value_get_string (value));
		break;
	case PROP_FIRST_PARTY:
		soup_message_set_first_party (msg, g_value_get_boxed (value));
		break;
	case PROP_TLS_CERTIFICATE:
		if (priv->tls_certificate)
			g_object_unref (priv->tls_certificate);
		priv->tls_certificate = g_value_dup_object (value);
		if (priv->tls_errors)
			priv->msg_flags &= ~SOUP_MESSAGE_CERTIFICATE_TRUSTED;
		else if (priv->tls_certificate)
			priv->msg_flags |= SOUP_MESSAGE_CERTIFICATE_TRUSTED;
		break;
	case PROP_TLS_ERRORS:
		priv->tls_errors = g_value_get_flags (value);
		if (priv->tls_errors)
			priv->msg_flags &= ~SOUP_MESSAGE_CERTIFICATE_TRUSTED;
		else if (priv->tls_certificate)
			priv->msg_flags |= SOUP_MESSAGE_CERTIFICATE_TRUSTED;
		break;
	case PROP_PRIORITY:
		priv->priority = g_value_get_enum (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_message_get_property (GObject *object, guint prop_id,
			   GValue *value, GParamSpec *pspec)
{
	SoupMessage *msg = SOUP_MESSAGE (object);
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, msg->method);
		break;
	case PROP_URI:
		g_value_set_boxed (value, priv->uri);
		break;
	case PROP_SITE_FOR_COOKIES:
		g_value_set_boxed (value, priv->site_for_cookies);
		break;
	case PROP_IS_TOP_LEVEL_NAVIGATION:
		g_value_set_boolean (value, priv->is_top_level_navigation);
		break;
	case PROP_HTTP_VERSION:
		g_value_set_enum (value, priv->http_version);
		break;
	case PROP_FLAGS:
		g_value_set_flags (value, priv->msg_flags);
		break;
	case PROP_STATUS_CODE:
		g_value_set_uint (value, msg->status_code);
		break;
	case PROP_REASON_PHRASE:
		g_value_set_string (value, msg->reason_phrase);
		break;
	case PROP_FIRST_PARTY:
		g_value_set_boxed (value, priv->first_party);
		break;
	case PROP_REQUEST_HEADERS:
		g_value_set_boxed (value, msg->request_headers);
		break;
	case PROP_RESPONSE_HEADERS:
		g_value_set_boxed (value, msg->response_headers);
		break;
	case PROP_TLS_CERTIFICATE:
		g_value_set_object (value, priv->tls_certificate);
		break;
	case PROP_TLS_ERRORS:
		g_value_set_flags (value, priv->tls_errors);
		break;
	case PROP_PRIORITY:
		g_value_set_enum (value, priv->priority);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_message_class_init (SoupMessageClass *message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (message_class);

	/* virtual method override */
	object_class->finalize = soup_message_finalize;
	object_class->set_property = soup_message_set_property;
	object_class->get_property = soup_message_get_property;

	/* signals */

	/**
	 * SoupMessage::wrote-headers:
	 * @msg: the message
	 *
	 * Emitted immediately after writing the request headers for a
	 * message.
	 **/
	signals[WROTE_HEADERS] =
		g_signal_new ("wrote_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_headers),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::wrote-body-data:
	 * @msg: the message
	 * @chunk: the data written
	 *
	 * Emitted immediately after writing a portion of the message
	 * body to the network.
	 *
	 * Since: 2.24
	 **/
	signals[WROTE_BODY_DATA] =
		g_signal_new ("wrote_body_data",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0, /* FIXME after next ABI break */
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 1,
			      G_TYPE_BYTES);

	/**
	 * SoupMessage::wrote-body:
	 * @msg: the message
	 *
	 * Emitted immediately after writing the complete body for a
	 * message.
	 **/
	signals[WROTE_BODY] =
		g_signal_new ("wrote_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_body),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-informational:
	 * @msg: the message
	 *
	 * Emitted after receiving a 1xx (Informational) response for
	 * a (client-side) message. The response_headers will be
	 * filled in with the headers associated with the
	 * informational response; however, those header values will
	 * be erased after this signal is done.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * then the current HTTP I/O will be stopped after this signal
	 * emission finished, and @msg's connection will be closed.
	 **/
	signals[GOT_INFORMATIONAL] =
		g_signal_new ("got_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_informational),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-headers:
	 * @msg: the message
	 *
	 * Emitted after receiving the Status-Line and response headers.
	 *
	 * See also soup_message_add_header_handler() and
	 * soup_message_add_status_code_handler(), which can be used
	 * to connect to a subset of emissions of this signal.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * then the current HTTP I/O will be stopped after this signal
	 * emission finished, and @msg's connection will be closed.
	 * (If you need to requeue a message--eg, after handling
	 * authentication or redirection--it is usually better to
	 * requeue it from a #SoupMessage::got_body handler rather
	 * than a #SoupMessage::got_headers handler, so that the
	 * existing HTTP connection can be reused.)
	 **/
	signals[GOT_HEADERS] =
		g_signal_new ("got_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_headers),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-body:
	 * @msg: the message
	 *
	 * Emitted after receiving the complete message request body.
	 *
	 * See also soup_message_add_header_handler() and
	 * soup_message_add_status_code_handler(), which can be used
	 * to connect to a subset of emissions of this signal.
	 **/
	signals[GOT_BODY] =
		g_signal_new ("got_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_body),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::content-sniffed:
	 * @msg: the message
	 * @type: the content type that we got from sniffing
	 * @params: (element-type utf8 utf8): a #GHashTable with the parameters
	 *
	 * This signal is emitted after #SoupMessage::got-headers, and
	 * before the first #SoupMessage::got-chunk. If content
	 * sniffing is disabled, or no content sniffing will be
	 * performed, due to the sniffer deciding to trust the
	 * Content-Type sent by the server, this signal is emitted
	 * immediately after #SoupMessage::got-headers, and @type is
	 * %NULL.
	 *
	 * If the #SoupContentSniffer feature is enabled, and the
	 * sniffer decided to perform sniffing, the first
	 * #SoupMessage::got-chunk emission may be delayed, so that the
	 * sniffer has enough data to correctly sniff the content. It
	 * notified the library user that the content has been
	 * sniffed, and allows it to change the header contents in the
	 * message, if desired.
	 *
	 * After this signal is emitted, the data that was spooled so
	 * that sniffing could be done is delivered on the first
	 * emission of #SoupMessage::got-chunk.
	 *
	 * Since: 2.28
	 **/
	signals[CONTENT_SNIFFED] =
		g_signal_new ("content_sniffed",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      G_TYPE_STRING,
			      G_TYPE_HASH_TABLE);

	/**
	 * SoupMessage::starting:
	 * @msg: the message
	 *
	 * Emitted just before a message is sent.
	 *
	 * Since: 2.50
	 */
	signals[STARTING] =
		g_signal_new ("starting",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, starting),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::restarted:
	 * @msg: the message
	 *
	 * Emitted when a request that was already sent once is now
	 * being sent again (eg, because the first attempt received a
	 * redirection response, or because we needed to use
	 * authentication).
	 **/
	signals[RESTARTED] =
		g_signal_new ("restarted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, restarted),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::finished:
	 * @msg: the message
	 *
	 * Emitted when all HTTP processing is finished for a message.
	 * (After #SoupMessage::got_body).
	 **/
	signals[FINISHED] =
		g_signal_new ("finished",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, finished),
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::network-event:
	 * @msg: the message
	 * @event: the network event
	 * @connection: the current state of the network connection
	 *
	 * Emitted to indicate that some network-related event
	 * related to @msg has occurred. This essentially proxies the
	 * #GSocketClient::event signal, but only for events that
	 * occur while @msg "owns" the connection; if @msg is sent on
	 * an existing persistent connection, then this signal will
	 * not be emitted. (If you want to force the message to be
	 * sent on a new connection, set the
	 * %SOUP_MESSAGE_NEW_CONNECTION flag on it.)
	 *
	 * See #GSocketClient::event for more information on what
	 * the different values of @event correspond to, and what
	 * @connection will be in each case.
	 *
	 * Since: 2.38
	 **/
	signals[NETWORK_EVENT] =
		g_signal_new ("network_event",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      0,
			      NULL, NULL,
			      NULL,
			      G_TYPE_NONE, 2,
			      G_TYPE_SOCKET_CLIENT_EVENT,
			      G_TYPE_IO_STREAM);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_METHOD,
		g_param_spec_string ("method",
				     "Method",
				     "The message's HTTP method",
				     SOUP_METHOD_GET,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_URI,
		g_param_spec_boxed ("uri",
				    "URI",
				    "The message's Request-URI",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_HTTP_VERSION,
		g_param_spec_enum ("http-version",
				   "HTTP Version",
				   "The HTTP protocol version to use",
				   SOUP_TYPE_HTTP_VERSION,
				   SOUP_HTTP_1_1,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_FLAGS,
		g_param_spec_flags ("flags",
				    "Flags",
				    "Various message options",
				    SOUP_TYPE_MESSAGE_FLAGS,
				    0,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_STATUS_CODE,
		g_param_spec_uint ("status-code",
				   "Status code",
				   "The HTTP response status code",
				   0, 999, 0,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_REASON_PHRASE,
		g_param_spec_string ("reason-phrase",
				     "Reason phrase",
				     "The HTTP response reason phrase",
				     NULL,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupMessage:first-party:
	 *
	 * The #SoupURI loaded in the application when the message was
	 * queued.
	 *
	 * Since: 2.30
	 */
	g_object_class_install_property (
		object_class, PROP_FIRST_PARTY,
		g_param_spec_boxed ("first-party",
				    "First party",
				    "The URI loaded in the application when the message was requested.",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 * SoupMessage:site-for-cookkies:
	 *
	 * Site used to compare cookies against. Used for SameSite cookie support.
	 *
	 * Since: 2.70
	 */
	g_object_class_install_property (
		object_class, PROP_SITE_FOR_COOKIES,
		g_param_spec_boxed ("site-for-cookies",
				    "Site for cookies",
				    "The URI for the site to compare cookies against",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE));
	/**
	 * SoupMessage:is-top-level-navigation:
	 *
	 * Set when the message is navigating between top level domains.
	 *
	 * Since: 2.70
	 */
	g_object_class_install_property (
		object_class, PROP_IS_TOP_LEVEL_NAVIGATION,
		g_param_spec_boolean ("is-top-level-navigation",
				     "Is top-level navigation",
				     "If the current messsage is navigating between top-levels",
				     FALSE,
				     G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_REQUEST_HEADERS,
		g_param_spec_boxed ("request-headers",
				    "Request Headers",
				    "The HTTP request headers",
				    SOUP_TYPE_MESSAGE_HEADERS,
				    G_PARAM_READABLE |
				    G_PARAM_STATIC_STRINGS));
	g_object_class_install_property (
		object_class, PROP_RESPONSE_HEADERS,
		g_param_spec_boxed ("response-headers",
				    "Response Headers",
				     "The HTTP response headers",
				    SOUP_TYPE_MESSAGE_HEADERS,
				    G_PARAM_READABLE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 * SoupMessage:tls-certificate:
	 *
	 * The #GTlsCertificate associated with the message
	 *
	 * Since: 2.34
	 */	 
	g_object_class_install_property (
		object_class, PROP_TLS_CERTIFICATE,
		g_param_spec_object ("tls-certificate",
				     "TLS Certificate",
				     "The TLS certificate associated with the message",
				     G_TYPE_TLS_CERTIFICATE,
				     G_PARAM_READWRITE |
				     G_PARAM_STATIC_STRINGS));
	/**
	 * SoupMessage:tls-errors:
	 *
	 * The verification errors on #SoupMessage:tls-certificate
	 *
	 * Since: 2.34
	 */	 
	g_object_class_install_property (
		object_class, PROP_TLS_ERRORS,
		g_param_spec_flags ("tls-errors",
				    "TLS Errors",
				    "The verification errors on the message's TLS certificate",
				    G_TYPE_TLS_CERTIFICATE_FLAGS, 0,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS));
	/**
	 SoupMessage:priority:
	 *
	 * Sets the priority of the #SoupMessage. See
	 * soup_message_set_priority() for further details.
	 *
	 * Since: 2.44
	 **/
	g_object_class_install_property (
		object_class, PROP_PRIORITY,
		g_param_spec_enum ("priority",
				   "Priority",
				   "The priority of the message",
				   SOUP_TYPE_MESSAGE_PRIORITY,
				   SOUP_MESSAGE_PRIORITY_NORMAL,
				   G_PARAM_READWRITE |
				   G_PARAM_STATIC_STRINGS));
}


/**
 * soup_message_new:
 * @method: the HTTP method for the created request
 * @uri_string: the destination endpoint (as a string)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: (nullable): the new #SoupMessage (or %NULL if @uri
 * could not be parsed).
 */
SoupMessage *
soup_message_new (const char *method, const char *uri_string)
{
	SoupMessage *msg;
	SoupURI *uri;

	g_return_val_if_fail (method != NULL, NULL);
	g_return_val_if_fail (uri_string != NULL, NULL);

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;
	if (!uri->host) {
		soup_uri_free (uri);
		return NULL;
	}

	msg = soup_message_new_from_uri (method, uri);
	soup_uri_free (uri);
	return msg;
}

/**
 * soup_message_new_from_uri:
 * @method: the HTTP method for the created request
 * @uri: the destination endpoint (as a #SoupURI)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage
 */
SoupMessage *
soup_message_new_from_uri (const char *method, SoupURI *uri)
{
	return g_object_new (SOUP_TYPE_MESSAGE,
			     "method", method,
			     "uri", uri,
			     NULL);
}

/**
 * soup_message_set_request_body:
 * @msg: the message
 * @content_type: (allow-none): MIME Content-Type of the body
 * @stream: (allow-none): a #GInputStream to read the request body from
 * @content_length: the byte length of @tream or -1 if unknown
 *
 * Set the request body of a #SoupMessage. If
 * @content_type is %NULL, the request body must be empty (or @stream %NULL) as well.
 * The request body needs to be set again in case @msg is restarted
 * (in case of redirection or authentication).
 */
void
soup_message_set_request_body (SoupMessage  *msg,
                               const char   *content_type,
                               GInputStream *stream,
                               gssize        content_length)
{
        g_return_if_fail (SOUP_IS_MESSAGE (msg));
        g_return_if_fail (content_type != NULL || content_length == 0);
        g_return_if_fail (content_type == NULL || G_IS_INPUT_STREAM (stream));

        g_clear_object (&msg->request_body_stream);

        if (content_type) {
                g_warn_if_fail (strchr (content_type, '/') != NULL);

                if (soup_message_headers_get_content_type (msg->request_headers, NULL) != content_type)
                        soup_message_headers_replace (msg->request_headers, "Content-Type", content_type);
                if (content_length == -1)
                        soup_message_headers_set_encoding (msg->request_headers, SOUP_ENCODING_CHUNKED);
                else
                        soup_message_headers_set_content_length (msg->request_headers, content_length);
                msg->request_body_stream = g_object_ref (stream);
        } else {
                soup_message_headers_remove (msg->request_headers, "Content-Type");
                soup_message_headers_remove (msg->request_headers, "Content-Length");
        }
}

/**
 * soup_message_set_request_body_from_bytes:
 * @msg: the message
 * @content_type: (allow-none): MIME Content-Type of the body
 * @bytes: (allow-none): a #GBytes with the request body data
 *
 * Set the request body of a #SoupMessage from #GBytes. If
 * @content_type is %NULL, the request body must be empty (or @bytes %NULL) as well.
 * The request body needs to be set again in case @msg is restarted
 * (in case of redirection or authentication).
 */
void
soup_message_set_request_body_from_bytes (SoupMessage  *msg,
                                          const char   *content_type,
                                          GBytes       *bytes)
{
        g_return_if_fail (SOUP_IS_MESSAGE (msg));
        g_return_if_fail (content_type == NULL || bytes != NULL);
        g_return_if_fail (content_type != NULL || g_bytes_get_size (bytes) == 0);

	if (bytes) {
		GInputStream *stream;

		stream = g_memory_input_stream_new_from_bytes (bytes);
		soup_message_set_request_body (msg, content_type, stream, g_bytes_get_size (bytes));
		g_object_unref (stream);
	} else
		soup_message_set_request_body (msg, NULL, NULL, 0);
}

void
soup_message_wrote_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_HEADERS], 0);
}

void
soup_message_wrote_body_data (SoupMessage *msg, GBytes *chunk)
{
	g_signal_emit (msg, signals[WROTE_BODY_DATA], 0, chunk);
}

void
soup_message_wrote_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_BODY], 0);
}

void
soup_message_got_informational (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_INFORMATIONAL], 0);
}

void
soup_message_got_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_HEADERS], 0);
}

void
soup_message_got_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_BODY], 0);
}

void
soup_message_content_sniffed (SoupMessage *msg, const char *content_type, GHashTable *params)
{
	g_signal_emit (msg, signals[CONTENT_SNIFFED], 0, content_type, params);
}

void
soup_message_starting (SoupMessage *msg)
{
	g_signal_emit (msg, signals[STARTING], 0);
}

void
soup_message_restarted (SoupMessage *msg)
{
	g_clear_object (&msg->request_body_stream);

	g_signal_emit (msg, signals[RESTARTED], 0);
}

void
soup_message_finished (SoupMessage *msg)
{
	g_signal_emit (msg, signals[FINISHED], 0);
}

void
soup_message_network_event (SoupMessage         *msg,
			    GSocketClientEvent   event,
			    GIOStream           *connection)
{
	g_signal_emit (msg, signals[NETWORK_EVENT], 0,
		       event, connection);
}

static void
header_handler_free (gpointer header_name, GClosure *closure)
{
	g_free (header_name);
}

static void
header_handler_metamarshal (GClosure *closure, GValue *return_value,
			    guint n_param_values, const GValue *param_values,
			    gpointer invocation_hint, gpointer marshal_data)
{
	SoupMessage *msg = g_value_get_object (&param_values[0]);
	const char *header_name = marshal_data;

	if (soup_message_headers_get_one (msg->response_headers, header_name)) {
		closure->marshal (closure, return_value, n_param_values,
				  param_values, invocation_hint,
				  ((GCClosure *)closure)->callback);
	}
}

/**
 * soup_message_add_header_handler: (skip)
 * @msg: a #SoupMessage
 * @signal: signal to connect the handler to.
 * @header: HTTP response header to match against
 * @callback: the header handler
 * @user_data: data to pass to @handler_cb
 *
 * Adds a signal handler to @msg for @signal, as with
 * g_signal_connect(), but the @callback will only be run if @msg's
 * incoming messages headers (that is, the <literal>request_headers</literal>)
 * contain a header named @header.
 *
 * Return value: the handler ID from g_signal_connect()
 **/
guint
soup_message_add_header_handler (SoupMessage *msg,
				 const char  *signal,
				 const char  *header,
				 GCallback    callback,
				 gpointer     user_data)
{
	GClosure *closure;
	char *header_name;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);
	g_return_val_if_fail (signal != NULL, 0);
	g_return_val_if_fail (header != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	closure = g_cclosure_new (callback, user_data, NULL);

	header_name = g_strdup (header);
	g_closure_set_meta_marshal (closure, header_name,
				    header_handler_metamarshal);
	g_closure_add_finalize_notifier (closure, header_name,
					 header_handler_free);

	return g_signal_connect_closure (msg, signal, closure, FALSE);
}

static void
status_handler_metamarshal (GClosure *closure, GValue *return_value,
			    guint n_param_values, const GValue *param_values,
			    gpointer invocation_hint, gpointer marshal_data)
{
	SoupMessage *msg = g_value_get_object (&param_values[0]);
	guint status = GPOINTER_TO_UINT (marshal_data);

	if (msg->status_code == status) {
		closure->marshal (closure, return_value, n_param_values,
				  param_values, invocation_hint,
				  ((GCClosure *)closure)->callback);
	}
}

/**
 * soup_message_add_status_code_handler: (skip)
 * @msg: a #SoupMessage
 * @signal: signal to connect the handler to.
 * @status_code: status code to match against
 * @callback: the header handler
 * @user_data: data to pass to @handler_cb
 *
 * Adds a signal handler to @msg for @signal, as with
 * g_signal_connect(), but the @callback will only be run if @msg has
 * the status @status_code.
 *
 * @signal must be a signal that will be emitted after @msg's status
 * is set (this means it can't be a "wrote" signal).
 *
 * Return value: the handler ID from g_signal_connect()
 **/
guint
soup_message_add_status_code_handler (SoupMessage *msg,
				      const char  *signal,
				      guint        status_code,
				      GCallback    callback,
				      gpointer     user_data)
{
	GClosure *closure;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);
	g_return_val_if_fail (signal != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	closure = g_cclosure_new (callback, user_data, NULL);
	g_closure_set_meta_marshal (closure, GUINT_TO_POINTER (status_code),
				    status_handler_metamarshal);

	return g_signal_connect_closure (msg, signal, closure, FALSE);
}

void
soup_message_set_auth (SoupMessage *msg, SoupAuth *auth)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (auth == NULL || SOUP_IS_AUTH (auth));

	priv = soup_message_get_instance_private (msg);

	if (priv->auth == auth)
		return;

	if (priv->auth)
		g_object_unref (priv->auth);
	priv->auth = auth ? g_object_ref (auth) : NULL;
}

SoupAuth *
soup_message_get_auth (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	priv = soup_message_get_instance_private (msg);

	return priv->auth;
}

void
soup_message_set_proxy_auth (SoupMessage *msg, SoupAuth *auth)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (auth == NULL || SOUP_IS_AUTH (auth));

	priv = soup_message_get_instance_private (msg);

	if (priv->proxy_auth == auth)
		return;

	if (priv->proxy_auth)
		g_object_unref (priv->proxy_auth);
	priv->proxy_auth = auth ? g_object_ref (auth) : NULL;
}

SoupAuth *
soup_message_get_proxy_auth (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	priv = soup_message_get_instance_private (msg);

	return priv->proxy_auth;
}

SoupConnection *
soup_message_get_connection (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	return priv->connection;
}

void
soup_message_set_connection (SoupMessage    *msg,
			     SoupConnection *conn)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	priv->connection = conn;
}

/**
 * soup_message_cleanup_response:
 * @msg: a #SoupMessage
 *
 * Cleans up all response data on @msg, so that the request can be sent
 * again and receive a new response. (Eg, as a result of a redirect or
 * authorization request.)
 **/
void
soup_message_cleanup_response (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	soup_message_headers_clear (msg->response_headers);

	priv->msg_flags &= ~SOUP_MESSAGE_CONTENT_DECODED;

	msg->status_code = SOUP_STATUS_NONE;
	if (msg->reason_phrase) {
		g_free (msg->reason_phrase);
		msg->reason_phrase = NULL;
	}
	priv->http_version = priv->orig_http_version;

	g_object_notify (G_OBJECT (msg), "status-code");
	g_object_notify (G_OBJECT (msg), "reason-phrase");
	g_object_notify (G_OBJECT (msg), "http-version");
	g_object_notify (G_OBJECT (msg), "flags");
	g_object_notify (G_OBJECT (msg), "tls-certificate");
	g_object_notify (G_OBJECT (msg), "tls-errors");
}

/**
 * SoupMessageFlags:
 * @SOUP_MESSAGE_NO_REDIRECT: The session should not follow redirect
 *   (3xx) responses received by this message.
 * @SOUP_MESSAGE_CONTENT_DECODED: Set by #SoupContentDecoder to
 *   indicate that it has removed the Content-Encoding on a message (and
 *   so headers such as Content-Length may no longer accurately describe
 *   the body).
 * @SOUP_MESSAGE_CERTIFICATE_TRUSTED: if set after an https response
 *   has been received, indicates that the server's SSL certificate is
 *   trusted according to the session's CA.
 * @SOUP_MESSAGE_NEW_CONNECTION: Requests that the message should be
 *   sent on a newly-created connection, not reusing an existing
 *   persistent connection. Note that messages with non-idempotent
 *   #SoupMessage:method<!-- -->s behave this way by default, unless
 *   #SOUP_MESSAGE_IDEMPOTENT is set.
 * @SOUP_MESSAGE_IDEMPOTENT: The message is considered idempotent,
 *   regardless its #SoupMessage:method, and allows reuse of existing
 *   idle connections, instead of always requiring a new one, unless
 *   #SOUP_MESSAGE_NEW_CONNECTION is set.
 * @SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS: Request that a new connection is
 *   created for the message if there aren't idle connections available
 *   and it's not possible to create new connections due to any of the
 *   connection limits has been reached. If a dedicated connection is
 *   eventually created for this message, it will be dropped when the
 *   message finishes. Since 2.50
 * @SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE: The #SoupAuthManager should not use
 *   the credentials cache for this message, neither to use cached credentials
 *   to automatically authenticate this message nor to cache the credentials
 *   after the message is successfully authenticated. This applies to both server
 *   and proxy authentication. Note that #SoupSession::authenticate signal will
 *   be emitted, if you want to disable authentication for a message use
 *   soup_message_disable_feature() passing #SOUP_TYPE_AUTH_MANAGER instead. Since 2.58
 *
 * Various flags that can be set on a #SoupMessage to alter its
 * behavior.
 **/

/**
 * soup_message_set_flags:
 * @msg: a #SoupMessage
 * @flags: a set of #SoupMessageFlags values
 *
 * Sets the specified flags on @msg.
 **/
void
soup_message_set_flags (SoupMessage *msg, SoupMessageFlags flags)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	priv = soup_message_get_instance_private (msg);

	priv->msg_flags = flags;
	g_object_notify (G_OBJECT (msg), "flags");
}

/**
 * soup_message_get_flags:
 * @msg: a #SoupMessage
 *
 * Gets the flags on @msg
 *
 * Return value: the flags
 **/
SoupMessageFlags
soup_message_get_flags (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);

	priv = soup_message_get_instance_private (msg);

	return priv->msg_flags;
}

/**
 * soup_message_set_http_version:
 * @msg: a #SoupMessage
 * @version: the HTTP version
 *
 * Sets the HTTP version on @msg. The default version is
 * %SOUP_HTTP_1_1. Setting it to %SOUP_HTTP_1_0 will prevent certain
 * functionality from being used.
 **/
void
soup_message_set_http_version (SoupMessage *msg, SoupHTTPVersion version)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	priv = soup_message_get_instance_private (msg);

	priv->http_version = version;
	if (msg->status_code == SOUP_STATUS_NONE)
		priv->orig_http_version = version;
	g_object_notify (G_OBJECT (msg), "http-version");
}

/**
 * soup_message_get_http_version:
 * @msg: a #SoupMessage
 *
 * Gets the HTTP version of @msg. This is the minimum of the
 * version from the request and the version from the response.
 *
 * Return value: the HTTP version
 **/
SoupHTTPVersion
soup_message_get_http_version (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_HTTP_1_0);

	priv = soup_message_get_instance_private (msg);

	return priv->http_version;
}

/**
 * soup_message_is_keepalive:
 * @msg: a #SoupMessage
 *
 * Determines whether or not @msg's connection can be kept alive for
 * further requests after processing @msg, based on the HTTP version,
 * Connection header, etc.
 *
 * Return value: %TRUE or %FALSE.
 **/
gboolean
soup_message_is_keepalive (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	if (msg->status_code == SOUP_STATUS_OK &&
	    msg->method == SOUP_METHOD_CONNECT)
		return TRUE;

	/* Not persistent if the server sent a terminate-by-EOF response */
	if (soup_message_headers_get_encoding (msg->response_headers) == SOUP_ENCODING_EOF)
		return FALSE;

	if (priv->http_version == SOUP_HTTP_1_0) {
		/* In theory, HTTP/1.0 connections are only persistent
		 * if the client requests it, and the server agrees.
		 * But some servers do keep-alive even if the client
		 * doesn't request it. So ignore c_conn.
		 */

		if (!soup_message_headers_header_contains (msg->response_headers,
							   "Connection", "Keep-Alive"))
			return FALSE;
	} else {
		/* Normally persistent unless either side requested otherwise */
		if (soup_message_headers_header_contains (msg->request_headers,
							  "Connection", "close") ||
		    soup_message_headers_header_contains (msg->response_headers,
							  "Connection", "close"))
			return FALSE;

		return TRUE;
	}

	return TRUE;
}

/**
 * soup_message_set_uri:
 * @msg: a #SoupMessage
 * @uri: the new #SoupURI
 *
 * Sets @msg's URI to @uri. If @msg has already been sent and you want
 * to re-send it with the new URI, you need to call
 * soup_session_requeue_message().
 **/
void
soup_message_set_uri (SoupMessage *msg, SoupURI *uri)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	priv = soup_message_get_instance_private (msg);

	if (priv->uri)
		soup_uri_free (priv->uri);
	priv->uri = soup_uri_copy (uri);

	g_object_notify (G_OBJECT (msg), "uri");
}

/**
 * soup_message_get_uri:
 * @msg: a #SoupMessage
 *
 * Gets @msg's URI
 *
 * Return value: (transfer none): the URI @msg is targeted for.
 **/
SoupURI *
soup_message_get_uri (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	priv = soup_message_get_instance_private (msg);

	return priv->uri;
}

/**
 * soup_message_set_status:
 * @msg: a #SoupMessage
 * @status_code: an HTTP status code
 *
 * Sets @msg's status code to @status_code. If @status_code is a
 * known value, it will also set @msg's reason_phrase.
 **/
void
soup_message_set_status (SoupMessage *msg, guint status_code)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (status_code != 0);

	g_free (msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (soup_status_get_phrase (status_code));
	g_object_notify (G_OBJECT (msg), "status-code");
	g_object_notify (G_OBJECT (msg), "reason-phrase");
}

/**
 * soup_message_set_status_full:
 * @msg: a #SoupMessage
 * @status_code: an HTTP status code
 * @reason_phrase: a description of the status
 *
 * Sets @msg's status code and reason phrase.
 **/
void
soup_message_set_status_full (SoupMessage *msg,
			      guint        status_code,
			      const char  *reason_phrase)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (status_code != 0);
	g_return_if_fail (reason_phrase != NULL);

	g_free (msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (reason_phrase);
	g_object_notify (G_OBJECT (msg), "status-code");
	g_object_notify (G_OBJECT (msg), "reason-phrase");
}

/**
 * soup_message_disable_feature:
 * @msg: a #SoupMessage
 * @feature_type: the #GType of a #SoupSessionFeature
 *
 * This disables the actions of #SoupSessionFeature<!-- -->s with the
 * given @feature_type (or a subclass of that type) on @msg, so that
 * @msg is processed as though the feature(s) hadn't been added to the
 * session. Eg, passing #SOUP_TYPE_CONTENT_SNIFFER for @feature_type
 * will disable Content-Type sniffing on the message.
 *
 * You must call this before queueing @msg on a session; calling it on
 * a message that has already been queued is undefined. In particular,
 * you cannot call this on a message that is being requeued after a
 * redirect or authentication.
 *
 * Since: 2.28
 **/
void
soup_message_disable_feature (SoupMessage *msg, GType feature_type)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_message_get_instance_private (msg);

	if (!priv->disabled_features)
		priv->disabled_features = g_hash_table_new (g_direct_hash, g_direct_equal);

	g_hash_table_add (priv->disabled_features, GSIZE_TO_POINTER (feature_type));
}

gboolean
soup_message_disables_feature (SoupMessage *msg, gpointer feature)
{
	SoupMessagePrivate *priv;
        GHashTableIter iter;
        gpointer key;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);

	priv = soup_message_get_instance_private (msg);

        if (!priv->disabled_features)
                return FALSE;

        g_hash_table_iter_init (&iter, priv->disabled_features);
        while (g_hash_table_iter_next (&iter, &key, NULL)) {
                if (G_TYPE_CHECK_INSTANCE_TYPE (feature, GPOINTER_TO_SIZE (key)))
                        return TRUE;
        }
        return FALSE;
}

/**
 * soup_message_is_feature_disabled:
 * @msg: a #SoupMessage
 * @feature_type: the #GType of a #SoupSessionFeature
 *
 * Get whether #SoupSessionFeature<!-- -->s of the given @feature_type
 * (or a subclass of that type) are disabled on @msg.
 * See soup_message_disable_feature().
 *
 * Returns: %TRUE if feature is disabled, or %FALSE otherwise.
 *
 * Since: 2.72
 */
gboolean
soup_message_is_feature_disabled (SoupMessage *msg, GType feature_type)
{
        SoupMessagePrivate *priv;
        GHashTableIter iter;
        gpointer key;

        g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);

        priv = soup_message_get_instance_private (msg);

        if (!priv->disabled_features)
                return FALSE;

        g_hash_table_iter_init (&iter, priv->disabled_features);
        while (g_hash_table_iter_next (&iter, &key, NULL)) {
                if (g_type_is_a (GPOINTER_TO_SIZE (key), feature_type))
                        return TRUE;
        }
        return FALSE;
}

GList *
soup_message_get_disabled_features (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	return priv->disabled_features ? g_hash_table_get_keys (priv->disabled_features) : NULL;
}

/**
 * soup_message_get_first_party:
 * @msg: a #SoupMessage
 *
 * Gets @msg's first-party #SoupURI
 * 
 * Returns: (transfer none): the @msg's first party #SoupURI
 * 
 * Since: 2.30
 **/
SoupURI *
soup_message_get_first_party (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	priv = soup_message_get_instance_private (msg);
	return priv->first_party;
}

/**
 * soup_message_set_first_party:
 * @msg: a #SoupMessage
 * @first_party: the #SoupURI for the @msg's first party
 * 
 * Sets @first_party as the main document #SoupURI for @msg. For
 * details of when and how this is used refer to the documentation for
 * #SoupCookieJarAcceptPolicy.
 *
 * Since: 2.30
 **/
void
soup_message_set_first_party (SoupMessage *msg,
			      SoupURI     *first_party)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (first_party != NULL);

	priv = soup_message_get_instance_private (msg);

	if (priv->first_party) {
		if (soup_uri_equal (priv->first_party, first_party))
			return;

		soup_uri_free (priv->first_party);
	}

	priv->first_party = soup_uri_copy (first_party);
	g_object_notify (G_OBJECT (msg), "first-party");
}

/**
 * soup_message_get_site_for_cookies:
 * @msg: a #SoupMessage
 *
 * Gets @msg's site for cookies #SoupURI
 *
 * Returns: (transfer none): the @msg's site for cookies #SoupURI
 *
 * Since: 2.70
 **/
SoupURI *
soup_message_get_site_for_cookies (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	priv = soup_message_get_instance_private (msg);
	return priv->site_for_cookies;
}

/**
 * soup_message_set_site_for_cookies:
 * @msg: a #SoupMessage
 * @site_for_cookies: (nullable): the #SoupURI for the @msg's site for cookies
 *
 * Sets @site_for_cookies as the policy URL for same-site cookies for @msg.
 *
 * It is either the URL of the top-level document or %NULL depending on whether the registrable
 * domain of this document's URL matches the registrable domain of its parent's/opener's
 * URL. For the top-level document it is set to the document's URL.
 *
 * See the [same-site spec](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00)
 * for more information.
 *
 * Since: 2.70
 **/
void
soup_message_set_site_for_cookies (SoupMessage *msg,
			           SoupURI     *site_for_cookies)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_message_get_instance_private (msg);

	if (priv->site_for_cookies == site_for_cookies)
		return;

	if (priv->site_for_cookies) {
		if (site_for_cookies && soup_uri_equal (priv->site_for_cookies, site_for_cookies))
			return;

		soup_uri_free (priv->site_for_cookies);
	}

	priv->site_for_cookies = site_for_cookies ? soup_uri_copy (site_for_cookies) : NULL;
	g_object_notify (G_OBJECT (msg), "site-for-cookies");
}

/**
 * soup_message_set_is_top_level_navigation:
 * @msg: a #SoupMessage
 * @is_top_level_navigation: if %TRUE indicate the current request is a top-level navigation
 *
 * See the [same-site spec](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00)
 * for more information.
 *
 * Since: 2.70
 **/
void
soup_message_set_is_top_level_navigation (SoupMessage *msg,
			                 gboolean     is_top_level_navigation)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	priv = soup_message_get_instance_private (msg);

	if (priv->is_top_level_navigation == is_top_level_navigation)
		return;

	priv->is_top_level_navigation = is_top_level_navigation;
	g_object_notify (G_OBJECT (msg), "is-top-level-navigation");
}

/**
 * soup_message_get_is_top_level_navigation:
 * @msg: a #SoupMessage
 *
 * Since: 2.70
 **/
gboolean
soup_message_get_is_top_level_navigation (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);

	priv = soup_message_get_instance_private (msg);
	return priv->is_top_level_navigation;
}

void
soup_message_set_https_status (SoupMessage *msg, SoupConnection *conn)
{
	SoupSocket *sock;

	sock = conn ? soup_connection_get_socket (conn) : NULL;
	if (sock && soup_socket_is_ssl (sock)) {
		GTlsCertificate *certificate;
		GTlsCertificateFlags errors;

		g_object_get (sock,
			      "tls-certificate", &certificate,
			      "tls-errors", &errors,
			      NULL);
		g_object_set (msg,
			      "tls-certificate", certificate,
			      "tls-errors", errors,
			      NULL);
		if (certificate)
			g_object_unref (certificate);
	} else {
		g_object_set (msg,
			      "tls-certificate", NULL,
			      "tls-errors", 0,
			      NULL);
	}
}

/**
 * soup_message_get_https_status:
 * @msg: a #SoupMessage
 * @certificate: (out) (transfer none): @msg's TLS certificate
 * @errors: (out): the verification status of @certificate
 *
 * If @msg is using https (or attempted to use https but got
 * %SOUP_STATUS_SSL_FAILED), this retrieves the #GTlsCertificate
 * associated with its connection, and the #GTlsCertificateFlags
 * showing what problems, if any, have been found with that
 * certificate.
 *
 * Return value: %TRUE if @msg used/attempted https, %FALSE if not
 *
 * Since: 2.34
 */
gboolean
soup_message_get_https_status (SoupMessage           *msg,
			       GTlsCertificate      **certificate,
			       GTlsCertificateFlags  *errors)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), FALSE);

	priv = soup_message_get_instance_private (msg);

	if (certificate)
		*certificate = priv->tls_certificate;
	if (errors)
		*errors = priv->tls_errors;
	return priv->tls_certificate != NULL;
}

/**
 * SoupMessagePriority:
 * @SOUP_MESSAGE_PRIORITY_VERY_LOW: The lowest priority, the messages
 *   with this priority will be the last ones to be attended.
 * @SOUP_MESSAGE_PRIORITY_LOW: Use this for low priority messages, a
 *   #SoupMessage with the default priority will be processed first.
 * @SOUP_MESSAGE_PRIORITY_NORMAL: The default priotity, this is the
 *   priority assigned to the #SoupMessage by default.
 * @SOUP_MESSAGE_PRIORITY_HIGH: High priority, a #SoupMessage with
 *   this priority will be processed before the ones with the default
 *   priority.
 * @SOUP_MESSAGE_PRIORITY_VERY_HIGH: The highest priority, use this
 *   for very urgent #SoupMessage as they will be the first ones to be
 *   attended.
 *
 * Priorities that can be set on a #SoupMessage to instruct the
 * message queue to process it before any other message with lower
 * priority.
 **/

/**
 * soup_message_set_priority:
 * @msg: a #SoupMessage
 * @priority: the #SoupMessagePriority
 *
 * Sets the priority of a message. Note that this won't have any
 * effect unless used before the message is added to the session's
 * message processing queue.
 *
 * The message will be placed just before any other previously added
 * message with lower priority (messages with the same priority are
 * processed on a FIFO basis).
 *
 * Setting priorities does not currently work with synchronous messages
 * because in the synchronous/blocking case, priority ends up being determined
 * semi-randomly by thread scheduling.
 *
 * Since: 2.44
 */
void
soup_message_set_priority (SoupMessage        *msg,
			   SoupMessagePriority priority)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	g_object_set (msg, "priority", priority, NULL);
}

/**
 * soup_message_get_priority:
 * @msg: a #SoupMessage
 *
 * Retrieves the #SoupMessagePriority. If not set this value defaults
 * to #SOUP_MESSAGE_PRIORITY_NORMAL.
 *
 * Return value: the priority of the message.
 *
 * Since: 2.44
 */
SoupMessagePriority
soup_message_get_priority (SoupMessage *msg)
{
	SoupMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_MESSAGE_PRIORITY_NORMAL);

	priv = soup_message_get_instance_private (msg);

	return priv->priority;
}

SoupClientMessageIOData *
soup_message_get_io_data (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	return priv->io_data;
}

void
soup_message_set_io_data (SoupMessage             *msg,
			  SoupClientMessageIOData *io)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	soup_client_message_io_data_free (priv->io_data);
	priv->io_data = io;
}

SoupContentSniffer *
soup_message_get_content_sniffer (SoupMessage *msg)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	return priv->sniffer;
}

void
soup_message_set_content_sniffer (SoupMessage *msg, SoupContentSniffer *sniffer)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	if (priv->sniffer)
		g_object_unref (priv->sniffer);

	priv->sniffer = sniffer ? g_object_ref (sniffer) : NULL;
}

void
soup_message_set_bytes_for_sniffing (SoupMessage *msg, gsize bytes)
{
	SoupMessagePrivate *priv = soup_message_get_instance_private (msg);

	priv->bytes_for_sniffing = bytes;
}
