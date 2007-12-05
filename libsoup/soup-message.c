/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: HTTP request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <stdlib.h>
#include <string.h>

#include "soup-auth.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup-server-message.h"
#include "soup-uri.h"

G_DEFINE_TYPE (SoupMessage, soup_message, G_TYPE_OBJECT)

enum {
	WROTE_INFORMATIONAL,
	WROTE_HEADERS,
	WROTE_CHUNK,
	WROTE_BODY,

	GOT_INFORMATIONAL,
	GOT_HEADERS,
	GOT_CHUNK,
	GOT_BODY,

	RESTARTED,
	FINISHED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void wrote_body (SoupMessage *req);
static void got_headers (SoupMessage *req);
static void got_chunk (SoupMessage *req);
static void got_body (SoupMessage *req);
static void restarted (SoupMessage *req);
static void finished (SoupMessage *req);
static void free_chunks (SoupMessage *msg);

static void
soup_message_init (SoupMessage *msg)
{
	msg->status  = SOUP_MESSAGE_STATUS_IDLE;

	msg->request_headers = soup_message_headers_new ();
	msg->response_headers = soup_message_headers_new ();

	SOUP_MESSAGE_GET_PRIVATE (msg)->http_version = SOUP_HTTP_1_1;
}

static void
finalize (GObject *object)
{
	SoupMessage *msg = SOUP_MESSAGE (object);
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	soup_message_io_cleanup (msg);

	if (priv->uri)
		soup_uri_free (priv->uri);

	if (priv->auth)
		g_object_unref (priv->auth);
	if (priv->proxy_auth)
		g_object_unref (priv->proxy_auth);

	if (msg->request.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->request.body);
	if (msg->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (msg->response.body);
	free_chunks (msg);

	soup_message_headers_free (msg->request_headers);
	soup_message_headers_free (msg->response_headers);

	g_slist_foreach (priv->content_handlers, (GFunc) g_free, NULL);
	g_slist_free (priv->content_handlers);

	g_free ((char *) msg->reason_phrase);

	G_OBJECT_CLASS (soup_message_parent_class)->finalize (object);
}

static void
soup_message_class_init (SoupMessageClass *message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (message_class);

	g_type_class_add_private (message_class, sizeof (SoupMessagePrivate));

	/* virtual method definition */
	message_class->wrote_body   = wrote_body;
	message_class->got_headers  = got_headers;
	message_class->got_chunk    = got_chunk;
	message_class->got_body     = got_body;
	message_class->restarted    = restarted;
	message_class->finished     = finished;

	/* virtual method override */
	object_class->finalize = finalize;

	/* signals */

	/**
	 * SoupMessage::wrote-informational:
	 * @msg: the message
	 *
	 * Emitted immediately after writing a 1xx (Informational)
	 * response for a message.
	 **/
	signals[WROTE_INFORMATIONAL] =
		g_signal_new ("wrote_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_informational),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::wrote-headers:
	 * @msg: the message
	 *
	 * Emitted immediately after writing the headers for a message.
	 **/
	signals[WROTE_HEADERS] =
		g_signal_new ("wrote_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_headers),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::wrote-chunk:
	 * @msg: the message
	 *
	 * Emitted immediately after writing a body chunk for a message.
	 **/
	signals[WROTE_CHUNK] =
		g_signal_new ("wrote_chunk",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_chunk),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::wrote-body:
	 * @msg: the message
	 *
	 * Emitted immediately after writing the complete body for a message.
	 **/
	signals[WROTE_BODY] =
		g_signal_new ("wrote_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, wrote_body),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-informational:
	 * @msg: the message
	 *
	 * Emitted after receiving a 1xx (Informational) response for
	 * a message.
	 **/
	signals[GOT_INFORMATIONAL] =
		g_signal_new ("got_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_informational),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-headers:
	 * @msg: the message
	 *
	 * Emitted after receiving all message headers for a message.
	 **/
	signals[GOT_HEADERS] =
		g_signal_new ("got_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_headers),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-chunk:
	 * @msg: the message
	 *
	 * Emitted after receiving a chunk of a message body. Note
	 * that "chunk" in this context means any subpiece of the
	 * body, not necessarily the specific HTTP 1.1 chunks sent by
	 * the other side.
	 **/
	signals[GOT_CHUNK] =
		g_signal_new ("got_chunk",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_chunk),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-body:
	 * @msg: the message
	 *
	 * Emitted after receiving the complete message body.
	 **/
	signals[GOT_BODY] =
		g_signal_new ("got_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_body),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::restarted:
	 * @msg: the message
	 *
	 * Emitted when a message is about to be re-queued.
	 **/
	signals[RESTARTED] =
		g_signal_new ("restarted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, restarted),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::finished:
	 * @msg: the message
	 *
	 * Emitted when all HTTP processing is finished for a message.
	 * (After #read-body for client-side code, or after
	 * #wrote-body for server-side code.)
	 **/
	signals[FINISHED] =
		g_signal_new ("finished",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, finished),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);
}


/**
 * soup_message_new:
 * @method: the HTTP method for the created request
 * @uri_string: the destination endpoint (as a string)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage (or %NULL if @uri could not
 * be parsed).
 */
SoupMessage *
soup_message_new (const char *method, const char *uri_string)
{
	SoupMessage *msg;
	SoupUri *uri;

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;

	if (!uri->host) {
		soup_uri_free (uri);
		return NULL;
	}

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	SOUP_MESSAGE_GET_PRIVATE (msg)->uri = uri;

	return msg;
}

/**
 * soup_message_new_from_uri:
 * @method: the HTTP method for the created request
 * @uri: the destination endpoint (as a #SoupUri)
 * 
 * Creates a new empty #SoupMessage, which will connect to @uri
 *
 * Return value: the new #SoupMessage
 */
SoupMessage *
soup_message_new_from_uri (const char *method, const SoupUri *uri)
{
	SoupMessage *msg;

	msg = g_object_new (SOUP_TYPE_MESSAGE, NULL);
	msg->method = method ? method : SOUP_METHOD_GET;
	SOUP_MESSAGE_GET_PRIVATE (msg)->uri = soup_uri_copy (uri);

	return msg;
}

/**
 * soup_message_set_request:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_owner: the #SoupOwnership of the passed data buffer.
 * @req_body: a data buffer containing the body of the message request.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the request body of a #SoupMessage
 */
void
soup_message_set_request (SoupMessage   *msg,
			  const char    *content_type,
			  SoupOwnership  req_owner,
			  char          *req_body,
			  gulong         req_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (req_body != NULL || req_length == 0);

	soup_message_headers_append (msg->request_headers, "Content-Type", content_type);
	msg->request.owner = req_owner;
	msg->request.body = req_body;
	msg->request.length = req_length;
}

/**
 * soup_message_set_response:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @resp_owner: the #SoupOwnership of the passed data buffer.
 * @resp_body: a data buffer containing the body of the message response.
 * @resp_length: the byte length of @resp_body.
 * 
 * Convenience function to set the response body of a #SoupMessage
 */
void
soup_message_set_response (SoupMessage   *msg,
			   const char    *content_type,
			   SoupOwnership  resp_owner,
			   char          *resp_body,
			   gulong         resp_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL);
	g_return_if_fail (resp_body != NULL || resp_length == 0);

	soup_message_headers_append (msg->response_headers, "Content-Type", content_type);
	msg->response.owner = resp_owner;
	msg->response.body = resp_body;
	msg->response.length = resp_length;
}

/**
 * soup_message_wrote_informational:
 * @msg: a #SoupMessage
 *
 * Emits the %wrote_informational signal, indicating that the IO layer
 * finished writing an informational (1xx) response for @msg.
 **/
void
soup_message_wrote_informational (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_INFORMATIONAL], 0);
}

/**
 * soup_message_wrote_headers:
 * @msg: a #SoupMessage
 *
 * Emits the %wrote_headers signal, indicating that the IO layer
 * finished writing the (non-informational) headers for @msg.
 **/
void
soup_message_wrote_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_HEADERS], 0);
}

/**
 * soup_message_wrote_chunk:
 * @msg: a #SoupMessage
 *
 * Emits the %wrote_chunk signal, indicating that the IO layer
 * finished writing a chunk of @msg's body.
 **/
void
soup_message_wrote_chunk (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_CHUNK], 0);
}

static void
wrote_body (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_POST_REQUEST);
	g_object_unref (req);
}

/**
 * soup_message_wrote_body:
 * @msg: a #SoupMessage
 *
 * Emits the %wrote_body signal, indicating that the IO layer finished
 * writing the body for @msg.
 **/
void
soup_message_wrote_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[WROTE_BODY], 0);
}

/**
 * soup_message_got_informational:
 * @msg: a #SoupMessage
 *
 * Emits the %got_informational signal, indicating that the IO layer
 * read a complete informational (1xx) response for @msg.
 **/
void
soup_message_got_informational (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_INFORMATIONAL], 0);
}

static void
got_headers (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_PRE_BODY);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_HEADERS], 0);
	g_object_unref (req);
}

/**
 * soup_message_got_headers:
 * @msg: a #SoupMessage
 *
 * Emits the %got_headers signal, indicating that the IO layer
 * finished reading the (non-informational) headers for @msg.
 **/
void
soup_message_got_headers (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_HEADERS], 0);
}

static void
got_chunk (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_BODY_CHUNK);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_CHUNK], 0);
	g_object_unref (req);
}

/**
 * soup_message_got_chunk:
 * @msg: a #SoupMessage
 *
 * Emits the %got_chunk signal, indicating that the IO layer finished
 * reading a chunk of @msg's body.
 **/
void
soup_message_got_chunk (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_CHUNK], 0);
}

static void
got_body (SoupMessage *req)
{
	g_object_ref (req);
	soup_message_run_handlers (req, SOUP_HANDLER_POST_BODY);
	if (SOUP_MESSAGE_IS_STARTING (req))
		g_signal_stop_emission (req, signals[GOT_BODY], 0);
	g_object_unref (req);
}

/**
 * soup_message_got_body:
 * @msg: a #SoupMessage
 *
 * Emits the %got_body signal, indicating that the IO layer finished
 * reading the body for @msg.
 **/
void
soup_message_got_body (SoupMessage *msg)
{
	g_signal_emit (msg, signals[GOT_BODY], 0);
}

static void
restarted (SoupMessage *req)
{
	soup_message_io_stop (req);
}

/**
 * soup_message_restarted:
 * @msg: a #SoupMessage
 *
 * Emits the %restarted signal, indicating that @msg should be
 * requeued.
 **/
void
soup_message_restarted (SoupMessage *msg)
{
	g_signal_emit (msg, signals[RESTARTED], 0);
}

static void
finished (SoupMessage *req)
{
	soup_message_io_stop (req);
	req->status = SOUP_MESSAGE_STATUS_FINISHED;
}

/**
 * soup_message_finished:
 * @msg: a #SoupMessage
 *
 * Emits the %finished signal, indicating that @msg has been completely
 * processed.
 **/
void
soup_message_finished (SoupMessage *msg)
{
	g_signal_emit (msg, signals[FINISHED], 0);
}

/**
 * soup_message_set_auth:
 * @msg: a #SoupMessage
 * @auth: a #SoupAuth, or %NULL
 *
 * Sets @msg to authenticate to its destination using @auth, which
 * must have already been fully authenticated. If @auth is %NULL, @msg
 * will not authenticate to its destination.
 **/
void
soup_message_set_auth (SoupMessage *msg, SoupAuth *auth)
{
	SoupMessagePrivate *priv;
	char *token;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (auth == NULL || SOUP_IS_AUTH (auth));
	g_return_if_fail (auth == NULL || soup_auth_is_authenticated (auth));

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	if (priv->auth) {
		g_object_unref (priv->auth);
		soup_message_headers_remove (msg->request_headers,
					     "Authorization");
	}
	priv->auth = auth;
	if (!priv->auth)
		return;

	g_object_ref (priv->auth);
	token = soup_auth_get_authorization (auth, msg);
	soup_message_headers_append (msg->request_headers,
				     "Authorization", token);
	g_free (token);
}

/**
 * soup_message_get_auth:
 * @msg: a #SoupMessage
 *
 * Gets the #SoupAuth used by @msg for authentication.
 *
 * Return value: the #SoupAuth used by @msg for authentication, or
 * %NULL if @msg is unauthenticated.
 **/
SoupAuth *
soup_message_get_auth (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->auth;
}

/**
 * soup_message_set_proxy_auth:
 * @msg: a #SoupMessage
 * @auth: a #SoupAuth, or %NULL
 *
 * Sets @msg to authenticate to its proxy using @auth, which must have
 * already been fully authenticated. If @auth is %NULL, @msg will not
 * authenticate to its proxy.
 **/
void
soup_message_set_proxy_auth (SoupMessage *msg, SoupAuth *auth)
{
	SoupMessagePrivate *priv;
	char *token;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (auth == NULL || SOUP_IS_AUTH (auth));
	g_return_if_fail (auth == NULL || soup_auth_is_authenticated (auth));

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	if (priv->proxy_auth) {
		g_object_unref (priv->proxy_auth);
		soup_message_headers_remove (msg->request_headers,
					     "Proxy-Authorization");
	}
	priv->proxy_auth = auth;
	if (!priv->proxy_auth)
		return;

	g_object_ref (priv->proxy_auth);
	token = soup_auth_get_authorization (auth, msg);
	soup_message_headers_append (msg->request_headers,
				     "Proxy-Authorization", token);
	g_free (token);
}

/**
 * soup_message_get_proxy_auth:
 * @msg: a #SoupMessage
 *
 * Gets the #SoupAuth used by @msg for authentication to its proxy..
 *
 * Return value: the #SoupAuth used by @msg for authentication to its
 * proxy, or %NULL if @msg isn't authenticated to its proxy.
 **/
SoupAuth *
soup_message_get_proxy_auth (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->proxy_auth;
}

/**
 * soup_message_cleanup_response:
 * @req: a #SoupMessage
 *
 * Cleans up all response data on @req, so that the request can be sent
 * again and receive a new response. (Eg, as a result of a redirect or
 * authorization request.)
 **/
void
soup_message_cleanup_response (SoupMessage *req)
{
	if (req->response.owner == SOUP_BUFFER_SYSTEM_OWNED)
		g_free (req->response.body);

	req->response.owner = 0;
	req->response.body = NULL;
	req->response.length = 0;

	free_chunks (req);

	soup_message_headers_clear (req->response_headers);

	req->status_code = SOUP_STATUS_NONE;
	if (req->reason_phrase) {
		g_free ((char *) req->reason_phrase);
		req->reason_phrase = NULL;
	}
}

/**
 * soup_message_set_flags:
 * @msg: a #SoupMessage
 * @flags: a set of #SoupMessageFlags values
 *
 * Sets the specified flags on @msg.
 **/
void
soup_message_set_flags (SoupMessage *msg, guint flags)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_MESSAGE_GET_PRIVATE (msg)->msg_flags = flags;
}

/**
 * soup_message_get_flags:
 * @msg: a #SoupMessage
 *
 * Gets the flags on @msg
 *
 * Return value: the flags
 **/
guint
soup_message_get_flags (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->msg_flags;
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
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	SOUP_MESSAGE_GET_PRIVATE (msg)->http_version = version;
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
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_HTTP_1_0);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->http_version;
}

/**
 * soup_message_is_keepalive:
 * @msg: a #SoupMessage
 *
 * Determines whether or not @msg's connection can be kept alive for
 * further requests after processing @msg.
 *
 * Return value: %TRUE or %FALSE.
 **/
gboolean
soup_message_is_keepalive (SoupMessage *msg)
{
	const char *c_conn, *s_conn;

	c_conn = soup_message_headers_find (msg->request_headers, "Connection");
	s_conn = soup_message_headers_find (msg->response_headers, "Connection");

	if (msg->status_code == SOUP_STATUS_OK &&
	    soup_method_get_id (msg->method) == SOUP_METHOD_ID_CONNECT)
		return TRUE;

	if (SOUP_MESSAGE_GET_PRIVATE (msg)->http_version == SOUP_HTTP_1_0) {
		/* Only persistent if the client requested keepalive
		 * and the server agreed.
		 */

		if (!c_conn || !s_conn)
			return FALSE;
		if (g_ascii_strcasecmp (c_conn, "Keep-Alive") != 0 ||
		    g_ascii_strcasecmp (s_conn, "Keep-Alive") != 0)
			return FALSE;

		return TRUE;
	} else {
		/* Normally persistent unless either side requested otherwise */
		if (c_conn && g_ascii_strcasecmp (c_conn, "close") == 0)
			return FALSE;
		if (s_conn && g_ascii_strcasecmp (s_conn, "close") == 0)
			return FALSE;

		/* But not if the server sent a terminate-by-EOF response */
		if (soup_message_get_response_encoding (msg, NULL) == SOUP_TRANSFER_EOF)
			return FALSE;

		return TRUE;
	}
}

/**
 * soup_message_set_uri:
 * @msg: a #SoupMessage
 * @uri: the new #SoupUri
 *
 * Sets @msg's URI to @uri. If @msg has already been sent and you want
 * to re-send it with the new URI, you need to call
 * soup_session_requeue_message().
 **/
void
soup_message_set_uri (SoupMessage *msg, const SoupUri *uri)
{
	SoupMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	if (priv->uri)
		soup_uri_free (priv->uri);
	priv->uri = soup_uri_copy (uri);
}

/**
 * soup_message_get_uri:
 * @msg: a #SoupMessage
 *
 * Gets @msg's URI
 *
 * Return value: the URI @msg is targeted for.
 **/
const SoupUri *
soup_message_get_uri (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->uri;
}

/**
 * soup_message_get_request_encoding:
 * @msg: a #SoupMessage
 * @content_length: a pointer to store the Content-Length in (or
 * %NULL).
 *
 * Gets @msg's request encoding. For an outgoing (client) request,
 * this is only valid after the message has been fully set up (from
 * the library's perspective, that means not until the message has
 * been queued). For an incoming (server) request, this is valid after
 * the request headers have been read and @msg->request_headers filled
 * in.
 *
 * Return value: the request encoding (which cannot be
 * %SOUP_TRANSFER_UNKNOWN or %SOUP_TRANSFER_EOF). If it is
 * %SOUP_TRANSFER_CONTENT_LENGTH, *@content_length will be set to the
 * request body's length.
 **/
SoupTransferEncoding
soup_message_get_request_encoding  (SoupMessage *msg, guint *content_length)
{
	if (SOUP_IS_SERVER_MESSAGE (msg)) {
		const char *enc, *len;

		enc = soup_message_headers_find (msg->request_headers,
						 "Transfer-Encoding");
		len = soup_message_headers_find (msg->request_headers,
						 "Content-Length");
		if (enc) {
			if (g_ascii_strcasecmp (enc, "chunked") == 0)
				return SOUP_TRANSFER_CHUNKED;
			else
				return SOUP_TRANSFER_UNKNOWN;
		} else if (len) {
			int lval = atoi (len);

			if (lval < 0)
				return SOUP_TRANSFER_UNKNOWN;
			else {
				if (content_length)
					*content_length = lval;
				return SOUP_TRANSFER_CONTENT_LENGTH;
			}
		} else
			return SOUP_TRANSFER_NONE;
	} else {
		if (msg->request.length) {
			if (content_length)
				*content_length = msg->request.length;
			return SOUP_TRANSFER_CONTENT_LENGTH;
		} else
			return SOUP_TRANSFER_NONE;
	}
}

/**
 * soup_message_get_response_encoding:
 * @msg: a #SoupMessage
 * @content_length: a pointer to store the Content-Length in (or
 * %NULL).
 *
 * Gets @msg's response encoding. For an outgoing (client) request,
 * this is only valid after the response headers have been read and
 * @msg->response_headers filled in. For an incoming (server) request,
 * this is valid after the server handler has run.
 *
 * Note that the returned value is the encoding actually used on the
 * wire; this will not agree with the response headers in some cases
 * (eg, a HEAD response may have a Content-Length header, but will
 * still be considered %SOUP_TRANSFER_NONE by this function).
 *
 * Return value: the response encoding (which will not be
 * %SOUP_TRANSFER_UNKNOWN). If it is %SOUP_TRANSFER_CONTENT_LENGTH,
 * *@content_length will be set to the response body's length.
 **/
SoupTransferEncoding
soup_message_get_response_encoding (SoupMessage *msg, guint *content_length)
{
	SoupMethodId method = soup_method_get_id (msg->method);

	if (method == SOUP_METHOD_ID_HEAD ||
	    msg->status_code  == SOUP_STATUS_NO_CONTENT ||
	    msg->status_code  == SOUP_STATUS_NOT_MODIFIED ||
	    SOUP_STATUS_IS_INFORMATIONAL (msg->status_code))
		return SOUP_TRANSFER_NONE;

	if (SOUP_IS_SERVER_MESSAGE (msg)) {
		SoupTransferEncoding enc =
			soup_server_message_get_encoding ((SoupServerMessage *)msg);
		if (enc == SOUP_TRANSFER_UNKNOWN)
			enc = SOUP_TRANSFER_CONTENT_LENGTH;
		if (enc == SOUP_TRANSFER_CONTENT_LENGTH && content_length)
			*content_length = msg->response.length;
		return enc;
	} else {
		const char *enc, *len;

		enc = soup_message_headers_find (msg->response_headers,
						 "Transfer-Encoding");
		len = soup_message_headers_find (msg->response_headers,
						 "Content-Length");
		if (enc) {
			if (g_ascii_strcasecmp (enc, "chunked") == 0)
				return SOUP_TRANSFER_CHUNKED;
			else
				return SOUP_TRANSFER_UNKNOWN;
		} else if (len) {
			int lval = atoi (len);

			if (lval < 0)
				return SOUP_TRANSFER_UNKNOWN;
			else {
				if (content_length)
					*content_length = lval;
				return SOUP_TRANSFER_CONTENT_LENGTH;
			}
		} else if (method == SOUP_METHOD_ID_CONNECT)
			return SOUP_TRANSFER_NONE;
		else
			return SOUP_TRANSFER_EOF;
	}
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

	g_free ((char *) msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (soup_status_get_phrase (status_code));
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

	g_free ((char *) msg->reason_phrase);

	msg->status_code = status_code;
	msg->reason_phrase = g_strdup (reason_phrase);
}


/**
 * soup_message_add_chunk:
 * @msg: a #SoupMessage
 * @owner: the ownership of @body
 * @body: body data
 * @length: length of @body
 *
 * Adds a chunk of response data to @body. (Note that currently
 * there is no way to send a request using chunked encoding.)
 **/
void
soup_message_add_chunk (SoupMessage   *msg,
			SoupOwnership  owner,
			const char    *body,
			guint          length)
{
	SoupMessagePrivate *priv;
	SoupDataBuffer *chunk;

	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	g_return_if_fail (body != NULL || length == 0);

	chunk = g_new0 (SoupDataBuffer, 1);
	if (owner == SOUP_BUFFER_USER_OWNED) {
		chunk->owner = SOUP_BUFFER_SYSTEM_OWNED;
		chunk->body = g_memdup (body, length);
	} else {
		chunk->owner = owner;
		chunk->body = (char *)body;
	}
	chunk->length = length;

	if (priv->chunks) {
		priv->last_chunk = g_slist_append (priv->last_chunk, chunk);
		priv->last_chunk = priv->last_chunk->next;
	} else {
		priv->chunks = priv->last_chunk =
			g_slist_append (NULL, chunk);
	}
}

/**
 * soup_message_add_final_chunk:
 * @msg: a #SoupMessage
 *
 * Adds a final, empty chunk of response data to @body. This must
 * be called after adding the last real chunk, to indicate that
 * there is no more data.
 **/
void
soup_message_add_final_chunk (SoupMessage *msg)
{
	soup_message_add_chunk (msg, SOUP_BUFFER_STATIC, NULL, 0);
}

/**
 * soup_message_pop_chunk:
 * @msg: a #SoupMessage
 *
 * Pops a chunk of response data from @msg's chunk list. The caller
 * must free @chunk itself, and must handle the data in @chunk
 * according to its %ownership.
 *
 * Return value: the chunk, or %NULL if there are no chunks left.
 **/
SoupDataBuffer *
soup_message_pop_chunk (SoupMessage *msg)
{
	SoupMessagePrivate *priv;
	SoupDataBuffer *chunk;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);
	priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	if (!priv->chunks)
		return NULL;

	chunk = priv->chunks->data;
	priv->chunks = g_slist_remove (priv->chunks, chunk);
	if (!priv->chunks)
		priv->last_chunk = NULL;

	return chunk;
}

static void
free_chunks (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);
	SoupDataBuffer *chunk;
	GSList *ch;

	for (ch = priv->chunks; ch; ch = ch->next) {
		chunk = ch->data;

		if (chunk->owner == SOUP_BUFFER_SYSTEM_OWNED)
			g_free (chunk->body);
		g_free (chunk);
	}

	g_slist_free (priv->chunks);
	priv->chunks = priv->last_chunk = NULL;
}
