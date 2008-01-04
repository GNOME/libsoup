/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.c: HTTP request/response
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#include <stdlib.h>
#include <string.h>

#include "soup-auth.h"
#include "soup-enum-types.h"
#include "soup-marshal.h"
#include "soup-message.h"
#include "soup-message-private.h"
#include "soup-misc.h"
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

enum {
	PROP_0,

	PROP_METHOD,
	PROP_URI,
	PROP_HTTP_VERSION,
	PROP_FLAGS,
	PROP_STATUS_CODE,
	PROP_REASON_PHRASE,

	LAST_PROP
};

static void got_foo_signal_wrapper (GClosure *closure, GValue *return_value,
				    guint n_param_values,
				    const GValue *param_values,
				    gpointer invocation_hint,
				    gpointer marshal_data);

static void got_body (SoupMessage *req);
static void restarted (SoupMessage *req);
static void finished (SoupMessage *req);

static void set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec);
static void get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec);

static void
soup_message_init (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	priv->io_status = SOUP_MESSAGE_IO_STATUS_IDLE;
	priv->http_version = SOUP_HTTP_1_1;

	msg->request_body = soup_message_body_new ();
	msg->request_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_REQUEST);
	msg->response_body = soup_message_body_new ();
	msg->response_headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
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

	soup_message_body_free (msg->request_body);
	soup_message_headers_free (msg->request_headers);
	soup_message_body_free (msg->response_body);
	soup_message_headers_free (msg->response_headers);

	g_free ((char *) msg->reason_phrase);

	G_OBJECT_CLASS (soup_message_parent_class)->finalize (object);
}

static void
soup_message_class_init (SoupMessageClass *message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (message_class);

	g_type_class_add_private (message_class, sizeof (SoupMessagePrivate));

	/* virtual method definition */
	message_class->got_body     = got_body;
	message_class->restarted    = restarted;
	message_class->finished     = finished;

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* signals */

	/**
	 * SoupMessage::wrote-informational:
	 * @msg: the message
	 *
	 * Emitted immediately after writing a 1xx (Informational)
	 * response for a (server-side) message.
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
	 * Emitted immediately after writing the headers for a
	 * message. (For a client-side message, this is after writing
	 * the request headers; for a server-side message, it is after
	 * writing the response headers.)
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
	 * Emitted immediately after writing the complete body for a
	 * message. (For a client-side message, this means that
	 * libsoup is done writing and is now waiting for the response
	 * from the server. For a server-side message, this means that
	 * libsoup has finished writing the response and is nearly
	 * done with the message.)
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
	 * a (client-side) message. The response_headers will be
	 * filled in with the headers associated with the
	 * informational response; however, those header values will
	 * be erased after this signal is done.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * the signal emission will be stopped, and @msg's connection
	 * will be closed.
	 **/
	signals[GOT_INFORMATIONAL] =
		g_signal_new ("got_informational",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_informational),
			      NULL, NULL,
			      got_foo_signal_wrapper,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-headers:
	 * @msg: the message
	 *
	 * Emitted after receiving all message headers for a message.
	 * (For a client-side message, this is after receiving the
	 * Status-Line and response headers; for a server-side
	 * message, it is after receiving the Request-Line and request
	 * headers.)
	 *
	 * See also soup_message_add_header_handler() and
	 * soup_message_add_status_code_handler(), which can be used
	 * to connect to a subset of emissions of this signal.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * the signal emission will be stopped, and @msg's connection
	 * will be closed. (If you need to requeue a message--eg,
	 * after handling authentication or redirection--it is usually
	 * better to requeue it from a ::got-body handler rather than
	 * a ::got-header handler, so that the existing HTTP
	 * connection can be reused.)
	 **/
	signals[GOT_HEADERS] =
		g_signal_new ("got_headers",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_headers),
			      NULL, NULL,
			      got_foo_signal_wrapper,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::got-chunk:
	 * @msg: the message
	 * @chunk: the just-read chunk
	 *
	 * Emitted after receiving a chunk of a message body. Note
	 * that "chunk" in this context means any subpiece of the
	 * body, not necessarily the specific HTTP 1.1 chunks sent by
	 * the other side.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * the signal emission will be stopped, and @msg's connection
	 * will be closed.
	 **/
	signals[GOT_CHUNK] =
		g_signal_new ("got_chunk",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_chunk),
			      NULL, NULL,
			      got_foo_signal_wrapper,
			      G_TYPE_NONE, 1,
			      G_TYPE_POINTER);

	/**
	 * SoupMessage::got-body:
	 * @msg: the message
	 *
	 * Emitted after receiving the complete message body. (For a
	 * server-side message, this means it has received the request
	 * body. For a client-side message, this means it has received
	 * the response body and is nearly done with the message.)
	 *
	 * See also soup_message_add_header_handler() and
	 * soup_message_add_status_code_handler(), which can be used
	 * to connect to a subset of emissions of this signal.
	 *
	 * If you cancel or requeue @msg while processing this signal,
	 * the signal emission will be stopped. However, unlike with
	 * the other "got" signals, this will not necessarily result
	 * in @msg's connection being closed, since the server is
	 * already done with the message at this point and so the
	 * connection is already ready for a new request.
	 **/
	signals[GOT_BODY] =
		g_signal_new ("got_body",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, got_body),
			      NULL, NULL,
			      got_foo_signal_wrapper,
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
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/**
	 * SoupMessage::finished:
	 * @msg: the message
	 *
	 * Emitted when all HTTP processing is finished for a message.
	 * (After ::got-body for client-side messages, or after
	 * ::wrote-body for server-side messages.)
	 **/
	signals[FINISHED] =
		g_signal_new ("finished",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_FIRST,
			      G_STRUCT_OFFSET (SoupMessageClass, finished),
			      NULL, NULL,
			      soup_marshal_NONE__NONE,
			      G_TYPE_NONE, 0);

	/* properties */
	g_object_class_install_property (
		object_class, PROP_METHOD,
		g_param_spec_string (SOUP_MESSAGE_METHOD,
				     "Method",
				     "The message's HTTP method",
				     SOUP_METHOD_GET,
				     G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_URI,
		g_param_spec_boxed (SOUP_MESSAGE_URI,
				    "URI",
				    "The message's Request-URI",
				    SOUP_TYPE_URI,
				    G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_HTTP_VERSION,
		g_param_spec_enum (SOUP_MESSAGE_HTTP_VERSION,
				   "HTTP Version",
				   "The HTTP protocol version to use",
				   SOUP_TYPE_HTTP_VERSION,
				   SOUP_HTTP_1_1,
				   G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_FLAGS,
		g_param_spec_flags (SOUP_MESSAGE_FLAGS,
				    "Flags",
				    "Various message options",
				    SOUP_TYPE_MESSAGE_FLAGS,
				    0,
				    G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_STATUS_CODE,
		g_param_spec_uint (SOUP_MESSAGE_STATUS_CODE,
				   "Status code",
				   "The HTTP response status code",
				   0, 599, 0,
				   G_PARAM_READWRITE));
	g_object_class_install_property (
		object_class, PROP_REASON_PHRASE,
		g_param_spec_string (SOUP_MESSAGE_REASON_PHRASE,
				     "Reason phrase",
				     "The HTTP response reason phrase",
				     NULL,
				     G_PARAM_READWRITE));
}

static void
set_property (GObject *object, guint prop_id,
	      const GValue *value, GParamSpec *pspec)
{
	SoupMessage *msg = SOUP_MESSAGE (object);

	switch (prop_id) {
	case PROP_METHOD:
		msg->method = g_intern_string (g_value_get_string (value));
		break;
	case PROP_URI:
		soup_message_set_uri (msg, g_value_get_boxed (value));
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
	default:
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
	      GValue *value, GParamSpec *pspec)
{
	SoupMessage *msg = SOUP_MESSAGE (object);
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, msg->method);
		break;
	case PROP_URI:
		g_value_set_boxed (value, priv->uri);
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
	default:
		break;
	}
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
			     SOUP_MESSAGE_METHOD, method,
			     SOUP_MESSAGE_URI, uri,
			     NULL);
}

/**
 * soup_message_set_request:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @req_use: a #SoupMemoryUse describing how to handle @req_body
 * @req_body: a data buffer containing the body of the message request.
 * @req_length: the byte length of @req_body.
 * 
 * Convenience function to set the request body of a #SoupMessage.
 * If @content_type is %NULL, the request body will be cleared.
 */
void
soup_message_set_request (SoupMessage    *msg,
			  const char     *content_type,
			  SoupMemoryUse   req_use,
			  const char     *req_body,
			  gsize           req_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL || req_length == 0);

	if (content_type) {
		soup_message_headers_replace (msg->request_headers,
					      "Content-Type", content_type);
		soup_message_body_append (msg->request_body, req_use,
					  req_body, req_length);
	} else {
		soup_message_headers_remove (msg->request_headers,
					     "Content-Type");
		soup_message_body_truncate (msg->request_body);
	}
}

/**
 * soup_message_set_response:
 * @msg: the message
 * @content_type: MIME Content-Type of the body
 * @resp_use: a #SoupMemoryUse describing how to handle @resp_body
 * @resp_body: a data buffer containing the body of the message response.
 * @resp_length: the byte length of @resp_body.
 * 
 * Convenience function to set the response body of a #SoupMessage.
 * If @content_type is %NULL, the response body will be cleared.
 */
void
soup_message_set_response (SoupMessage    *msg,
			   const char     *content_type,
			   SoupMemoryUse   resp_use,
			   const char     *resp_body,
			   gsize           resp_length)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));
	g_return_if_fail (content_type != NULL || resp_length == 0);

	if (content_type) {
		soup_message_headers_replace (msg->response_headers,
					      "Content-Type", content_type);
		soup_message_body_append (msg->response_body, resp_use,
					  resp_body, resp_length);
	} else {
		soup_message_headers_remove (msg->response_headers,
					     "Content-Type");
		soup_message_body_truncate (msg->response_body);
	}
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

/* Wraps the marshaller for got_informational, got_headers, got_chunk,
 * and got_body, and stops the emission afterward if the message has
 * been requeued. We can't use a GSignalAccumulator, because that
 * doesn't have access to the object it's accumulating for. Hrmph.
 */
static void
got_foo_signal_wrapper (GClosure *closure, GValue *return_value,
			guint n_param_values, const GValue *param_values,
			gpointer invocation_hint, gpointer marshal_data)
{
	SoupMessage *msg = g_value_get_object (&param_values[0]);
	GSignalInvocationHint *hint = invocation_hint;

	if (hint->signal_id == signals[GOT_CHUNK]) {
		soup_marshal_NONE__POINTER (closure, return_value,
					    n_param_values, param_values,
					    invocation_hint, marshal_data);
	} else {
		soup_marshal_NONE__NONE (closure, return_value,
					 n_param_values, param_values,
					 invocation_hint, marshal_data);
	}

	if (SOUP_MESSAGE_IS_STARTING (msg))
		g_signal_stop_emission (msg, hint->signal_id, hint->detail);
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

/**
 * soup_message_got_chunk:
 * @msg: a #SoupMessage
 * @chunk: the newly-read chunk
 *
 * Emits the %got_chunk signal, indicating that the IO layer finished
 * reading a chunk of @msg's body.
 **/
void
soup_message_got_chunk (SoupMessage *msg, SoupBuffer *chunk)
{
	g_signal_emit (msg, signals[GOT_CHUNK], 0, chunk);
}

static void
got_body (SoupMessage *req)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (req);

	if (!(priv->msg_flags & SOUP_MESSAGE_OVERWRITE_CHUNKS)) {
		SoupBuffer *buffer;

		/* Figure out *which* body we read, and flatten it. */
		if (req->status_code == 0)
			buffer = soup_message_body_flatten (req->request_body);
		else
			buffer = soup_message_body_flatten (req->response_body);
		soup_buffer_free (buffer);
	}
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
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (req);

	soup_message_io_stop (req);
	priv->io_status = SOUP_MESSAGE_IO_STATUS_FINISHED;
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

typedef struct {
	SoupMessage *msg;
	char *header_name;
} SoupMessageHeaderHandlerData;

static void
header_handler_free (gpointer data, GClosure *closure)
{
	SoupMessageHeaderHandlerData *hhd = data;

	g_free (hhd->header_name);
	g_slice_free (SoupMessageHeaderHandlerData, hhd);
}

static void
header_handler_metamarshal (GClosure *closure, GValue *return_value,
			    guint n_param_values, const GValue *param_values,
			    gpointer invocation_hint, gpointer marshal_data)
{
	SoupMessageHeaderHandlerData *hhd = marshal_data;
	SoupMessageHeaders *hdrs;

	/* If status_code is 0, we're still processing the request
	 * side; if it's not, we're processing the response side.
	 */
	hdrs = (hhd->msg->status_code == 0) ?
		hhd->msg->request_headers : hhd->msg->response_headers;

	if (soup_message_headers_get (hdrs, hhd->header_name)) {
		closure->marshal (closure, return_value, n_param_values,
				  param_values, invocation_hint,
				  ((GCClosure *)closure)->callback);
	}
}

/**
 * soup_message_add_header_handler:
 * @msg: a #SoupMessage
 * @signal: signal to connect the handler to.
 * @header: HTTP response header to match against
 * @callback: the header handler
 * @user_data: data to pass to @handler_cb
 *
 * Adds a signal handler to @msg for @signal, as with
 * g_signal_connect(). However, @callback will only be run if @msg has
 * a header named @header.
 *
 * If @signal is one of the "got" signals (eg, "got_headers"),
 * "finished" or "restarted", then @header is matched against the
 * incoming message headers (that is, the #request_headers for a
 * client #SoupMessage, or the #response_headers for a server
 * #SoupMessage). If @signal is one of the "wrote" signals, then
 * @header is matched against the outgoing message headers.
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
	SoupMessagePrivate *priv;
	GClosure *closure;
	SoupMessageHeaderHandlerData *hhd;

	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), 0);
	g_return_val_if_fail (signal != NULL, 0);
	g_return_val_if_fail (header != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	closure = g_cclosure_new (callback, user_data, NULL);

	hhd = g_slice_new (SoupMessageHeaderHandlerData);
	hhd->msg = msg;
	hhd->header_name = g_strdup (header);
	g_closure_set_meta_marshal (closure, hhd, header_handler_metamarshal);
	g_closure_add_finalize_notifier (closure, hhd, header_handler_free);

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
 * soup_message_add_status_code_handler:
 * @msg: a #SoupMessage
 * @signal: signal to connect the handler to.
 * @status_code: status code to match against
 * @callback: the header handler
 * @user_data: data to pass to @handler_cb
 *
 * Adds a signal handler to @msg for @signal, as with
 * g_signal_connect(). However, @callback will only be run if @msg has
 * the status @status_code.
 *
 * @signal must be a signal that will be emitted after @msg's status
 * is set. For a client #SoupMessage, this means it can't be a "wrote"
 * signal. For a server #SoupMessage, this means it can't be a "got"
 * signal.
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
	soup_message_body_truncate (req->response_body);
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

	c_conn = soup_message_headers_get (msg->request_headers, "Connection");
	s_conn = soup_message_headers_get (msg->response_headers, "Connection");

	if (msg->status_code == SOUP_STATUS_OK &&
	    msg->method == SOUP_METHOD_CONNECT)
		return TRUE;

	if (SOUP_MESSAGE_GET_PRIVATE (msg)->http_version == SOUP_HTTP_1_0) {
		/* Only persistent if the client requested keepalive
		 * and the server agreed.
		 */

		if (!c_conn || !s_conn)
			return FALSE;
		if (soup_header_contains (c_conn, "Keep-Alive") ||
		    soup_header_contains (s_conn, "Keep-Alive"))
			return FALSE;

		return TRUE;
	} else {
		/* Normally persistent unless either side requested otherwise */
		if (c_conn && soup_header_contains (c_conn, "close"))
			return FALSE;
		if (s_conn && soup_header_contains (s_conn, "close"))
			return FALSE;

		/* But not if the server sent a terminate-by-EOF response */
		if (soup_message_headers_get_encoding (msg->response_headers) == SOUP_ENCODING_EOF)
			return FALSE;

		return TRUE;
	}
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
SoupURI *
soup_message_get_uri (SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	return SOUP_MESSAGE_GET_PRIVATE (msg)->uri;
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

void
soup_message_set_io_status (SoupMessage          *msg,
			    SoupMessageIOStatus   status)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	priv->io_status = status;
}

SoupMessageIOStatus
soup_message_get_io_status (SoupMessage *msg)
{
	SoupMessagePrivate *priv = SOUP_MESSAGE_GET_PRIVATE (msg);

	return priv->io_status;
}
