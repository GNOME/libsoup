/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message-headers.h>
#include <libsoup/soup-method.h>

G_BEGIN_DECLS

#define SOUP_TYPE_MESSAGE            (soup_message_get_type ())
#define SOUP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_MESSAGE, SoupMessage))
#define SOUP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_MESSAGE, SoupMessageClass))
#define SOUP_IS_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_IS_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_MESSAGE, SoupMessageClass))

/**
 * SoupTransferEncoding:
 * @SOUP_TRANSFER_UNKNOWN: unknown / error
 * @SOUP_TRANSFER_CHUNKED: chunked encoding (currently only supported
 * for response)
 * @SOUP_TRANSFER_CONTENT_LENGTH: Content-Length encoding
 * @SOUP_TRANSFER_BYTERANGES: multipart/byteranges (Reserved for future
 * use: NOT CURRENTLY IMPLEMENTED)
 * @SOUP_TRANSFER_NONE: no body is present (which is not the same as a
 * 0-length body, and only occurs in certain places)
 * @SOUP_TRANSFER_EOF: Response body ends when the connection is closed
 *
 * How the length of a request or response is to be encoded.
 **/
typedef enum {
	SOUP_TRANSFER_UNKNOWN = 0,
	SOUP_TRANSFER_CHUNKED,
	SOUP_TRANSFER_CONTENT_LENGTH,
	SOUP_TRANSFER_BYTERANGES,
	SOUP_TRANSFER_NONE,
	SOUP_TRANSFER_EOF
} SoupTransferEncoding;

/**
 * SoupOwnership:
 * @SOUP_BUFFER_SYSTEM_OWNED: The data is owned by soup and it can
 * free it when it is done with it.
 * @SOUP_BUFFER_USER_OWNED: The data is owned by the user, who is
 * responsible for freeing it at the right point
 * @SOUP_BUFFER_STATIC: The data should not be freed.
 *
 * Used by #SoupDataBuffer (and several functions) to indicate the
 * ownership of a buffer.
 **/
typedef enum {
	SOUP_BUFFER_SYSTEM_OWNED = 0,
	SOUP_BUFFER_USER_OWNED,
	SOUP_BUFFER_STATIC
} SoupOwnership;

/**
 * SoupDataBuffer:
 * @owner: the ownership of the data
 * @body: the data itself
 * @length: length of @body
 *
 * A data buffer used in several places.
 **/
typedef struct {
	SoupOwnership  owner;
	char          *body;
	guint          length;
} SoupDataBuffer;

/**
 * SoupMessage:
 * @method: the HTTP method
 * @status_code: the HTTP status code
 * @reason_phrase: the status phrase associated with @status_code
 * @request: the request buffer
 * @request_headers: the request headers
 * @response: the response buffer
 * @response_headers: the response headers
 * @status: the processing status of the message
 *
 * Represents an HTTP message being sent or received.
 **/
struct SoupMessage {
	GObject parent;

	/*< public >*/
	const char         *method;

	guint               status_code;
	const char         *reason_phrase;

	SoupDataBuffer      request;
	SoupMessageHeaders *request_headers;

	SoupDataBuffer      response;
	SoupMessageHeaders *response_headers;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void     (*wrote_informational) (SoupMessage *msg);
	void     (*wrote_headers)       (SoupMessage *msg);
	void     (*wrote_chunk)         (SoupMessage *msg);
	void     (*wrote_body)          (SoupMessage *msg);
	void     (*got_informational)   (SoupMessage *msg);
	void     (*got_headers)         (SoupMessage *msg);
	void     (*got_chunk)           (SoupMessage *msg);
	void     (*got_body)            (SoupMessage *msg);
	void     (*restarted)           (SoupMessage *msg);
	void     (*finished)            (SoupMessage *msg);
} SoupMessageClass;

GType soup_message_get_type (void);

/**
 * SoupMessageCallbackFn:
 * @req: the #SoupMessage in question
 * @user_data: user data
 *
 * A callback function used by many #SoupMessage methods.
 **/
typedef void (*SoupMessageCallbackFn) (SoupMessage *req, gpointer user_data);

SoupMessage   *soup_message_new                 (const char        *method,
						 const char        *uri_string);
SoupMessage   *soup_message_new_from_uri        (const char        *method,
						 const SoupURI     *uri);

void           soup_message_set_request         (SoupMessage       *msg,
						 const char        *content_type,
						 SoupOwnership      req_owner,
						 char              *req_body,
						 gulong             req_length);

void           soup_message_set_response        (SoupMessage       *msg,
						 const char        *content_type,
						 SoupOwnership      resp_owner,
						 char              *resp_body,
						 gulong             resp_length);

/**
 * SoupHTTPVersion:
 * @SOUP_HTTP_1_0: HTTP 1.0 (RFC 1945)
 * @SOUP_HTTP_1_1: HTTP 1.1 (RFC 2616)
 *
 * Indicates the HTTP protocol version being used.
 **/
typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1
} SoupHTTPVersion;

void             soup_message_set_http_version    (SoupMessage       *msg,
						   SoupHTTPVersion    version);
SoupHTTPVersion  soup_message_get_http_version    (SoupMessage       *msg);

gboolean         soup_message_is_keepalive        (SoupMessage       *msg);

const SoupURI   *soup_message_get_uri             (SoupMessage       *msg);
void             soup_message_set_uri             (SoupMessage       *msg,
						   const SoupURI     *uri);

SoupTransferEncoding soup_message_get_request_encoding  (SoupMessage *msg,
							 guint       *content_length);
SoupTransferEncoding soup_message_get_response_encoding (SoupMessage *msg,
							 guint       *content_length);

/**
 * SoupMessageFlags:
 * @SOUP_MESSAGE_NO_REDIRECT: The session should not follow redirect
 * (3xx) responses received by this message.
 * @SOUP_MESSAGE_OVERWRITE_CHUNKS: Rather than building up the
 * response body in %response, each new chunk should overwrite the
 * previous one. (This can be used if you are connecting to the
 * %got_chunk signal or have installed a %SOUP_MESSAGE_BODY_CHUNK
 * handler.
 * @SOUP_MESSAGE_EXPECT_CONTINUE: This will cause an "Expect:
 * 100-continue" header to be added to the outgoing request, giving
 * the server the opportunity to reject the message (eg, with a 401
 * Unauthorized) before the full request body is sent.
 *
 * Various flags that can be set on a #SoupMessage to alter its
 * behavior.
 **/
typedef enum {
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3),
	SOUP_MESSAGE_EXPECT_CONTINUE  = (1 << 4)
} SoupMessageFlags;

void           soup_message_set_flags           (SoupMessage        *msg,
						 guint               flags);

guint          soup_message_get_flags           (SoupMessage        *msg);

/*
 * Handler Registration 
 */

/**
 * SoupHandlerPhase:
 * @SOUP_HANDLER_POST_REQUEST: The handler should run immediately
 * after sending the request body
 * @SOUP_HANDLER_PRE_BODY: The handler should run before reading the
 * response body (after reading the headers).
 * @SOUP_HANDLER_BODY_CHUNK: The handler should run after every body
 * chunk is read. (See also %SOUP_MESSAGE_OVERWRITE_CHUNKS.)
 * @SOUP_HANDLER_POST_BODY: The handler should run after the entire
 * message body has been read.
 *
 * Indicates when a handler added with soup_message_add_handler() or
 * the like will be run.
 **/
typedef enum {
	SOUP_HANDLER_POST_REQUEST = 1,
	SOUP_HANDLER_PRE_BODY,
	SOUP_HANDLER_BODY_CHUNK,
	SOUP_HANDLER_POST_BODY
} SoupHandlerPhase;

void           soup_message_add_handler         (SoupMessage       *msg,
						 SoupHandlerPhase   phase,
						 SoupMessageCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_header_handler  (SoupMessage       *msg,
						 const char        *header,
						 SoupHandlerPhase   phase,
						 SoupMessageCallbackFn handler_cb,
						 gpointer           user_data);

void           soup_message_add_status_code_handler (
						 SoupMessage       *msg,
						 guint              status_code,
						 SoupHandlerPhase   phase,
						 SoupMessageCallbackFn handler_cb,
						 gpointer           user_data);

void           soup_message_add_status_class_handler (
						 SoupMessage       *msg,
						 SoupStatusClass    status_class,
						 SoupHandlerPhase   phase,
						 SoupMessageCallbackFn handler_cb,
						 gpointer           user_data);

void           soup_message_remove_handler      (SoupMessage       *msg, 
						 SoupHandlerPhase   phase,
						 SoupMessageCallbackFn handler_cb,
						 gpointer           user_data);

/*
 * Status Setting
 */
void           soup_message_set_status          (SoupMessage       *msg, 
						 guint              status_code);

void           soup_message_set_status_full     (SoupMessage       *msg, 
						 guint              status_code, 
						 const char        *reason_phrase);


/* Chunked encoding */
void           soup_message_add_chunk           (SoupMessage       *msg,
						 SoupOwnership      owner,
						 const char        *body,
						 guint              length);
void           soup_message_add_final_chunk     (SoupMessage       *msg);

SoupDataBuffer*soup_message_pop_chunk           (SoupMessage       *msg);


void soup_message_wrote_informational (SoupMessage *msg);
void soup_message_wrote_headers       (SoupMessage *msg);
void soup_message_wrote_chunk         (SoupMessage *msg);
void soup_message_wrote_body          (SoupMessage *msg);
void soup_message_got_informational   (SoupMessage *msg);
void soup_message_got_headers         (SoupMessage *msg);
void soup_message_got_chunk           (SoupMessage *msg);
void soup_message_got_body            (SoupMessage *msg);
void soup_message_restarted           (SoupMessage *msg);
void soup_message_finished            (SoupMessage *msg);

G_END_DECLS

#endif /*SOUP_MESSAGE_H*/
