/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include <glib.h>
#include <libsoup/soup-context.h>

typedef enum {
	/*
	 * Transport Errors
	 */
	SOUP_ERROR_CANCELLED                = 1,
	SOUP_ERROR_CANT_CONNECT,
	SOUP_ERROR_CANT_CONNECT_PROXY,
	SOUP_ERROR_IO,
	SOUP_ERROR_MALFORMED,
	SOUP_ERROR_CANT_AUTHENTICATE,
	SOUP_ERROR_CANT_AUTHENTICATE_PROXY,

	/*
	 * HTTP Response Codes
	 */
	SOUP_ERROR_CONTINUE                 = 100,
	SOUP_ERROR_PROTOCOL_SWITCH          = 101,
	SOUP_ERROR_DAV_PROCESSING           = 102,

	SOUP_ERROR_OK                       = 200,
	SOUP_ERROR_CREATED                  = 201,
	SOUP_ERROR_ACCEPTED                 = 202,
	SOUP_ERROR_NON_AUTHORITATIVE        = 203,
	SOUP_ERROR_NO_CONTENT               = 204,
	SOUP_ERROR_RESET_CONTENT            = 205,
	SOUP_ERROR_PARTIAL_CONTENT          = 206,
	SOUP_ERROR_DAV_MULTISTATUS          = 207,

	SOUP_ERROR_MULTIPLE_CHOICES         = 300,
	SOUP_ERROR_MOVED_PERMANANTLY        = 301,
	SOUP_ERROR_FOUND                    = 302,
	SOUP_ERROR_SEE_OTHER                = 303,
	SOUP_ERROR_NOT_MODIFIED             = 304,
	SOUP_ERROR_USE_PROXY                = 305,
	SOUP_ERROR_TEMPORARY_REDIRECT       = 307,

	SOUP_ERROR_BAD_REQUEST              = 400,
	SOUP_ERROR_UNAUTHORIZED             = 401,
	SOUP_ERROR_PAYMENT_REQUIRED         = 402,
	SOUP_ERROR_FORBIDDEN                = 403,
	SOUP_ERROR_NOT_FOUND                = 404,
	SOUP_ERROR_METHOD_NOT_ALLOWED       = 405,
	SOUP_ERROR_NOT_ACCEPTABLE           = 406,
	SOUP_ERROR_PROXY_UNAUTHORIZED       = 407,
	SOUP_ERROR_TIMED_OUT                = 408,
	SOUP_ERROR_CONFLICT                 = 409,
	SOUP_ERROR_GONE                     = 410,
	SOUP_ERROR_LENGTH_REQUIRED          = 411,
	SOUP_ERROR_PRECONDITION_FAILED      = 412,
	SOUP_ERROR_BODY_TOO_LARGE           = 413,
	SOUP_ERROR_URI_TOO_LARGE            = 414,
	SOUP_ERROR_UNKNOWN_MEDIA_TYPE       = 415,
	SOUP_ERROR_INVALID_RANGE            = 416,
	SOUP_ERROR_EXPECTATION_FAILED       = 417,
	SOUP_ERROR_DAV_UNPROCESSABLE        = 422,
	SOUP_ERROR_DAV_LOCKED               = 423,
	SOUP_ERROR_DAV_DEPENDENCY_FAILED    = 423,

	SOUP_ERROR_INTERNAL                 = 500,
	SOUP_ERROR_NOT_IMPLEMENTED          = 501,
	SOUP_ERROR_BAD_GATEWAY              = 502,
	SOUP_ERROR_SERVICE_UNAVAILABLE      = 503,
	SOUP_ERROR_GATEWAY_TIMEOUT          = 504,
	SOUP_ERROR_VERSION_UNSUPPORTED      = 505,
	SOUP_ERROR_DAV_OUT_OF_SPACE         = 507,
	SOUP_ERROR_NOT_EXTENDED             = 510,
} SoupKnownErrorCode;

#define SOUP_ERROR_IS_TRANSPORT(x)     ((x) > 0 && (x) < 100)
#define SOUP_ERROR_IS_INFORMATIONAL(x) ((x) >= 100 && (x) < 200)
#define SOUP_ERROR_IS_SUCCESSFUL(x)    ((x) >= 200 && (x) < 300)
#define SOUP_ERROR_IS_REDIRECTION(x)   ((x) >= 300 && (x) < 400)
#define SOUP_ERROR_IS_CLIENT_ERROR(x)  ((x) >= 400 && (x) < 500)
#define SOUP_ERROR_IS_SERVER_ERROR(x)  ((x) >= 500 && (x) < 600)
#define SOUP_ERROR_IS_UNKNOWN(x)       ((x) >= 600)

typedef enum {
	SOUP_ERROR_CLASS_TRANSPORT = 1,
	SOUP_ERROR_CLASS_INFORMATIONAL,
	SOUP_ERROR_CLASS_SUCCESS,
	SOUP_ERROR_CLASS_REDIRECT,
	SOUP_ERROR_CLASS_CLIENT_ERROR,
	SOUP_ERROR_CLASS_SERVER_ERROR,
	SOUP_ERROR_CLASS_UNKNOWN,
	SOUP_ERROR_CLASS_HANDLER,
} SoupErrorClass;

#define SOUP_MESSAGE_IS_ERROR(_msg)                            \
        (_msg->errorclass &&                                   \
	 _msg->errorclass != SOUP_ERROR_CLASS_SUCCESS &&       \
         _msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL && \
	 _msg->errorclass != SOUP_ERROR_CLASS_UNKNOWN)

typedef enum {
	SOUP_STATUS_IDLE = 0,
	SOUP_STATUS_QUEUED,
        SOUP_STATUS_CONNECTING,
	SOUP_STATUS_SENDING_REQUEST,
	SOUP_STATUS_READING_RESPONSE,
	SOUP_STATUS_FINISHED
} SoupTransferStatus;

typedef enum {
	SOUP_BUFFER_SYSTEM_OWNED = 0,
	SOUP_BUFFER_USER_OWNED,
	SOUP_BUFFER_STATIC
} SoupOwnership;

typedef struct {
	SoupOwnership  owner;
	gchar         *body;
	guint          length;
} SoupDataBuffer;

#define SOUP_METHOD_POST      "POST"
#define SOUP_METHOD_GET       "GET"
#define SOUP_METHOD_HEAD      "HEAD"
#define SOUP_METHOD_OPTIONS   "OPTIONS"
#define SOUP_METHOD_PUT       "PUT"
#define SOUP_METHOD_MOVE      "MOVE"
#define SOUP_METHOD_COPY      "COPY"
#define SOUP_METHOD_DELETE    "DELETE"
#define SOUP_METHOD_TRACE     "TRACE"
#define SOUP_METHOD_CONNECT   "CONNECT"
#define SOUP_METHOD_MKCOL     "MKCOL"
#define SOUP_METHOD_PROPPATCH "PROPPATCH"
#define SOUP_METHOD_PROPFIND  "PROPFIND"
#define SOUP_METHOD_SEARCH    "SEARCH"

typedef struct _SoupMessage        SoupMessage;
typedef struct _SoupMessagePrivate SoupMessagePrivate;

struct _SoupMessage {
	SoupMessagePrivate *priv;

	SoupContext        *context;
	SoupConnection     *connection;

	const gchar        *method;

	SoupTransferStatus  status;

	guint               errorcode;
	SoupErrorClass      errorclass;
	const gchar        *errorphrase;

	SoupDataBuffer      request;
	GHashTable         *request_headers;

	SoupDataBuffer      response;
	GHashTable         *response_headers;
};

typedef void (*SoupCallbackFn) (SoupMessage *req, gpointer user_data);

SoupMessage   *soup_message_new                 (SoupContext       *context,
						 const gchar       *method);

SoupMessage   *soup_message_new_full            (SoupContext       *context,
						 const gchar       *method,
						 SoupOwnership      req_owner,
						 gchar             *req_body,
						 gulong             req_length);

void           soup_message_free                (SoupMessage       *req);

void           soup_message_cancel              (SoupMessage       *req);

SoupErrorClass soup_message_send                (SoupMessage       *msg);

void           soup_message_queue               (SoupMessage       *req, 
						 SoupCallbackFn     callback, 
						 gpointer           user_data);

void           soup_message_set_error           (SoupMessage       *msg, 
						 SoupKnownErrorCode errcode);

void           soup_message_set_error_full      (SoupMessage       *msg, 
						 guint              errcode, 
						 const gchar       *errphrase);

void           soup_message_set_handler_error   (SoupMessage       *msg, 
						 guint              errcode, 
						 const gchar       *errphrase);

void           soup_message_add_header          (GHashTable        *hash,
						 const gchar       *name,
						 const gchar       *value);

const gchar   *soup_message_get_header          (GHashTable        *hash,
						 const gchar       *name);

const GSList  *soup_message_get_header_list     (GHashTable        *hash,
						 const gchar       *name);

void           soup_message_foreach_header      (GHashTable        *hash,
						 GHFunc             func,
						 gpointer           user_data);

void           soup_message_clear_headers       (GHashTable        *hash);

/** DEPRECATED **/
void           soup_message_set_request_header  (SoupMessage       *req,
						 const gchar       *name,
						 const gchar       *value);

/** DEPRECATED **/
const gchar   *soup_message_get_request_header  (SoupMessage       *req,
						 const gchar       *name);

/** DEPRECATED **/
void           soup_message_set_response_header (SoupMessage       *req,
						 const gchar       *name,
						 const gchar       *value);

/** DEPRECATED **/
const gchar   *soup_message_get_response_header (SoupMessage       *req,
						 const gchar       *name);

typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1,
} SoupHttpVersion;

void           soup_message_set_http_version    (SoupMessage       *msg,
						 SoupHttpVersion    version);

typedef enum {
	SOUP_HANDLER_PRE_BODY = 1,
	SOUP_HANDLER_BODY_CHUNK,
	SOUP_HANDLER_POST_BODY
} SoupHandlerType;

void           soup_message_add_handler         (SoupMessage       *msg,
						 SoupHandlerType    type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_header_handler  (SoupMessage       *msg,
						 const gchar       *header,
						 SoupHandlerType    type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_error_code_handler (
						 SoupMessage       *msg,
						 guint              errorcode,
						 SoupHandlerType    type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_error_class_handler (
						 SoupMessage       *msg,
						 SoupErrorClass     errorclass,
						 SoupHandlerType    type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_remove_handler      (SoupMessage       *msg, 
						 SoupHandlerType    type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

typedef enum {
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),
	SOUP_MESSAGE_NO_COOKIE        = (1 << 2),
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3)
} SoupMessageFlags;

void           soup_message_set_flags          (SoupMessage        *msg,
						guint               flags);

guint          soup_message_get_flags          (SoupMessage        *msg);

const gchar   *soup_get_error_phrase           (SoupKnownErrorCode  errcode);

SoupErrorClass soup_get_error_class            (SoupKnownErrorCode  errcode);

#endif /*SOUP_MESSAGE_H*/
