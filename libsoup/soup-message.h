/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include <glib.h>
#include <libsoup/soup-context.h>
#include <libsoup/soup-error.h>

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

#define SOUP_MESSAGE_IS_ERROR(_msg)                            \
        (_msg->errorclass &&                                   \
	 _msg->errorclass != SOUP_ERROR_CLASS_SUCCESS &&       \
         _msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL && \
	 _msg->errorclass != SOUP_ERROR_CLASS_UNKNOWN)

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

void           soup_message_foreach_remove_header (
						 GHashTable        *hash,
						 GHRFunc            func,
						 gpointer           user_data);

void           soup_message_remove_header       (GHashTable        *hash,
						 const gchar       *name);

void           soup_message_clear_headers       (GHashTable        *hash);

typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1,
} SoupHttpVersion;

void           soup_message_set_http_version    (SoupMessage       *msg,
						 SoupHttpVersion    version);

void           soup_message_set_context         (SoupMessage       *msg,
						 SoupContext       *new_ctx);

SoupContext   *soup_message_get_context         (SoupMessage       *msg);

typedef enum {
	/*
	 * SOUP_MESSAGE_NO_PIPELINE: 
	 * Use a currently unused connection or establish a new 
	 * connection when issuing this request.
	 */
	SOUP_MESSAGE_NO_PIPELINE      = (1 << 0),

	/*
	 * SOUP_MESSAGE_NO_REDIRECT: 
	 * Do not follow redirection responses.
	 */
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),

	/*
	 * SOUP_MESSAGE_NO_COOKIE:
	 * Do not send cookie information with request, and do not 
	 * store cookie information from the response.
	 */
	SOUP_MESSAGE_NO_COOKIE        = (1 << 2),

	/*
	 * SOUP_MESSAGE_OVERWRITE_CHUNKS:
	 * Downloaded data chunks should not be stored in the response 
	 * data buffer.  Instead only send data to SOUP_HANDLER_BODY_CHUNK 
	 * handlers, then truncate the data buffer.
	 *
	 * Useful when the response is expected to be very large, and 
	 * storage in memory is not desired.
	 */
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3)
} SoupMessageFlags;

void           soup_message_set_flags           (SoupMessage        *msg,
						 guint               flags);

guint          soup_message_get_flags           (SoupMessage        *msg);

/*
 * Handler Registration 
 */
typedef enum {
	/*
	 * Client-side events
	 */
	SOUP_HANDLER_PREPARE = 0,
	SOUP_HANDLER_HEADERS,
	SOUP_HANDLER_DATA,
	SOUP_HANDLER_FINISHED,

	/*
	 * Server-side events
	 */
	SOUP_HANDLER_DATA_SENT
} SoupHandlerEvent;

enum {
	SOUP_FILTER_HEADER      = (1 << 0),
	SOUP_FILTER_ERROR_CODE  = (1 << 1),
	SOUP_FILTER_ERROR_CLASS = (1 << 2),
	SOUP_FILTER_TIMEOUT     = (1 << 3),
} SoupHandlerFilterType;

typedef struct {
	gint type;

	union {
		guint               errorcode;
		SoupErrorClass      errorclass;
		const gchar        *header;
		guint               timeout;
	} data;
} SoupHandlerFilter;

typedef enum {
	/*
	 * Continue processing as normal.
	 */
	SOUP_HANDLER_CONTINUE,

	/*
	 * Do not process further handlers.  Continue receiving data.
	 */
	SOUP_HANDLER_STOP,

	/*
	 * do not process further handlers.  Stop receiving data and 
	 * issue final callback.
	 */
	SOUP_HANDLER_KILL,

	/*
	 * Restart handler processing.  This should be returned if a 
	 * handler changes the message's errorcode.
	 */
	SOUP_HANDLER_RESTART,

	/*
	 * Requeue the request immediately.  Stop processing handlers 
	 * and do not issue final callback.
	 */
	SOUP_HANDLER_RESEND
} SoupHandlerResult;

typedef SoupHandlerResult (*SoupHandlerFn) (SoupMessage *req, 
					    gpointer     user_data);

void           soup_message_add_handler         (SoupMessage       *msg,
						 SoupHandlerEvent   type,
						 SoupHandlerFilter *filter,
						 SoupHandlerFn      handler_cb,
						 gpointer           user_data);

typedef enum {
	/*
	 * Run before global handlers and previously registered message
	 * handlers. 
	 */
	SOUP_HANDLER_FIRST,

	/*
	 * Run after global handlers and previously registered message
	 * handlers. 
	 */
	SOUP_HANDLER_LAST
} SoupHandlerWhen;

void           soup_message_add_handler_full    (SoupMessage       *msg,
						 const gchar       *name,
						 SoupHandlerEvent   type,
						 SoupHandlerWhen    order,
						 SoupHandlerFilter *filter,
						 SoupHandlerFn      handler_cb,
						 gpointer           user_data);

GSList        *soup_message_list_handlers       (SoupMessage       *msg);

void           soup_message_remove_handler      (SoupMessage       *msg, 
						 gchar             *name);

void           soup_message_remove_handler_by_func (
						 SoupMessage       *msg, 
						 SoupHandlerFn      handler_cb);

void           soup_message_remove_handler_by_func_and_data (
						 SoupMessage       *msg, 
						 SoupHandlerFn      handler_cb,
						 gpointer           user_data);

/*
 * Error Setting (for use by Handlers)
 */
void           soup_message_set_error           (SoupMessage       *msg, 
						 SoupKnownErrorCode errcode);

void           soup_message_set_error_full      (SoupMessage       *msg, 
						 guint              errcode, 
						 const gchar       *errphrase);

void           soup_message_set_handler_error   (SoupMessage       *msg, 
						 guint              errcode, 
						 const gchar       *errphrase);

#endif /*SOUP_MESSAGE_H*/
