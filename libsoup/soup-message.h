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
#include "soup-context.h"

typedef enum {
	SOUP_ERROR_NONE = 0,
	SOUP_ERROR_CANCELLED,
	SOUP_ERROR_CANT_CONNECT,
	SOUP_ERROR_IO,
	SOUP_ERROR_MALFORMED_HEADER,
	SOUP_ERROR_CANT_AUTHENTICATE,
	SOUP_ERROR_HANDLER
} SoupErrorCode;

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

typedef gchar * SoupAction;

typedef struct _SoupMessage        SoupMessage;
typedef struct _SoupMessagePrivate SoupMessagePrivate;

struct _SoupMessage {
	SoupMessagePrivate *priv;

	SoupContext        *context;

	SoupTransferStatus  status;

	SoupAction          action;

	SoupDataBuffer      request;
	GHashTable         *request_headers;

	SoupDataBuffer      response;
	guint               response_code;
	gchar              *response_phrase;
	GHashTable         *response_headers;

	const gchar        *method;
};

typedef void (*SoupCallbackFn) (SoupMessage   *req,
				SoupErrorCode  err,
				gpointer       user_data);

SoupMessage   *soup_message_new                (SoupContext       *context,
						SoupAction         action);

SoupMessage   *soup_message_new_full           (SoupContext       *context,
						SoupAction         action,
						SoupOwnership      req_owner,
						gchar             *req_body,
						gulong             req_length);

void           soup_message_free               (SoupMessage       *req);

void           soup_message_cancel             (SoupMessage       *req);

SoupErrorCode  soup_message_send               (SoupMessage       *msg);

void           soup_message_queue              (SoupMessage       *req, 
					        SoupCallbackFn     callback, 
					        gpointer           user_data);

void           soup_message_set_request_header (SoupMessage       *req,
						const gchar       *name,
						const gchar       *value);

const gchar   *soup_message_get_request_header (SoupMessage       *req,
						const gchar       *name);

void           soup_message_set_response_header (SoupMessage      *req,
						 const gchar      *name,
						 const gchar      *value);

const gchar   *soup_message_get_response_header (SoupMessage      *req,
						 const gchar      *name);

#define SOUP_METHOD_POST    "POST"
#define SOUP_METHOD_GET     "GET"
#define SOUP_METHOD_HEAD    "HEAD"
#define SOUP_METHOD_OPTIONS "OPTIONS"

void           soup_message_set_method          (SoupMessage      *msg,
						 const gchar      *method);

const gchar   *soup_message_get_method          (SoupMessage      *msg);

typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1,
} SoupHttpVersion;

void           soup_message_set_http_version    (SoupMessage      *msg,
						 SoupHttpVersion   version);

typedef enum {
	SOUP_HANDLER_PRE_BODY,
	SOUP_HANDLER_BODY_CHUNK,
	SOUP_HANDLER_POST_BODY
} SoupHandlerType;

typedef SoupErrorCode (*SoupHandlerFn) (SoupMessage *msg, gpointer user_data);

void           soup_message_add_header_handler  (SoupMessage      *msg,
						 const gchar      *header,
						 SoupHandlerType   type,
						 SoupHandlerFn     handler_cb,
						 gpointer          user_data);

void           soup_message_add_response_code_handler (
						 SoupMessage      *msg,
						 guint             code,
						 SoupHandlerType   type,
						 SoupHandlerFn     handler_cb,
						 gpointer          user_data);

void           soup_message_add_body_handler    (SoupMessage      *msg,
						 SoupHandlerType   type,
						 SoupHandlerFn     handler_cb,
						 gpointer          user_data);

typedef enum {
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),
	SOUP_MESSAGE_NO_COOKIE        = (1 << 2),
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3)
} SoupMessageFlags;

void           soup_message_set_flags          (SoupMessage       *msg,
						guint              flags);

guint          soup_message_get_flags          (SoupMessage       *msg);

#endif /*SOUP_MESSAGE_H*/
