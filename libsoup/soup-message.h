/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include "soup-context.h"

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
	SOUP_BUFFER_USER_OWNED
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
};

SoupMessage       *soup_message_new        (SoupContext       *context,
					    SoupAction         action);

SoupMessage       *soup_message_new_full   (SoupContext       *context,
					    SoupAction         action,
					    SoupOwnership      req_owner,
					    gchar             *req_body,
					    gulong             req_length);

void               soup_message_free       (SoupMessage       *req);

void               soup_message_cancel     (SoupMessage       *req);

void               soup_message_add_header (SoupMessage       *req,
					    gchar             *name,
					    gchar             *value);
#endif /*SOUP_MESSAGE_H*/
