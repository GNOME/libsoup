/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#ifndef SOUP_QUEUE_H
#define SOUP_QUEUE_H 1

#include <glib.h>

#include "soup-message.h"
#include "soup-context.h"

typedef enum {
	SOUP_RESULT_FREE_MESSAGE = 0,
	SOUP_RESULT_RESEND_MESSAGE,
	SOUP_RESULT_DO_NOTHING
} SoupCallbackResult;

typedef enum {
	SOUP_ERROR_NONE = 0,
	SOUP_ERROR_CANCELLED,
	SOUP_ERROR_CANT_CONNECT,
	SOUP_ERROR_IO,
	SOUP_ERROR_MALFORMED_HEADER
} SoupErrorCode;

typedef SoupCallbackResult (*SoupCallbackFn) (SoupMessage   *req,
					      SoupErrorCode  err,
					      gpointer       user_data);

void         soup_queue_message  (SoupMessage       *req, 
				  SoupCallbackFn     callback, 
				  gpointer           user_data);

void         soup_queue_shutdown (void);

#endif /* SOUP_QUEUE_H */
