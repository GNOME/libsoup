/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.h: Asyncronous Callback-based HTTP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2001, Ximian, Inc.
 */

#ifndef SOUP_QUEUE_H
#define SOUP_QUEUE_H 1

#include <glib.h>

#include <libsoup/soup-message.h>

void         soup_queue_message        (SoupMessage          *req,
					SoupCallbackFn        callback, 
					gpointer              user_data);

void         soup_queue_connect_cb     (SoupContext          *ctx,
					SoupConnectErrorCode  err,
					SoupConnection       *conn,
					gpointer              user_data);

void         soup_queue_add_request    (SoupMessage          *req);
void         soup_queue_remove_request (SoupMessage          *req);
SoupMessage *soup_queue_first_request  (void);
SoupMessage *soup_queue_next_request   (void);

void         soup_queue_shutdown       (void);

#endif /* SOUP_QUEUE_H */
