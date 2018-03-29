/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __SOUP_MESSAGE_QUEUE_H__
#define __SOUP_MESSAGE_QUEUE_H__ 1

#include "soup-connection.h"
#include "soup-message.h"
#include "soup-session.h"

G_BEGIN_DECLS

typedef enum {
	SOUP_MESSAGE_STARTING,
	SOUP_MESSAGE_GOT_CONNECTION,
	SOUP_MESSAGE_CONNECTING,
	SOUP_MESSAGE_CONNECTED,
	SOUP_MESSAGE_TUNNELING,
	SOUP_MESSAGE_TUNNELED,
	SOUP_MESSAGE_READY,
	SOUP_MESSAGE_RUNNING,
	SOUP_MESSAGE_CACHED,
	SOUP_MESSAGE_RESTARTING,
	SOUP_MESSAGE_FINISHING,
	SOUP_MESSAGE_FINISHED
} SoupMessageQueueItemState;

struct _SoupMessageQueueItem {
	/*< public >*/
	SoupSession *session;
	SoupMessageQueue *queue;
	SoupMessage *msg;
	SoupSessionCallback callback;
	gpointer callback_data;
	GMainContext *async_context;

	GCancellable *cancellable;
	GError *error;

	SoupConnection *conn;
	GTask *task;
	GSource *io_source;

	guint paused            : 1;
	guint new_api           : 1;
	guint io_started        : 1;
	guint async             : 1;
	guint async_pending     : 1;
	guint conn_is_dedicated : 1;
	guint connect_only      : 1;
	guint priority          : 3;
	guint resend_count      : 5;

	SoupMessageQueueItemState state;

	/*< private >*/
	guint removed           : 1;
	guint ref_count         : 31;
	SoupMessageQueueItem *prev, *next;
	SoupMessageQueueItem *related;
};

SoupMessageQueue     *soup_message_queue_new        (SoupSession          *session);
SoupMessageQueueItem *soup_message_queue_append     (SoupMessageQueue     *queue,
						     SoupMessage          *msg,
						     SoupSessionCallback   callback,
						     gpointer              user_data);

SoupMessageQueueItem *soup_message_queue_lookup     (SoupMessageQueue     *queue,
						     SoupMessage          *msg);

SoupMessageQueueItem *soup_message_queue_first      (SoupMessageQueue     *queue);
SoupMessageQueueItem *soup_message_queue_next       (SoupMessageQueue     *queue,
						     SoupMessageQueueItem *item);

void                  soup_message_queue_remove     (SoupMessageQueue     *queue,
						     SoupMessageQueueItem *item);

void                  soup_message_queue_destroy    (SoupMessageQueue     *queue);

void soup_message_queue_item_ref            (SoupMessageQueueItem *item);
void soup_message_queue_item_unref          (SoupMessageQueueItem *item);

G_END_DECLS

#endif /* __SOUP_MESSAGE_QUEUE_H__ */
