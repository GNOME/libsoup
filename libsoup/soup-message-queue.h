/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef SOUP_MESSAGE_QUEUE_H
#define SOUP_MESSAGE_QUEUE_H 1

#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup-connection.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-session.h>

G_BEGIN_DECLS

typedef struct SoupMessageQueue SoupMessageQueue; 
typedef struct SoupMessageQueueItem SoupMessageQueueItem;

struct SoupMessageQueueItem {
	/*< public >*/
	SoupSession *session;
	SoupMessageQueue *queue;
	SoupMessage *msg;
	SoupSessionCallback callback;
	gpointer callback_data;

	GCancellable *cancellable;
	SoupAddress *proxy_addr;
	SoupURI *proxy_uri;
	SoupConnection *conn;

	guint resolving_proxy_addr : 1;
	guint resolved_proxy_addr  : 1;

	/*< private >*/
	guint removed              : 1;
	guint ref_count            : 29;
	SoupMessageQueueItem *prev, *next;
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

void                  soup_message_queue_item_ref   (SoupMessageQueueItem *item);
void                  soup_message_queue_item_unref (SoupMessageQueueItem *item);

void                  soup_message_queue_destroy    (SoupMessageQueue     *queue);

G_END_DECLS

#endif /* SOUP_MESSAGE_QUEUE_H */
