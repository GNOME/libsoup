/*
 * Copyright (C) 2003 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-connection.h"
#include "soup-message.h"
#include "soup-session-private.h"

G_BEGIN_DECLS

typedef enum {
        SOUP_MESSAGE_STARTING,
        SOUP_MESSAGE_CONNECTING,
        SOUP_MESSAGE_CONNECTED,
        SOUP_MESSAGE_TUNNELING,
        SOUP_MESSAGE_READY,
        SOUP_MESSAGE_RUNNING,
        SOUP_MESSAGE_CACHED,
        SOUP_MESSAGE_REQUEUED,
        SOUP_MESSAGE_RESTARTING,
        SOUP_MESSAGE_FINISHING,
        SOUP_MESSAGE_FINISHED
} SoupMessageQueueItemState;

struct _SoupMessageQueueItem {
        SoupSession *session;
        SoupMessage *msg;
        GMainContext *context;

        GCancellable *cancellable;
        GError *error;

        GTask *task;

        guint paused       : 1;
        guint io_started   : 1;
        guint async        : 1;
        guint connect_only : 1;
        guint resend_count : 5;
        int io_priority;

        SoupMessageQueueItemState state;
        SoupMessageQueueItem *related;
};

SoupMessageQueueItem *soup_message_queue_item_new    (SoupSession          *session,
                                                      SoupMessage          *msg,
                                                      gboolean              async,
                                                      GCancellable         *cancellable);
SoupMessageQueueItem *soup_message_queue_item_ref    (SoupMessageQueueItem *item);
void                  soup_message_queue_item_unref  (SoupMessageQueueItem *item);
void                  soup_message_queue_item_cancel (SoupMessageQueueItem *item);

G_END_DECLS
