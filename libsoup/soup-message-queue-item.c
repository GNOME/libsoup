/*
 * soup-message-queue-item.c: Message queue item
 *
 * Copyright (C) 2003 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2021 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-message-queue-item.h"
#include "soup.h"

SoupMessageQueueItem *
soup_message_queue_item_new (SoupSession        *session,
                             SoupMessage        *msg,
                             gboolean            async,
                             GCancellable       *cancellable,
                             SoupSessionCallback callback,
                             gpointer            user_data)
{
        SoupMessageQueueItem *item;

        item = g_atomic_rc_box_new0 (SoupMessageQueueItem);
        item->session = g_object_ref (session);
        item->msg = g_object_ref (msg);
        item->async = async;
        item->callback = callback;
        item->callback_data = user_data;
        item->cancellable = cancellable ? g_object_ref (cancellable) : g_cancellable_new ();
        item->priority = soup_message_get_priority (msg);

        g_signal_connect_swapped (msg, "restarted",
                                  G_CALLBACK (g_cancellable_reset),
                                  item->cancellable);
        return item;
}

SoupMessageQueueItem *
soup_message_queue_item_ref (SoupMessageQueueItem *item)
{
        g_atomic_rc_box_acquire (item);

        return item;
}

static void
soup_message_queue_item_destroy (SoupMessageQueueItem *item)
{
        g_warn_if_fail (item->conn == NULL);

        g_signal_handlers_disconnect_by_data (item->msg, item->cancellable);

        g_object_unref (item->session);
        g_object_unref (item->msg);
        g_object_unref (item->cancellable);
        g_clear_error (&item->error);
        g_clear_object (&item->task);
}

void
soup_message_queue_item_unref (SoupMessageQueueItem *item)
{
        g_atomic_rc_box_release_full (item, (GDestroyNotify)soup_message_queue_item_destroy);
}

void
soup_message_queue_item_cancel (SoupMessageQueueItem *item)
{
        g_cancellable_cancel (item->cancellable);
}
