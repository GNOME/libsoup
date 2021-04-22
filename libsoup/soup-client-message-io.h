/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-message-io-data.h"
#include "soup-message-queue-item.h"

typedef struct _SoupClientMessageIO SoupClientMessageIO;

typedef struct {
        void          (*destroy)              (SoupClientMessageIO       *io);
        void          (*finished)             (SoupClientMessageIO       *io);
        void          (*stolen)               (SoupClientMessageIO       *io);
        void          (*send_item)            (SoupClientMessageIO       *io,
                                               SoupMessageQueueItem      *item,
                                               SoupMessageIOCompletionFn  completion_cb,
                                               gpointer                   user_data);
        GInputStream *(*get_response_stream)  (SoupClientMessageIO       *io,
                                               GError                   **error);
        void          (*pause)                (SoupClientMessageIO       *io);
        void          (*unpause)              (SoupClientMessageIO       *io);
        gboolean      (*is_paused)            (SoupClientMessageIO       *io);
        void          (*run)                  (SoupClientMessageIO       *io,
                                               gboolean                   blocking);
        gboolean      (*run_until_read)       (SoupClientMessageIO       *io,
                                               GCancellable              *cancellable,
                                               GError                   **error);
        void          (*run_until_read_async) (SoupClientMessageIO       *io,
                                               int                        io_priority,
                                               GCancellable              *cancellable,
                                               GAsyncReadyCallback        callback,
                                               gpointer                   user_data);
        gboolean      (*run_until_finish)     (SoupClientMessageIO       *io,
                                               gboolean                   blocking,
                                               GCancellable              *cancellable,
                                               GError                   **error);
} SoupClientMessageIOFuncs;

struct _SoupClientMessageIO {
        const SoupClientMessageIOFuncs *funcs;
};

void          soup_client_message_io_destroy              (SoupClientMessageIO       *io);
void          soup_client_message_io_finished             (SoupClientMessageIO       *io);
void          soup_client_message_io_stolen               (SoupClientMessageIO       *io);
void          soup_client_message_io_send_item            (SoupClientMessageIO       *io,
                                                           SoupMessageQueueItem      *item,
                                                           SoupMessageIOCompletionFn  completion_cb,
                                                           gpointer                   user_data);
void          soup_client_message_io_pause                (SoupClientMessageIO       *io);
void          soup_client_message_io_unpause              (SoupClientMessageIO       *io);
gboolean      soup_client_message_io_is_paused            (SoupClientMessageIO       *io);
void          soup_client_message_io_run                  (SoupClientMessageIO       *io,
                                                           gboolean                   blocking);
gboolean      soup_client_message_io_run_until_read       (SoupClientMessageIO       *io,
                                                           GCancellable              *cancellable,
                                                           GError                   **error);
void          soup_client_message_io_run_until_read_async (SoupClientMessageIO       *io,
                                                           int                        io_priority,
                                                           GCancellable              *cancellable,
                                                           GAsyncReadyCallback        callback,
                                                           gpointer                   user_data);
gboolean      soup_client_message_io_run_until_finish     (SoupClientMessageIO       *io,
                                                           gboolean                   blocking,
                                                           GCancellable              *cancellable,
                                                           GError                   **error);
GInputStream *soup_client_message_io_get_response_stream  (SoupClientMessageIO       *io,
                                                          GError                    **error);
