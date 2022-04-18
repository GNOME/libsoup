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
        void          (*finished)             (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        void          (*stolen)               (SoupClientMessageIO       *io);
        void          (*send_item)            (SoupClientMessageIO       *io,
                                               SoupMessageQueueItem      *item,
                                               SoupMessageIOCompletionFn  completion_cb,
                                               gpointer                   user_data);
        GInputStream *(*get_response_stream)  (SoupClientMessageIO       *io,
                                               SoupMessage               *msg,
                                               GError                   **error);
        void          (*pause)                (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        void          (*unpause)              (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        gboolean      (*is_paused)            (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        void          (*run)                  (SoupClientMessageIO       *io,
                                               SoupMessage               *msg,
                                               gboolean                   blocking);
        gboolean      (*run_until_read)       (SoupClientMessageIO       *io,
                                               SoupMessage               *msg,
                                               GCancellable              *cancellable,
                                               GError                   **error);
        void          (*run_until_read_async) (SoupClientMessageIO       *io,
                                               SoupMessage               *msg,
                                               int                        io_priority,
                                               GCancellable              *cancellable,
                                               GAsyncReadyCallback        callback,
                                               gpointer                   user_data);
        gboolean      (*close_async)          (SoupClientMessageIO       *io,
                                               SoupConnection            *conn,
                                               GAsyncReadyCallback        callback);
        gboolean      (*skip)                 (SoupClientMessageIO       *io,
                                               SoupMessage               *msg,
                                               gboolean                   blocking,
                                               GCancellable              *cancellable,
                                               GError                   **error);
        gboolean      (*is_open)              (SoupClientMessageIO       *io);
        gboolean      (*in_progress)          (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        gboolean      (*is_reusable)          (SoupClientMessageIO       *io);
        GCancellable *(*get_cancellable)      (SoupClientMessageIO       *io,
                                               SoupMessage               *msg);
        void          (*owner_changed)        (SoupClientMessageIO       *io);
} SoupClientMessageIOFuncs;

struct _SoupClientMessageIO {
        const SoupClientMessageIOFuncs *funcs;
};

void          soup_client_message_io_destroy              (SoupClientMessageIO       *io);
void          soup_client_message_io_finished             (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
void          soup_client_message_io_stolen               (SoupClientMessageIO       *io);
void          soup_client_message_io_send_item            (SoupClientMessageIO       *io,
                                                           SoupMessageQueueItem      *item,
                                                           SoupMessageIOCompletionFn  completion_cb,
                                                           gpointer                   user_data);
void          soup_client_message_io_pause                (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
void          soup_client_message_io_unpause              (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
gboolean      soup_client_message_io_is_paused            (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
void          soup_client_message_io_run                  (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg,
                                                           gboolean                   blocking);
gboolean      soup_client_message_io_run_until_read       (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg,
                                                           GCancellable              *cancellable,
                                                           GError                   **error);
void          soup_client_message_io_run_until_read_async (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg,
                                                           int                        io_priority,
                                                           GCancellable              *cancellable,
                                                           GAsyncReadyCallback        callback,
                                                           gpointer                   user_data);
gboolean      soup_client_message_io_close_async          (SoupClientMessageIO       *io,
                                                           SoupConnection            *conn,
                                                           GAsyncReadyCallback        callback);
gboolean      soup_client_message_io_skip                 (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg,
                                                           gboolean                   blocking,
                                                           GCancellable              *cancellable,
                                                           GError                   **error);
GInputStream *soup_client_message_io_get_response_stream  (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg,
                                                           GError                   **error);
gboolean      soup_client_message_io_is_open              (SoupClientMessageIO       *io);
gboolean      soup_client_message_io_in_progress          (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
gboolean      soup_client_message_io_is_reusable          (SoupClientMessageIO       *io);
GCancellable *soup_client_message_io_get_cancellable      (SoupClientMessageIO       *io,
                                                           SoupMessage               *msg);
void          soup_client_message_io_owner_changed        (SoupClientMessageIO       *io);
