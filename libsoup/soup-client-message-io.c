/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-client-message-io.h"

void
soup_client_message_io_destroy (SoupClientMessageIO *io)
{
        if (!io)
                return;

        io->funcs->destroy (io);
}

void
soup_client_message_io_finished (SoupClientMessageIO *io)
{
        io->funcs->finished (io);
}

void
soup_client_message_io_stolen (SoupClientMessageIO *io)
{
        io->funcs->stolen (io);
}

void
soup_client_message_io_send_item (SoupClientMessageIO       *io,
                                  SoupMessageQueueItem      *item,
                                  SoupMessageIOCompletionFn  completion_cb,
                                  gpointer                   user_data)
{
        io->funcs->send_item (io, item, completion_cb, user_data);
}

void
soup_client_message_io_pause (SoupClientMessageIO *io)
{
        io->funcs->pause (io);
}

void
soup_client_message_io_unpause (SoupClientMessageIO *io)
{
        io->funcs->unpause (io);
}

gboolean
soup_client_message_io_is_paused (SoupClientMessageIO *io)
{
        return io->funcs->is_paused (io);
}

void
soup_client_message_io_run (SoupClientMessageIO *io,
                            gboolean             blocking)
{
        io->funcs->run (io, blocking);
}

gboolean
soup_client_message_io_run_until_read (SoupClientMessageIO *io,
                                       GCancellable        *cancellable,
                                       GError             **error)
{
        return io->funcs->run_until_read (io, cancellable, error);
}

void
soup_client_message_io_run_until_read_async (SoupClientMessageIO *io,
                                             int                  io_priority,
                                             GCancellable        *cancellable,
                                             GAsyncReadyCallback  callback,
                                             gpointer             user_data)
{
        io->funcs->run_until_read_async (io, io_priority, cancellable, callback, user_data);
}

gboolean
soup_client_message_io_run_until_finish (SoupClientMessageIO *io,
                                         gboolean             blocking,
                                         GCancellable        *cancellable,
                                         GError             **error)
{
        return io->funcs->run_until_finish (io, blocking, cancellable, error);
}

GInputStream *
soup_client_message_io_get_response_stream (SoupClientMessageIO *io,
                                            GError             **error)
{
        return io->funcs->get_response_stream (io, error);
}
