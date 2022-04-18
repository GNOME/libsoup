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
soup_client_message_io_finished (SoupClientMessageIO *io,
                                 SoupMessage         *msg)
{
        io->funcs->finished (io, msg);
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
soup_client_message_io_pause (SoupClientMessageIO *io,
                              SoupMessage         *msg)
{
        io->funcs->pause (io, msg);
}

void
soup_client_message_io_unpause (SoupClientMessageIO *io,
                                SoupMessage         *msg)
{
        io->funcs->unpause (io, msg);
}

gboolean
soup_client_message_io_is_paused (SoupClientMessageIO *io,
                                  SoupMessage         *msg)
{
        return io->funcs->is_paused (io, msg);
}

void
soup_client_message_io_run (SoupClientMessageIO *io,
                            SoupMessage         *msg,
                            gboolean             blocking)
{
        io->funcs->run (io, msg, blocking);
}

gboolean
soup_client_message_io_run_until_read (SoupClientMessageIO *io,
                                       SoupMessage         *msg,
                                       GCancellable        *cancellable,
                                       GError             **error)
{
        return io->funcs->run_until_read (io, msg, cancellable, error);
}

void
soup_client_message_io_run_until_read_async (SoupClientMessageIO *io,
                                             SoupMessage         *msg,
                                             int                  io_priority,
                                             GCancellable        *cancellable,
                                             GAsyncReadyCallback  callback,
                                             gpointer             user_data)
{
        io->funcs->run_until_read_async (io, msg, io_priority, cancellable, callback, user_data);
}

gboolean
soup_client_message_io_close_async (SoupClientMessageIO *io,
                                    SoupConnection      *conn,
                                    GAsyncReadyCallback  callback)
{
        return io->funcs->close_async (io, conn, callback);
}

gboolean
soup_client_message_io_skip (SoupClientMessageIO *io,
                             SoupMessage         *msg,
                             gboolean             blocking,
                             GCancellable        *cancellable,
                             GError             **error)
{
        return io->funcs->skip (io, msg, blocking, cancellable, error);
}

GInputStream *
soup_client_message_io_get_response_stream (SoupClientMessageIO *io,
                                            SoupMessage         *msg,
                                            GError             **error)
{
        return io->funcs->get_response_stream (io, msg, error);
}

gboolean
soup_client_message_io_is_open (SoupClientMessageIO *io)
{
        return io->funcs->is_open (io);
}

gboolean
soup_client_message_io_in_progress (SoupClientMessageIO *io,
                                    SoupMessage         *msg)
{
        return io->funcs->in_progress (io, msg);
}

gboolean
soup_client_message_io_is_reusable (SoupClientMessageIO *io)
{
        return io->funcs->is_reusable (io);
}

GCancellable *
soup_client_message_io_get_cancellable (SoupClientMessageIO *io,
                                        SoupMessage         *msg)
{
        return io->funcs->get_cancellable (io, msg);
}

void
soup_client_message_io_owner_changed (SoupClientMessageIO *io)
{
        if (io->funcs->owner_changed)
                io->funcs->owner_changed (io);
}
