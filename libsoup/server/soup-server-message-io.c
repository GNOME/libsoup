/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "soup-server-message-io.h"

void
soup_server_message_io_destroy (SoupServerMessageIO *io)
{
        if (!io)
                return;

        io->funcs->destroy (io);
}

void
soup_server_message_io_finished (SoupServerMessageIO *io,
                                 SoupServerMessage   *msg)
{
        io->funcs->finished (io, msg);
}

GIOStream *
soup_server_message_io_steal (SoupServerMessageIO *io)
{
        return io->funcs->steal (io);
}

void
soup_server_message_io_read_request (SoupServerMessageIO       *io,
                                     SoupServerMessage         *msg,
                                     SoupMessageIOCompletionFn  completion_cb,
                                     gpointer                   user_data)
{
        io->funcs->read_request (io, msg, completion_cb, user_data);
}

void
soup_server_message_io_pause (SoupServerMessageIO *io,
                              SoupServerMessage   *msg)
{
        io->funcs->pause (io, msg);
}

void
soup_server_message_io_unpause (SoupServerMessageIO *io,
                                SoupServerMessage   *msg)
{
        io->funcs->unpause (io, msg);
}

gboolean
soup_server_message_io_is_paused (SoupServerMessageIO *io,
                                  SoupServerMessage   *msg)
{
        return io->funcs->is_paused (io, msg);
}
