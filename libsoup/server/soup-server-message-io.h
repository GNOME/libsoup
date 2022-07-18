/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 */

#pragma once

#include "soup-server-message.h"
#include "soup-message-io-completion.h"

typedef struct _SoupServerMessageIO SoupServerMessageIO;

typedef struct {
        void       (*destroy)      (SoupServerMessageIO       *io);
        void       (*finished)     (SoupServerMessageIO       *io,
                                    SoupServerMessage         *msg);
        GIOStream *(*steal)        (SoupServerMessageIO       *io);
        void       (*read_request) (SoupServerMessageIO       *io,
                                    SoupServerMessage         *msg,
                                    SoupMessageIOCompletionFn  completion_cb,
                                    gpointer                   user_data);
        void       (*pause)        (SoupServerMessageIO       *io,
                                    SoupServerMessage         *msg);
        void       (*unpause)      (SoupServerMessageIO       *io,
                                    SoupServerMessage         *msg);
        gboolean   (*is_paused)    (SoupServerMessageIO       *io,
                                    SoupServerMessage         *msg);
} SoupServerMessageIOFuncs;

struct _SoupServerMessageIO {
        const SoupServerMessageIOFuncs *funcs;
};

typedef void (* SoupMessageIOStartedFn) (SoupServerMessage *msg,
                                         gpointer           user_data);

void       soup_server_message_io_destroy      (SoupServerMessageIO       *io);
void       soup_server_message_io_finished     (SoupServerMessageIO       *io,
                                                SoupServerMessage         *msg);
GIOStream *soup_server_message_io_steal        (SoupServerMessageIO       *io);
void       soup_server_message_io_read_request (SoupServerMessageIO       *io,
                                                SoupServerMessage         *msg,
                                                SoupMessageIOCompletionFn  completion_cb,
                                                gpointer                   user_data);
void       soup_server_message_io_pause        (SoupServerMessageIO       *io,
                                                SoupServerMessage         *msg);
void       soup_server_message_io_unpause      (SoupServerMessageIO       *io,
                                                SoupServerMessage         *msg);
gboolean   soup_server_message_io_is_paused    (SoupServerMessageIO       *io,
                                                SoupServerMessage         *msg);
