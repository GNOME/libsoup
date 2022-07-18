/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 */

#pragma once

#include "soup-server-connection.h"
#include "soup-server-message-io.h"

SoupServerMessageIO *soup_server_message_io_http1_new (SoupServerConnection  *conn,
                                                       SoupServerMessage     *msg,
                                                       SoupMessageIOStartedFn started_cb,
                                                       gpointer               user_data);
