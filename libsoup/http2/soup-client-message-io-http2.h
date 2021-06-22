/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-client-message-io.h"

G_BEGIN_DECLS

SoupClientMessageIO *soup_client_message_io_http2_new (SoupConnection *conn);

G_END_DECLS
