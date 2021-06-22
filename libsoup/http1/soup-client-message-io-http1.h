/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-client-message-io.h"

SoupClientMessageIO *soup_client_message_io_http1_new (SoupConnection *conn);
