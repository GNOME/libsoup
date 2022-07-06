/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 */

#pragma once

#include "soup-server-message-private.h"

SoupServerMessageIOData *soup_server_message_io_http1_new (GIOStream *iostream);
