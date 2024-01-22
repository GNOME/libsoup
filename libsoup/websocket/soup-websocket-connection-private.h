/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2024 Axis Communications AB, SWEDEN.
 */

#ifndef __SOUP_WEBSOCKET_CONNECTION_PRIVATE_H__
#define __SOUP_WEBSOCKET_CONNECTION_PRIVATE_H__ 1

#include "soup-websocket-connection.h"

void soup_websocket_connection_set_suppress_pongs_for_tests (SoupWebsocketConnection *self,
                                                             gboolean suppress);

#endif /* __SOUP_WEBSOCKET_CONNECTION_PRIVATE_H__ */
