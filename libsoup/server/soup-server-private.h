/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022, Igalia S.L.
 */

#ifndef __SOUP_SERVER_PRIVATE_H__
#define __SOUP_SERVER_PRIVATE_H__ 1

#include "soup-server.h"

void soup_server_set_http2_enabled (SoupServer *server,
                                    gboolean    enabled);
GSList *soup_server_get_clients (SoupServer *server);

#endif /* __SOUP_SERVER_PRIVATE_H__ */
