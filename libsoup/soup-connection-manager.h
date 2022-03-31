/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2022 Igalia S.L.
 */

#ifndef __SOUP_CONNECTION_MANAGER_H__
#define __SOUP_CONNECTION_MANAGER_H__ 1

#include "soup-connection.h"
#include "soup-message-queue-item.h"
#include <gio/gio.h>

typedef struct _SoupConnectionManager SoupConnectionManager;

SoupConnectionManager *soup_connection_manager_new                    (SoupSession           *session,
                                                                       guint                  max_conns,
                                                                       guint                  max_conns_per_host);
void                   soup_connection_manager_free                   (SoupConnectionManager *manager);
void                   soup_connection_manager_set_max_conns          (SoupConnectionManager *manager,
                                                                       guint                  max_conns);
guint                  soup_connection_manager_get_max_conns          (SoupConnectionManager *manager);
void                   soup_connection_manager_set_max_conns_per_host (SoupConnectionManager *manager,
                                                                       guint                  max_conns_per_host);
guint                  soup_connection_manager_get_max_conns_per_host (SoupConnectionManager *manager);
void                   soup_connection_manager_set_remote_connectable (SoupConnectionManager *manager,
                                                                       GSocketConnectable    *connectable);
GSocketConnectable    *soup_connection_manager_get_remote_connectable (SoupConnectionManager *manager);
guint                  soup_connection_manager_get_num_conns          (SoupConnectionManager *manager);
SoupConnection        *soup_connection_manager_get_connection         (SoupConnectionManager *manager,
                                                                       SoupMessageQueueItem  *item);
gboolean               soup_connection_manager_cleanup                (SoupConnectionManager *manager,
                                                                       gboolean               cleanup_idle);
GIOStream             *soup_connection_manager_steal_connection       (SoupConnectionManager *manager,
                                                                       SoupMessage           *msg);

#endif /* __SOUP_CONNECTION_MANAGER_H__ */
