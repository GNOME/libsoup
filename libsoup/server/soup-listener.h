/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2022 Igalia S.L.
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_LISTENER (soup_listener_get_type ())
G_DECLARE_FINAL_TYPE (SoupListener, soup_listener, SOUP, LISTENER, GObject)

SoupListener       *soup_listener_new              (GSocket        *socket,
                                                    GError        **error);
SoupListener       *soup_listener_new_for_address  (GSocketAddress *address,
                                                    GError        **error);

void                soup_listener_disconnect       (SoupListener   *listener);
gboolean            soup_listener_is_ssl           (SoupListener   *listener);
GSocket            *soup_listener_get_socket       (SoupListener   *listener);
GInetSocketAddress *soup_listener_get_address      (SoupListener   *listener);

G_END_DECLS
