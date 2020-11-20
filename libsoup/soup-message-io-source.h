/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-message-io-source.c
 *
 * Copyright (C) 2000-2003, Ximian, Inc.
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup.h"

typedef struct {
        GSource source;
        GObject *msg;
        gboolean (*check_func) (GSource*);
        gboolean paused;
} SoupMessageIOSource;

typedef gboolean (*SoupMessageIOSourceFunc) (GObject     *msg,
                                             gpointer     user_data);

GSource *soup_message_io_source_new (GSource     *base_source,
                                     GObject     *msg,
                                     gboolean     paused,
                                     gboolean   (*check_func) (GSource*));
