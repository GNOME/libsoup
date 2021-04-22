/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include <glib-object.h>

typedef enum {
        SOUP_MESSAGE_IO_COMPLETE,
        SOUP_MESSAGE_IO_INTERRUPTED,
        SOUP_MESSAGE_IO_STOLEN
} SoupMessageIOCompletion;

typedef void (*SoupMessageIOCompletionFn) (GObject                *msg,
                                           SoupMessageIOCompletion completion,
                                           gpointer                user_data);
