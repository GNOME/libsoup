/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2021 Igalia S.L.
 */

#pragma once

#include "soup-message-headers.h"
#include "soup-header-names.h"

G_BEGIN_DECLS

void        soup_message_headers_append_untrusted_data  (SoupMessageHeaders *hdrs,
                                                         const char         *name,
                                                         const char         *value);
void        soup_message_headers_append_common          (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name,
                                                         const char         *value);
const char *soup_message_headers_get_one_common         (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name);
const char *soup_message_headers_get_list_common        (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name);
void        soup_message_headers_remove_common          (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name);
void        soup_message_headers_replace_common         (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name,
                                                         const char         *value);
gboolean    soup_message_headers_header_contains_common (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name,
                                                         const char         *token);
gboolean    soup_message_headers_header_equals_common   (SoupMessageHeaders *hdrs,
                                                         SoupHeaderName      name,
                                                         const char         *value);

G_END_DECLS
