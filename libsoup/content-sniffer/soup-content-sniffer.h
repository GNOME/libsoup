/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-body.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONTENT_SNIFFER (soup_content_sniffer_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupContentSniffer, soup_content_sniffer, SOUP, CONTENT_SNIFFER, GObject)

SOUP_AVAILABLE_IN_ALL
SoupContentSniffer *soup_content_sniffer_new   (void);

SOUP_AVAILABLE_IN_ALL
char               *soup_content_sniffer_sniff (SoupContentSniffer  *sniffer,
                                                SoupMessage         *msg,
                                                GBytes              *buffer,
                                                GHashTable         **params);

G_END_DECLS

