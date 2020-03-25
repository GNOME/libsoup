/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2009 Gustavo Noronha Silva.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-body.h"

G_BEGIN_DECLS

#define SOUP_TYPE_CONTENT_SNIFFER (soup_content_sniffer_get_type ())
SOUP_AVAILABLE_IN_2_28
G_DECLARE_DERIVABLE_TYPE (SoupContentSniffer, soup_content_sniffer, SOUP, CONTENT_SNIFFER, GObject)

struct _SoupContentSnifferClass {
	GObjectClass parent_class;

	char* (*sniff)              (SoupContentSniffer *sniffer,
				     SoupMessage *msg,
				     SoupBuffer *buffer,
				     GHashTable **params);
	gsize (*get_buffer_size)    (SoupContentSniffer *sniffer);

	gpointer padding[6];
};

SOUP_AVAILABLE_IN_2_28
SoupContentSniffer *soup_content_sniffer_new             (void);

SOUP_AVAILABLE_IN_2_28
char               *soup_content_sniffer_sniff           (SoupContentSniffer  *sniffer,
							  SoupMessage         *msg,
							  SoupBuffer          *buffer,
							  GHashTable         **params);
SOUP_AVAILABLE_IN_2_28
gsize               soup_content_sniffer_get_buffer_size (SoupContentSniffer  *sniffer);

G_END_DECLS

