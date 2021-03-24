/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"

G_BEGIN_DECLS

typedef enum {
	SOUP_MEMORY_STATIC,
	SOUP_MEMORY_TAKE,
	SOUP_MEMORY_COPY,
} SoupMemoryUse;

typedef struct {
	const char *data;
	goffset     length;
} SoupMessageBody;

SOUP_AVAILABLE_IN_ALL
GType soup_message_body_get_type (void);
#define SOUP_TYPE_MESSAGE_BODY (soup_message_body_get_type ())

SOUP_AVAILABLE_IN_ALL
SoupMessageBody *soup_message_body_new           (void);

SOUP_AVAILABLE_IN_ALL
SoupMessageBody *soup_message_body_ref           (SoupMessageBody *body);

SOUP_AVAILABLE_IN_ALL
void             soup_message_body_unref         (SoupMessageBody *body);

SOUP_AVAILABLE_IN_ALL
void             soup_message_body_set_accumulate(SoupMessageBody *body,
						  gboolean         accumulate);
SOUP_AVAILABLE_IN_ALL
gboolean         soup_message_body_get_accumulate(SoupMessageBody *body);

SOUP_AVAILABLE_IN_ALL
void             soup_message_body_append        (SoupMessageBody *body,
						  SoupMemoryUse    use,
						  gconstpointer    data,
						  gsize            length);
SOUP_AVAILABLE_IN_ALL
void             soup_message_body_append_take   (SoupMessageBody *body,
						  guchar          *data,
						  gsize            length);
SOUP_AVAILABLE_IN_ALL
void             soup_message_body_append_bytes (SoupMessageBody *body,
						  GBytes          *buffer);
SOUP_AVAILABLE_IN_ALL
void             soup_message_body_truncate      (SoupMessageBody *body);
SOUP_AVAILABLE_IN_ALL
void             soup_message_body_complete      (SoupMessageBody *body);

SOUP_AVAILABLE_IN_ALL
GBytes          *soup_message_body_flatten       (SoupMessageBody *body);

SOUP_AVAILABLE_IN_ALL
GBytes          *soup_message_body_get_chunk     (SoupMessageBody *body,
						  goffset          offset);

SOUP_AVAILABLE_IN_ALL
void             soup_message_body_got_chunk     (SoupMessageBody *body,
						  GBytes          *chunk);
SOUP_AVAILABLE_IN_ALL
void             soup_message_body_wrote_chunk   (SoupMessageBody *body,
						  GBytes          *chunk);

G_END_DECLS
