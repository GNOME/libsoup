/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2005 Novell, Inc.
 */

#ifndef SOUP_MESSAGE_HEADERS_H
#define SOUP_MESSAGE_HEADERS_H 1

#include <libsoup/soup-types.h>

typedef struct SoupMessageHeaders SoupMessageHeaders;

SoupMessageHeaders *soup_message_headers_new      (void);

void                soup_message_headers_free     (SoupMessageHeaders *hdrs);

void                soup_message_headers_append   (SoupMessageHeaders *hdrs,
						   const char         *name,
						   const char         *value);
void                soup_message_headers_replace  (SoupMessageHeaders *hdrs,
						   const char         *name,
						   const char         *value);

void                soup_message_headers_remove   (SoupMessageHeaders *hdrs,
						   const char         *name);
void                soup_message_headers_clear    (SoupMessageHeaders *hdrs);

const char         *soup_message_headers_find_nth (SoupMessageHeaders *hdrs,
						   const char         *name,
						   int                 index);
#define soup_message_headers_find(hdrs, name) (soup_message_headers_find_nth (hdrs, name, 0))

typedef void      (*SoupMessageHeadersForeachFunc)(const char         *name,
						   const char         *value,
						   gpointer            user_data);

void                soup_message_headers_foreach  (SoupMessageHeaders *hdrs,
						   SoupMessageHeadersForeachFunc func,
						   gpointer            user_data);

#endif /* SOUP_MESSAGE_HEADERS_H */
