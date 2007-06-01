/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_FILTER_H
#define SOUP_MESSAGE_FILTER_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

#define SOUP_TYPE_MESSAGE_FILTER            (soup_message_filter_get_type ())
#define SOUP_MESSAGE_FILTER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_MESSAGE_FILTER, SoupMessageFilter))
#define SOUP_MESSAGE_FILTER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_MESSAGE_FILTER, SoupMessageFilterClass))
#define SOUP_IS_MESSAGE_FILTER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_MESSAGE_FILTER))
#define SOUP_IS_MESSAGE_FILTER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_MESSAGE_FILTER))
#define SOUP_MESSAGE_FILTER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_INTERFACE ((obj), SOUP_TYPE_MESSAGE_FILTER, SoupMessageFilterClass))

typedef struct {
	GTypeInterface parent;

	/* methods */
	void  (*setup_message) (SoupMessageFilter *filter, SoupMessage *msg);
} SoupMessageFilterClass;

GType soup_message_filter_get_type (void);

void soup_message_filter_setup_message (SoupMessageFilter *filter,
					SoupMessage       *msg);

G_END_DECLS

#endif /* SOUP_MESSAGE_FILTER_H */
