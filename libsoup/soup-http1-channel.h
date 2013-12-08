/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef SOUP_HTTP1_CHANNEL_H
#define SOUP_HTTP1_CHANNEL_H 1

#include "soup-http-channel.h"
#include "soup-connection.h"

#define SOUP_TYPE_HTTP1_CHANNEL            (soup_http1_channel_get_type ())
#define SOUP_HTTP1_CHANNEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP1_CHANNEL, SoupHTTP1Channel))
#define SOUP_HTTP1_CHANNEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP1_CHANNEL, SoupHTTP1ChannelClass))
#define SOUP_IS_HTTP1_CHANNEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP1_CHANNEL))
#define SOUP_IS_HTTP1_CHANNEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP1_CHANNEL))
#define SOUP_HTTP1_CHANNEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP1_CHANNEL, SoupHTTP1ChannelClass))

typedef struct {
	SoupHTTPChannel parent;

} SoupHTTP1Channel;

typedef struct {
	SoupHTTPChannelClass parent_class;

} SoupHTTP1ChannelClass;

GType soup_http1_channel_get_type (void);

SoupHTTPChannel *soup_http1_channel_new_client (SoupMessage *msg);
SoupHTTPChannel *soup_http1_channel_new_server (SoupMessage *msg,
						SoupSocket *socket);

#endif /* SOUP_HTTP1_CHANNEL_H */
