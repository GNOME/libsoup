/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef SOUP_HTTP_CHANNEL_H
#define SOUP_HTTP_CHANNEL_H 1

#include "soup-types.h"

#define SOUP_TYPE_HTTP_CHANNEL            (soup_http_channel_get_type ())
#define SOUP_HTTP_CHANNEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_HTTP_CHANNEL, SoupHTTPChannel))
#define SOUP_HTTP_CHANNEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_HTTP_CHANNEL, SoupHTTPChannelClass))
#define SOUP_IS_HTTP_CHANNEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_HTTP_CHANNEL))
#define SOUP_IS_HTTP_CHANNEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_HTTP_CHANNEL))
#define SOUP_HTTP_CHANNEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_HTTP_CHANNEL, SoupHTTPChannelClass))

#define SOUP_HTTP_CHANNEL_MESSAGE "message"
#define SOUP_HTTP_CHANNEL_MODE    "mode"

typedef struct {
	GObject parent;

} SoupHTTPChannel;

typedef struct {
	GObjectClass parent_class;

	gboolean        (*read_request_headers)   (SoupHTTPChannel  *channel,
						   gboolean          blocking,
						   GCancellable     *cancellable,
						   GError          **error);

	gboolean        (*read_response_headers)  (SoupHTTPChannel  *channel,
						   gboolean          blocking,
						   GCancellable     *cancellable,
						   GError          **error);

	gboolean        (*write_request_headers)  (SoupHTTPChannel  *channel,
						   gboolean          blocking,
						   GCancellable     *cancellable,
						   GError          **error);

	gboolean        (*write_response_headers) (SoupHTTPChannel  *channel,
						   gboolean          blocking,
						   GCancellable     *cancellable,
						   GError          **error);

	GInputStream *  (*get_body_input_stream)  (SoupHTTPChannel  *channel);
	GOutputStream * (*get_body_output_stream) (SoupHTTPChannel  *channel);

	GSource *       (*create_oneshot_source)  (SoupHTTPChannel  *channel,
						   GIOCondition      cond,
						   GCancellable     *cancellable);

} SoupHTTPChannelClass;

typedef enum {
	SOUP_HTTP_CHANNEL_CLIENT,
	SOUP_HTTP_CHANNEL_SERVER
} SoupHTTPChannelMode;

GType soup_http_channel_get_type (void);

gboolean            soup_http_channel_read_headers           (SoupHTTPChannel  *channel,
							      gboolean          blocking,
							      GCancellable     *cancellable,
							      GError          **error);

gboolean            soup_http_channel_write_headers          (SoupHTTPChannel  *channel,
							      gboolean          blocking,
							      GCancellable     *cancellable,
							      GError          **error);

GInputStream *      soup_http_channel_get_body_input_stream  (SoupHTTPChannel  *channel);
GOutputStream *     soup_http_channel_get_body_output_stream (SoupHTTPChannel  *channel);

GSource *           soup_http_channel_create_oneshot_source  (SoupHTTPChannel  *channel,
							      GIOCondition      cond,
							      GCancellable     *cancellable);

SoupMessage *       soup_http_channel_get_message            (SoupHTTPChannel  *channel);
SoupHTTPChannelMode soup_http_channel_get_mode               (SoupHTTPChannel  *channel);

#endif /* SOUP_HTTP_CHANNEL_H */
