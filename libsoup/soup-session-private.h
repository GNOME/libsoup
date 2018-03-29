/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_SESSION_PRIVATE_H__
#define __SOUP_SESSION_PRIVATE_H__ 1

#include "soup-session.h"
#include "soup-message-private.h"
#include "soup-proxy-uri-resolver.h"

G_BEGIN_DECLS

/* "protected" methods for subclasses */
SoupMessageQueue     *soup_session_get_queue            (SoupSession          *session);

SoupMessageQueueItem *soup_session_append_queue_item    (SoupSession          *session,
							 SoupMessage          *msg,
							 gboolean              async,
							 gboolean              new_api,
							 SoupSessionCallback   callback,
							 gpointer              user_data);

void                  soup_session_kick_queue           (SoupSession          *session);

GInputStream         *soup_session_send_request         (SoupSession          *session,
							 SoupMessage          *msg,
							 GCancellable         *cancellable,
							 GError              **error);

void                  soup_session_send_request_async   (SoupSession          *session,
							 SoupMessage          *msg,
							 GCancellable         *cancellable,
							 GAsyncReadyCallback   callback,
							 gpointer              user_data);
GInputStream         *soup_session_send_request_finish  (SoupSession          *session,
							 GAsyncResult         *result,
							 GError              **error);

void                  soup_session_process_queue_item   (SoupSession          *session,
							 SoupMessageQueueItem *item,
							 gboolean             *should_prune,
							 gboolean              loop);

G_END_DECLS

#endif /* __SOUP_SESSION_PRIVATE_H__ */
