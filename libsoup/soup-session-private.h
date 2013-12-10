/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SESSION_PRIVATE_H
#define SOUP_SESSION_PRIVATE_H 1

#include "soup-session.h"
#include "soup-message-private.h"
#include "soup-proxy-uri-resolver.h"

G_BEGIN_DECLS

/* "protected" methods for subclasses */
SoupMessageQueueItem *soup_session_lookup_queue_item    (SoupSession          *session,
							 SoupMessage          *msg);

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

#endif /* SOUP_SESSION_PRIVATE_H */
