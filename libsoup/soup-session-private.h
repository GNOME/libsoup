/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SESSION_PRIVATE_H
#define SOUP_SESSION_PRIVATE_H 1

#include "soup-session.h"
#include "soup-connection.h"
#include "soup-message-queue.h"
#include "soup-proxy-resolver.h"

G_BEGIN_DECLS

/* "protected" methods for subclasses */
SoupMessageQueue *soup_session_get_queue            (SoupSession *session);

SoupConnection   *soup_session_get_connection       (SoupSession *session,
						     SoupMessage *msg,
						     SoupAddress *proxy,
						     gboolean    *try_pruning,
						     gboolean    *is_new);
gboolean          soup_session_try_prune_connection (SoupSession *session);

SoupProxyResolver *soup_session_get_proxy_resolver  (SoupSession *session);

G_END_DECLS

#endif /* SOUP_SESSION_PRIVATE_H */
