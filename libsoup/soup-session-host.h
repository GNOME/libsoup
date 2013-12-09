/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef SOUP_SESSION_HOST_H
#define SOUP_SESSION_HOST_H 1

#include "soup-types.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SESSION_HOST            (soup_session_host_get_type ())
#define SOUP_SESSION_HOST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SESSION_HOST, SoupSessionHost))
#define SOUP_SESSION_HOST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SESSION_HOST, SoupSessionHostClass))
#define SOUP_IS_SESSION_HOST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SESSION_HOST))
#define SOUP_IS_SESSION_HOST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SESSION_HOST))
#define SOUP_SESSION_HOST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SESSION_HOST, SoupSessionHostClass))

typedef struct {
	GObject parent;

} SoupSessionHost;

typedef struct {
	GObjectClass parent_class;

} SoupSessionHostClass;

GType soup_session_host_get_type (void);

SoupSessionHost *soup_session_host_new                 (SoupSession          *session,
							SoupURI              *uri);

SoupURI         *soup_session_host_get_uri             (SoupSessionHost      *host);
SoupAddress     *soup_session_host_get_address         (SoupSessionHost      *host);

void             soup_session_host_add_message         (SoupSessionHost      *host,
							SoupMessage          *msg);
void             soup_session_host_remove_message      (SoupSessionHost      *host,
							SoupMessage          *msg);

SoupConnection  *soup_session_host_get_connection      (SoupSessionHost      *host,
							gboolean              need_new_connection,
							gboolean              at_max_conns,
							gboolean             *try_cleanup);
int              soup_session_host_get_num_connections (SoupSessionHost      *host);
GSList          *soup_session_host_get_connections     (SoupSessionHost      *host);

gboolean         soup_session_host_cleanup_connections (SoupSessionHost      *host,
							gboolean              cleanup_idle);

gboolean         soup_session_host_get_ssl_fallback    (SoupSessionHost      *host);
void             soup_session_host_set_ssl_fallback    (SoupSessionHost      *host,
							gboolean              ssl_fallback);

G_END_DECLS

#endif /* SOUP_SESSION_HOST_H */
