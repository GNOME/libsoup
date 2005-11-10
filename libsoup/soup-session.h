/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SESSION_H
#define SOUP_SESSION_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-message-queue.h>

#define SOUP_TYPE_SESSION            (soup_session_get_type ())
#define SOUP_SESSION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SESSION, SoupSession))
#define SOUP_SESSION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SESSION, SoupSessionClass))
#define SOUP_IS_SESSION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SESSION))
#define SOUP_IS_SESSION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SESSION))
#define SOUP_SESSION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SESSION, SoupSessionClass))

struct SoupSession {
	GObject parent;

	/* protected */
	SoupMessageQueue *queue;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void (*authenticate)   (SoupSession *, SoupMessage *,
				const char *auth_type, const char *auth_realm,
				char **username, char **password);
	void (*reauthenticate) (SoupSession *, SoupMessage *,
				const char *auth_type, const char *auth_realm,
				char **username, char **password);

	/* methods */
	void  (*queue_message)   (SoupSession *session, SoupMessage *msg,
				  SoupMessageCallbackFn callback,
				  gpointer user_data);
	void  (*requeue_message) (SoupSession *session, SoupMessage *msg);
	guint (*send_message)    (SoupSession *session, SoupMessage *msg);

	void  (*cancel_message)  (SoupSession *session, SoupMessage *msg);

} SoupSessionClass;

GType soup_session_get_type (void);

#define SOUP_SESSION_PROXY_URI          "proxy-uri"
#define SOUP_SESSION_MAX_CONNS          "max-conns"
#define SOUP_SESSION_MAX_CONNS_PER_HOST "max-conns-per-host"
#define SOUP_SESSION_USE_NTLM           "use-ntlm"
#define SOUP_SESSION_SSL_CA_FILE        "ssl-ca-file"
#define SOUP_SESSION_ASYNC_CONTEXT      "async-context"

void            soup_session_add_filter       (SoupSession           *session,
					       SoupMessageFilter     *filter);
void            soup_session_remove_filter    (SoupSession           *session,
					       SoupMessageFilter     *filter);

void            soup_session_queue_message    (SoupSession           *session,
					       SoupMessage           *msg,
					       SoupMessageCallbackFn  callback,
					       gpointer               user_data);
void            soup_session_requeue_message  (SoupSession           *session,
					       SoupMessage           *msg);

guint           soup_session_send_message     (SoupSession           *session,
					       SoupMessage           *msg);

void            soup_session_cancel_message   (SoupSession           *session,
					       SoupMessage           *msg);
void            soup_session_abort            (SoupSession           *session);


/* Protected methods */
SoupConnection *soup_session_get_connection       (SoupSession    *session,
						   SoupMessage    *msg,
						   gboolean       *try_pruning,
						   gboolean       *is_new);
gboolean        soup_session_try_prune_connection (SoupSession    *session);


#endif /* SOUP_SESSION_H */
