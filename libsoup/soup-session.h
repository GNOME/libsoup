/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-message.h"
#include "soup-websocket-connection.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SESSION soup_session_get_type ()
SOUP_AVAILABLE_IN_ALL
G_DECLARE_DERIVABLE_TYPE (SoupSession, soup_session, SOUP, SESSION, GObject)

struct _SoupSessionClass {
        GObjectClass parent_class;

        void (* request_queued)   (SoupSession *session,
                                   SoupMessage *msg);
        void (* request_unqueued) (SoupSession *session,
                                   SoupMessage *msg);

        void (*_soup_reserved1) (void);
        void (*_soup_reserved2) (void);
        void (*_soup_reserved3) (void);
        void (*_soup_reserved4) (void);
        void (*_soup_reserved5) (void);
        void (*_soup_reserved6) (void);
        void (*_soup_reserved7) (void);
        void (*_soup_reserved8) (void);
};

/**
 * soup_session_error_quark:
 * Registers error quark for SoupSession if needed.
 *
 * Returns: Error quark for SoupSession.
 */
SOUP_AVAILABLE_IN_ALL
GQuark soup_session_error_quark (void);
#define SOUP_SESSION_ERROR soup_session_error_quark ()

typedef enum {
	SOUP_SESSION_ERROR_PARSING,
	SOUP_SESSION_ERROR_ENCODING,
	SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS,
	SOUP_SESSION_ERROR_TOO_MANY_RESTARTS,
	SOUP_SESSION_ERROR_REDIRECT_NO_LOCATION,
	SOUP_SESSION_ERROR_REDIRECT_BAD_URI,
        SOUP_SESSION_ERROR_MESSAGE_ALREADY_IN_QUEUE,
} SoupSessionError;

SOUP_AVAILABLE_IN_ALL
SoupSession        *soup_session_new                      (void);

SOUP_AVAILABLE_IN_ALL
SoupSession        *soup_session_new_with_options         (const char      *optname1,
							   ...) G_GNUC_NULL_TERMINATED;

SOUP_AVAILABLE_IN_ALL
GInetSocketAddress *soup_session_get_local_address        (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
guint               soup_session_get_max_conns            (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
guint               soup_session_get_max_conns_per_host   (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_proxy_resolver       (SoupSession     *session,
							   GProxyResolver  *proxy_resolver);

SOUP_AVAILABLE_IN_ALL
GProxyResolver     *soup_session_get_proxy_resolver       (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_tls_database         (SoupSession     *session,
							   GTlsDatabase    *tls_database);

SOUP_AVAILABLE_IN_ALL
GTlsDatabase       *soup_session_get_tls_database         (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_tls_interaction      (SoupSession     *session,
							   GTlsInteraction *tls_interaction);

SOUP_AVAILABLE_IN_ALL
GTlsInteraction    *soup_session_get_tls_interaction      (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_timeout              (SoupSession     *session,
							   guint            timeout);

SOUP_AVAILABLE_IN_ALL
guint               soup_session_get_timeout              (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_idle_timeout         (SoupSession     *session,
							   guint            timeout);

SOUP_AVAILABLE_IN_ALL
guint               soup_session_get_idle_timeout         (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_user_agent           (SoupSession     *session,
							   const char      *user_agent);

SOUP_AVAILABLE_IN_ALL
const char         *soup_session_get_user_agent           (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_accept_language      (SoupSession     *session,
							   const char      *accept_language);

SOUP_AVAILABLE_IN_ALL
const char         *soup_session_get_accept_language      (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void                soup_session_set_accept_language_auto (SoupSession     *session,
							   gboolean         accept_language_auto);

SOUP_AVAILABLE_IN_ALL
gboolean            soup_session_get_accept_language_auto (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
GSocketConnectable *soup_session_get_remote_connectable   (SoupSession     *session);

SOUP_AVAILABLE_IN_ALL
void            soup_session_abort               (SoupSession           *session);

SOUP_AVAILABLE_IN_ALL
void            soup_session_send_async          (SoupSession           *session,
						  SoupMessage           *msg,
						  int                    io_priority,
						  GCancellable          *cancellable,
						  GAsyncReadyCallback    callback,
						  gpointer               user_data);
SOUP_AVAILABLE_IN_ALL
GInputStream   *soup_session_send_finish         (SoupSession           *session,
						  GAsyncResult          *result,
						  GError               **error);
SOUP_AVAILABLE_IN_ALL
GInputStream   *soup_session_send                (SoupSession           *session,
						  SoupMessage           *msg,
						  GCancellable          *cancellable,
						  GError               **error) G_GNUC_WARN_UNUSED_RESULT;
SOUP_AVAILABLE_IN_ALL
void            soup_session_send_and_read_async (SoupSession           *session,
						  SoupMessage           *msg,
						  int                    io_priority,
						  GCancellable          *cancellable,
						  GAsyncReadyCallback    callback,
						  gpointer               user_data);

SOUP_AVAILABLE_IN_ALL
GBytes         *soup_session_send_and_read_finish (SoupSession          *session,
						   GAsyncResult         *result,
						   GError              **error);

SOUP_AVAILABLE_IN_ALL
GBytes         *soup_session_send_and_read        (SoupSession          *session,
						   SoupMessage          *msg,
						   GCancellable         *cancellable,
						   GError              **error);

SOUP_AVAILABLE_IN_3_4
void            soup_session_send_and_splice_async(SoupSession          *session,
                                                   SoupMessage          *msg,
                                                   GOutputStream        *out_stream,
                                                   GOutputStreamSpliceFlags flags,
                                                   int                   io_priority,
                                                   GCancellable         *cancellable,
                                                   GAsyncReadyCallback   callback,
                                                   gpointer              user_data);

SOUP_AVAILABLE_IN_3_4
gssize          soup_session_send_and_splice_finish(SoupSession         *session,
                                                    GAsyncResult        *result,
                                                    GError             **error);

SOUP_AVAILABLE_IN_3_4
gssize          soup_session_send_and_splice      (SoupSession         *session,
                                                   SoupMessage         *msg,
                                                   GOutputStream       *out_stream,
                                                   GOutputStreamSpliceFlags flags,
                                                   GCancellable        *cancellable,
                                                   GError             **error);

SOUP_AVAILABLE_IN_ALL
SoupMessage    *soup_session_get_async_result_message (SoupSession  *session,
						       GAsyncResult *result);

SOUP_AVAILABLE_IN_ALL
void                soup_session_add_feature            (SoupSession        *session,
							 SoupSessionFeature *feature);
SOUP_AVAILABLE_IN_ALL
void                soup_session_add_feature_by_type    (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_ALL
void                soup_session_remove_feature         (SoupSession        *session,
							 SoupSessionFeature *feature);
SOUP_AVAILABLE_IN_ALL
void                soup_session_remove_feature_by_type (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_ALL
gboolean            soup_session_has_feature            (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_ALL
SoupSessionFeature *soup_session_get_feature            (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_ALL
SoupSessionFeature *soup_session_get_feature_for_message(SoupSession        *session,
							 GType               feature_type,
							 SoupMessage        *msg);

SOUP_AVAILABLE_IN_ALL
void                     soup_session_websocket_connect_async  (SoupSession          *session,
								SoupMessage          *msg,
								const char           *origin,
								char                **protocols,
								int                   io_priority,
								GCancellable         *cancellable,
								GAsyncReadyCallback   callback,
								gpointer              user_data);

SOUP_AVAILABLE_IN_ALL
SoupWebsocketConnection *soup_session_websocket_connect_finish (SoupSession          *session,
								GAsyncResult         *result,
								GError              **error);


SOUP_AVAILABLE_IN_ALL
void       soup_session_preconnect_async  (SoupSession        *session,
					   SoupMessage        *msg,
					   int                 io_priority,
					   GCancellable       *cancellable,
					   GAsyncReadyCallback callback,
					   gpointer            user_data);
SOUP_AVAILABLE_IN_ALL
gboolean   soup_session_preconnect_finish (SoupSession        *session,
					   GAsyncResult       *result,
					   GError            **error);


G_END_DECLS
