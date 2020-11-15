/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-message.h"
#include "websocket/soup-websocket-connection.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SESSION soup_session_get_type ()
SOUP_AVAILABLE_IN_2_42
G_DECLARE_FINAL_TYPE (SoupSession, soup_session, SOUP, SESSION, GObject)

SOUP_AVAILABLE_IN_ALL
GQuark soup_session_error_quark (void);
#define SOUP_SESSION_ERROR soup_session_error_quark ()

typedef enum {
	SOUP_SESSION_ERROR_BAD_URI,
	SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME,
	SOUP_SESSION_ERROR_PARSING,
	SOUP_SESSION_ERROR_ENCODING,
	SOUP_SESSION_ERROR_TOO_MANY_REDIRECTS,
	SOUP_SESSION_ERROR_TOO_MANY_RESTARTS,
	SOUP_SESSION_ERROR_REDIRECT_NO_LOCATION,
	SOUP_SESSION_ERROR_REDIRECT_BAD_URI
} SoupSessionError;

SOUP_AVAILABLE_IN_2_42
SoupSession    *soup_session_new              (void);

SOUP_AVAILABLE_IN_2_42
SoupSession    *soup_session_new_with_options (const char *optname1,
					       ...) G_GNUC_NULL_TERMINATED;

SOUP_AVAILABLE_IN_2_4
void            soup_session_abort            (SoupSession           *session);

SOUP_AVAILABLE_IN_2_42
void            soup_session_send_async       (SoupSession           *session,
					       SoupMessage           *msg,
					       int                    io_priority,
					       GCancellable          *cancellable,
					       GAsyncReadyCallback    callback,
					       gpointer               user_data);
SOUP_AVAILABLE_IN_2_42
GInputStream   *soup_session_send_finish      (SoupSession           *session,
					       GAsyncResult          *result,
					       GError               **error);
SOUP_AVAILABLE_IN_2_42
GInputStream   *soup_session_send             (SoupSession           *session,
					       SoupMessage           *msg,
					       GCancellable          *cancellable,
					       GError               **error);

SOUP_AVAILABLE_IN_2_38
gboolean        soup_session_would_redirect   (SoupSession           *session,
					       SoupMessage           *msg);
SOUP_AVAILABLE_IN_2_38
gboolean        soup_session_redirect_message (SoupSession           *session,
					       SoupMessage           *msg,
					       GError               **error);

SOUP_AVAILABLE_IN_2_24
void                soup_session_add_feature            (SoupSession        *session,
							 SoupSessionFeature *feature);
SOUP_AVAILABLE_IN_2_24
void                soup_session_add_feature_by_type    (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_2_24
void                soup_session_remove_feature         (SoupSession        *session,
							 SoupSessionFeature *feature);
SOUP_AVAILABLE_IN_2_24
void                soup_session_remove_feature_by_type (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_2_42
gboolean            soup_session_has_feature            (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_2_26
GSList             *soup_session_get_features           (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_2_26
SoupSessionFeature *soup_session_get_feature            (SoupSession        *session,
							 GType               feature_type);
SOUP_AVAILABLE_IN_2_28
SoupSessionFeature *soup_session_get_feature_for_message(SoupSession        *session,
							 GType               feature_type,
							 SoupMessage        *msg);

SOUP_AVAILABLE_IN_ALL
GInputStream       *soup_session_read_uri               (SoupSession        *session,
							 const char         *uri,
							 GCancellable       *cancellable,
							 goffset            *content_length,
							 char              **content_type,
							 GError            **error);
SOUP_AVAILABLE_IN_ALL
void                soup_session_read_uri_async         (SoupSession        *session,
							 const char         *uri,
							 int                 io_priority,
							 GCancellable       *cancellable,
							 GAsyncReadyCallback callback,
							 gpointer            user_data);
SOUP_AVAILABLE_IN_ALL
GInputStream       *soup_session_read_uri_finish        (SoupSession        *session,
							 GAsyncResult       *result,
							 goffset            *content_length,
							 char              **content_type,
							 GError            **error);
SOUP_AVAILABLE_IN_ALL
GBytes             *soup_session_load_uri_bytes         (SoupSession        *session,
							 const char         *uri,
							 GCancellable       *cancellable,
							 char              **content_type,
							 GError            **error);
SOUP_AVAILABLE_IN_ALL
void                soup_session_load_uri_bytes_async   (SoupSession        *session,
							 const char         *uri,
							 int                 io_priority,
							 GCancellable       *cancellable,
							 GAsyncReadyCallback callback,
							 gpointer            user_data);
SOUP_AVAILABLE_IN_ALL
GBytes             *soup_session_load_uri_bytes_finish  (SoupSession        *session,
							 GAsyncResult       *result,
							 char              **content_type,
							 GError            **error);

SOUP_AVAILABLE_IN_2_50
void                     soup_session_websocket_connect_async  (SoupSession          *session,
								SoupMessage          *msg,
								const char           *origin,
								char                **protocols,
								int                   io_priority,
								GCancellable         *cancellable,
								GAsyncReadyCallback   callback,
								gpointer              user_data);

SOUP_AVAILABLE_IN_2_50
SoupWebsocketConnection *soup_session_websocket_connect_finish (SoupSession          *session,
								GAsyncResult         *result,
								GError              **error);

G_END_DECLS
