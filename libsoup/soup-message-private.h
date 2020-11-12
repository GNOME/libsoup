/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_MESSAGE_PRIVATE_H__
#define __SOUP_MESSAGE_PRIVATE_H__ 1

#include "soup-filter-input-stream.h"
#include "soup-message.h"
#include "soup-message-io-data.h"
#include "auth/soup-auth.h"
#include "soup-content-processor.h"
#include "content-sniffer/soup-content-sniffer.h"
#include "soup-session.h"

typedef struct _SoupClientMessageIOData SoupClientMessageIOData;
void soup_client_message_io_data_free (SoupClientMessageIOData *io);

void             soup_message_set_status       (SoupMessage      *msg,
						guint             status_code,
						const char       *reason_phrase);
void             soup_message_cleanup_response (SoupMessage      *msg);

typedef void     (*SoupMessageGetHeadersFn)  (SoupMessage      *msg,
					      GString          *headers,
					      SoupEncoding     *encoding,
					      gpointer          user_data);
typedef guint    (*SoupMessageParseHeadersFn)(SoupMessage      *msg,
					      char             *headers,
					      guint             header_len,
					      SoupEncoding     *encoding,
					      gpointer          user_data,
					      GError          **error);

void soup_message_send_request (SoupMessageQueueItem      *item,
				SoupMessageIOCompletionFn  completion_cb,
				gpointer                   user_data);

/* Auth handling */
void           soup_message_set_auth       (SoupMessage *msg,
					    SoupAuth    *auth);
SoupAuth      *soup_message_get_auth       (SoupMessage *msg);
void           soup_message_set_proxy_auth (SoupMessage *msg,
					    SoupAuth    *auth);
SoupAuth      *soup_message_get_proxy_auth (SoupMessage *msg);
GUri          *soup_message_get_uri_for_auth (SoupMessage *msg);

/* I/O */
void       soup_message_io_run         (SoupMessage *msg,
					gboolean     blocking);
void       soup_message_io_finished    (SoupMessage *msg);
void       soup_message_io_cleanup     (SoupMessage *msg);
void       soup_message_io_pause       (SoupMessage *msg);
void       soup_message_io_unpause     (SoupMessage *msg);
gboolean   soup_message_is_io_paused   (SoupMessage *msg);
gboolean   soup_message_io_in_progress (SoupMessage *msg);
void       soup_message_io_stolen      (SoupMessage *msg);

gboolean soup_message_io_read_headers          (SoupMessage           *msg,
                                                SoupFilterInputStream *stream,
                                                GByteArray            *buffer,
                                                gboolean               blocking,
                                                GCancellable          *cancellable,
                                                GError               **error);

gboolean soup_message_io_run_until_finish      (SoupMessage        *msg,
                                                gboolean            blocking,
                                                GCancellable       *cancellable,
                                                GError            **error);

gboolean soup_message_io_run_until_read        (SoupMessage        *msg,
                                                GCancellable       *cancellable,
                                                GError            **error);
void     soup_message_io_run_until_read_async  (SoupMessage        *msg,
						int                 io_priority,
                                                GCancellable       *cancellable,
                                                GAsyncReadyCallback callback,
                                                gpointer            user_data);
gboolean soup_message_io_run_until_read_finish (SoupMessage        *msg,
                                                GAsyncResult       *result,
                                                GError            **error);

typedef gboolean (*SoupMessageSourceFunc) (SoupMessage *, gpointer);
GSource *soup_message_io_get_source       (SoupMessage           *msg,
					   GCancellable          *cancellable,
					   SoupMessageSourceFunc  callback,
					   gpointer               user_data);

GInputStream *soup_message_io_get_response_istream (SoupMessage  *msg,
						    GError      **error);

void soup_message_wrote_headers     (SoupMessage *msg);
void soup_message_wrote_body_data   (SoupMessage *msg,
				     gsize        chunk_size);
void soup_message_wrote_body        (SoupMessage *msg);
void soup_message_got_informational (SoupMessage *msg);
void soup_message_got_headers       (SoupMessage *msg);
void soup_message_got_body          (SoupMessage *msg);
void soup_message_content_sniffed   (SoupMessage *msg,
				     const char  *content_type,
				     GHashTable  *params);
void soup_message_starting          (SoupMessage *msg);
void soup_message_restarted         (SoupMessage *msg);
void soup_message_finished          (SoupMessage *msg);
gboolean soup_message_authenticate  (SoupMessage *msg,
				     SoupAuth    *auth,
				     gboolean     retrying);

gboolean soup_message_disables_feature (SoupMessage *msg,
					gpointer     feature);

GList *soup_message_get_disabled_features (SoupMessage *msg);

GInputStream *soup_message_setup_body_istream (GInputStream *body_stream,
					       SoupMessage *msg,
					       SoupSession *session,
					       SoupProcessingStage start_at_stage);

SoupConnection *soup_message_get_connection (SoupMessage    *msg);
void            soup_message_set_connection (SoupMessage    *msg,
					     SoupConnection *conn);

SoupClientMessageIOData *soup_message_get_io_data (SoupMessage             *msg);
void                     soup_message_set_io_data (SoupMessage             *msg,
						   SoupClientMessageIOData *io);

SoupContentSniffer *soup_message_get_content_sniffer    (SoupMessage        *msg);
void                soup_message_set_content_sniffer    (SoupMessage        *msg,
							 SoupContentSniffer *sniffer);
void                soup_message_set_bytes_for_sniffing (SoupMessage        *msg,
							 gsize               bytes);

GInputStream       *soup_message_get_request_body_stream (SoupMessage        *msg);

void                soup_message_set_reason_phrase       (SoupMessage        *msg,
                                                          const char         *reason_phrase);

void                soup_message_set_method              (SoupMessage        *msg,
                                                          const char         *method);

gboolean            soup_message_is_options_ping         (SoupMessage        *msg);

#endif /* __SOUP_MESSAGE_PRIVATE_H__ */
