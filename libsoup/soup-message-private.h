/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_MESSAGE_PRIVATE_H__
#define __SOUP_MESSAGE_PRIVATE_H__ 1

#include "soup-filter-input-stream.h"
#include "soup-message.h"
#include "soup-client-message-io.h"
#include "auth/soup-auth.h"
#include "content-sniffer/soup-content-sniffer.h"
#include "soup-session.h"

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

void soup_message_send_item (SoupMessage              *msg,
                             SoupMessageQueueItem     *item,
                             SoupMessageIOCompletionFn completion_cb,
                             gpointer                  user_data);

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
void       soup_message_io_pause       (SoupMessage *msg);
void       soup_message_io_unpause     (SoupMessage *msg);
gboolean   soup_message_is_io_paused   (SoupMessage *msg);
gboolean   soup_message_io_in_progress (SoupMessage *msg);

gboolean soup_message_io_skip                  (SoupMessage        *msg,
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

GInputStream *soup_message_io_get_response_istream (SoupMessage  *msg,
						    GError      **error);

GCancellable *soup_message_io_get_cancellable  (SoupMessage *msg);

void soup_message_wrote_headers     (SoupMessage *msg);
void soup_message_wrote_body_data   (SoupMessage *msg,
				     gsize        chunk_size);
void soup_message_wrote_body        (SoupMessage *msg);
void soup_message_got_informational (SoupMessage *msg);
void soup_message_got_headers       (SoupMessage *msg);
void soup_message_got_body_data     (SoupMessage *msg,
                                     gsize        chunk_size);
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
void soup_message_hsts_enforced     (SoupMessage *msg);

gboolean soup_message_disables_feature (SoupMessage *msg,
					gpointer     feature);

GList *soup_message_get_disabled_features (SoupMessage *msg);

SoupConnection *soup_message_get_connection (SoupMessage    *msg);
void            soup_message_set_connection (SoupMessage    *msg,
					     SoupConnection *conn);
void            soup_message_transfer_connection (SoupMessage *preconnect_msg,
                                                  SoupMessage *msg);
void            soup_message_set_is_preconnect   (SoupMessage *msg,
                                                  gboolean     is_preconnect);
gboolean        soup_message_has_pending_tls_cert_request      (SoupMessage *msg);
gboolean        soup_message_has_pending_tls_cert_pass_request (SoupMessage *msg);

SoupClientMessageIO *soup_message_get_io_data (SoupMessage             *msg);

void                soup_message_set_content_sniffer    (SoupMessage        *msg,
							 SoupContentSniffer *sniffer);
gboolean            soup_message_has_content_sniffer    (SoupMessage        *msg);
gboolean            soup_message_try_sniff_content      (SoupMessage        *msg,
                                                         GInputStream       *stream,
                                                         gboolean            blocking,
                                                         GCancellable       *cancellable,
                                                         GError            **error);
GInputStream       *soup_message_get_request_body_stream (SoupMessage        *msg);

void                soup_message_set_reason_phrase       (SoupMessage        *msg,
                                                          const char         *reason_phrase);

void                soup_message_set_http_version        (SoupMessage       *msg,
						          SoupHTTPVersion    version);

typedef enum {
        SOUP_MESSAGE_METRICS_FETCH_START,
        SOUP_MESSAGE_METRICS_DNS_START,
        SOUP_MESSAGE_METRICS_DNS_END,
        SOUP_MESSAGE_METRICS_CONNECT_START,
        SOUP_MESSAGE_METRICS_CONNECT_END,
        SOUP_MESSAGE_METRICS_TLS_START,
        SOUP_MESSAGE_METRICS_REQUEST_START,
        SOUP_MESSAGE_METRICS_RESPONSE_START,
        SOUP_MESSAGE_METRICS_RESPONSE_END
} SoupMessageMetricsType;

void soup_message_set_metrics_timestamp (SoupMessage           *msg,
                                         SoupMessageMetricsType type);

void soup_message_set_request_host_from_uri     (SoupMessage *msg,
                                                 GUri        *uri);

void soup_message_update_request_host_if_needed (SoupMessage *msg);

void soup_message_force_keep_alive_if_needed    (SoupMessage *msg);

void     soup_message_set_force_http_version    (SoupMessage *msg,
                                                 guint8       version);

guint8   soup_message_get_force_http_version    (SoupMessage *msg);

void     soup_message_set_is_misdirected_retry  (SoupMessage *msg,
                                                 gboolean     is_misdirected_retry);
gboolean soup_message_is_misdirected_retry      (SoupMessage *msg);

#endif /* __SOUP_MESSAGE_PRIVATE_H__ */
