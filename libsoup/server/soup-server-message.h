/*
 * Copyright (C) 2020 Igalia S.L.
 */

#ifndef __SOUP_SERVER_MESSAGE_H__
#define __SOUP_SERVER_MESSAGE_H__ 1

#include "soup-types.h"
#include "soup-message-body.h"
#include "soup-message-headers.h"
#include "soup-method.h"

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER_MESSAGE (soup_server_message_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupServerMessage, soup_server_message, SOUP, SERVER_MESSAGE, GObject)

SOUP_AVAILABLE_IN_ALL
SoupMessageHeaders *soup_server_message_get_request_headers  (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageHeaders *soup_server_message_get_response_headers (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageBody    *soup_server_message_get_request_body     (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageBody    *soup_server_message_get_response_body    (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
const char         *soup_server_message_get_method           (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
SoupHTTPVersion     soup_server_message_get_http_version     (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
void                soup_server_message_set_http_version     (SoupServerMessage *msg,
                                                              SoupHTTPVersion    version);

SOUP_AVAILABLE_IN_ALL
const char         *soup_server_message_get_reason_phrase    (SoupServerMessage  *msg);

SOUP_AVAILABLE_IN_ALL
guint               soup_server_message_get_status           (SoupServerMessage  *msg);

SOUP_AVAILABLE_IN_ALL
void                soup_server_message_set_status           (SoupServerMessage *msg,
                                                              guint              status_code,
                                                              const char        *reason_phrase);
SOUP_AVAILABLE_IN_ALL
GUri               *soup_server_message_get_uri              (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
void                soup_server_message_set_response         (SoupServerMessage *msg,
                                                              const char        *content_type,
                                                              SoupMemoryUse      resp_use,
                                                              const char        *resp_body,
                                                              gsize              resp_length);
SOUP_AVAILABLE_IN_ALL
void                soup_server_message_set_redirect          (SoupServerMessage *msg,
                                                               guint              status_code,
                                                               const char        *redirect_uri);

SOUP_AVAILABLE_IN_ALL
GSocket            *soup_server_message_get_socket            (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
GSocketAddress     *soup_server_message_get_local_address     (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
GSocketAddress     *soup_server_message_get_remote_address    (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
const char         *soup_server_message_get_remote_host       (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
GIOStream          *soup_server_message_steal_connection      (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_ALL
gboolean            soup_server_message_is_options_ping       (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_3_2
void                 soup_server_message_pause                (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_3_2
void                 soup_server_message_unpause              (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_3_2
GTlsCertificate     *soup_server_message_get_tls_peer_certificate          (SoupServerMessage *msg);

SOUP_AVAILABLE_IN_3_2
GTlsCertificateFlags soup_server_message_get_tls_peer_certificate_errors   (SoupServerMessage *msg);

G_END_DECLS

#endif /* __SOUP_SERVER_MESSAGE_H__ */
