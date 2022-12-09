/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#pragma once

#include "soup-types.h"
#include "soup-message-body.h"
#include "soup-message-headers.h"
#include "soup-method.h"
#include "soup-multipart.h"

G_BEGIN_DECLS

#define SOUP_TYPE_MESSAGE (soup_message_get_type ())
SOUP_AVAILABLE_IN_ALL
G_DECLARE_FINAL_TYPE (SoupMessage, soup_message, SOUP, MESSAGE, GObject)

SOUP_AVAILABLE_IN_ALL
SoupMessage   *soup_message_new                   (const char        *method,
						   const char        *uri_string);
SOUP_AVAILABLE_IN_ALL
SoupMessage   *soup_message_new_from_uri          (const char        *method,
						   GUri              *uri);

SOUP_AVAILABLE_IN_ALL
SoupMessage   *soup_message_new_options_ping      (GUri              *base_uri);

SOUP_AVAILABLE_IN_ALL
SoupMessage   *soup_message_new_from_encoded_form (const char        *method,
						   const char        *uri_string,
						   char              *encoded_form);

SOUP_AVAILABLE_IN_ALL
SoupMessage   *soup_message_new_from_multipart    (const char        *uri_string,
						   SoupMultipart     *multipart);

SOUP_AVAILABLE_IN_ALL
void           soup_message_set_request_body    (SoupMessage       *msg,
						 const char        *content_type,
						 GInputStream      *stream,
						 gssize             content_length);
SOUP_AVAILABLE_IN_ALL
void           soup_message_set_request_body_from_bytes (SoupMessage  *msg,
							 const char   *content_type,
							 GBytes       *bytes);

SOUP_AVAILABLE_IN_ALL
SoupHTTPVersion  soup_message_get_http_version    (SoupMessage       *msg);

SOUP_AVAILABLE_IN_ALL
gboolean         soup_message_is_keepalive        (SoupMessage       *msg);

SOUP_AVAILABLE_IN_ALL
GUri           *soup_message_get_uri             (SoupMessage       *msg);
SOUP_AVAILABLE_IN_ALL
void             soup_message_set_uri             (SoupMessage       *msg,
						   GUri              *uri);
SOUP_AVAILABLE_IN_ALL
GUri            *soup_message_get_first_party     (SoupMessage       *msg);
SOUP_AVAILABLE_IN_ALL
void             soup_message_set_first_party     (SoupMessage       *msg,
						   GUri              *first_party);
SOUP_AVAILABLE_IN_ALL
GUri            *soup_message_get_site_for_cookies (SoupMessage      *msg);
SOUP_AVAILABLE_IN_ALL
void             soup_message_set_site_for_cookies (SoupMessage      *msg,
						    GUri             *site_for_cookies);
SOUP_AVAILABLE_IN_ALL
void             soup_message_set_is_top_level_navigation (SoupMessage      *msg,
			                                   gboolean          is_top_level_navigation);
SOUP_AVAILABLE_IN_ALL
gboolean         soup_message_get_is_top_level_navigation (SoupMessage      *msg);

typedef enum {
	SOUP_MESSAGE_NO_REDIRECT              = (1 << 1),
	SOUP_MESSAGE_NEW_CONNECTION           = (1 << 2),
	SOUP_MESSAGE_IDEMPOTENT               = (1 << 3),
	SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE    = (1 << 4),
        SOUP_MESSAGE_COLLECT_METRICS          = (1 << 5)
} SoupMessageFlags;

SOUP_AVAILABLE_IN_ALL
void             soup_message_set_flags           (SoupMessage           *msg,
						   SoupMessageFlags       flags);

SOUP_AVAILABLE_IN_ALL
SoupMessageFlags soup_message_get_flags           (SoupMessage           *msg);

SOUP_AVAILABLE_IN_ALL
void             soup_message_add_flags           (SoupMessage           *msg,
						   SoupMessageFlags       flags);

SOUP_AVAILABLE_IN_ALL
void             soup_message_remove_flags        (SoupMessage           *msg,
						   SoupMessageFlags       flags);

SOUP_AVAILABLE_IN_ALL
gboolean         soup_message_query_flags         (SoupMessage           *msg,
                                                   SoupMessageFlags       flags);

SOUP_AVAILABLE_IN_ALL
GTlsCertificate     *soup_message_get_tls_peer_certificate                         (SoupMessage     *msg);

SOUP_AVAILABLE_IN_ALL
GTlsCertificateFlags soup_message_get_tls_peer_certificate_errors                  (SoupMessage     *msg);

SOUP_AVAILABLE_IN_ALL
GTlsProtocolVersion  soup_message_get_tls_protocol_version                         (SoupMessage     *msg);

SOUP_AVAILABLE_IN_ALL
const char          *soup_message_get_tls_ciphersuite_name                         (SoupMessage     *msg);

SOUP_AVAILABLE_IN_ALL
void                 soup_message_set_tls_client_certificate                       (SoupMessage     *msg,
                                                                                    GTlsCertificate *certificate);

SOUP_AVAILABLE_IN_ALL
void                 soup_message_tls_client_certificate_password_request_complete (SoupMessage     *msg);


/* Specialized signal handlers */
SOUP_AVAILABLE_IN_ALL
guint          soup_message_add_header_handler  (SoupMessage       *msg,
						 const char        *signal,
						 const char        *header,
						 GCallback          callback,
						 gpointer           user_data);

SOUP_AVAILABLE_IN_ALL
guint          soup_message_add_status_code_handler (
						 SoupMessage       *msg,
						 const char        *signal,
						 guint              status_code,
						 GCallback          callback,
						 gpointer           user_data);

SOUP_AVAILABLE_IN_ALL
void           soup_message_disable_feature     (SoupMessage       *msg,
						 GType              feature_type);

SOUP_AVAILABLE_IN_ALL
gboolean       soup_message_is_feature_disabled (SoupMessage       *msg,
						 GType              feature_type);


typedef enum {
	SOUP_MESSAGE_PRIORITY_VERY_LOW = 0,
	SOUP_MESSAGE_PRIORITY_LOW,
	SOUP_MESSAGE_PRIORITY_NORMAL,
	SOUP_MESSAGE_PRIORITY_HIGH,
	SOUP_MESSAGE_PRIORITY_VERY_HIGH
} SoupMessagePriority;

SOUP_AVAILABLE_IN_ALL
void                soup_message_set_priority   (SoupMessage        *msg,
						 SoupMessagePriority priority);


SOUP_AVAILABLE_IN_ALL
SoupMessagePriority soup_message_get_priority   (SoupMessage        *msg);

SOUP_AVAILABLE_IN_ALL
const char         *soup_message_get_method     (SoupMessage        *msg);

SOUP_AVAILABLE_IN_ALL
void                soup_message_set_method     (SoupMessage        *msg,
                                                 const char         *method);

SOUP_AVAILABLE_IN_ALL
SoupStatus          soup_message_get_status     (SoupMessage        *msg);

SOUP_AVAILABLE_IN_ALL
const char         *soup_message_get_reason_phrase (SoupMessage     *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageHeaders *soup_message_get_request_headers  (SoupMessage  *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageHeaders *soup_message_get_response_headers (SoupMessage  *msg);

SOUP_AVAILABLE_IN_ALL
gboolean            soup_message_get_is_options_ping  (SoupMessage  *msg);

SOUP_AVAILABLE_IN_ALL
void                soup_message_set_is_options_ping  (SoupMessage  *msg,
                                                       gboolean      is_options_ping);
SOUP_AVAILABLE_IN_ALL
guint64             soup_message_get_connection_id    (SoupMessage *msg);

SOUP_AVAILABLE_IN_ALL
GSocketAddress     *soup_message_get_remote_address   (SoupMessage *msg);

SOUP_AVAILABLE_IN_ALL
SoupMessageMetrics *soup_message_get_metrics          (SoupMessage  *msg);

SOUP_AVAILABLE_IN_3_4
void                soup_message_set_force_http1      (SoupMessage *msg,
                                                       gboolean value);
SOUP_AVAILABLE_IN_3_4
gboolean            soup_message_get_force_http1      (SoupMessage *msg);

G_END_DECLS
