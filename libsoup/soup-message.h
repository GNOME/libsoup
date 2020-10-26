/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef __SOUP_MESSAGE_H__
#define __SOUP_MESSAGE_H__ 1

#include "soup-types.h"
#include "soup-message-body.h"
#include "soup-message-headers.h"
#include "soup-method.h"

G_BEGIN_DECLS

#define SOUP_TYPE_MESSAGE            (soup_message_get_type ())
#define SOUP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_MESSAGE, SoupMessage))
#define SOUP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_MESSAGE, SoupMessageClass))
#define SOUP_IS_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_IS_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_MESSAGE, SoupMessageClass))

struct _SoupMessage {
	GObject parent;

	/*< public >*/
	const char         *method;

	guint               status_code;
	char               *reason_phrase;

	GInputStream       *request_body_stream;
	SoupMessageHeaders *request_headers;
	SoupMessageHeaders *response_headers;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void     (*wrote_headers)       (SoupMessage *msg);
	void     (*wrote_body)          (SoupMessage *msg);
	void     (*got_informational)   (SoupMessage *msg);
	void     (*got_headers)         (SoupMessage *msg);
	void     (*got_body)            (SoupMessage *msg);
	void     (*restarted)           (SoupMessage *msg);
	void     (*finished)            (SoupMessage *msg);
	void     (*starting)            (SoupMessage *msg);
	void     (*authenticate)        (SoupMessage *msg,
					 SoupAuth    *auth,
					 gboolean     retrying);

	/* Padding for future expansion */
	void (*_libsoup_reserved1) (void);
	void (*_libsoup_reserved2) (void);
	void (*_libsoup_reserved3) (void);
} SoupMessageClass;

SOUP_AVAILABLE_IN_2_4
GType soup_message_get_type (void);

SOUP_AVAILABLE_IN_2_4
SoupMessage   *soup_message_new                 (const char        *method,
						 const char        *uri_string);
SOUP_AVAILABLE_IN_2_4
SoupMessage   *soup_message_new_from_uri        (const char        *method,
						 SoupURI           *uri);

SOUP_AVAILABLE_IN_ALL
void           soup_message_set_request_body    (SoupMessage       *msg,
						 const char        *content_type,
						 GInputStream      *stream,
						 gssize             content_length);
SOUP_AVAILABLE_IN_ALL
void           soup_message_set_request_body_from_bytes (SoupMessage  *msg,
							 const char   *content_type,
							 GBytes       *bytes);

SOUP_AVAILABLE_IN_2_4
void             soup_message_set_http_version    (SoupMessage       *msg,
						   SoupHTTPVersion    version);
SOUP_AVAILABLE_IN_2_4
SoupHTTPVersion  soup_message_get_http_version    (SoupMessage       *msg);

SOUP_AVAILABLE_IN_2_4
gboolean         soup_message_is_keepalive        (SoupMessage       *msg);

SOUP_AVAILABLE_IN_2_4
SoupURI         *soup_message_get_uri             (SoupMessage       *msg);
SOUP_AVAILABLE_IN_2_4
void             soup_message_set_uri             (SoupMessage       *msg,
						   SoupURI           *uri);
SOUP_AVAILABLE_IN_2_30
SoupURI         *soup_message_get_first_party     (SoupMessage       *msg);
SOUP_AVAILABLE_IN_2_30
void             soup_message_set_first_party     (SoupMessage       *msg,
						   SoupURI           *first_party);
SOUP_AVAILABLE_IN_2_70
SoupURI         *soup_message_get_site_for_cookies (SoupMessage      *msg);
SOUP_AVAILABLE_IN_2_70
void             soup_message_set_site_for_cookies (SoupMessage      *msg,
						    SoupURI          *site_for_cookies);
SOUP_AVAILABLE_IN_2_70
void             soup_message_set_is_top_level_navigation (SoupMessage      *msg,
			                                   gboolean          is_top_level_navigation);
SOUP_AVAILABLE_IN_2_70
gboolean         soup_message_get_is_top_level_navigation (SoupMessage      *msg);

typedef enum {
	SOUP_MESSAGE_NO_REDIRECT              = (1 << 1),
	SOUP_MESSAGE_CONTENT_DECODED          = (1 << 2),
	SOUP_MESSAGE_CERTIFICATE_TRUSTED      = (1 << 3),
	SOUP_MESSAGE_NEW_CONNECTION           = (1 << 4),
	SOUP_MESSAGE_IDEMPOTENT               = (1 << 5),
	SOUP_MESSAGE_IGNORE_CONNECTION_LIMITS = (1 << 6),
	SOUP_MESSAGE_DO_NOT_USE_AUTH_CACHE    = (1 << 7)
} SoupMessageFlags;

SOUP_AVAILABLE_IN_2_4
void             soup_message_set_flags           (SoupMessage           *msg,
						   SoupMessageFlags       flags);

SOUP_AVAILABLE_IN_2_4
SoupMessageFlags soup_message_get_flags           (SoupMessage           *msg);

SOUP_AVAILABLE_IN_2_34
gboolean         soup_message_get_https_status    (SoupMessage           *msg,
						   GTlsCertificate      **certificate,
						   GTlsCertificateFlags  *errors);


/* Specialized signal handlers */
SOUP_AVAILABLE_IN_2_4
guint          soup_message_add_header_handler  (SoupMessage       *msg,
						 const char        *signal,
						 const char        *header,
						 GCallback          callback,
						 gpointer           user_data);

SOUP_AVAILABLE_IN_2_4
guint          soup_message_add_status_code_handler (
						 SoupMessage       *msg,
						 const char        *signal,
						 guint              status_code,
						 GCallback          callback,
						 gpointer           user_data);

/*
 * Status Setting
 */
SOUP_AVAILABLE_IN_2_4
void           soup_message_set_status          (SoupMessage       *msg, 
						 guint              status_code);

SOUP_AVAILABLE_IN_2_4
void           soup_message_set_status_full     (SoupMessage       *msg, 
						 guint              status_code, 
						 const char        *reason_phrase);

SOUP_AVAILABLE_IN_2_28
void           soup_message_disable_feature     (SoupMessage       *msg,
						 GType              feature_type);

SOUP_AVAILABLE_IN_2_72
gboolean       soup_message_is_feature_disabled (SoupMessage       *msg,
						 GType              feature_type);


typedef enum {
	SOUP_MESSAGE_PRIORITY_VERY_LOW = 0,
	SOUP_MESSAGE_PRIORITY_LOW,
	SOUP_MESSAGE_PRIORITY_NORMAL,
	SOUP_MESSAGE_PRIORITY_HIGH,
	SOUP_MESSAGE_PRIORITY_VERY_HIGH
} SoupMessagePriority;

SOUP_AVAILABLE_IN_2_44
void                soup_message_set_priority   (SoupMessage        *msg,
						 SoupMessagePriority priority);


SOUP_AVAILABLE_IN_2_44
SoupMessagePriority soup_message_get_priority   (SoupMessage        *msg);

G_END_DECLS

#endif /* __SOUP_MESSAGE_H__ */
