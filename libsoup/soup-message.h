/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MESSAGE_H
#define SOUP_MESSAGE_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-method.h>

#define SOUP_TYPE_MESSAGE            (soup_message_get_type ())
#define SOUP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_MESSAGE, SoupMessage))
#define SOUP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_MESSAGE, SoupMessageClass))
#define SOUP_IS_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_IS_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_MESSAGE))
#define SOUP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_MESSAGE, SoupMessageClass))

typedef struct SoupMessagePrivate SoupMessagePrivate;

typedef enum {
	SOUP_TRANSFER_UNKNOWN = 0,
	SOUP_TRANSFER_CHUNKED,
	SOUP_TRANSFER_CONTENT_LENGTH,
} SoupTransferEncoding;

typedef enum {
	SOUP_BUFFER_SYSTEM_OWNED = 0,
	SOUP_BUFFER_USER_OWNED,
	SOUP_BUFFER_STATIC
} SoupOwnership;

typedef struct {
	SoupOwnership  owner;
	char          *body;
	guint          length;
} SoupDataBuffer;

struct SoupMessage {
	GObject parent;

	SoupMessagePrivate *priv;

	const char         *method;

	guint               errorcode;
	SoupErrorClass      errorclass;
	const char         *errorphrase;

	SoupDataBuffer      request;
	GHashTable         *request_headers;

	SoupDataBuffer      response;
	GHashTable         *response_headers;
};

typedef struct {
	GObjectClass parent_class;

	/* signals */
	void     (*wrote_headers) (SoupMessage *msg);
	void     (*wrote_chunk)   (SoupMessage *msg);
	void     (*wrote_body)    (SoupMessage *msg);
	void     (*got_headers)   (SoupMessage *msg);
	void     (*got_chunk)     (SoupMessage *msg);
	void     (*got_body)      (SoupMessage *msg);
	void     (*finished)      (SoupMessage *msg);
} SoupMessageClass;

GType soup_message_get_type (void);

#define SOUP_MESSAGE_IS_ERROR(msg)                            \
        (msg->errorclass &&                                   \
	 msg->errorclass != SOUP_ERROR_CLASS_SUCCESS &&       \
         msg->errorclass != SOUP_ERROR_CLASS_INFORMATIONAL && \
	 msg->errorclass != SOUP_ERROR_CLASS_UNKNOWN)

typedef void (*SoupMessageCallbackFn) (SoupMessage *req, gpointer user_data);
/* Backward compat; FIXME */
typedef SoupMessageCallbackFn SoupCallbackFn;

SoupMessage   *soup_message_new                 (const char        *method,
						 const char        *uri);
SoupMessage   *soup_message_new_from_uri        (const char        *method,
						 const SoupUri     *uri);

void           soup_message_set_request         (SoupMessage       *msg,
						 const char        *content_type,
						 SoupOwnership      req_owner,
						 char              *req_body,
						 gulong             req_len);

void           soup_message_set_response        (SoupMessage       *msg,
						 const char        *content_type,
						 SoupOwnership      resp_owner,
						 char              *resp_body,
						 gulong             resp_len);

void           soup_message_cancel              (SoupMessage       *req);

void           soup_message_disconnect          (SoupMessage       *req);

SoupErrorClass soup_message_send                (SoupMessage       *msg);

void           soup_message_queue               (SoupMessage       *req, 
						 SoupCallbackFn     callback, 
						 gpointer           user_data);

void           soup_message_requeue             (SoupMessage       *req);

void           soup_message_add_header          (GHashTable        *hash,
						 const char        *name,
						 const char        *value);

const char    *soup_message_get_header          (GHashTable        *hash,
						 const char        *name);

const GSList  *soup_message_get_header_list     (GHashTable        *hash,
						 const char        *name);

void           soup_message_foreach_header      (GHashTable        *hash,
						 GHFunc             func,
						 gpointer           user_data);

void           soup_message_remove_header       (GHashTable        *hash,
						 const char        *name);

void           soup_message_clear_headers       (GHashTable        *hash);

typedef enum {
	SOUP_HTTP_1_0 = 0,
	SOUP_HTTP_1_1 = 1,
} SoupHttpVersion;

void             soup_message_set_http_version    (SoupMessage       *msg,
						   SoupHttpVersion    version);
SoupHttpVersion  soup_message_get_http_version    (SoupMessage       *msg);

gboolean         soup_message_is_keepalive        (SoupMessage       *msg);

const SoupUri   *soup_message_get_uri             (SoupMessage       *msg);

typedef enum {
	/*
	 * SOUP_MESSAGE_NO_PIPELINE: 
	 * Use a currently unused connection or establish a new 
	 * connection when issuing this request.
	 */
	SOUP_MESSAGE_NO_PIPELINE      = (1 << 0),

	/*
	 * SOUP_MESSAGE_NO_REDIRECT: 
	 * Do not follow redirection responses.
	 */
	SOUP_MESSAGE_NO_REDIRECT      = (1 << 1),

	/*
	 * SOUP_MESSAGE_NO_COOKIE:
	 * Do not send cookie information with request, and do not 
	 * store cookie information from the response.
	 */
	SOUP_MESSAGE_NO_COOKIE        = (1 << 2),

	/*
	 * SOUP_MESSAGE_OVERWRITE_CHUNKS:
	 * Downloaded data chunks should not be stored in the response 
	 * data buffer.  Instead only send data to SOUP_HANDLER_BODY_CHUNK 
	 * handlers, then truncate the data buffer.
	 *
	 * Useful when the response is expected to be very large, and 
	 * storage in memory is not desired.
	 */
	SOUP_MESSAGE_OVERWRITE_CHUNKS = (1 << 3),

	/*
	 * SOUP_MESSAGE_EXPECT_CONTINUE:
	 * The message includes an "Expect: 100-continue" header, and we
	 * should not send the body until the Continue response has been
	 * received. (This should be synchronized with the existence
	 * of the "Expect: 100-continue" header. FIXME!)
	 */
	SOUP_MESSAGE_EXPECT_CONTINUE = (1 << 4)
} SoupMessageFlags;

void           soup_message_set_flags           (SoupMessage        *msg,
						 guint               flags);

guint          soup_message_get_flags           (SoupMessage        *msg);

/*
 * Handler Registration 
 */
typedef enum {
	SOUP_HANDLER_PRE_BODY = 1,
	SOUP_HANDLER_BODY_CHUNK,
	SOUP_HANDLER_POST_BODY
} SoupHandlerPhase;

void           soup_message_add_handler         (SoupMessage       *msg,
						 SoupHandlerPhase   type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_header_handler  (SoupMessage       *msg,
						 const char        *header,
						 SoupHandlerPhase   type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_error_code_handler (
						 SoupMessage       *msg,
						 guint              errorcode,
						 SoupHandlerPhase   type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_add_error_class_handler (
						 SoupMessage       *msg,
						 SoupErrorClass     errorclass,
						 SoupHandlerPhase   type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

void           soup_message_remove_handler      (SoupMessage       *msg, 
						 SoupHandlerPhase   type,
						 SoupCallbackFn     handler_cb,
						 gpointer           user_data);

/*
 * Error Setting
 */
void           soup_message_set_error           (SoupMessage       *msg, 
						 SoupKnownErrorCode errcode);

void           soup_message_set_error_full      (SoupMessage       *msg, 
						 guint              errcode, 
						 const char        *errphrase);


/* Chunked encoding */
void           soup_message_add_chunk           (SoupMessage       *msg,
						 SoupOwnership      owner,
						 const char        *body,
						 guint              length);
void           soup_message_add_final_chunk     (SoupMessage       *msg);

SoupDataBuffer*soup_message_pop_chunk           (SoupMessage       *msg);


/* I/O */
void           soup_message_send_request        (SoupMessage       *req,
						 SoupSocket        *sock,
						 gboolean           via_proxy);
void           soup_message_read_request        (SoupMessage       *req,
						 SoupSocket        *sock);
void           soup_message_io_pause            (SoupMessage       *msg);
void           soup_message_io_unpause          (SoupMessage       *msg);


void soup_message_wrote_headers  (SoupMessage *msg);
void soup_message_wrote_chunk    (SoupMessage *msg);
void soup_message_wrote_body     (SoupMessage *msg);
void soup_message_got_headers    (SoupMessage *msg);
void soup_message_got_chunk      (SoupMessage *msg);
void soup_message_got_body       (SoupMessage *msg);
void soup_message_finished       (SoupMessage *msg);

#endif /*SOUP_MESSAGE_H*/
