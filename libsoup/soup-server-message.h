/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SERVER_MESSAGE_H
#define SOUP_SERVER_MESSAGE_H 1

#include <libsoup/soup-message.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SERVER_MESSAGE            (soup_server_message_get_type ())
#define SOUP_SERVER_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SERVER_MESSAGE, SoupServerMessage))
#define SOUP_SERVER_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SERVER_MESSAGE, SoupServerMessageClass))
#define SOUP_IS_SERVER_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SERVER_MESSAGE))
#define SOUP_IS_SERVER_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SERVER_MESSAGE))
#define SOUP_SERVER_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SERVER_MESSAGE, SoupServerMessageClass))

struct SoupServerMessage {
	SoupMessage parent;

};

typedef struct {
	SoupMessageClass parent_class;

} SoupServerMessageClass;

GType soup_server_message_get_type (void);


SoupServerMessage    *soup_server_message_new          (SoupServer           *server);

SoupServer           *soup_server_message_get_server   (SoupServerMessage    *smsg);

void                  soup_server_message_set_encoding (SoupServerMessage    *smsg,
							SoupTransferEncoding  encoding);
SoupTransferEncoding  soup_server_message_get_encoding (SoupServerMessage    *smsg);

void                  soup_server_message_start        (SoupServerMessage    *smsg);
gboolean              soup_server_message_is_started   (SoupServerMessage    *smsg);

void                  soup_server_message_finish       (SoupServerMessage    *smsg);
gboolean              soup_server_message_is_finished  (SoupServerMessage    *smsg);

G_END_DECLS

#endif /* SOUP_SERVER_H */
