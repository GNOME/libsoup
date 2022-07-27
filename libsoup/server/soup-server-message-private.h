/*
 * Copyright (C) 2020 Igalia S.L.
 */

#ifndef __SOUP_SERVER_MESSAGE_PRIVATE_H__
#define __SOUP_SERVER_MESSAGE_PRIVATE_H__ 1

#include "soup-server-message.h"
#include "soup-auth-domain.h"
#include "soup-message-io-data.h"
#include "soup-server-connection.h"

SoupServerMessage *soup_server_message_new                 (SoupServerConnection     *conn);
void               soup_server_message_set_uri             (SoupServerMessage        *msg,
                                                            GUri                     *uri);
void               soup_server_message_set_method          (SoupServerMessage        *msg,
                                                            const char               *method);
SoupServerConnection *soup_server_message_get_connection   (SoupServerMessage        *msg);
void               soup_server_message_set_auth            (SoupServerMessage        *msg,
                                                            SoupAuthDomain           *domain,
                                                            char                     *user);
gboolean           soup_server_message_is_keepalive        (SoupServerMessage        *msg);
gboolean           soup_server_message_is_io_paused        (SoupServerMessage        *msg);
void               soup_server_message_finish              (SoupServerMessage        *msg);
void               soup_server_message_cleanup_response    (SoupServerMessage        *msg);
void               soup_server_message_wrote_informational (SoupServerMessage        *msg);
void               soup_server_message_wrote_headers       (SoupServerMessage        *msg);
void               soup_server_message_wrote_chunk         (SoupServerMessage        *msg);
void               soup_server_message_wrote_body_data     (SoupServerMessage        *msg,
                                                            gsize                     chunk_size);
void               soup_server_message_wrote_body          (SoupServerMessage        *msg);
void               soup_server_message_got_headers         (SoupServerMessage        *msg);
void               soup_server_message_got_chunk           (SoupServerMessage        *msg,
                                                            GBytes                   *chunk);
void               soup_server_message_got_body            (SoupServerMessage        *msg);
void               soup_server_message_finished            (SoupServerMessage        *msg);
void               soup_server_message_read_request        (SoupServerMessage        *msg,
                                                            SoupMessageIOCompletionFn completion_cb,
                                                            gpointer                  user_data);

void               soup_server_message_set_options_ping    (SoupServerMessage        *msg,
                                                            gboolean                  is_options_ping);

SoupServerMessageIO *soup_server_message_get_io_data       (SoupServerMessage        *msg);


#endif /* __SOUP_SERVER_MESSAGE_PRIVATE_H__ */
