/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_SERVER_MESSAGE_H
#define SOUP_SERVER_MESSAGE_H 1

#include <glib.h>
#include <libsoup/soup-message.h>

typedef struct SoupServerMessage SoupServerMessage;

SoupServerMessage *soup_server_message_new        (SoupMessage       *src_msg);

void               soup_server_message_start      (SoupServerMessage *servmsg);

void               soup_server_message_add_data   (SoupServerMessage *servmsg,
						   SoupOwnership      owner,
						   char              *body,
						   gulong             length);

void               soup_server_message_finish     (SoupServerMessage *servmsg);

SoupMessage       *soup_server_message_get_source (SoupServerMessage *servmsg);

#endif /* SOUP_SERVER_H */
