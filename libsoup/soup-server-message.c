/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-server-message.c: Server-side messages
 *
 * Copyright (C) 2001-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "soup-server-message.h"
#include "soup-private.h"
#include "soup-transfer.h"

struct SoupServerMessage {
	SoupMessage *msg;
	GSList      *chunks;           /* CONTAINS: SoupDataBuffer* */
	gboolean     started;
	gboolean     finished;
};

SoupServerMessage *
soup_server_message_new (SoupMessage *src_msg)
{
	SoupServerMessage *ret;

	g_return_val_if_fail (src_msg != NULL, NULL);

	if (src_msg->priv->server_msg) 
		return src_msg->priv->server_msg;

	ret = g_new0 (SoupServerMessage, 1);
	ret->msg = src_msg;

	src_msg->priv->server_msg = ret;

	return ret;
}

void
soup_server_message_start (SoupServerMessage *server_msg)
{
	g_return_if_fail (server_msg != NULL);

	server_msg->started = TRUE;

	soup_transfer_write_unpause (server_msg->msg->priv->write_tag);
}

void
soup_server_message_add_data (SoupServerMessage *server_msg,
			      SoupOwnership      owner,
			      char              *body,
			      gulong             length)
{
	SoupDataBuffer *buf;

	g_return_if_fail (server_msg != NULL);
	g_return_if_fail (body != NULL);
	g_return_if_fail (length != 0);

	buf = g_new0 (SoupDataBuffer, 1);
	buf->length = length;

	if (owner == SOUP_BUFFER_USER_OWNED) {
		buf->body = g_memdup (body, length);
		buf->owner = SOUP_BUFFER_SYSTEM_OWNED;
	} else {
		buf->body = body;
		buf->owner = owner;
	}

	server_msg->chunks = g_slist_append (server_msg->chunks, buf);

	soup_transfer_write_unpause (server_msg->msg->priv->write_tag);
}

void
soup_server_message_finish  (SoupServerMessage *server_msg)
{
	g_return_if_fail (server_msg != NULL);

	server_msg->started = TRUE;
	server_msg->finished = TRUE;

	soup_transfer_write_unpause (server_msg->msg->priv->write_tag);
}

SoupMessage *
soup_server_message_get_source (SoupServerMessage *server_msg)
{
	g_return_val_if_fail (server_msg != NULL, NULL);
	return server_msg->msg;
}
