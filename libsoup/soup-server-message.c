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
#include "soup-server.h"

typedef struct {
	SoupServer *server;

	SoupTransferEncoding encoding;

	gboolean  started;
	gboolean  finished;
} SoupServerMessagePrivate;
#define SOUP_SERVER_MESSAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_SERVER_MESSAGE, SoupServerMessagePrivate))

G_DEFINE_TYPE (SoupServerMessage, soup_server_message, SOUP_TYPE_MESSAGE)

static void
soup_server_message_init (SoupServerMessage *smsg)
{
}

static void
finalize (GObject *object)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (object);

	/* FIXME */
	g_free ((char *) ((SoupMessage *)smsg)->method);

	G_OBJECT_CLASS (soup_server_message_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	SoupServerMessagePrivate *priv = SOUP_SERVER_MESSAGE_GET_PRIVATE (object);

	if (priv->server)
		g_object_unref (priv->server);

	G_OBJECT_CLASS (soup_server_message_parent_class)->dispose (object);
}

static void
soup_server_message_class_init (SoupServerMessageClass *soup_server_message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (soup_server_message_class);

	g_type_class_add_private (soup_server_message_class, sizeof (SoupServerMessagePrivate));

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->dispose = dispose;
}


SoupServerMessage *
soup_server_message_new (SoupServer *server)
{
	SoupServerMessage *smsg;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);

	smsg = g_object_new (SOUP_TYPE_SERVER_MESSAGE, NULL);
	SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->server = g_object_ref (server);

	return smsg;
}

SoupServer *
soup_server_message_get_server (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), NULL);

	return SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->server;
}

void
soup_server_message_set_encoding (SoupServerMessage *smsg,
				  SoupTransferEncoding encoding)
{
	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));

	SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->encoding = encoding;
}

SoupTransferEncoding
soup_server_message_get_encoding (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), SOUP_TRANSFER_UNKNOWN);

	return SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->encoding;
}

void
soup_server_message_start (SoupServerMessage *smsg)
{
	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));

	SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->started = TRUE;

	soup_message_io_unpause (SOUP_MESSAGE (smsg));
}

gboolean
soup_server_message_is_started (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), TRUE);

	return SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->started;
}

void
soup_server_message_finish  (SoupServerMessage *smsg)
{
	SoupServerMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));
	priv = SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg);

	priv->started = TRUE;
	priv->finished = TRUE;

	soup_message_io_unpause (SOUP_MESSAGE (smsg));
}

gboolean
soup_server_message_is_finished (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), TRUE);

	return SOUP_SERVER_MESSAGE_GET_PRIVATE (smsg)->finished;
}
