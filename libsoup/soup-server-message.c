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

struct SoupServerMessagePrivate {
	SoupServer *server;

	SoupTransferEncoding encoding;

	gboolean  started;
	gboolean  finished;
};

#define PARENT_TYPE SOUP_TYPE_MESSAGE
static SoupMessageClass *parent_class;

static void
init (GObject *object)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (object);

	smsg->priv = g_new0 (SoupServerMessagePrivate, 1);
}

static void
finalize (GObject *object)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (object);

	/* FIXME */
	g_free ((char *) ((SoupMessage *)smsg)->method);

	g_free (smsg->priv);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
	SoupServerMessage *smsg = SOUP_SERVER_MESSAGE (object);

	if (smsg->priv->server)
		g_object_unref (smsg->priv->server);

	G_OBJECT_CLASS (parent_class)->dispose (object);
}



static void
class_init (GObjectClass *object_class)
{
	parent_class = g_type_class_ref (PARENT_TYPE);

	/* virtual method override */
	object_class->finalize = finalize;
	object_class->dispose = dispose;
}

SOUP_MAKE_TYPE (soup_server_message, SoupServerMessage, class_init, init, PARENT_TYPE)


SoupServerMessage *
soup_server_message_new (SoupServer *server)
{
	SoupServerMessage *smsg;

	g_return_val_if_fail (SOUP_IS_SERVER (server), NULL);

	smsg = g_object_new (SOUP_TYPE_SERVER_MESSAGE, NULL);
	smsg->priv->server = g_object_ref (server);

	return smsg;
}

SoupServer *
soup_server_message_get_server (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), NULL);

	return smsg->priv->server;
}

void
soup_server_message_set_encoding (SoupServerMessage *smsg,
				  SoupTransferEncoding encoding)
{
	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));

	smsg->priv->encoding = encoding;
}

SoupTransferEncoding
soup_server_message_get_encoding (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), SOUP_TRANSFER_UNKNOWN);

	return smsg->priv->encoding;
}

void
soup_server_message_start (SoupServerMessage *smsg)
{
	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));

	smsg->priv->started = TRUE;

	soup_message_io_unpause (SOUP_MESSAGE (smsg));
}

gboolean
soup_server_message_is_started (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), TRUE);

	return smsg->priv->started;
}

void
soup_server_message_finish  (SoupServerMessage *smsg)
{
	g_return_if_fail (SOUP_IS_SERVER_MESSAGE (smsg));

	smsg->priv->started = TRUE;
	smsg->priv->finished = TRUE;

	soup_message_io_unpause (SOUP_MESSAGE (smsg));
}

gboolean
soup_server_message_is_finished (SoupServerMessage *smsg)
{
	g_return_val_if_fail (SOUP_IS_SERVER_MESSAGE (smsg), TRUE);

	return smsg->priv->finished;
}
