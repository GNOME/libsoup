/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#include "soup-soap-message.h"
#include "soup-uri.h"

#define PARENT_TYPE SOUP_TYPE_MESSAGE

struct _SoupSoapMessagePrivate {
};

static GObjectClass *parent_class = NULL;

static void
finalize (GObject *object)
{
	SoupSoapMessage *msg = SOUP_SOAP_MESSAGE (object);

	/* free memory */
	g_free (msg->priv);
	msg->priv = NULL;

	parent_class->finalize (object);
}

static void
class_init (SoupSoapMessageClass *klass)
{
	GObjectClass *object_class;

	parent_class = g_type_class_peek_parent (klass);

	object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = finalize;
}

static void
init (SoupSoapMessage *msg, SoupSoapMessageClass *klass)
{
	msg->priv = g_new0 (SoupSoapMessagePrivate, 1);
}

SOUP_MAKE_TYPE (soup_soap_message, SoupSoapMessage, class_init, init, PARENT_TYPE)

/**
 * soup_soap_message_new:
 * @method: the HTTP method for the created request.
 * @uri_string: the destination endpoint (as a string).
 *
 * Creates a new empty #SoupSoapMessage, which will connect to @uri_string.
 *
 * Returns: the new #SoupSoapMessage (or %NULL if @uri_string could not be
 * parsed).
 */
SoupSoapMessage *
soup_soap_message_new (const char *method, const char *uri_string)
{
	SoupSoapMessage *msg;
	SoupUri *uri;

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;

	msg = g_object_new (SOUP_TYPE_SOAP_MESSAGE, NULL);
	SOUP_MESSAGE (msg)->method = method ? method : SOUP_METHOD_GET;
	soup_message_set_uri (SOUP_MESSAGE (msg), (const SoupUri *) uri);

	soup_uri_free (uri);

	return msg;
}

/**
 * soup_soap_message_new_from_uri:
 * @method: the HTTP method for the created request.
 * @uri: the destination endpoint (as a #SoupUri).
 *
 * * Creates a new empty #SoupSoapMessage, which will connect to @uri
 *
 * Returns: the new #SoupSoapMessage
 */
SoupSoapMessage *
soup_soap_message_new_from_uri (const char *method, const SoupUri *uri)
{
	SoupSoapMessage *msg;

	msg = g_object_new (SOUP_TYPE_SOAP_MESSAGE, NULL);
	SOUP_MESSAGE (msg)->method = method ? method : SOUP_METHOD_GET;
	soup_message_set_uri (SOUP_MESSAGE (msg), uri);

	return msg;
}
