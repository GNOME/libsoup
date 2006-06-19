/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-xmlrpc-message.c: XMLRPC request message
 *
 * Copyright (C) 2003, Novell, Inc.
 * Copyright (C) 2004, Mariano Suarez-Alvarez <mariano@gnome.org>
 * Copyright (C) 2004, Fernando Herrera  <fherrera@onirica.com>
 * Copyright (C) 2005, Jeff Bailey  <jbailey@ubuntu.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <time.h>

#include "soup-date.h"
#include "soup-misc.h"
#include "soup-xmlrpc-message.h"

G_DEFINE_TYPE (SoupXmlrpcMessage, soup_xmlrpc_message, SOUP_TYPE_MESSAGE)

typedef struct {
	xmlDocPtr doc;
	xmlNodePtr last_node;
} SoupXmlrpcMessagePrivate;
#define SOUP_XMLRPC_MESSAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_XMLRPC_MESSAGE, SoupXmlrpcMessagePrivate))

static void soup_xmlrpc_message_end_element (SoupXmlrpcMessage *msg);

static void
finalize (GObject *object)
{
	SoupXmlrpcMessagePrivate *priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (object);

	if (priv->doc)
		xmlFreeDoc (priv->doc);

	G_OBJECT_CLASS (soup_xmlrpc_message_parent_class)->finalize (object);
}

static void
soup_xmlrpc_message_class_init (SoupXmlrpcMessageClass *soup_xmlrpc_message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (soup_xmlrpc_message_class);

	g_type_class_add_private (soup_xmlrpc_message_class, sizeof (SoupXmlrpcMessagePrivate));

	object_class->finalize = finalize;
}

static void
soup_xmlrpc_message_init (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	xmlKeepBlanksDefault (0);

	priv->doc = xmlNewDoc ((xmlChar *)"1.0");
	priv->doc->standalone = FALSE;
	priv->doc->encoding = xmlCharStrdup ("UTF-8");
}


SoupXmlrpcMessage *
soup_xmlrpc_message_new (const char *uri_string)
{
	SoupXmlrpcMessage *msg;
	SoupUri *uri;

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;

	msg = soup_xmlrpc_message_new_from_uri (uri);

	soup_uri_free (uri);

	return msg;
}

SoupXmlrpcMessage *
soup_xmlrpc_message_new_from_uri (const SoupUri *uri)
{
	SoupXmlrpcMessage *msg;

	msg = g_object_new (SOUP_TYPE_XMLRPC_MESSAGE, NULL);
	SOUP_MESSAGE (msg)->method = SOUP_METHOD_POST;
	soup_message_set_uri (SOUP_MESSAGE (msg), uri);

	return msg;
}

void
soup_xmlrpc_message_start_call (SoupXmlrpcMessage *msg, const char *method_name)
{
	SoupXmlrpcMessagePrivate *priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);
	xmlNodePtr root;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	root = xmlNewDocNode (priv->doc, NULL, (xmlChar *)"methodCall", NULL);
	xmlDocSetRootElement (priv->doc, root);

	xmlNewChild (root, NULL, (xmlChar *)"methodName", (xmlChar *)method_name);

	priv->last_node = root;

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"params", NULL);
}

void
soup_xmlrpc_message_end_call (SoupXmlrpcMessage *msg)
{
	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	soup_xmlrpc_message_end_element (msg);
	soup_xmlrpc_message_end_element (msg);
	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_start_param (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"param", NULL);
}

void
soup_xmlrpc_message_end_param (SoupXmlrpcMessage *msg)
{
	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_write_int (SoupXmlrpcMessage *msg, long i)
{
	SoupXmlrpcMessagePrivate *priv;
	char *str;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	str = g_strdup_printf ("%ld", i);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewTextChild (priv->last_node, NULL, (xmlChar *)"i4", (xmlChar *)str);
	soup_xmlrpc_message_end_element (msg);

	g_free (str);
}

void
soup_xmlrpc_message_write_boolean (SoupXmlrpcMessage *msg, gboolean b)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewChild (priv->last_node, NULL, (xmlChar *)"boolean", b ? (xmlChar *)"1" : (xmlChar *)"0");
	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_write_string (SoupXmlrpcMessage *msg, const char *str)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewTextChild (priv->last_node, NULL, (xmlChar *)"string", (xmlChar *)str);
	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_write_double (SoupXmlrpcMessage *msg, double d)
{
	SoupXmlrpcMessagePrivate *priv;
	char *str;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	str = g_strdup_printf ("%f", d);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewTextChild (priv->last_node, NULL, (xmlChar *)"double", (xmlChar *)str);
	soup_xmlrpc_message_end_element (msg);

	g_free (str);
}

void
soup_xmlrpc_message_write_datetime (SoupXmlrpcMessage *msg, const time_t timeval)
{
	SoupXmlrpcMessagePrivate *priv;
	struct tm time;
	char str[128];

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	soup_gmtime (&timeval, &time);
	strftime (str, 128, "%Y%m%dT%H:%M:%S", &time);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewTextChild (priv->last_node, NULL, (xmlChar *)"dateTime.iso8601", (xmlChar *)str);
	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_write_base64 (SoupXmlrpcMessage *msg, gconstpointer buf, int len)
{
	SoupXmlrpcMessagePrivate *priv;
	char *str;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	str = soup_base64_encode (buf, len);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	xmlNewTextChild (priv->last_node, NULL, (xmlChar *)"base64", (xmlChar *)str);
	soup_xmlrpc_message_end_element (msg);

	g_free (str);
}

void
soup_xmlrpc_message_start_struct (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"struct", NULL);
}

void
soup_xmlrpc_message_end_struct (SoupXmlrpcMessage *msg)
{
	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	soup_xmlrpc_message_end_element (msg);
	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_start_member (SoupXmlrpcMessage *msg, const char *name)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"member", NULL);
	xmlNewChild (priv->last_node, NULL, (xmlChar *)"name", (xmlChar *)name);
}

void
soup_xmlrpc_message_end_member (SoupXmlrpcMessage *msg)
{
	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	soup_xmlrpc_message_end_element (msg);
}

void
soup_xmlrpc_message_start_array (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"value", NULL);
	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"array", NULL);
	priv->last_node = xmlNewChild (priv->last_node, NULL, (xmlChar *)"data", NULL);
}

void
soup_xmlrpc_message_end_array (SoupXmlrpcMessage *msg)
{
	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));

	soup_xmlrpc_message_end_element (msg);
	soup_xmlrpc_message_end_element (msg);
	soup_xmlrpc_message_end_element (msg);
}

static void
soup_xmlrpc_message_end_element (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = priv->last_node->parent;
}

xmlChar *
soup_xmlrpc_message_to_string (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;
	xmlChar *body;
	int len;

	g_return_val_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg), NULL);
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	xmlDocDumpMemory (priv->doc, &body, &len);

	return body;
}

void
soup_xmlrpc_message_persist (SoupXmlrpcMessage *msg)
{
	SoupXmlrpcMessagePrivate *priv;
	xmlChar *body;
	int len;

	g_return_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg));
	priv = SOUP_XMLRPC_MESSAGE_GET_PRIVATE (msg);

	xmlDocDumpMemory (priv->doc, &body, &len);

	soup_message_set_request (SOUP_MESSAGE (msg), "text/xml",
				  SOUP_BUFFER_SYSTEM_OWNED, (char *)body, len);
}

SoupXmlrpcResponse *
soup_xmlrpc_message_parse_response (SoupXmlrpcMessage *msg)
{
	char *str;
	SoupXmlrpcResponse *response;

	g_return_val_if_fail (SOUP_IS_XMLRPC_MESSAGE (msg), NULL);

	str = g_malloc0 (SOUP_MESSAGE (msg)->response.length + 1);
	strncpy (str, SOUP_MESSAGE (msg)->response.body, SOUP_MESSAGE (msg)->response.length);

	response = soup_xmlrpc_response_new_from_string (str);
	g_free (str);

	return response;
}
