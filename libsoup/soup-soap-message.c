/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#include "soup-soap-message.h"
#include "soup-uri.h"

#define PARENT_TYPE SOUP_TYPE_MESSAGE

struct _SoupSoapMessagePrivate {
	/* Serialization fields */
	xmlDocPtr doc;
	xmlNodePtr last_node;
	xmlNsPtr soap_ns;
	xmlNsPtr xsi_ns;
	gchar *env_prefix;
	gchar *env_uri;
	gboolean body_started;
	gchar *action;
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

	/* initialize XML structures */
	msg->priv->doc = xmlNewDoc ("1.0");
	msg->priv->doc->standalone = FALSE;
	msg->priv->doc->encoding = g_strdup ("UTF-8");
}

SOUP_MAKE_TYPE (soup_soap_message, SoupSoapMessage, class_init, init, PARENT_TYPE)

static xmlNsPtr
fetch_ns (SoupSoapMessage *msg, const char *prefix, const char *ns_uri)
{
        xmlNsPtr ns = NULL;
                                                                                
        if (prefix && ns_uri)
                ns = xmlNewNs (msg->priv->last_node, ns_uri, prefix);
        else if (prefix && !ns_uri) {
                ns = xmlSearchNs (msg->priv->doc, msg->priv->last_node, prefix);
                if (!ns) ns = xmlNewNs (msg->priv->last_node, "", prefix);
        }
                                                                                
        return ns;
}

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
soup_soap_message_new (const char *method, const char *uri_string,
		       gboolean standalone, const char *xml_encoding,
		       const char *env_prefix, const char *env_uri)
{
	SoupSoapMessage *msg;
	SoupUri *uri;

	uri = soup_uri_new (uri_string);
	if (!uri)
		return NULL;

	msg = soup_soap_message_new_from_uri (method, uri, standalone,
					      xml_encoding, env_prefix, env_uri);

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
soup_soap_message_new_from_uri (const char *method, const SoupUri *uri,
				gboolean standalone, const char *xml_encoding,
				const char *env_prefix, const char *env_uri)
{
	SoupSoapMessage *msg;

	msg = g_object_new (SOUP_TYPE_SOAP_MESSAGE, NULL);
	SOUP_MESSAGE (msg)->method = method ? method : SOUP_METHOD_GET;
	soup_message_set_uri (SOUP_MESSAGE (msg), (const SoupUri *) uri);

	msg->priv->doc->standalone = standalone;

	if (xml_encoding) {
		g_free ((char *) msg->priv->doc->encoding);
		msg->priv->doc->encoding = g_strdup (xml_encoding);
	}

	if (env_prefix || env_uri) {
		msg->priv->env_prefix = g_strdup (env_prefix);
		msg->priv->env_uri = g_strdup (env_uri);
	}

	return msg;
}

/**
 * soup_soap_message_start_envelope:
 * @msg: the %SoupSoapMessage.
 *
 * Starts the top level SOAP Envelope element.
 */
void
soup_soap_message_start_envelope (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	msg->priv->last_node = msg->priv->doc->xmlRootNode =
		xmlNewDocNode (msg->priv->doc, NULL, "Envelope", NULL);

	msg->priv->soap_ns = xmlNewNs (msg->priv->doc->xmlRootNode,
				       msg->priv->env_uri ? msg->priv->env_uri :
				       "http://schemas.xmlsoap.org/soap/envelope/",
				       msg->priv->env_prefix ? msg->priv->env_prefix : "SOAP-ENV");
	if (msg->priv->env_uri) {
		g_free (msg->priv->env_uri);
		msg->priv->env_uri = NULL;
	}
	if (msg->priv->env_prefix) {
		g_free (msg->priv->env_prefix);
		msg->priv->env_prefix = NULL;
	}

	xmlSetNs (msg->priv->doc->xmlRootNode, msg->priv->soap_ns);

	xmlNewNs (msg->priv->doc->xmlRootNode,
		  "http://schemas.xmlsoap.org/soap/encoding/",
                  "SOAP-ENC");
	xmlNewNs (msg->priv->doc->xmlRootNode,
                  "http://www.w3.org/1999/XMLSchema",
                  "xsd");
	msg->priv->xsi_ns = xmlNewNs (msg->priv->doc->xmlRootNode,
				      "http://www.w3.org/1999/XMLSchema-instance",
				      "xsi");
}

/**
 * soup_soap_message_end_envelope:
 * @msg: the %SoupSoapMessage.
 *
 * Closes the top level SOAP Envelope element.
 */
void
soup_soap_message_end_envelope (SoupSoapMessage *msg)
{
	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_start_body:
 * @msg: the %SoupSoapMessage.
 *
 * Starts the SOAP Body element.
 */
void
soup_soap_message_start_body (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	if (msg->priv->body_started)
		return;

	msg->priv->last_node = xmlNewChild (msg->priv->last_node,
					    msg->priv->soap_ns,
					    "Body", NULL);

	msg->priv->body_started = TRUE;
}

/**
 * soup_soap_end_body:
 * @msg: the %SoupSoapMessage.
 *
 * Closes the SOAP Body element.
 */
void
soup_soap_message_end_body (SoupSoapMessage *msg)
{
	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_start_element:
 * @msg: the %SoupSoapMessage.
 * @name: the element name.
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI
 *
 * Starts a new arbitrary message element, with @name as the element name,
 * @prefix as the XML Namespace prefix, and @ns_uri as the XML Namespace uri for * the created element.
 *
 * Passing @prefix with no @ns_uri will cause a recursive search for an
 * existing namespace with the same prefix. Failing that a new ns will be
 * created with an empty uri.
 *
 * Passing both @prefix and @ns_uri always causes new namespace attribute
 * creation.
 *
 * Passing NULL for both @prefix and @ns_uri causes no prefix to be used, and
 * the element will be in the default namespace.
 */
void
soup_soap_message_start_element (SoupSoapMessage *msg,
				 const char *name,
				 const char *prefix,
				 const char *ns_uri)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	msg->priv->last_node = xmlNewChild (msg->priv->last_node, NULL, name, NULL);

	xmlSetNs (msg->priv->last_node, fetch_ns (msg, prefix, ns_uri));

	if (msg->priv->body_started && !msg->priv->action)
		msg->priv->action = g_strconcat (ns_uri ? ns_uri : "",
						 "#", name, NULL);
}

/**
 * soup_soap_message_end_element:
 * @msg: the %SoupSoapMessage.
 *
 * Closes the current message element.
 */
void
soup_soap_message_end_element (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	msg->priv->last_node = msg->priv->last_node->parent;
}

/**
 * soup_soap_message_get_xml_doc:
 * @msg: the %SoupSoapMessage.
 *
 * Returns the internal XML representation tree of the %SoupSoapMessage pointed
 * to by @msg.
 *
 * Return value: the xmlDocPtr representing the SOAP message.
 */
xmlDocPtr
soup_soap_message_get_xml_doc (SoupSoapMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);

	return msg->priv->doc;
}
