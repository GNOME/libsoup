/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#include <string.h>
#include "soup-misc.h"
#include "soup-soap-message.h"
#include "soup-uri.h"

G_DEFINE_TYPE (SoupSoapMessage, soup_soap_message, SOUP_TYPE_MESSAGE)

typedef struct {
	/* Serialization fields */
	xmlDocPtr doc;
	xmlNodePtr last_node;
	xmlNsPtr soap_ns;
	xmlNsPtr xsi_ns;
	xmlChar *env_prefix;
	xmlChar *env_uri;
	gboolean body_started;
	gchar *action;
} SoupSoapMessagePrivate;
#define SOUP_SOAP_MESSAGE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessagePrivate))

static void
finalize (GObject *object)
{
	SoupSoapMessagePrivate *priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (object);

	if (priv->doc) 
		xmlFreeDoc (priv->doc);
	if (priv->action)
		g_free (priv->action);
	if (priv->env_uri)
                xmlFree (priv->env_uri);
	if (priv->env_prefix)
                xmlFree (priv->env_prefix);

	G_OBJECT_CLASS (soup_soap_message_parent_class)->finalize (object);
}

static void
soup_soap_message_class_init (SoupSoapMessageClass *soup_soap_message_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (soup_soap_message_class);

	g_type_class_add_private (soup_soap_message_class, sizeof (SoupSoapMessagePrivate));

	object_class->finalize = finalize;
}

static void
soup_soap_message_init (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	/* initialize XML structures */
	priv->doc = xmlNewDoc ((const xmlChar *)"1.0");
	priv->doc->standalone = FALSE;
	priv->doc->encoding = xmlCharStrdup ("UTF-8");
}


static xmlNsPtr
fetch_ns (SoupSoapMessage *msg, const char *prefix, const char *ns_uri)
{
	SoupSoapMessagePrivate *priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);
        xmlNsPtr ns = NULL;
                                                                                
        if (prefix && ns_uri)
                ns = xmlNewNs (priv->last_node, (const xmlChar *)ns_uri, (const xmlChar *)prefix);
        else if (prefix && !ns_uri) {
                ns = xmlSearchNs (priv->doc, priv->last_node, (const xmlChar *)prefix);
                if (!ns)
			ns = xmlNewNs (priv->last_node, (const xmlChar *)"", (const xmlChar *)prefix);
        }
                                                                                
        return ns;
}

/**
 * soup_soap_message_new:
 * @method: the HTTP method for the created request.
 * @uri_string: the destination endpoint (as a string).
 * @standalone: ??? FIXME
 * @xml_encoding: ??? FIXME
 * @env_prefix: ??? FIXME
 * @env_uri: ??? FIXME
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
 * @standalone: ??? FIXME
 * @xml_encoding: ??? FIXME
 * @env_prefix: ??? FIXME
 * @env_uri: ??? FIXME
 *
 * Creates a new empty #SoupSoapMessage, which will connect to @uri
 *
 * Returns: the new #SoupSoapMessage
 */
SoupSoapMessage *
soup_soap_message_new_from_uri (const char *method, const SoupUri *uri,
				gboolean standalone, const char *xml_encoding,
				const char *env_prefix, const char *env_uri)
{
	SoupSoapMessage *msg;
	SoupSoapMessagePrivate *priv;

	msg = g_object_new (SOUP_TYPE_SOAP_MESSAGE, NULL);
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);
	SOUP_MESSAGE (msg)->method = method ? method : SOUP_METHOD_GET;
	soup_message_set_uri (SOUP_MESSAGE (msg), (const SoupUri *) uri);

	priv->doc->standalone = standalone;

	if (xml_encoding) {
		xmlFree ((xmlChar *)priv->doc->encoding);
		priv->doc->encoding = xmlCharStrdup (xml_encoding);
	}

	if (env_prefix)
		priv->env_prefix = xmlCharStrdup (env_prefix);
	if (env_uri)
		priv->env_uri = xmlCharStrdup (env_uri);

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
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = priv->doc->xmlRootNode =
		xmlNewDocNode (priv->doc, NULL, (const xmlChar *)"Envelope", NULL);

	priv->soap_ns = xmlNewNs (priv->doc->xmlRootNode,
				  priv->env_uri ? priv->env_uri :
				  (const xmlChar *)"http://schemas.xmlsoap.org/soap/envelope/",
				  priv->env_prefix ? priv->env_prefix : (const xmlChar *)"SOAP-ENV");
	if (priv->env_uri) {
		xmlFree (priv->env_uri);
		priv->env_uri = NULL;
	}
	if (priv->env_prefix) {
		xmlFree (priv->env_prefix);
		priv->env_prefix = NULL;
	}

	xmlSetNs (priv->doc->xmlRootNode, priv->soap_ns);

	xmlNewNs (priv->doc->xmlRootNode,
		  (const xmlChar *)"http://schemas.xmlsoap.org/soap/encoding/",
                  (const xmlChar *)"SOAP-ENC");
	xmlNewNs (priv->doc->xmlRootNode,
                  (const xmlChar *)"http://www.w3.org/1999/XMLSchema",
                  (const xmlChar *)"xsd");
	xmlNewNs (priv->doc->xmlRootNode,
		  (const xmlChar *)"http://schemas.xmlsoap.org/soap/envelope/",
		  (const xmlChar *)"SOAP-ENV");
	priv->xsi_ns = xmlNewNs (priv->doc->xmlRootNode,
				 (const xmlChar *)"http://www.w3.org/1999/XMLSchema-instance",
				 (const xmlChar *)"xsi");
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
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	if (priv->body_started)
		return;

	priv->last_node = xmlNewChild (priv->last_node,
				       priv->soap_ns,
				       (const xmlChar *)"Body", NULL);

	priv->body_started = TRUE;
}

/**
 * soup_soap_message_end_body:
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
 * @msg: the #SoupSoapMessage.
 * @name: the element name.
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI
 *
 * Starts a new arbitrary message element, with @name as the element
 * name, @prefix as the XML Namespace prefix, and @ns_uri as the XML
 * Namespace uri for * the created element.
 *
 * Passing @prefix with no @ns_uri will cause a recursive search for
 * an existing namespace with the same prefix. Failing that a new ns
 * will be created with an empty uri.
 *
 * Passing both @prefix and @ns_uri always causes new namespace
 * attribute creation.
 *
 * Passing NULL for both @prefix and @ns_uri causes no prefix to be
 * used, and the element will be in the default namespace.
 */
void
soup_soap_message_start_element (SoupSoapMessage *msg,
				 const char *name,
				 const char *prefix,
				 const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, NULL, (const xmlChar *)name, NULL);

	xmlSetNs (priv->last_node, fetch_ns (msg, prefix, ns_uri));

	if (priv->body_started && !priv->action)
		priv->action = g_strconcat (ns_uri ? ns_uri : "",
					    "#", name, NULL);
}

/**
 * soup_soap_message_end_element:
 * @msg: the #SoupSoapMessage.
 *
 * Closes the current message element.
 */
void
soup_soap_message_end_element (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = priv->last_node->parent;
}

/**
 * soup_soap_message_start_fault:
 * @msg: the #SoupSoapMessage.
 * @faultcode: faultcode element value
 * @faultstring: faultstring element value
 * @faultfactor: faultfactor element value
 *
 * Starts a new SOAP Fault element, creating faultcode, faultstring,
 * and faultfactor child elements.
 *
 * If you wish to add the faultdetail element, use
 * soup_soap_message_start_fault_detail(), and then
 * soup_soap_message_start_element() to add arbitrary sub-elements.
 */
void
soup_soap_message_start_fault (SoupSoapMessage *msg,
			       const char *faultcode,
			       const char *faultstring,
			       const char *faultfactor)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node,
				       priv->soap_ns,
				       (const xmlChar *)"Fault", NULL);
	xmlNewChild (priv->last_node, priv->soap_ns, (const xmlChar *)"faultcode", (const xmlChar *)faultcode);
	xmlNewChild (priv->last_node, priv->soap_ns, (const xmlChar *)"faultstring", (const xmlChar *)faultstring);

	priv->last_node = xmlNewChild (priv->last_node, priv->soap_ns,
				       (const xmlChar *)"faultfactor", (const xmlChar *)faultfactor);
	if (!faultfactor)
		soup_soap_message_set_null (msg);

	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_end_fault:
 * @msg: the #SoupSoapMessage.
 *
 * Closes the current SOAP Fault element.
 */
void
soup_soap_message_end_fault (SoupSoapMessage *msg)
{
        soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_start_fault_detail:
 * @msg: the #SoupSoapMessage.
 *
 * Start the faultdetail child element of the current SOAP Fault
 * element. The faultdetail element allows arbitrary data to be sent
 * in a returned fault.
 **/
void
soup_soap_message_start_fault_detail (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

        g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);
                                                                                
        priv->last_node = xmlNewChild (priv->last_node,
				       priv->soap_ns,
				       (const xmlChar *)"detail",
				       NULL);
}

/**
 * soup_soap_message_end_fault_detail:
 * @msg: the #SoupSoapMessage.
 *
 * Closes the current SOAP faultdetail element.
 */
void
soup_soap_message_end_fault_detail (SoupSoapMessage *msg)
{
	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_start_header:
 * @msg: the #SoupSoapMessage.
 *
 * Creates a new SOAP Header element. You can call
 * soup_soap_message_start_header_element() after this to add a new
 * header child element. SOAP Header elements allow out-of-band data
 * to be transferred while not interfering with the message body.
 *
 * This should be called after soup_soap_message_start_envelope() and
 * before soup_soap_message_start_body().
 */
void
soup_soap_message_start_header (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	priv->last_node = xmlNewChild (priv->last_node, priv->soap_ns,
				       (const xmlChar *)"Header", NULL);
}

/**
 * soup_soap_message_end_header:
 * @msg: the #SoupSoapMessage.
 *
 * Closes the current SOAP Header element.
 */
void
soup_soap_message_end_header (SoupSoapMessage *msg)
{
	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_start_header_element:
 * @msg: the #SoupSoapMessage.
 * @name: name of the header element
 * @must_understand: whether the recipient must understand the header in order
 * to proceed with processing the message
 * @actor_uri: the URI which represents the destination actor for this header.
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI
 *
 * Starts a new SOAP arbitrary header element.
 */
void
soup_soap_message_start_header_element (SoupSoapMessage *msg,
					const char *name,
					gboolean must_understand,
					const char *actor_uri,
					const char *prefix,
					const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	soup_soap_message_start_element (msg, name, prefix, ns_uri);
	if (actor_uri)
		xmlNewNsProp (priv->last_node, priv->soap_ns, (const xmlChar *)"actorUri", (const xmlChar *)actor_uri);
	if (must_understand)
		xmlNewNsProp (priv->last_node, priv->soap_ns, (const xmlChar *)"mustUnderstand", (const xmlChar *)"1");
}

/**
 * soup_soap_message_end_header_element:
 * @msg: the #SoupSoapMessage.
 *
 * Closes the current SOAP header element.
 */
void
soup_soap_message_end_header_element (SoupSoapMessage *msg)
{
	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_write_int:
 * @msg: the #SoupSoapMessage.
 * @i: the integer value to write.
 *
 * Writes the stringified value of @i as the current element's content.
 */
void
soup_soap_message_write_int (SoupSoapMessage *msg, glong i)
{
	char *str = g_strdup_printf ("%ld", i);
	soup_soap_message_write_string (msg, str);
	g_free (str);
}

/**
 * soup_soap_message_write_double:
 * @msg: the #SoupSoapMessage.
 * @d: the double value to write.
 *
 * Writes the stringified value of @d as the current element's content.
 */
void
soup_soap_message_write_double (SoupSoapMessage *msg, double d)
{
	char *str = g_strdup_printf ("%f", d);
	soup_soap_message_write_string (msg, str);
	g_free (str);
}

/**
 * soup_soap_message_write_base64:
 * @msg: the #SoupSoapMessage
 * @string: the binary data buffer to encode
 * @len: the length of data to encode
 *
 * Writes the Base-64 encoded value of @string as the current
 * element's content.
 **/
void
soup_soap_message_write_base64 (SoupSoapMessage *msg, const char *string, int len)
{
        gchar *str = g_base64_encode ((const guchar *)string, len);
        soup_soap_message_write_string (msg, str);
        g_free (str);
}

/**
 * soup_soap_message_write_time:
 * @msg: the #SoupSoapMessage.
 * @timeval: pointer to a time_t to encode
 *
 * Writes the stringified value of @timeval as the current element's
 * content.
 **/
void
soup_soap_message_write_time (SoupSoapMessage *msg, const time_t *timeval)
{
        gchar *str = g_strchomp (ctime (timeval));
        soup_soap_message_write_string (msg, str);
}

/**
 * soup_soap_message_write_string:
 * @msg: the #SoupSoapMessage.
 * @string: string to write.
 *
 * Writes the @string as the current element's content.
 */
void
soup_soap_message_write_string (SoupSoapMessage *msg, const char *string)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNodeAddContent (priv->last_node, (const xmlChar *)string);
}

/**
 * soup_soap_message_write_buffer:
 * @msg: the #SoupSoapMessage.
 * @buffer: the string data buffer to write.
 * @len: length of @buffer.
 *
 * Writes the string buffer pointed to by @buffer as the current
 * element's content.
 */
void
soup_soap_message_write_buffer (SoupSoapMessage *msg, const char *buffer, int len)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNodeAddContentLen (priv->last_node, (const xmlChar *)buffer, len);
}

/**
 * soup_soap_message_set_element_type:
 * @msg: the #SoupSoapMessage.
 * @xsi_type: the type name for the element.
 *
 * Sets the current element's XML schema xsi:type attribute, which
 * specifies the element's type name.
 */
void
soup_soap_message_set_element_type (SoupSoapMessage *msg, const char *xsi_type)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNewNsProp (priv->last_node, priv->xsi_ns, (const xmlChar *)"type", (const xmlChar *)xsi_type);
}

/**
 * soup_soap_message_set_null:
 * @msg: the #SoupSoapMessage.
 *
 * Sets the current element's XML Schema xsi:null attribute.
 */
void
soup_soap_message_set_null (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNewNsProp (priv->last_node, priv->xsi_ns, (const xmlChar *)"null", (const xmlChar *)"1");
}

/**
 * soup_soap_message_add_attribute:
 * @msg: the #SoupSoapMessage.
 * @name: name of the attribute
 * @value: value of the attribute
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI
 *
 * Adds an XML attribute to the current element.
 */
void
soup_soap_message_add_attribute (SoupSoapMessage *msg,
				 const char *name,
				 const char *value,
				 const char *prefix,
				 const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNewNsProp (priv->last_node,
		      fetch_ns (msg, prefix, ns_uri),
		      (const xmlChar *)name, (const xmlChar *)value);
}

/**
 * soup_soap_message_add_namespace:
 * @msg: the #SoupSoapMessage.
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI, or NULL for empty namespace
 *
 * Adds a new XML namespace to the current element.
 */
void
soup_soap_message_add_namespace (SoupSoapMessage *msg, const char *prefix, const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNewNs (priv->last_node, (const xmlChar *)(ns_uri ? ns_uri : ""), (const xmlChar *)prefix);
}

/**
 * soup_soap_message_set_default_namespace:
 * @msg: the #SoupSoapMessage.
 * @ns_uri: the namespace URI.
 *
 * Sets the default namespace to the URI specified in @ns_uri. The
 * default namespace becomes the namespace all non-explicitly
 * namespaced child elements fall into.
 */
void
soup_soap_message_set_default_namespace (SoupSoapMessage *msg, const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	soup_soap_message_add_namespace (msg, NULL, ns_uri);
}

/**
 * soup_soap_message_set_encoding_style:
 * @msg: the #SoupSoapMessage.
 * @enc_style: the new encodingStyle value
 *
 * Sets the encodingStyle attribute on the current element to the
 * value of @enc_style.
 */
void
soup_soap_message_set_encoding_style (SoupSoapMessage *msg, const char *enc_style)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlNewNsProp (priv->last_node, priv->soap_ns, (const xmlChar *)"encodingStyle", (const xmlChar *)enc_style);
}

/**
 * soup_soap_message_reset:
 * @msg: the #SoupSoapMessage.
 *
 * Resets the internal XML representation of the SOAP message.
 */
void
soup_soap_message_reset (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlFreeDoc (priv->doc);
	priv->doc = xmlNewDoc ((const xmlChar *)"1.0");
	priv->last_node = NULL;

	g_free (priv->action);
	priv->action = NULL;
	priv->body_started = FALSE;

	if (priv->env_uri)
		xmlFree (priv->env_uri);
	priv->env_uri = NULL;

	if (priv->env_prefix)
		xmlFree (priv->env_prefix);
	priv->env_prefix = NULL;
}

/**
 * soup_soap_message_persist:
 * @msg: the #SoupSoapMessage.
 *
 * Writes the serialized XML tree to the #SoupMessage's buffer.
 */
void
soup_soap_message_persist (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;
	xmlChar *body;
	int len;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlDocDumpMemory (priv->doc, &body, &len);

	/* serialize to SoupMessage class */
	soup_message_set_request (SOUP_MESSAGE (msg), "text/xml",
				  SOUP_BUFFER_SYSTEM_OWNED, (char *)body, len);
}

/**
 * soup_soap_message_get_namespace_prefix:
 * @msg: the #SoupSoapMessage.
 * @ns_uri: the namespace URI.
 *
 * Returns the namespace prefix for @ns_uri (or an empty string if
 * @ns_uri is set to the default namespace)
 *
 * Return value: The namespace prefix, or %NULL if no namespace exists
 * for the URI given.
 */
const char *
soup_soap_message_get_namespace_prefix (SoupSoapMessage *msg, const char *ns_uri)
{
	SoupSoapMessagePrivate *priv;
	xmlNsPtr ns = NULL;

	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);
	g_return_val_if_fail (ns_uri != NULL, NULL);

	ns = xmlSearchNsByHref (priv->doc, priv->last_node, (const xmlChar *)ns_uri);
	if (ns) {
		if (ns->prefix)
			return (const char *)ns->prefix;
		else
			return "";
	}

	return NULL;
}

/**
 * soup_soap_message_get_xml_doc:
 * @msg: the #SoupSoapMessage.
 *
 * Returns the internal XML representation tree of the
 * #SoupSoapMessage pointed to by @msg.
 *
 * Return value: the #xmlDocPtr representing the SOAP message.
 */
xmlDocPtr
soup_soap_message_get_xml_doc (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;

	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	return priv->doc;
}

/**
 * soup_soap_message_parse_response:
 * @msg: the #SoupSoapMessage.
 *
 * Parses the response returned by the server.
 *
 * Return value: a #SoupSoapResponse representing the response from
 * the server, or %NULL if there was an error.
 */
SoupSoapResponse *
soup_soap_message_parse_response (SoupSoapMessage *msg)
{
	SoupSoapMessagePrivate *priv;
	char *xmlstr;
	SoupSoapResponse *soap_response;

	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);
	priv = SOUP_SOAP_MESSAGE_GET_PRIVATE (msg);

	xmlstr = g_malloc0 (SOUP_MESSAGE (msg)->response.length + 1);
	strncpy (xmlstr, SOUP_MESSAGE (msg)->response.body, SOUP_MESSAGE (msg)->response.length);

	soap_response = soup_soap_response_new_from_string (xmlstr);
	g_free (xmlstr);

	return soap_response;
}
