/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#include <string.h>
#include "soup-misc.h"
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
                if (!ns)
			ns = xmlNewNs (msg->priv->last_node, "", prefix);
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
	xmlNewNs (msg->priv->doc->xmlRootNode,
		  "http://schemas.xmlsoap.org/soap/envelope/",
		  "SOAP-ENV");
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
 * soup_soap_message_start_fault:
 * @msg: the %SoupSoapMessage.
 * @faultcode: faultcode element value
 * @faultstring: faultstring element value
 * @faultactor: faultactor element value
 *
 * Starts a new SOAP Fault element, creating faultcode, faultstring, and
 * faultactor child elements.
 *
 * If you wish to add the faultdetail element, use
 * %soup_soap_message_start_fault_detail, and then %soup_soap_message_start_element
 * to add arbitrary sub-elements.
 */
void
soup_soap_message_start_fault (SoupSoapMessage *msg,
			       const char *faultcode,
			       const char *faultstring,
			       const char *faultfactor)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	msg->priv->last_node = xmlNewChild (msg->priv->last_node,
					    msg->priv->soap_ns,
					    "Fault", NULL);
	xmlNewChild (msg->priv->last_node, msg->priv->soap_ns, "faultcode", faultcode);
	xmlNewChild (msg->priv->last_node, msg->priv->soap_ns, "faultstring", faultstring);

	msg->priv->last_node = xmlNewChild (msg->priv->last_node, msg->priv->soap_ns,
					    "faultfactor", faultfactor);
	if (!faultfactor)
		soup_soap_message_set_null (msg);

	soup_soap_message_end_element (msg);
}

/**
 * soup_soap_message_end_fault:
 * @msg: the %SoupSoapMessage.
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
 * @msg: the %SoupSoapMessage.
 *
 * Start the faultdetail child element of the current SOAP Fault element. The
 * faultdetail element allows arbitrary data to be sent in a returned fault.
 **/
void
soup_soap_message_start_fault_detail (SoupSoapMessage *msg)
{
        g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));
                                                                                
        msg->priv->last_node = xmlNewChild (msg->priv->last_node,
					    msg->priv->soap_ns,
					    "detail",
					    NULL);
}

/**
 * soup_soap_message_end_fault_detail:
 * @msg: the %SoupSoapMessage.
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
 * @msg: the %SoupSoapMessage.
 *
 * Creates a new SOAP Header element. You can call
 * %soup_soap_message_start_header_element after this to add a new header child
 * element. SOAP Header elements allow out-of-band data to be transferred while
 * not interfering with the message body.
 *
 * This should be called after %soup_soap_message_start_envelope and before
 * %soup_soap_message_start_body.
 */
void
soup_soap_message_start_header (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	msg->priv->last_node = xmlNewChild (msg->priv->last_node, msg->priv->soap_ns,
					    "Header", NULL);
}

/**
 * soup_soap_message_end_header:
 * @msg: the %SoupSoapMessage.
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
 * @msg: the %SoupSoapMessage.
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
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	soup_soap_message_start_element (msg, name, prefix, ns_uri);
	if (actor_uri)
		xmlNewNsProp (msg->priv->last_node, msg->priv->soap_ns, "actorUri", actor_uri);
	if (must_understand)
		xmlNewNsProp (msg->priv->last_node, msg->priv->soap_ns, "mustUnderstand", "1");
}

/**
 * soup_soap_message_end_header_element:
 * @msg: the %SoupSoapMessage.
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
 * @msg: the %SoupSoapMessage.
 * @i: the integer value to write.
 *
 * Writes the stringified value if @i as the current element's content.
 */
void
soup_soap_message_write_int (SoupSoapMessage *msg, long i)
{
	char *str = g_strdup_printf ("%ld", i);
	soup_soap_message_write_string (msg, str);
	g_free (str);
}

/**
 * soup_soap_message_write_double:
 * @msg: the %SoupSoapMessage.
 * @d: the double value to write.
 *
 * Writes the stringified value if @d as the current element's content.
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
 * @msg: the %SoupSoapMessage
 * @string: the binary data buffer to encode
 * @len: the length of data to encode
 *
 * Writes the Base-64 encoded value of @string as the current element's content. **/
void
soup_soap_message_write_base64 (SoupSoapMessage *msg, const char *string, int len)
{
        gchar *str = soup_base64_encode (string, len);
        soup_soap_message_write_string (msg, str);
        g_free (str);
}

/**
 * soup_soap_message_write_time:
 * @msg: the %SoupSoapMessage.
 * @timeval: pointer to a time_t to encode
 *
 * Writes the stringified value of @timeval as the current element's content.
 **/
void
soup_soap_message_write_time (SoupSoapMessage *msg, const time_t *timeval)
{
        gchar *str = g_strchomp (ctime (timeval));
        soup_soap_message_write_string (msg, str);
}

/**
 * soup_soap_message_write_string:
 * @msg: the %SoupSoapMessage.
 * @string: string to write.
 *
 * Writes the @string as the current element's content.
 */
void
soup_soap_message_write_string (SoupSoapMessage *msg, const char *string)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNodeAddContent (msg->priv->last_node, string);
}

/**
 * soup_soap_message_write_buffer:
 * @msg: the %SoupSoapMessage.
 * @buffer: the string data buffer to write.
 * @len: length of @buffer.
 *
 * Writes the string buffer pointed to by @buffer as the current element's content.
 */
void
soup_soap_message_write_buffer (SoupSoapMessage *msg, const char *buffer, int len)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNodeAddContentLen (msg->priv->last_node, buffer, len);
}

/**
 * soup_soap_message_set_element_type:
 * @msg: the %SoupSoapMessage.
 * @xsi_type: the type name for the element.
 *
 * Sets the current element's XML schema xsi:type attribute, which specifies
 * the element's type name.
 */
void
soup_soap_message_set_element_type (SoupSoapMessage *msg, const char *xsi_type)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNewNsProp (msg->priv->last_node, msg->priv->xsi_ns, "type", xsi_type);
}

/**
 * soup_soap_message_set_null:
 * @msg: the %SoupSoapMessage.
 *
 * Sets the current element's XML Schema xsi:null attribute.
 */
void
soup_soap_message_set_null (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNewNsProp (msg->priv->last_node, msg->priv->xsi_ns, "null", "1");
}

/**
 * soup_soap_message_add_attribute:
 * @msg: the %SoupSoapMessage.
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
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNewNsProp (msg->priv->last_node,
		      fetch_ns (msg, prefix, ns_uri),
		      name, value);
}

/**
 * soup_soap_message_add_namespace:
 * @msg: the %SoupSoapMessage.
 * @prefix: the namespace prefix
 * @ns_uri: the namespace URI, or NULL for empty namespace
 *
 * Adds a new XML namespace to the current element.
 */
void
soup_soap_message_add_namespace (SoupSoapMessage *msg, const char *prefix, const char *ns_uri)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNewNs (msg->priv->last_node, ns_uri ? ns_uri : "", prefix);
}

/**
 * soup_soap_set_default_namespace:
 * @msg: the %SoupSoapMessage.
 * @ns_uri: the namespace URI.
 *
 * Sets the default namespace to the URI specified in @ns_uri. The default
 * namespace becomes the namespace all non-explicitly namespaced child elements
 * fall into.
 */
void
soup_soap_message_set_default_namespace (SoupSoapMessage *msg, const char *ns_uri)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	soup_soap_message_add_namespace (msg, NULL, ns_uri);
}

/**
 * soup_soap_message_set_encoding_style:
 * @msg: the %SoupSoapMessage.
 * @enc_style: the new encodingStyle value
 *
 * Sets the encodingStyle attribute on the current element to the value of
 * @enc_style.
 */
void
soup_soap_message_set_encoding_style (SoupSoapMessage *msg, const char *enc_style)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlNewNsProp (msg->priv->last_node, msg->priv->soap_ns, "encodingStyle", enc_style);
}

/**
 * soup_soap_message_reset:
 * @msg: the %SoupSoapMessage.
 *
 * Resets the internal XML representation of the SOAP message.
 */
void
soup_soap_message_reset (SoupSoapMessage *msg)
{
	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlFreeDoc (msg->priv->doc);
	msg->priv->doc = xmlNewDoc ("1.0");
	msg->priv->last_node = NULL;

	g_free (msg->priv->action);
	msg->priv->action = NULL;
	msg->priv->body_started = FALSE;

	if (msg->priv->env_uri)
		g_free (msg->priv->env_uri);
	msg->priv->env_uri = NULL;

	if (msg->priv->env_prefix)
		g_free (msg->priv->env_prefix);
	msg->priv->env_prefix = NULL;
}

/**
 * soup_soap_message_persist:
 * @msg: the %SoupSoapMessage.
 *
 * Writes the serialized XML tree to the %SoupMessage's buffer.
 */
void
soup_soap_message_persist (SoupSoapMessage *msg)
{
	char *body;
	unsigned int len;

	g_return_if_fail (SOUP_IS_SOAP_MESSAGE (msg));

	xmlDocDumpMemory (msg->priv->doc, (xmlChar **) &body, &len);

	/* serialize to SoupMessage class */
	soup_message_set_request (SOUP_MESSAGE (msg), "text/xml",
				  SOUP_BUFFER_SYSTEM_OWNED, body, len);
#ifdef G_ENABLE_DEBUG
	g_message ("SOAP message: %s", body);
#endif
}

/**
 * soup_soap_message_get_namespace_prefix:
 * @msg: the %SoupSoapMessage.
 * @ns_uri: the namespace URI.
 *
 * Return value: The namespace prefix for @ns_uri or an empty string if @ns_uri
 * is set to the default namespace. If no namespace exists for the URI given,
 * NULL is returned.
 */
const char *
soup_soap_message_get_namespace_prefix (SoupSoapMessage *msg, const char *ns_uri)
{
	xmlNsPtr ns = NULL;

	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);
	g_return_val_if_fail (ns_uri != NULL, NULL);

	ns = xmlSearchNsByHref (msg->priv->doc, msg->priv->last_node, ns_uri);
	if (ns) {
		if (ns->prefix)
			return ns->prefix;
		else
			return "";
	}

	return NULL;
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

/**
 * soup_soap_message_parse_response:
 * @msg: the %SoupSoapMessage.
 *
 * Parses the response returned by the server.
 *
 * Return value: a %SoupSoapResponse representing the response from the server,
 * or %NULL if there was an error.
 */
SoupSoapResponse *
soup_soap_message_parse_response (SoupSoapMessage *msg)
{
	char *xmlstr;
	SoupSoapResponse *soap_response;

	g_return_val_if_fail (SOUP_IS_SOAP_MESSAGE (msg), NULL);

	xmlstr = g_malloc0 (SOUP_MESSAGE (msg)->response.length + 1);
	strncpy (xmlstr, SOUP_MESSAGE (msg)->response.body, SOUP_MESSAGE (msg)->response.length);

#ifdef G_ENABLE_DEBUG
	g_message ("SOAP response: %s", xmlstr);
#endif

	soap_response = soup_soap_response_new_from_string (xmlstr);
	g_free (xmlstr);

	return soap_response;
}
