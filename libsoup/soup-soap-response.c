/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#include <string.h>
#include <libxml/tree.h>
#include "soup-misc.h"
#include "soup-soap-response.h"
#include "soup-types.h"

#define PARENT_TYPE G_TYPE_OBJECT

struct _SoupSoapResponsePrivate {
	xmlDocPtr xmldoc;
};

static GObjectClass *parent_class = NULL;

static void
finalize (GObject *object)
{
	SoupSoapResponse *response = SOUP_SOAP_RESPONSE (object);

	/* free memory */
	if (response->priv->xmldoc) {
		xmlFreeDoc (response->priv->xmldoc);
		response->priv->xmldoc = NULL;
	}

	g_free (response->priv);
	response->priv = NULL;

	parent_class->finalize (object);
}

static void
class_init (SoupSoapResponseClass *klass)
{
	GObjectClass *object_class;

	parent_class = g_type_class_peek_parent (klass);

	object_class = G_OBJECT_CLASS (klass);
	object_class->finalize = finalize;
}

static void
init (SoupSoapResponse *response, SoupSoapResponseClass *klass)
{
	response->priv = g_new0 (SoupSoapResponsePrivate, 1);

	response->priv->xmldoc = xmlNewDoc ("1.0");
}

SOUP_MAKE_TYPE (soup_soap_response, SoupSoapResponse, class_init, init, PARENT_TYPE)

/**
 * soup_soap_response_new:
 *
 * Create a new empty %SoupSoapResponse object, which can be modified with the
 * accessor functions provided with this class.
 *
 * Return value: the new %SoupSoapResponse (or %NULL if there was an error).
 */
SoupSoapResponse *
soup_soap_response_new (void)
{
	SoupSoapResponse *response;

	response = g_object_new (SOUP_TYPE_SOAP_RESPONSE, NULL);
	return response;
}

/**
 * soup_soap_response_new_from_string:
 * @xmlstr: the XML string to parse.
 *
 * Create a new %SoupSoapResponse object from the XML string contained in
 * @xmlstr.
 *
 * Return value: the new %SoupSoapResponse (or %NULL if there was an error).
 */
SoupSoapResponse *
soup_soap_response_new_from_string (const char *xmlstr)
{
	SoupSoapResponse *response;

	g_return_val_if_fail (xmlstr != NULL, NULL);

	response = g_object_new (SOUP_TYPE_SOAP_RESPONSE, NULL);
	if (!soup_soap_response_from_string (response, xmlstr)) {
		g_object_unref (response);
		return NULL;
	}

	return response;
}

/**
 * soup_soap_response_from_string:
 * @response: the %SoupSoapResponse object.
 * @xmlstr: XML string to parse.
 *
 * Parses the string contained in @xmlstr and sets all properties from it in the
 * @response object.
 *
 * Return value: %TRUE if successful, %FALSE otherwise.
 */
gboolean
soup_soap_response_from_string (SoupSoapResponse *response, const char *xmlstr)
{
	xmlDocPtr old_doc = NULL;

	g_return_val_if_fail (SOUP_IS_SOAP_RESPONSE (response), FALSE);
	g_return_val_if_fail (xmlstr != NULL, FALSE);

	/* clear the previous contents */
	if (response->priv->xmldoc)
		old_doc = response->priv->xmldoc;

	/* parse the string */
	response->priv->xmldoc = xmlParseMemory (xmlstr, strlen (xmlstr));
	if (!response->priv->xmldoc) {
		response->priv->xmldoc = old_doc;
		return FALSE;
	}

	xmlFreeDoc (old_doc);

	return TRUE;
}
