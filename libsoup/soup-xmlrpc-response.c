/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-xmlrpc-response.c: XMLRPC response message
 *
 * Copyright (C) 2003, Novell, Inc.
 * Copyright (C) 2004, Mariano Suarez-Alvarez <mariano@gnome.org>
 * Copyright (C) 2004, Fernando Herrera  <fherrera@onirica.com>
 * Copyright (C) 2005, Jeff Bailey  <jbailey@ubuntu.com>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <libxml/tree.h>

#include "soup-date.h"
#include "soup-misc.h"
#include "soup-xmlrpc-response.h"


G_DEFINE_TYPE (SoupXmlrpcResponse, soup_xmlrpc_response, G_TYPE_OBJECT)

typedef struct {
	xmlDocPtr doc;
	gboolean fault;
	xmlNodePtr value;
} SoupXmlrpcResponsePrivate;
#define SOUP_XMLRPC_RESPONSE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SOUP_TYPE_XMLRPC_RESPONSE, SoupXmlrpcResponsePrivate))

static void
finalize (GObject *object)
{
	SoupXmlrpcResponsePrivate *priv = SOUP_XMLRPC_RESPONSE_GET_PRIVATE (object);

	if (priv->doc)
		xmlFreeDoc (priv->doc);

	G_OBJECT_CLASS (soup_xmlrpc_response_parent_class)->finalize (object);
}

static void
soup_xmlrpc_response_class_init (SoupXmlrpcResponseClass *soup_xmlrpc_response_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (soup_xmlrpc_response_class);

	g_type_class_add_private (soup_xmlrpc_response_class, sizeof (SoupXmlrpcResponsePrivate));

	object_class->finalize = finalize;
}

static void
soup_xmlrpc_response_init (SoupXmlrpcResponse *response)
{
	SoupXmlrpcResponsePrivate *priv = SOUP_XMLRPC_RESPONSE_GET_PRIVATE (response);

	priv->doc = xmlNewDoc ("1.0");
	priv->fault = FALSE;
}


SoupXmlrpcResponse *
soup_xmlrpc_response_new (void)
{
	SoupXmlrpcResponse *response;

	response = g_object_new (SOUP_TYPE_XMLRPC_RESPONSE, NULL);
	return response;
}

SoupXmlrpcResponse *
soup_xmlrpc_response_new_from_string (const char *xmlstr)
{
	SoupXmlrpcResponse *response;

	g_return_val_if_fail (xmlstr != NULL, NULL);

	response = g_object_new (SOUP_TYPE_XMLRPC_RESPONSE, NULL);

	if (!soup_xmlrpc_response_from_string (response, xmlstr)) {
		g_object_unref (response);
		return NULL;
	}

	return response;
}

static xmlNode *
exactly_one_child (xmlNode *node)
{
	xmlNode *child, *tmp;

	tmp = node->children;
	while (tmp && xmlIsBlankNode (tmp))
		tmp = tmp->next;

	child = tmp;
	if (tmp && tmp->next) {
		tmp = tmp->next;
		while (tmp && xmlIsBlankNode (tmp))
			tmp = tmp->next;
		if (tmp)
			return NULL;
	}

	return child;
}

gboolean
soup_xmlrpc_response_from_string (SoupXmlrpcResponse *response, const char *xmlstr)
{
	SoupXmlrpcResponsePrivate *priv;
	xmlDocPtr newdoc;
	xmlNodePtr body;
	gboolean fault = TRUE;

	g_return_val_if_fail (SOUP_IS_XMLRPC_RESPONSE (response), FALSE);
	priv = SOUP_XMLRPC_RESPONSE_GET_PRIVATE (response);
	g_return_val_if_fail (xmlstr != NULL, FALSE);

	xmlKeepBlanksDefault (0);
	newdoc = xmlParseMemory (xmlstr, strlen (xmlstr));
	if (!newdoc)
		goto very_bad;

	body = xmlDocGetRootElement (newdoc);
	if (!body || strcmp (body->name, "methodResponse"))
		goto bad;

	body = exactly_one_child (body);
	if (!body)
		goto bad;

	if (strcmp (body->name, "params") == 0) {
		fault = FALSE;
		body = exactly_one_child (body);
		if (!body || strcmp (body->name, "param"))
			goto bad;
	} else if (strcmp (body->name, "fault") != 0)
		goto bad;

	body = exactly_one_child (body);
	if (!body || strcmp (body->name, "value"))
		goto bad;

	/* body should be pointing by now to the struct of a fault, or the value of a
	 * normal response
	 */

	xmlFreeDoc (priv->doc);
	priv->doc = newdoc;
	priv->value = body;

	return TRUE;

bad:
	xmlFreeDoc (newdoc);
very_bad:
	return FALSE;
}

xmlChar *
soup_xmlrpc_response_to_string (SoupXmlrpcResponse *response)
{
	SoupXmlrpcResponsePrivate *priv;
	xmlChar *str;
	int size;

	g_return_val_if_fail (SOUP_IS_XMLRPC_RESPONSE (response), FALSE);
	priv = SOUP_XMLRPC_RESPONSE_GET_PRIVATE (response);

	xmlDocDumpMemoryEnc (priv->doc, &str, &size, "UTF-8");

	return str;
}

SoupXmlrpcValue *
soup_xmlrpc_response_get_value (SoupXmlrpcResponse *response)
{
	SoupXmlrpcResponsePrivate *priv;
	g_return_val_if_fail (SOUP_IS_XMLRPC_RESPONSE (response), FALSE);
	priv = SOUP_XMLRPC_RESPONSE_GET_PRIVATE (response);

	return (SoupXmlrpcValue*) priv->value;
}

SoupXmlrpcValueType
soup_xmlrpc_value_get_type (SoupXmlrpcValue *value)
{
	xmlNode *xml;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return SOUP_XMLRPC_VALUE_TYPE_BAD;

	xml = exactly_one_child (xml);
	if (!xml)
		return SOUP_XMLRPC_VALUE_TYPE_BAD;

	if (strcmp (xml->name, "i4") == 0 || strcmp (xml->name, "int") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_INT;
	else if (strcmp (xml->name, "boolean") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_BOOLEAN;
	else if (strcmp (xml->name, "string") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_STRING;
	else if (strcmp (xml->name, "double") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_DOUBLE;
	else if (strcmp (xml->name, "dateTime.iso8601") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_DATETIME;
	else if (strcmp (xml->name, "base64") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_BASE64;
	else if (strcmp (xml->name, "struct") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_STRUCT;
	else if (strcmp (xml->name, "array") == 0)
		return SOUP_XMLRPC_VALUE_TYPE_ARRAY;
	else
		return SOUP_XMLRPC_VALUE_TYPE_BAD;
}

gboolean
soup_xmlrpc_value_get_int (SoupXmlrpcValue *value, long *i)
{
	xmlNode *xml;
	xmlChar *content;
	char *tail;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || (strcmp (xml->name, "int") && strcmp (xml->name, "i4")))
		return FALSE;

	/* FIXME this should be exactly one text node */
	content = xmlNodeGetContent (xml);
	*i = strtol (BAD_CAST (content), &tail, 10);
	xmlFree (content);

	if (tail != '\0')
		return FALSE;
	else
		return TRUE;
}

gboolean
soup_xmlrpc_value_get_double (SoupXmlrpcValue *value, double *b)
{
	xmlNode *xml;
	xmlChar *content;
	char *tail;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || (strcmp (xml->name, "double")))
		return FALSE;

	/* FIXME this should be exactly one text node */
	content = xmlNodeGetContent (xml);
	*b = g_ascii_strtod (BAD_CAST (content), &tail);
	xmlFree (content);

	if (tail != '\0')
		return FALSE;
	else
		return TRUE;
}

gboolean
soup_xmlrpc_value_get_boolean (SoupXmlrpcValue *value, gboolean *b)
{
	xmlNode *xml;
	xmlChar *content;
	char *tail;
	int i;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || strcmp (xml->name, "boolean"))
		return FALSE;

	content = xmlNodeGetContent (xml);
	i = strtol (BAD_CAST (content), &tail, 10);
	xmlFree (content);

	if (tail != '\0')
		return FALSE;

	if (i != 0 && i != 1)
		return FALSE;
	return i == 1;
}

gboolean
soup_xmlrpc_value_get_string (SoupXmlrpcValue *value, char **str)
{
	xmlNode *xml;
	xmlChar *content;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || strcmp (xml->name, "string"))
		return FALSE;

	content = xmlNodeGetContent (xml);
	*str = content ? g_strdup (content) : g_strdup ("");
	xmlFree (content);

	return TRUE;
}

gboolean
soup_xmlrpc_value_get_datetime (SoupXmlrpcValue *value, time_t *timeval)
{
	xmlNode *xml;
	xmlChar *content;
	char *ptr;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || (strcmp (xml->name, "dateTime.iso8601")))
		return FALSE;

	/* FIXME this should be exactly one text node */
	content = xmlNodeGetContent (xml);
	ptr = BAD_CAST (content);
	if (strlen (ptr) != 17) {
		xmlFree (content);
		return FALSE;
	}

	*timeval = soup_date_iso8601_parse (ptr);
	xmlFree (content);
	return TRUE;
}

gboolean
soup_xmlrpc_value_get_base64 (SoupXmlrpcValue *value, char **buf)
{
	xmlNode *xml;
	xmlChar *content;
	char *ret;
	int inlen, state = 0, save = 0;


	xml = (xmlNode *) value;
	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml || strcmp (xml->name, "base64"))
		return FALSE;

	content = xmlNodeGetContent (xml);

	/* FIXME If we can decode it, is it a valid base64? */
	inlen = strlen (content);
	ret = g_malloc0 (inlen);
	soup_base64_decode_step (content, inlen, ret, &state, &save);
	g_free (ret);
	if (state != 0)
		return FALSE;

	*buf = content ? g_strdup (content) : g_strdup ("");
	xmlFree (content);

	return TRUE;
}


gboolean
soup_xmlrpc_value_get_struct (SoupXmlrpcValue *value, GHashTable **table)
{
	xmlNode *xml;
	GHashTable *t;

	xml = (xmlNode *) value;

	if (strcmp (xml->name, "value"))
		return FALSE;
	xml = exactly_one_child (xml);

	if (!xml || strcmp (xml->name, "struct"))
		return FALSE;

	t = g_hash_table_new_full (g_str_hash, g_str_equal, xmlFree, NULL);

	for (xml = xml->children; xml; xml = xml->next) {
		xmlChar *name;
		xmlNode *val, *cur;

		if (strcmp (xml->name, "member") || !xml->children)
			goto bad;

		name = NULL;
		val = NULL;

		for (cur = xml->children; cur; cur = cur->next) {
			if (strcmp(cur->name, "name") == 0) {
				if (name)
					goto local_bad;
				name = xmlNodeGetContent (cur);
			}
			else if (strcmp (cur->name, "value") == 0)
				val = cur;
			else goto local_bad;

			continue;
local_bad:
			if (name) xmlFree (name);
			goto bad;
		}

		if (!name || !val) {
			if (name) xmlFree (name);
			goto bad;
		}
		g_hash_table_insert (t, name, val);
	}

	*table = t;
	return TRUE;

bad:
	g_hash_table_destroy (t);
	return FALSE;
}

gboolean
soup_xmlrpc_value_array_get_iterator (SoupXmlrpcValue *value, SoupXmlrpcValueArrayIterator **iter)
{
	xmlNode *xml;

	xml = (xmlNode *) value;

	if (!xml->children || strcmp(xml->children->name, "data") == 0 || xml->children->next)
		return FALSE;

	*iter = (SoupXmlrpcValueArrayIterator *) xml->children;

	return TRUE;
}


SoupXmlrpcValueArrayIterator *
soup_xmlrpc_value_array_iterator_prev (SoupXmlrpcValueArrayIterator *iter)
{
	xmlNode *xml;

	xml = (xmlNode *) iter;

	return (SoupXmlrpcValueArrayIterator *) xml->prev;
}

SoupXmlrpcValueArrayIterator *
soup_xmlrpc_value_array_iterator_next (SoupXmlrpcValueArrayIterator *iter)
{
	xmlNode *xml;

	xml = (xmlNode *) iter;

	return (SoupXmlrpcValueArrayIterator *) xml->next;
}

gboolean
soup_xmlrpc_value_array_iterator_get_value (SoupXmlrpcValueArrayIterator *iter,
					    SoupXmlrpcValue **value)
{
	xmlNode *xml;

	xml = (xmlNode *) iter;

	if (!xml || strcmp(xml->name, "data"))
		return FALSE;
	xml = exactly_one_child (xml);
	if (!xml)
		return FALSE;

	*value = (SoupXmlrpcValue *) xml;

	return TRUE;
}

static void
indent (int d)
{
	while (d--)
		g_printerr (" ");
}

static void
soup_xmlrpc_value_dump_internal (SoupXmlrpcValue *value, int d);

static void
soup_xmlrpc_value_dump_struct_member (const char *name, SoupXmlrpcValue *value, gpointer d)
{
	indent (GPOINTER_TO_INT (d));
	g_printerr ("MEMBER: %s\n", name);
	soup_xmlrpc_value_dump_internal (value, GPOINTER_TO_INT (d));
}

static void
soup_xmlrpc_value_dump_array_element (const int i, SoupXmlrpcValue *value, gpointer d)
{
	indent (GPOINTER_TO_INT (d));
	g_printerr ("ELEMENT: %d\n", i);
	soup_xmlrpc_value_dump_internal (value, GPOINTER_TO_INT (d));
}

static void
soup_xmlrpc_value_dump_internal (SoupXmlrpcValue *value, int d)
{
	long i;
	gboolean b;
	char *str;
	double f;
	time_t timeval;
	GHashTable *hash;
	SoupXmlrpcValueArrayIterator *iter;

	g_printerr ("\n\n[%s]\n", ((xmlNode*)value)->name);
	switch (soup_xmlrpc_value_get_type (value)) {

		case SOUP_XMLRPC_VALUE_TYPE_BAD:
			indent (d);
			g_printerr ("BAD\n");
			break;

		case SOUP_XMLRPC_VALUE_TYPE_INT:
			indent (d);
			if (!soup_xmlrpc_value_get_int (value, &i))
				g_printerr ("BAD INT\n");
			else
				g_printerr ("INT: %ld\n", i);
			break;

		case SOUP_XMLRPC_VALUE_TYPE_BOOLEAN:
			indent (d);
			if (!soup_xmlrpc_value_get_boolean (value, &b))
				g_printerr ("BAD BOOLEAN\n");
			else
				g_printerr ("BOOLEAN: %s\n", b ? "true" : "false");
			break;

		case SOUP_XMLRPC_VALUE_TYPE_STRING:
			indent (d);
			if (!soup_xmlrpc_value_get_string (value, &str))
				g_printerr ("BAD STRING\n");
			else {
				g_printerr ("STRING: \"%s\"\n", str);
				g_free (str);
			}
			break;

		case SOUP_XMLRPC_VALUE_TYPE_DOUBLE:
			indent (d);
			if (!soup_xmlrpc_value_get_double (value, &f))
				g_printerr ("BAD DOUBLE\n");
			else
				g_printerr ("DOUBLE: %f\n", f);
			break;

		case SOUP_XMLRPC_VALUE_TYPE_DATETIME:
			indent (d);
			if (!soup_xmlrpc_value_get_datetime (value, &timeval))
				g_printerr ("BAD DATETIME\n");
			else
				g_printerr ("DATETIME: %s\n", asctime (gmtime (&timeval)));
			break;

		case SOUP_XMLRPC_VALUE_TYPE_BASE64:
			indent (d);
			if (!soup_xmlrpc_value_get_base64 (value, &str))
				g_printerr ("BAD BASE64\n");
			else
				g_printerr ("BASE64: %s\n", str);

			break;

		case SOUP_XMLRPC_VALUE_TYPE_STRUCT:
			indent (d);
			if (!soup_xmlrpc_value_get_struct (value, &hash))
				g_printerr ("BAD STRUCT\n");
			else {
				g_printerr ("STRUCT\n");
				g_hash_table_foreach (hash, (GHFunc) soup_xmlrpc_value_dump_struct_member,
						      GINT_TO_POINTER (d+1));
				g_hash_table_destroy (hash);
			}
			break;

		case SOUP_XMLRPC_VALUE_TYPE_ARRAY:
			indent (d);
			if (!soup_xmlrpc_value_array_get_iterator (value, &iter))
				g_printerr ("BAD ARRAY\n");
			else {
				g_printerr ("ARRAY\n");
				SoupXmlrpcValue *evalue;
				int i = 0;
				while (iter != NULL) {
					soup_xmlrpc_value_array_iterator_get_value (iter, &evalue);
					soup_xmlrpc_value_dump_array_element (i, evalue, GINT_TO_POINTER (d+1));
					iter = soup_xmlrpc_value_array_iterator_next (iter);
					i++;
				}
			}
			break;
	}

}

void
soup_xmlrpc_value_dump (SoupXmlrpcValue *value)
{
	soup_xmlrpc_value_dump_internal (value, 0);
}

