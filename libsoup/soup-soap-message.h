/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#ifndef SOUP_SOAP_MESSAGE_H
#define SOUP_SOAP_MESSAGE_H 1

#include <libxml/tree.h>
#include <libsoup/soup-message.h>

#define SOUP_TYPE_SOAP_MESSAGE            (soup_soap_message_get_type ())
#define SOUP_SOAP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessage))
#define SOUP_SOAP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessageClass))
#define SOUP_IS_SOAP_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOAP_MESSAGE))
#define SOUP_IS_SOAP_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_SOAP_MESSAGE))
#define SOUP_SOAP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessageClass))

typedef struct _SoupSoapMessagePrivate SoupSoapMessagePrivate;

typedef struct {
	SoupMessage parent;
	SoupSoapMessagePrivate *priv;
} SoupSoapMessage;

typedef struct {
	SoupMessageClass parent_class;
} SoupSoapMessageClass;

GType            soup_soap_message_get_type (void);

SoupSoapMessage *soup_soap_message_new (const char *method, const char *uri_string,
					gboolean standalone, const char *xml_encoding,
					const char *env_prefix, const char *env_uri);
SoupSoapMessage *soup_soap_message_new_from_uri (const char *method, const SoupUri *uri,
						 gboolean standalone, const char *xml_encoding,
						 const char *env_prefix, const char *env_uri);

void             soup_soap_message_start_envelope (SoupSoapMessage *msg);
void             soup_soap_message_end_envelope (SoupSoapMessage *msg);
void             soup_soap_message_start_body (SoupSoapMessage *msg);
void             soup_soap_message_end_body (SoupSoapMessage *msg);
void             soup_soap_message_start_element (SoupSoapMessage *msg,
						  const char *name,
						  const char *prefix,
						  const char *ns_uri);
void             soup_soap_message_end_element (SoupSoapMessage *msg);

xmlDocPtr        soup_soap_message_get_xml_doc (SoupSoapMessage *msg);

#endif
