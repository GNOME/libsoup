/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#ifndef SOUP_SOAP_MESSAGE_H
#define SOUP_SOAP_MESSAGE_H 1

#include <time.h>
#include <libxml/tree.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-soap-response.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SOAP_MESSAGE            (soup_soap_message_get_type ())
#define SOUP_SOAP_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessage))
#define SOUP_SOAP_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessageClass))
#define SOUP_IS_SOAP_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOAP_MESSAGE))
#define SOUP_IS_SOAP_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_SOAP_MESSAGE))
#define SOUP_SOAP_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOAP_MESSAGE, SoupSoapMessageClass))

typedef struct {
	SoupMessage parent;

} SoupSoapMessage;

typedef struct {
	SoupMessageClass parent_class;
} SoupSoapMessageClass;

GType             soup_soap_message_get_type (void);

SoupSoapMessage  *soup_soap_message_new (const char *method, const char *uri_string,
					 gboolean standalone, const char *xml_encoding,
					 const char *env_prefix, const char *env_uri);
SoupSoapMessage  *soup_soap_message_new_from_uri (const char *method, SoupURI *uri,
						  gboolean standalone, const char *xml_encoding,
						  const char *env_prefix, const char *env_uri);

void              soup_soap_message_start_envelope (SoupSoapMessage *msg);
void              soup_soap_message_end_envelope (SoupSoapMessage *msg);
void              soup_soap_message_start_body (SoupSoapMessage *msg);
void              soup_soap_message_end_body (SoupSoapMessage *msg);
void              soup_soap_message_start_element (SoupSoapMessage *msg,
						   const char *name,
						   const char *prefix,
						   const char *ns_uri);
void              soup_soap_message_end_element (SoupSoapMessage *msg);
void              soup_soap_message_start_fault (SoupSoapMessage *msg,
						 const char *faultcode,
						 const char *faultstring,
						 const char *faultfactor);
void              soup_soap_message_end_fault (SoupSoapMessage *msg);
void              soup_soap_message_start_fault_detail (SoupSoapMessage *msg);
void              soup_soap_message_end_fault_detail (SoupSoapMessage *msg);
void              soup_soap_message_start_header (SoupSoapMessage *msg);
void              soup_soap_message_end_header (SoupSoapMessage *msg);
void              soup_soap_message_start_header_element (SoupSoapMessage *msg,
							  const char *name,
							  gboolean must_understand,
							  const char *actor_uri,
							  const char *prefix,
							  const char *ns_uri);
void              soup_soap_message_end_header_element (SoupSoapMessage *msg);
void              soup_soap_message_write_int (SoupSoapMessage *msg, glong i);
void              soup_soap_message_write_double (SoupSoapMessage *msg, double d);
void              soup_soap_message_write_base64 (SoupSoapMessage *msg, const char *string, int len);
void              soup_soap_message_write_time (SoupSoapMessage *msg, const time_t *timeval);
void              soup_soap_message_write_string (SoupSoapMessage *msg, const char *string);
void              soup_soap_message_write_buffer (SoupSoapMessage *msg, const char *buffer, int len);
void              soup_soap_message_set_element_type (SoupSoapMessage *msg, const char *xsi_type);
void              soup_soap_message_set_null (SoupSoapMessage *msg);
void              soup_soap_message_add_attribute (SoupSoapMessage *msg,
						   const char *name,
						   const char *value,
						   const char *prefix,
						   const char *ns_uri);
void              soup_soap_message_add_namespace (SoupSoapMessage *msg,
						   const char *prefix,
						   const char *ns_uri);
void              soup_soap_message_set_default_namespace (SoupSoapMessage *msg,
							   const char *ns_uri);
void              soup_soap_message_set_encoding_style (SoupSoapMessage *msg, const char *enc_style);
void              soup_soap_message_reset (SoupSoapMessage *msg);
void              soup_soap_message_persist (SoupSoapMessage *msg);

const char       *soup_soap_message_get_namespace_prefix (SoupSoapMessage *msg, const char *ns_uri);

xmlDocPtr         soup_soap_message_get_xml_doc (SoupSoapMessage *msg);

SoupSoapResponse *soup_soap_message_parse_response (SoupSoapMessage *msg);

G_END_DECLS

#endif
