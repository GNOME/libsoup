/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2003, Novell, Inc.
 */

#ifndef SOUP_SOAP_RESPONSE_H
#define SOUP_SOAP_RESPONSE_H

#include <glib-object.h>
#include <libxml/tree.h>

G_BEGIN_DECLS

#define SOUP_TYPE_SOAP_RESPONSE            (soup_soap_response_get_type ())
#define SOUP_SOAP_RESPONSE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_SOAP_RESPONSE, SoupSoapResponse))
#define SOUP_SOAP_RESPONSE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_SOAP_RESPONSE, SoupSoapResponseClass))
#define SOUP_IS_SOAP_RESPONSE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_SOAP_RESPONSE))
#define SOUP_IS_SOAP_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_SOAP_RESPONSE))
#define SOUP_SOAP_RESPONSE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_SOAP_RESPONSE, SoupSoapResponseClass))

typedef struct _SoupSoapResponsePrivate SoupSoapResponsePrivate;

typedef struct {
	GObject parent;
	SoupSoapResponsePrivate *priv;
} SoupSoapResponse;

typedef struct {
	GObjectClass parent_class;
} SoupSoapResponseClass;

GType             soup_soap_response_get_type (void);

SoupSoapResponse *soup_soap_response_new (void);
SoupSoapResponse *soup_soap_response_new_from_string (const char *xmlstr);

gboolean          soup_soap_response_from_string (SoupSoapResponse *response, const char *xmlstr);
char             *soup_soap_response_to_string (SoupSoapResponse *response);

const char       *soup_soap_response_get_method_name (SoupSoapResponse *response);
void              soup_soap_response_set_method_name (SoupSoapResponse *response,
						      const char *method_name);

typedef xmlNode SoupSoapParameter;

const char        *soup_soap_parameter_get_name (SoupSoapParameter *param);
int                soup_soap_parameter_get_int_value (SoupSoapParameter *param);
char              *soup_soap_parameter_get_string_value (SoupSoapParameter *param);
SoupSoapParameter *soup_soap_parameter_get_first_child (SoupSoapParameter *param);
SoupSoapParameter *soup_soap_parameter_get_first_child_by_name (SoupSoapParameter *param,
								const char *name);
SoupSoapParameter *soup_soap_parameter_get_next_child (SoupSoapParameter *param);
SoupSoapParameter *soup_soap_parameter_get_next_child_by_name (SoupSoapParameter *param,
							       const char *name);
char              *soup_soap_parameter_get_property (SoupSoapParameter *param, const char *prop_name);

const GList       *soup_soap_response_get_parameters (SoupSoapResponse *response);
SoupSoapParameter *soup_soap_response_get_first_parameter (SoupSoapResponse *response);
SoupSoapParameter *soup_soap_response_get_first_parameter_by_name (SoupSoapResponse *response,
								   const char *name);
SoupSoapParameter *soup_soap_response_get_next_parameter (SoupSoapResponse *response,
							  SoupSoapParameter *from);
SoupSoapParameter *soup_soap_response_get_next_parameter_by_name (SoupSoapResponse *response,
								  SoupSoapParameter *from,
								  const char *name);

G_END_DECLS

#endif
