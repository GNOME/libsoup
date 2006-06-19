/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * FIXME Copyright
 */

#ifndef SOUP_XMLRPC_RESPONSE_H
#define SOUP_XMLRPC_RESPONSE_H

#include <glib-object.h>
#include <libxml/tree.h>

G_BEGIN_DECLS

#define SOUP_TYPE_XMLRPC_RESPONSE            (soup_xmlrpc_response_get_type ())
#define SOUP_XMLRPC_RESPONSE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_XMLRPC_RESPONSE, SoupXmlrpcResponse))
#define SOUP_XMLRPC_RESPONSE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_XMLRPC_RESPONSE, SoupXmlrpcResponseClass))
#define SOUP_IS_XMLRPC_RESPONSE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_XMLRPC_RESPONSE))
#define SOUP_IS_XMLRPC_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SOUP_TYPE_XMLRPC_RESPONSE))
#define SOUP_XMLRPC_RESPONSE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_XMLRPC_RESPONSE, SoupXmlrpcResponseClass))

typedef struct {
	GObject parent;

} SoupXmlrpcResponse;

typedef struct {
	GObjectClass parent_class;
} SoupXmlrpcResponseClass;

GType               soup_xmlrpc_response_get_type (void);

SoupXmlrpcResponse *soup_xmlrpc_response_new             (void);
SoupXmlrpcResponse *soup_xmlrpc_response_new_from_string (const char *xmlstr);

gboolean            soup_xmlrpc_response_from_string     (SoupXmlrpcResponse *response,
							  const char         *xmlstr);
xmlChar            *soup_xmlrpc_response_to_string       (SoupXmlrpcResponse *response);

typedef xmlNode *SoupXmlrpcValue;

typedef enum {
	SOUP_XMLRPC_VALUE_TYPE_BAD,
	SOUP_XMLRPC_VALUE_TYPE_INT,
	SOUP_XMLRPC_VALUE_TYPE_BOOLEAN,
	SOUP_XMLRPC_VALUE_TYPE_STRING,
	SOUP_XMLRPC_VALUE_TYPE_DOUBLE,
	SOUP_XMLRPC_VALUE_TYPE_DATETIME,
	SOUP_XMLRPC_VALUE_TYPE_BASE64,
	SOUP_XMLRPC_VALUE_TYPE_STRUCT,
	SOUP_XMLRPC_VALUE_TYPE_ARRAY
} SoupXmlrpcValueType;

gboolean             soup_xmlrpc_response_is_fault  (SoupXmlrpcResponse *response);
SoupXmlrpcValue     *soup_xmlrpc_response_get_value (SoupXmlrpcResponse *response);
SoupXmlrpcValueType  soup_xmlrpc_value_get_type     (SoupXmlrpcValue *value);

gboolean soup_xmlrpc_value_get_int      (SoupXmlrpcValue  *value,
					 long             *i);
gboolean soup_xmlrpc_value_get_double   (SoupXmlrpcValue  *value,
					 double           *b);
gboolean soup_xmlrpc_value_get_boolean  (SoupXmlrpcValue  *value,
					 gboolean         *b);
gboolean soup_xmlrpc_value_get_string   (SoupXmlrpcValue  *value,
					 char            **str);
gboolean soup_xmlrpc_value_get_datetime (SoupXmlrpcValue  *value,
					 time_t           *timeval);
gboolean soup_xmlrpc_value_get_base64   (SoupXmlrpcValue  *value,
					 GByteArray      **data);

gboolean soup_xmlrpc_value_get_struct   (SoupXmlrpcValue  *value,
					 GHashTable      **table);


typedef xmlNodePtr SoupXmlrpcValueArrayIterator;

gboolean                      soup_xmlrpc_value_array_get_iterator       (SoupXmlrpcValue               *value,
									  SoupXmlrpcValueArrayIterator **iter);

SoupXmlrpcValueArrayIterator *soup_xmlrpc_value_array_iterator_prev      (SoupXmlrpcValueArrayIterator  *iter);
SoupXmlrpcValueArrayIterator *soup_xmlrpc_value_array_iterator_next      (SoupXmlrpcValueArrayIterator  *iter);
gboolean                      soup_xmlrpc_value_array_iterator_get_value (SoupXmlrpcValueArrayIterator  *iter,
                                                                          SoupXmlrpcValue              **value);

void soup_xmlrpc_value_dump (SoupXmlrpcValue *value);

G_END_DECLS

#endif
