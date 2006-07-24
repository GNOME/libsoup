/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * FIXME Copyright
 */

#ifndef SOUP_XMLRPC_MESSAGE_H
#define SOUP_XMLRPC_MESSAGE_H

#include <time.h>
#include <libxml/tree.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-uri.h>

#include "soup-xmlrpc-response.h"

G_BEGIN_DECLS

#define SOUP_TYPE_XMLRPC_MESSAGE            (soup_xmlrpc_message_get_type ())
#define SOUP_XMLRPC_MESSAGE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SOUP_TYPE_XMLRPC_MESSAGE, SoupXmlrpcMessage))
#define SOUP_XMLRPC_MESSAGE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SOUP_TYPE_XMLRPC_MESSAGE, SoupXmlrpcMessageClass))
#define SOUP_IS_XMLRPC_MESSAGE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SOUP_TYPE_XMLRPC_MESSAGE))
#define SOUP_IS_XMLRPC_MESSAGE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SOUP_TYPE_XMLRPC_MESSAGE))
#define SOUP_XMLRPC_MESSAGE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SOUP_TYPE_XMLRPC_MESSAGE, SoupXmlrpcMessageClass))

typedef struct {
	SoupMessage parent;

} SoupXmlrpcMessage;

typedef struct {
	SoupMessageClass parent_class;
} SoupXmlrpcMessageClass;

GType soup_xmlrpc_message_get_type (void);

SoupXmlrpcMessage *soup_xmlrpc_message_new          (const char *uri_string);
SoupXmlrpcMessage *soup_xmlrpc_message_new_from_uri (const SoupUri *uri);

void soup_xmlrpc_message_start_call     (SoupXmlrpcMessage *msg,
					 const char        *method_name);
void soup_xmlrpc_message_end_call       (SoupXmlrpcMessage *msg);

void soup_xmlrpc_message_start_param    (SoupXmlrpcMessage *msg);
void soup_xmlrpc_message_end_param      (SoupXmlrpcMessage *msg);

void soup_xmlrpc_message_write_int      (SoupXmlrpcMessage *msg,
					 long               i);
void soup_xmlrpc_message_write_boolean  (SoupXmlrpcMessage *msg,
					 gboolean           b);
void soup_xmlrpc_message_write_string   (SoupXmlrpcMessage *msg,
					 const char        *str);
void soup_xmlrpc_message_write_double   (SoupXmlrpcMessage *msg,
					 double             d);
void soup_xmlrpc_message_write_datetime (SoupXmlrpcMessage *msg,
					 const time_t       timeval);
void soup_xmlrpc_message_write_base64   (SoupXmlrpcMessage *msg,
					 gconstpointer      buf,
					 int                len);

void soup_xmlrpc_message_start_struct   (SoupXmlrpcMessage *msg);
void soup_xmlrpc_message_end_struct     (SoupXmlrpcMessage *msg);

void soup_xmlrpc_message_start_member   (SoupXmlrpcMessage *msg,
					 const char        *name);
void soup_xmlrpc_message_end_member     (SoupXmlrpcMessage *msg);

void soup_xmlrpc_message_start_array    (SoupXmlrpcMessage *msg);
void soup_xmlrpc_message_end_array      (SoupXmlrpcMessage *msg);

gboolean  soup_xmlrpc_message_from_string (SoupXmlrpcMessage *message,
					   const char        *xmlstr);

xmlChar  *soup_xmlrpc_message_to_string   (SoupXmlrpcMessage *msg);
void      soup_xmlrpc_message_persist     (SoupXmlrpcMessage *msg);

SoupXmlrpcResponse *soup_xmlrpc_message_parse_response (SoupXmlrpcMessage *msg);

#endif
