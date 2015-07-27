/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright 2015 - Collabora Ltd.
 */

#ifndef SOUP_XMLRPC_H
#define SOUP_XMLRPC_H 1

#include <libsoup/soup-types.h>
#include <libsoup/soup-xmlrpc-old.h>

G_BEGIN_DECLS

/* XML-RPC client */
SOUP_AVAILABLE_IN_2_52
char       *soup_xmlrpc_build_request  (const char *method_name,
					 GVariant    *params,
					 GError     **error);
SOUP_AVAILABLE_IN_2_52
SoupMessage *soup_xmlrpc_message_new    (const char *uri,
					 const char *method_name,
					 GVariant    *params,
					 GError     **error);
SOUP_AVAILABLE_IN_2_52
GVariant    *soup_xmlrpc_parse_response (const char *method_response,
					 int         length,
					 const char *signature,
					 GError     **error);

/* XML-RPC server */
typedef struct _SoupXMLRPCParams SoupXMLRPCParams;
SOUP_AVAILABLE_IN_2_52
void         soup_xmlrpc_params_free          (SoupXMLRPCParams  *self);
SOUP_AVAILABLE_IN_2_52
GVariant    *soup_xmlrpc_params_parse         (SoupXMLRPCParams  *self,
					       const char       *signature,
					       GError           **error);
SOUP_AVAILABLE_IN_2_52
char       *soup_xmlrpc_parse_request        (const gchar       *method_call,
					       int               length,
					       SoupXMLRPCParams **params,
					       GError           **error);
SOUP_AVAILABLE_IN_2_52
char       *soup_xmlrpc_parse_request_full   (const gchar       *method_call,
					       int               length,
					       const char       *signature,
					       GVariant         **parameters,
					       GError           **error);
SOUP_AVAILABLE_IN_2_52
char       *soup_xmlrpc_build_response       (GVariant          *value,
					       GError           **error);
SOUP_AVAILABLE_IN_2_52
gboolean     soup_xmlrpc_message_set_response (SoupMessage       *msg,
					       GVariant          *value,
					       GError           **error);

/* Utils */
SOUP_AVAILABLE_IN_2_52
GVariant *soup_xmlrpc_new_custom   (const char *type,
				    const char *value);
SOUP_AVAILABLE_IN_2_52
GVariant *soup_xmlrpc_new_datetime (time_t       timestamp);

G_END_DECLS

#endif /* SOUP_XMLRPC_H */
