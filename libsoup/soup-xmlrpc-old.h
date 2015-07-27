/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifndef SOUP_XMLRPC_OLD_H
#define SOUP_XMLRPC_OLD_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

/* XML-RPC client */
char        *soup_xmlrpc_build_method_call       (const char   *method_name,
						  GValue       *params,
						  int           n_params);
SoupMessage *soup_xmlrpc_request_new             (const char   *uri,
						  const char   *method_name,
						  ...);
gboolean     soup_xmlrpc_parse_method_response   (const char   *method_response,
						  int           length,
						  GValue       *value,
						  GError      **error);
gboolean     soup_xmlrpc_extract_method_response (const char   *method_response,
						  int           length,
						  GError      **error,
						  GType         type,
						  ...);

/* XML-RPC server */
gboolean     soup_xmlrpc_parse_method_call       (const char   *method_call,
						  int           length,
						  char        **method_name,
						  GValueArray **params);
gboolean     soup_xmlrpc_extract_method_call     (const char   *method_call,
						  int           length,
						  char        **method_name,
						  ...);
char        *soup_xmlrpc_build_method_response   (GValue       *value);
void         soup_xmlrpc_set_response            (SoupMessage  *msg,
						  GType         type,
						  ...);
void         soup_xmlrpc_set_fault               (SoupMessage  *msg,
						  int           fault_code,
						  const char   *fault_format,
						  ...) G_GNUC_PRINTF (3, 4);

G_END_DECLS

#endif /* SOUP_XMLRPC_OLD_H */
