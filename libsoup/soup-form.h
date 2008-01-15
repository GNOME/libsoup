/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* 
 * Copyright 2008 Red Hat, Inc.
 */

#ifndef  SOUP_FORM_H
#define  SOUP_FORM_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

GHashTable *soup_form_decode_urlencoded      (const char  *encoded_form);

char       *soup_form_encode_urlencoded      (GHashTable  *form_data_set);
char       *soup_form_encode_urlencoded_list (GData      **form_data_set);

G_END_DECLS

#endif /* SOUP_FORM_H */
