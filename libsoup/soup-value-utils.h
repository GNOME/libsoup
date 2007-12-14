/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2007 Red Hat, Inc.
 */

#ifndef SOUP_VALUE_UTILS_H
#define SOUP_VALUE_UTILS_H 1

#include <libsoup/soup-types.h>

G_BEGIN_DECLS

gboolean     soup_value_getv              (GValue      *val,
					   GType        type,
					   va_list      args);
gboolean     soup_value_setv              (GValue      *val,
					   GType        type,
					   va_list      args);

GHashTable  *soup_value_hash_new          (void);
void         soup_value_hash_insert_value (GHashTable  *hash,
					   const char  *key,
					   GValue      *value);
gboolean     soup_value_hash_insert       (GHashTable  *hash,
					   const char  *key,
					   GType        type,
					   ...);
gboolean     soup_value_hash_lookup       (GHashTable  *hash,
					   const char  *key,
					   GType        type,
					   ...);

GValueArray *soup_value_array_from_args   (va_list      args);
gboolean     soup_value_array_to_args     (GValueArray *array,
					   va_list      args);

gboolean     soup_value_array_insert      (GValueArray *array,
					   guint        index_,
					   GType        type,
					   ...);
gboolean     soup_value_array_append      (GValueArray *array,
					   GType        type,
					   ...);
gboolean     soup_value_array_appendv     (GValueArray *array,
					   GType        type,
					   va_list      args);
gboolean     soup_value_array_get_nth     (GValueArray *array,
					   guint        index_,
					   GType        type,
					   ...);


GType        soup_byte_array_get_type     (void);
#define SOUP_TYPE_BYTE_ARRAY (soup_byte_array_get_type ())

G_END_DECLS

#endif /* SOUP_VALUE_UTILS_H */
