/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifndef SOUP_MISC_H
#define SOUP_MISC_H 1

#include <glib-object.h>

/* SSL setup routines */

void               soup_set_ssl_ca_file      (const char   *ca_file);

void               soup_set_ssl_cert_files   (const char   *cert_file, 
					      const char   *key_file);

const char        *soup_get_ssl_ca_file      (void);
void               soup_get_ssl_cert_files   (const char  **cert_file,
					      const char  **key_file);

/* Base64 encoding/decoding */

char              *soup_base64_encode        (const char   *text,
					      int           len);

int                soup_base64_encode_close  (const guchar *in, 
					      int           inlen, 
					      gboolean      break_lines, 
					      guchar       *out, 
					      int          *state, 
					      int          *save);

int                soup_base64_encode_step   (const guchar *in, 
					      int           len, 
					      gboolean      break_lines, 
					      guchar       *out, 
					      int          *state, 
					      int          *save);

char              *soup_base64_decode        (const gchar  *text,
					      int          *out_len);

int                soup_base64_decode_step   (const guchar *in, 
					      int           len, 
					      guchar       *out, 
					      int          *state, 
					      guint        *save);

/* Misc utils */

guint              soup_signal_connect_once  (gpointer      instance,
					      const char   *signal,
					      GCallback     c_handler,
					      gpointer      data);

guint              soup_str_case_hash        (gconstpointer key);
gboolean           soup_str_case_equal       (gconstpointer v1,
					      gconstpointer v2);

#endif /* SOUP_MISC_H */
