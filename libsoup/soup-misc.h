/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-misc.h: Miscellaneous settings and configuration file handling.
 *
 * Authors:
 *      Alex Graveley (alex@ximian.com)
 *
 * Copyright (C) 2000-2002, Ximian, Inc.
 */

#ifndef SOUP_MISC_H
#define SOUP_MISC_H 1

#include <glib.h>
#include <libsoup/soup-context.h>
#include <libsoup/soup-message.h>
#include <libsoup/soup-uri.h>

/* Configuration routines */

void               soup_load_config          (gchar       *config_file);

void               soup_shutdown             (void);

void               soup_set_proxy            (SoupContext *context);

SoupContext       *soup_get_proxy            (void);

void               soup_set_connection_limit (guint        max_conn);

guint              soup_get_connection_limit (void);

typedef enum {
	SOUP_SECURITY_DOMESTIC = 1,
	SOUP_SECURITY_EXPORT   = 2,
	SOUP_SECURITY_FRANCE   = 3
} SoupSecurityPolicy;

void               soup_set_security_policy  (SoupSecurityPolicy policy);

SoupSecurityPolicy soup_get_security_policy  (void);

/* SSL setup routines */

void               soup_set_ssl_ca_file      (const gchar *ca_file);

void               soup_set_ssl_ca_dir       (const gchar *ca_dir);

void               soup_set_ssl_cert_files   (const gchar *cert_file, 
					      const gchar *key_file);

const char        *soup_get_ssl_ca_file      (void);
const char        *soup_get_ssl_ca_dir       (void);
void               soup_get_ssl_cert_files   (const gchar **cert_file,
					      const gchar **key_file);

/* Authentication callback */

typedef void (*SoupAuthorizeFn) (const char    *scheme_name,
				 SoupUri       *uri,
				 const char    *realm,
				 gpointer       user_data);

void               soup_set_authorize_callback (SoupAuthorizeFn authfn,
						gpointer        user_data);

/* Base64 encoding/decoding */

gchar             *soup_base64_encode          (const gchar    *text,
						gint            len);

int                soup_base64_encode_close    (const guchar   *in, 
						int             inlen, 
						gboolean        break_lines, 
						guchar         *out, 
						int            *state, 
						int            *save);

int                soup_base64_encode_step     (const guchar   *in, 
						int             len, 
						gboolean        break_lines, 
						guchar         *out, 
						int            *state, 
						int            *save);

gchar             *soup_base64_decode          (const gchar    *text,
						gint           *out_len);

int                soup_base64_decode_step     (const guchar   *in, 
						int             len, 
						guchar         *out, 
						int            *state, 
						guint          *save);

/* Useful debugging routines */

void               soup_debug_print_headers  (SoupMessage *req);

void               soup_debug_print_uri      (SoupUri     *uri);

#endif /* SOUP_MISC_H */
