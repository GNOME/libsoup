/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-queue.c: Asyncronous Callback-based SOAP Request Queue.
 *
 * Authors:
 *      Alex Graveley (alex@helixcode.com)
 *
 * soup_base64_encode() written by Joe Orton, borrowed from ghttp.
 *
 * Copyright (C) 2000, Helix Code, Inc.
 */

#include <ctype.h>
#include <string.h>

#include "soup-misc.h"
#include "soup-private.h"

static gint max_connections = -1;

static SoupContext *proxy_context;

void         
soup_set_proxy (SoupContext *context)
{
	if (proxy_context)
		soup_context_unref (proxy_context);

	proxy_context = context;
	soup_context_ref (proxy_context);
}

SoupContext *
soup_get_proxy (void)
{
	return proxy_context;
}

void         
soup_set_connection_limit (guint max_conn)
{
	max_connections = max_conn;
}

guint
soup_get_connection_limit (void)
{
	return max_connections;
}


guint
soup_str_case_hash (gconstpointer key)
{
	const char *p = key;
	guint h = toupper(*p);
	
	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + toupper(*p);
	
	return h;
}

gboolean
soup_str_case_equal (gconstpointer v1,
		     gconstpointer v2)
{
	const gchar *string1 = v1;
	const gchar *string2 = v2;
	
	return g_strcasecmp (string1, string2) == 0;
}

gint
soup_substring_index (gchar *str, gint len, gchar *substr) 
{
	int i, sublen = strlen (substr);
	
	for (i = 0; i < len - sublen; ++i)
		if (str[i] == substr[0])
			if (memcmp (&str[i], substr, sublen) == 0)
				return i;

	return -1;
}

const char base64_alphabet[65] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

gchar *
soup_base64_encode (gchar *text)
{
	char *buffer = NULL;
	char *point = NULL;
	int inlen = 0;
	int outlen = 0;

	/* check our args */
	if (text == NULL)
		return NULL;
  
	/* Use 'buffer' to store the output. Work out how big it should be...
	 * This must be a multiple of 4 bytes */
  
	inlen = strlen (text);
	/* check our arg...avoid a pesky FPE */
	if (inlen == 0) {
		buffer = g_malloc (sizeof(char));
		buffer[0] = '\0';
		return buffer;
	}

	outlen = (inlen*4)/3;
	if ((inlen % 3) > 0) /* got to pad */
		outlen += 4 - (inlen % 3);
  
	buffer = g_malloc (outlen + 1); /* +1 for the \0 */
	memset (buffer, 0, outlen + 1); /* initialize to zero */
  
	/* now do the main stage of conversion, 3 bytes at a time,
	 * leave the trailing bytes (if there are any) for later */
  
	for (point=buffer; inlen>=3; inlen-=3, text+=3) {
		*(point++) = base64_alphabet [*text>>2]; 
		*(point++) = base64_alphabet [(*text<<4 & 0x30) | 
					     *(text+1)>>4]; 
		*(point++) = base64_alphabet [(*(text+1)<<2 & 0x3c) | 
					     *(text+2)>>6];
		*(point++) = base64_alphabet [*(text+2) & 0x3f];
	}
  
	/* Now deal with the trailing bytes */
	if (inlen) {
		/* We always have one trailing byte */
		*(point++) = base64_alphabet [*text>>2];
		*(point++) = base64_alphabet [(*text<<4 & 0x30) |
					     (inlen==2?*(text+1)>>4:0)]; 
		*(point++) = (inlen == 1 ? 
			      '=' : 
			      base64_alphabet [*(text+1)<<2 & 0x3c]);
		*(point++) = '=';
	}
	
	*point = '\0';
	
	return buffer;
}
