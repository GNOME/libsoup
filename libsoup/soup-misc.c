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
#include <stdio.h>
#include <stdlib.h>

#include "soup-misc.h"
#include "soup-private.h"

gboolean soup_initialized = FALSE;

static guint max_connections = 0;

static SoupContext *proxy_context = NULL;

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

#define ALLOW_UNLESS_DENIED TRUE
#define DENY_UNLESS_ALLOWED FALSE

static gboolean allow_policy = ALLOW_UNLESS_DENIED;
static GSList *allow_tokens = NULL;
static GSList *deny_tokens = NULL;

static void
soup_config_reset_allow_deny (void)
{
	GSList *iter;
	
	for (iter = allow_tokens; iter; iter = iter->next) g_free (iter->data);
	for (iter = deny_tokens; iter; iter = iter->next) g_free (iter->data);

	g_slist_free (allow_tokens);
	g_slist_free (deny_tokens);

	allow_tokens = deny_tokens = NULL;
}

static gboolean
soup_config_allow_deny (gchar *key)
{
	GSList **list;
	gchar **iter, **split;

	key = g_strchomp (key);

	if (!g_strncasecmp (key, "allow", 5)) list = &allow_tokens;
	else if (!g_strncasecmp (key, "deny", 4)) list = &deny_tokens;
	else return FALSE;

	iter = split = g_strsplit (key, " ", 0);
	if (!split || !split [1]) return TRUE;

	while (*(++iter)) {
		if (!g_strcasecmp (iter [0], "all")) {
			GSList *iter;
			allow_policy = (*list == allow_tokens);
			for (iter = *list; iter; iter = iter->next) 
				g_free (iter->data);
			g_slist_free (*list);
			*list = NULL;
			*list = g_slist_prepend (*list, NULL);
			break;
		}

		*list = g_slist_prepend (*list, g_strdup (iter [0]));
	}

	g_strfreev (split);
	return TRUE;
}

static gboolean
soup_config_token_allowed (gchar *key)
{
	gboolean allow;
	GSList *list;

	list = (allow_policy == ALLOW_UNLESS_DENIED) ? deny_tokens:allow_tokens;
	allow = (allow_policy == ALLOW_UNLESS_DENIED) ? TRUE : FALSE;

	if (!list) return allow;

	for (; list; list = list->next)
		if (!list->data ||
		    !g_strncasecmp (key, 
				    (gchar *) list->data, 
				    strlen ((gchar *) list->data)))
			return !allow;

	return allow;
}

static void 
soup_load_config_internal (gchar *config_file, gboolean admin)
{
	FILE *cfg;
	char buf[128];

	cfg = fopen (config_file, "r");
	if (!cfg) return;

	if (admin) soup_config_reset_allow_deny();

	while (fgets (buf, sizeof (buf), cfg)) {
		char *key, *value, *iter, *iter2, **split;

		iter = g_strstrip (buf);
		if (!*iter || *iter == '#') continue;

		iter2 = strchr (iter, '#');
		if (iter2) *iter2 = '\0';

		if (admin && soup_config_allow_deny (iter)) continue;

		if (!admin && !soup_config_token_allowed (iter)) continue;

		split = g_strsplit (g_strchomp (iter), "=", 2);
		if (!split || !split[1] || split[2]) continue;

		key = g_strchomp (split[0]);
		value = g_strchug (split[1]);

		if (!g_strcasecmp (key, "connection-limit"))
			soup_set_connection_limit (MAX (atoi (value), 0));
		else if (!g_strcasecmp (key, "proxy-url") ||
			 !g_strcasecmp (key, "proxy-uri")) {
			SoupContext *con = soup_context_get (value);
			if (con) soup_set_proxy (con);
		}

		g_strfreev (split);
	}
}

void
soup_load_config (gchar *config_file)
{
	/* Reset values */
	if (soup_initialized) {
		soup_set_proxy (NULL);
		soup_set_connection_limit (0);
	}

	/* Load system global config */
	soup_load_config_internal (SYSCONFDIR G_DIR_SEPARATOR_S "/souprc",
				   TRUE);

	/* Load requested file or user local config */
	if (!config_file) {
		gchar *dfile = g_strconcat (g_get_home_dir(),
					    G_DIR_SEPARATOR_S ".souprc", 
					    NULL);
		soup_load_config_internal (dfile, FALSE);
		g_free (dfile);
	} else
		soup_load_config_internal (config_file, FALSE);

	soup_initialized = TRUE;
}
