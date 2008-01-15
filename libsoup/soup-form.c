/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/* soup-form.c : utility functions for HTML forms */

/*
 * Copyright 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-form.h"

#define XDIGIT(c) ((c) <= '9' ? (c) - '0' : ((c) & 0x4F) - 'A' + 10)
#define HEXCHAR(s) ((XDIGIT (s[1]) << 4) + XDIGIT (s[2]))

static gboolean
form_decode (char *part)
{
	unsigned char *s, *d;

	s = d = (unsigned char *)part;
	do {
		if (*s == '%') {
			if (!g_ascii_isxdigit (s[1]) ||
			    !g_ascii_isxdigit (s[2]))
				return FALSE;
			*d++ = HEXCHAR (s);
			s += 2;
		} else if (*s == '+')
			*d++ = ' ';
		else
			*d++ = *s;
	} while (*s++);

	return TRUE;
}

/**
 * soup_form_decode_urlencoded:
 * @encoded_form: data of type "application/x-www-form-urlencoded"
 *
 * Decodes @form, which is an urlencoded dataset as defined in the
 * HTML 4.01 spec.
 *
 * Return value: a hash table containing the name/value pairs from
 * @encoded_form, which you can free with g_hash_table_destroy().
 **/
GHashTable *
soup_form_decode_urlencoded (const char *encoded_form)
{
	GHashTable *form_data_set;
	char **pairs, *eq, *name, *value;
	int i;

	form_data_set = g_hash_table_new_full (g_str_hash, g_str_equal,
					       g_free, NULL);
	pairs = g_strsplit (encoded_form, "&", -1);
	for (i = 0; pairs[i]; i++) {
		name = pairs[i];
		eq = strchr (name, '=');
		if (!form_decode (name)) {
			g_free (name);
			continue;
		}
		if (eq) {
			*eq = '\0';
			value = eq + 1;
		} else
			value = NULL;

		g_hash_table_insert (form_data_set, name, value);
	}
	g_free (pairs);

	return form_data_set;
}

static void
append_form_encoded (GString *str, const char *in)
{
	const unsigned char *s = (const unsigned char *)in;

	while (*s) {
		if (*s == ' ') {
			g_string_append_c (str, '+');
			s++;
		} else if (!g_ascii_isalnum (*s))
			g_string_append_printf (str, "%%%02X", (int)*s++);
		else
			g_string_append_c (str, *s++);
	}
}

static void
encode_pair (GString *str, const char *name, const char *value)
{
	if (str->len)
		g_string_append_c (str, '&');
	append_form_encoded (str, name);
	g_string_append_c (str, '=');
	append_form_encoded (str, value);
}

static void
hash_encode_foreach (gpointer name, gpointer value, gpointer str)
{
	encode_pair (str, name, value);
}

/**
 * soup_form_encode_urlencoded:
 * @form_data_set: a hash table containing name/value pairs
 *
 * Encodes @form_data_set into a value of type
 * "application/x-www-form-urlencoded", as defined in the HTML 4.01
 * spec.
 *
 * Note that the spec states that "The control names/values are listed
 * in the order they appear in the document." Since
 * soup_form_encode_urlencoded() takes a hash table, this cannot be
 * enforced; if you care about the ordering of the form fields, use
 * soup_form_encode_urlencoded_list().
 *
 * Return value: the encoded form
 **/
char *
soup_form_encode_urlencoded (GHashTable *form_data_set)
{
	GString *str = g_string_new (NULL);

	g_hash_table_foreach (form_data_set, hash_encode_foreach, str);
	return g_string_free (str, FALSE);
}

static void
datalist_encode_foreach (GQuark key_id, gpointer value, gpointer str)
{
	encode_pair (str, g_quark_to_string (key_id), value);
}

/**
 * soup_form_encode_urlencoded_list:
 * @form_data_set: a hash table containing name/value pairs
 *
 * Encodes @form_data_set into a value of type
 * "application/x-www-form-urlencoded", as defined in the HTML 4.01
 * spec. Unlike soup_form_encode_urlencoded(), this preserves the
 * ordering of the form elements, which may be required in some
 * situations.
 *
 * Return value: the encoded form
 **/
char *
soup_form_encode_urlencoded_list (GData **form_data_set)
{
	GString *str = g_string_new (NULL);

	g_datalist_foreach (form_data_set, datalist_encode_foreach, str);
	return g_string_free (str, FALSE);
}
