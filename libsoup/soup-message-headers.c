/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-message-headers.c: HTTP message header arrays
 *
 * Copyright (C) 2005 Novell, Inc.
 */

#include "soup-message-headers.h"
#include "soup-misc.h"

static const char *intern_header_name (const char *name);

typedef struct {
	const char *name;
	char *value;
} SoupHeader;

/**
 * soup_message_headers_new:
 *
 * Creates a #SoupMessageHeaders
 *
 * Return value: a new #SoupMessageHeaders
 **/
SoupMessageHeaders *
soup_message_headers_new (void)
{
	/* FIXME: is "5" a good default? */
	GArray *array = g_array_sized_new (TRUE, FALSE, sizeof (SoupHeader), 5);

	return (SoupMessageHeaders *)array;
}

/**
 * soup_message_headers_free:
 * @hdrs: a #SoupMessageHeaders
 *
 * Frees @hdrs.
 **/
void
soup_message_headers_free (SoupMessageHeaders *hdrs)
{
	soup_message_headers_clear (hdrs);
	g_array_free ((GArray *)hdrs, TRUE);
}

/**
 * soup_message_headers_clear:
 * @hdrs: a #SoupMessageHeaders
 *
 * Clears @hdrs.
 **/
void
soup_message_headers_clear (SoupMessageHeaders *hdrs)
{
	GArray *array = (GArray *)hdrs;
	SoupHeader *hdr_array = (SoupHeader *)array->data;
	int i;

	for (i = 0; i < array->len; i++)
		g_free (hdr_array[i].value);
	g_array_set_size (array, 0);
}

/**
 * soup_message_headers_append:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to add
 * @value: the new value of @name
 *
 * Appends a new header with name @name and value @value to @hdrs. If
 * there were already other instances of header @name in @hdrs, they
 * are preserved.
 **/
void
soup_message_headers_append (SoupMessageHeaders *hdrs,
			     const char *name, const char *value)
{
	SoupHeader header;

	header.name = intern_header_name (name);
	header.value = g_strdup (value);
	g_array_append_val ((GArray *)hdrs, header);
}

/**
 * soup_message_headers_replace:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to replace
 * @value: the new value of @name
 *
 * Replaces the value of the header @name in @hdrs with @value. If
 * there were previously multiple values for @name, all of the other
 * values are removed.
 **/
void
soup_message_headers_replace (SoupMessageHeaders *hdrs,
			      const char *name, const char *value)
{
	soup_message_headers_remove (hdrs, name);
	soup_message_headers_append (hdrs, name, value);
}

static int
find_header (SoupHeader *hdr_array, const char *interned_name, int nth)
{
	int i;

	for (i = 0; hdr_array[i].name; i++) {
		if (hdr_array[i].name == interned_name) {
			if (nth-- == 0)
				return i;
		}
	}
	return -1;
}

/**
 * soup_message_headers_remove:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to remove
 *
 * Removes @name from @hdrs. If there are multiple values for @name,
 * they are all removed.
 **/
void
soup_message_headers_remove (SoupMessageHeaders *hdrs, const char *name)
{
	GArray *array = (GArray *)hdrs;
	SoupHeader *hdr_array = (SoupHeader *)(array->data);
	int index;

	name = intern_header_name (name);
	while ((index = find_header (hdr_array, name, 0)) != -1) {
		g_free (hdr_array[index].value);
		g_array_remove_index (array, index);
	}
}

/**
 * soup_message_headers_find:
 * @hdrs: a #SoupMessageHeaders
 * @name: header name
 * 
 * Finds the first header in @hdrs with name @name.
 * 
 * Return value: the header's value or %NULL if not found.
 **/

/**
 * soup_message_headers_find_nth:
 * @hdrs: a #SoupMessageHeaders
 * @name: header name
 * @nth: which instance of header @name to find
 * 
 * Finds the @nth header in @hdrs with name @name (counting from 0).
 * 
 * Return value: the header's value or %NULL if not found.
 **/
const char *
soup_message_headers_find_nth (SoupMessageHeaders *hdrs,
			       const char *name, int nth)
{
	GArray *array = (GArray *)hdrs;
	SoupHeader *hdr_array = (SoupHeader *)(array->data);
	int index = find_header (hdr_array, intern_header_name (name), nth);
	return index == -1 ? NULL : hdr_array[index].value;
}


/**
 * soup_message_headers_foreach:
 * @hdrs: a #SoupMessageHeaders
 * @func: callback function to run for each header
 * @user_data: data to pass to @func
 * 
 * Calls @func once for each header value in @hdrs. (If there are
 * headers with multiple values, @func will be called once on each
 * value.)
 **/
void
soup_message_headers_foreach (SoupMessageHeaders *hdrs,
			      SoupMessageHeadersForeachFunc func,
			      gpointer            user_data)
{
	GArray *array = (GArray *)hdrs;
	SoupHeader *hdr_array = (SoupHeader *)array->data;
	int i;

	for (i = 0; i < array->len; i++)
		func (hdr_array[i].name, hdr_array[i].value, user_data);
}



static GStaticMutex header_pool_mutex = G_STATIC_MUTEX_INIT;
static GHashTable *header_pool;

static const char *
intern_header_name (const char *name)
{
	const char *interned;

	g_static_mutex_lock (&header_pool_mutex);

	if (!header_pool)
		header_pool = g_hash_table_new (soup_str_case_hash, soup_str_case_equal);

	interned = g_hash_table_lookup (header_pool, name);
	if (!interned) {
		char *dup = g_strdup (name);
		g_hash_table_insert (header_pool, dup, dup);
		interned = dup;
	}

	g_static_mutex_unlock (&header_pool_mutex);
	return interned;
}

