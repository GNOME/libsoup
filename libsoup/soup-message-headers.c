/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-message-headers.c: HTTP message header arrays
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-message-headers-private.h"
#include "soup.h"
#include "soup-misc.h"

/**
 * SoupMessageHeaders:
 *
 * The HTTP message headers associated with a request or response.
 */

/**
 * SoupMessageHeadersType:
 * @SOUP_MESSAGE_HEADERS_REQUEST: request headers
 * @SOUP_MESSAGE_HEADERS_RESPONSE: response headers
 * @SOUP_MESSAGE_HEADERS_MULTIPART: multipart body part headers
 *
 * Value passed to [ctor@MessageHeaders.new] to set certain default
 * behaviors.
 **/

static gboolean parse_content_foo (SoupMessageHeaders *hdrs,
                                   SoupHeaderName      header_name,
                                   char              **foo,
                                   GHashTable        **params);
typedef struct {
        SoupHeaderName name;
        char *value;
} SoupCommonHeader;

typedef struct {
	char *name;
	char *value;
} SoupUncommonHeader;

struct _SoupMessageHeaders {
        GArray *common_headers;
        GHashTable *common_concat;
	GArray *uncommon_headers;
	GHashTable *uncommon_concat;
	SoupMessageHeadersType type;

	SoupEncoding encoding;
	goffset content_length;
	SoupExpectation expectations;
	char *content_type;
};

/**
 * soup_message_headers_new:
 * @type: the type of headers
 *
 * Creates a [struct@MessageHeaders].
 *
 * ([class@Message] does this automatically for its own headers. You would only
 * need to use this method if you are manually parsing or generating message
 * headers.)
 *
 * Returns: a new #SoupMessageHeaders
 **/
SoupMessageHeaders *
soup_message_headers_new (SoupMessageHeadersType type)
{
	SoupMessageHeaders *hdrs;

	hdrs = g_atomic_rc_box_new0 (SoupMessageHeaders);
	hdrs->type = type;
	hdrs->encoding = -1;

	return hdrs;
}

/**
 * soup_message_headers_ref:
 * @hdrs: a #SoupMessageHeaders
 *
 * Atomically increments the reference count of @hdrs by one.
 *
 * Returns: the passed in #SoupMessageHeaders
 */
SoupMessageHeaders *
soup_message_headers_ref (SoupMessageHeaders *hdrs)
{
	g_atomic_rc_box_acquire (hdrs);

	return hdrs;
}

static void
soup_message_headers_destroy (SoupMessageHeaders *hdrs)
{
        soup_message_headers_clear (hdrs);
        if (hdrs->common_headers)
                g_array_free (hdrs->common_headers, TRUE);
        g_clear_pointer (&hdrs->common_concat, g_hash_table_destroy);
        if (hdrs->uncommon_headers)
                g_array_free (hdrs->uncommon_headers, TRUE);
        g_clear_pointer (&hdrs->uncommon_concat, g_hash_table_destroy);
}

/**
 * soup_message_headers_unref:
 * @hdrs: a #SoupMessageHeaders
 *
 * Atomically decrements the reference count of @hdrs by one.
 *
 * When the reference count reaches zero, the resources allocated by
 * @hdrs are freed
 */
void
soup_message_headers_unref (SoupMessageHeaders *hdrs)
{
        g_atomic_rc_box_release_full (hdrs, (GDestroyNotify)soup_message_headers_destroy);
}

G_DEFINE_BOXED_TYPE (SoupMessageHeaders, soup_message_headers, soup_message_headers_ref, soup_message_headers_unref)

/**
 * soup_message_headers_get_headers_type:
 * @hdrs: a #SoupMessageHeaders
 *
 * Gets the type of headers.
 *
 * Returns: the header's type.
 **/
SoupMessageHeadersType
soup_message_headers_get_headers_type (SoupMessageHeaders *hdrs)
{
	g_return_val_if_fail (hdrs, 0);

	return hdrs->type;
}

static void
soup_message_headers_set (SoupMessageHeaders *hdrs,
                          SoupHeaderName      name,
                          const char         *value)
{
        switch (name) {
        case SOUP_HEADER_CONTENT_LENGTH:
                if (hdrs->encoding == SOUP_ENCODING_CHUNKED)
                        return;

                if (value) {
                        char *end;

                        hdrs->content_length = g_ascii_strtoull (value, &end, 10);
                        if (*end)
                                hdrs->encoding = SOUP_ENCODING_UNRECOGNIZED;
                        else
                                hdrs->encoding = SOUP_ENCODING_CONTENT_LENGTH;
                } else
                        hdrs->encoding = -1;
                break;
        case SOUP_HEADER_CONTENT_TYPE:
                g_clear_pointer (&hdrs->content_type, g_free);
                if (value) {
                        char *content_type = NULL, *p;

                        parse_content_foo (hdrs, SOUP_HEADER_CONTENT_TYPE, &content_type, NULL);
                        g_assert (content_type != NULL);

                        p = strpbrk (content_type, " /");
                        if (!p || *p != '/' || strpbrk (p + 1, " /"))
                                g_free (content_type);
                        else
                                hdrs->content_type = content_type;
                }
                break;
        case SOUP_HEADER_EXPECT:
                if (value) {
                        if (!g_ascii_strcasecmp (value, "100-continue"))
                                hdrs->expectations = SOUP_EXPECTATION_CONTINUE;
                        else
                                hdrs->expectations = SOUP_EXPECTATION_UNRECOGNIZED;
                } else
                        hdrs->expectations = 0;
                break;
        case SOUP_HEADER_TRANSFER_ENCODING:
                if (value) {
                        /* "identity" is a wrong value according to RFC errata 408,
                         * and RFC 7230 does not list it as valid transfer-coding.
                         * Nevertheless, the obsolete RFC 2616 stated "identity"
                         * as valid, so we can't handle it as unrecognized here
                         * for compatibility reasons.
                         */
                        if (g_ascii_strcasecmp (value, "chunked") == 0)
                                hdrs->encoding = SOUP_ENCODING_CHUNKED;
                        else if (g_ascii_strcasecmp (value, "identity") != 0)
                                hdrs->encoding = SOUP_ENCODING_UNRECOGNIZED;
                } else
                        hdrs->encoding = -1;
                break;
        default:
                break;
        }
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
	guint i;

	g_return_if_fail (hdrs);

        if (hdrs->common_headers) {
                SoupCommonHeader *hdr_array_common = (SoupCommonHeader *)hdrs->common_headers->data;

                for (i = 0; i < hdrs->common_headers->len; i++) {
                        g_free (hdr_array_common[i].value);
                        soup_message_headers_set (hdrs, hdr_array_common[i].name, NULL);
                }
                g_array_set_size (hdrs->common_headers, 0);
        }

        if (hdrs->common_concat)
                g_hash_table_remove_all (hdrs->common_concat);

        if (hdrs->uncommon_headers) {
                SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)hdrs->uncommon_headers->data;

                for (i = 0; i < hdrs->uncommon_headers->len; i++) {
                        g_free (hdr_array[i].name);
                        g_free (hdr_array[i].value);
                }
                g_array_set_size (hdrs->uncommon_headers, 0);
        }

	if (hdrs->uncommon_concat)
		g_hash_table_remove_all (hdrs->uncommon_concat);
}

/**
 * soup_message_headers_clean_connection_headers:
 * @hdrs: a #SoupMessageHeaders
 *
 * Removes all the headers listed in the Connection header.
 */
void
soup_message_headers_clean_connection_headers (SoupMessageHeaders *hdrs)
{
	/* RFC 2616 14.10 */
	const char *connection;
	GSList *tokens, *t;

	g_return_if_fail (hdrs);

	connection = soup_message_headers_get_list_common (hdrs, SOUP_HEADER_CONNECTION);
	if (!connection)
		return;

	tokens = soup_header_parse_list (connection);
	for (t = tokens; t; t = t->next)
		soup_message_headers_remove (hdrs, t->data);
	soup_header_free_list (tokens);
}

void
soup_message_headers_append_common (SoupMessageHeaders *hdrs,
                                    SoupHeaderName      name,
                                    const char         *value)
{
        SoupCommonHeader header;

        if (!hdrs->common_headers)
                hdrs->common_headers = g_array_sized_new (FALSE, FALSE, sizeof (SoupCommonHeader), 6);

        header.name = name;
        header.value = g_strdup (value);
        g_array_append_val (hdrs->common_headers, header);
        if (hdrs->common_concat)
                g_hash_table_remove (hdrs->common_concat, GUINT_TO_POINTER (header.name));

        soup_message_headers_set (hdrs, name, value);
}

/**
 * soup_message_headers_append:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to add
 * @value: the new value of @name
 *
 * Appends a new header with name @name and value @value to @hdrs.
 *
 * (If there is an existing header with name @name, then this creates a second
 * one, which is only allowed for list-valued headers; see also
 * [method@MessageHeaders.replace].)
 *
 * The caller is expected to make sure that @name and @value are
 * syntactically correct.
 **/
void
soup_message_headers_append (SoupMessageHeaders *hdrs,
			     const char *name, const char *value)
{
	SoupUncommonHeader header;
        SoupHeaderName header_name;

	g_return_if_fail (hdrs);
	g_return_if_fail (name != NULL);
	g_return_if_fail (value != NULL);

	/* Setting a syntactically invalid header name or value is
	 * considered to be a programming error. However, it can also
	 * be a security hole, so we want to fail here even if
	 * compiled with G_DISABLE_CHECKS.
	 */
#ifndef G_DISABLE_CHECKS
	g_return_if_fail (*name && strpbrk (name, " \t\r\n:") == NULL);
	g_return_if_fail (strpbrk (value, "\r\n") == NULL);
#else
	if (*name && strpbrk (name, " \t\r\n:")) {
		g_warning ("soup_message_headers_append: Ignoring bad name '%s'", name);
		return;
	}
	if (strpbrk (value, "\r\n")) {
		g_warning ("soup_message_headers_append: Ignoring bad value '%s'", value);
		return;
	}
#endif

        header_name = soup_header_name_from_string (name);
        if (header_name != SOUP_HEADER_UNKNOWN) {
                soup_message_headers_append_common (hdrs, header_name, value);
                return;
        }

        if (!hdrs->uncommon_headers)
                hdrs->uncommon_headers = g_array_sized_new (FALSE, FALSE, sizeof (SoupUncommonHeader), 6);

	header.name = g_strdup (name);
	header.value = g_strdup (value);
	g_array_append_val (hdrs->uncommon_headers, header);
	if (hdrs->uncommon_concat)
		g_hash_table_remove (hdrs->uncommon_concat, header.name);
}

/*
 * Appends a header value ensuring that it is valid UTF8.
 */
void
soup_message_headers_append_untrusted_data (SoupMessageHeaders *hdrs,
                                            const char         *name,
                                            const char         *value)
{
        char *safe_value = g_utf8_make_valid (value, -1);
        char *safe_name = g_utf8_make_valid (name, -1);
        soup_message_headers_append (hdrs, safe_name, safe_value);
        g_free (safe_value);
        g_free (safe_name);
}

void
soup_message_headers_replace_common (SoupMessageHeaders *hdrs,
                                     SoupHeaderName      name,
                                     const char         *value)
{
        soup_message_headers_remove_common (hdrs, name);
        soup_message_headers_append_common (hdrs, name, value);
}

/**
 * soup_message_headers_replace:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to replace
 * @value: the new value of @name
 *
 * Replaces the value of the header @name in @hdrs with @value.
 *
 * See also [method@MessageHeaders.append].
 *
 * The caller is expected to make sure that @name and @value are
 * syntactically correct.
 **/
void
soup_message_headers_replace (SoupMessageHeaders *hdrs,
			      const char *name, const char *value)
{
	g_return_if_fail (hdrs);

	soup_message_headers_remove (hdrs, name);
	soup_message_headers_append (hdrs, name, value);
}

static int
find_common_header (GArray        *array,
                    SoupHeaderName name,
                    int            nth)
{
        SoupCommonHeader *hdr_array = (SoupCommonHeader *)array->data;
        int i;

        for (i = 0; i < array->len; i++) {
                if (hdr_array[i].name == name) {
                        if (nth-- == 0)
                                return i;
                }
        }
        return -1;
}

static int
find_uncommon_header (GArray     *array,
                      const char *name,
                      int         nth)
{
        SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)array->data;
	int i;

	for (i = 0; i < array->len; i++) {
                if (g_ascii_strcasecmp (hdr_array[i].name, name) == 0) {
			if (nth-- == 0)
				return i;
		}
	}
	return -1;
}

static int
find_last_common_header (GArray        *array,
                         SoupHeaderName name,
                         int            nth)
{
        SoupCommonHeader *hdr_array = (SoupCommonHeader *)array->data;
        int i;

        for (i = array->len - 1; i >= 0; i--) {
                if (hdr_array[i].name == name) {
                        if (nth-- == 0)
                                return i;
                }
        }
        return -1;
}

static int
find_last_uncommon_header (GArray     *array,
                           const char *name,
                           int         nth)
{
        SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)array->data;
	int i;

	for (i = array->len - 1; i >= 0; i--) {
                if (g_ascii_strcasecmp (hdr_array[i].name, name) == 0) {
			if (nth-- == 0)
				return i;
		}
	}
	return -1;
}

void
soup_message_headers_remove_common (SoupMessageHeaders *hdrs,
                                    SoupHeaderName      name)
{
        int index;

	g_return_if_fail (hdrs);

        if (hdrs->common_headers) {
                while ((index = find_common_header (hdrs->common_headers, name, 0)) != -1) {
#ifndef __clang_analyzer__ /* False positive for double-free */
                        SoupCommonHeader *hdr_array = (SoupCommonHeader *)hdrs->common_headers->data;

                        g_free (hdr_array[index].value);
#endif
                        g_array_remove_index (hdrs->common_headers, index);
                }
        }

        if (hdrs->common_concat)
                g_hash_table_remove (hdrs->common_concat, GUINT_TO_POINTER (name));

        soup_message_headers_set (hdrs, name, NULL);
}

/**
 * soup_message_headers_remove:
 * @hdrs: a #SoupMessageHeaders
 * @name: the header name to remove
 *
 * Removes @name from @hdrs.
 *
 * If there are multiple values for @name, they are all removed.
 **/
void
soup_message_headers_remove (SoupMessageHeaders *hdrs, const char *name)
{
	int index;
        SoupHeaderName header_name;

	g_return_if_fail (hdrs);
	g_return_if_fail (name != NULL);

        header_name = soup_header_name_from_string (name);
        if (header_name != SOUP_HEADER_UNKNOWN) {
                soup_message_headers_remove_common (hdrs, header_name);
                return;
        }

        if (hdrs->uncommon_headers) {
                while ((index = find_uncommon_header (hdrs->uncommon_headers, name, 0)) != -1) {
#ifndef __clang_analyzer__ /* False positive for double-free */
                        SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)hdrs->uncommon_headers->data;

                        g_free (hdr_array[index].name);
                        g_free (hdr_array[index].value);
#endif
                        g_array_remove_index (hdrs->uncommon_headers, index);
                }
        }

	if (hdrs->uncommon_concat)
		g_hash_table_remove (hdrs->uncommon_concat, name);
}

const char *
soup_message_headers_get_one_common (SoupMessageHeaders *hdrs,
                                     SoupHeaderName      name)
{
        SoupCommonHeader *hdr_array;
        int index;

        if (!hdrs->common_headers)
                return NULL;

        hdr_array = (SoupCommonHeader *)hdrs->common_headers->data;
        index = find_last_common_header (hdrs->common_headers, name, 0);

        return index == -1 ? NULL : hdr_array[index].value;
}

/**
 * soup_message_headers_get_one:
 * @hdrs: a #SoupMessageHeaders
 * @name: (in): header name
 * 
 * Gets the value of header @name in @hdrs.
 *
 * Use this for headers whose values are *not* comma-delimited lists, and which
 * therefore can only appear at most once in the headers. For list-valued
 * headers, use [method@MessageHeaders.get_list].
 *
 * If @hdrs does erroneously contain multiple copies of the header, it
 * is not defined which one will be returned. (Ideally, it will return
 * whichever one makes libsoup most compatible with other HTTP
 * implementations.)
 *
 * Returns: (nullable) (transfer none): the header's value or %NULL if not found.
 **/
const char *
soup_message_headers_get_one (SoupMessageHeaders *hdrs, const char *name)
{
        SoupUncommonHeader *hdr_array;
	int index;
        SoupHeaderName header_name;

	g_return_val_if_fail (hdrs, NULL);
	g_return_val_if_fail (name != NULL, NULL);

        header_name = soup_header_name_from_string (name);
        if (header_name != SOUP_HEADER_UNKNOWN)
                return soup_message_headers_get_one_common (hdrs, header_name);

        if (!hdrs->uncommon_headers)
                return NULL;

        hdr_array = (SoupUncommonHeader *)hdrs->uncommon_headers->data;
	index = find_last_uncommon_header (hdrs->uncommon_headers, name, 0);

	return (index == -1) ? NULL : hdr_array[index].value;
}

gboolean
soup_message_headers_header_contains_common (SoupMessageHeaders *hdrs,
                                             SoupHeaderName      name,
                                             const char         *token)
{
        const char *value;

        value = soup_message_headers_get_list_common (hdrs, name);
        return value ? soup_header_contains (value, token) : FALSE;
}

/**
 * soup_message_headers_header_contains:
 * @hdrs: a #SoupMessageHeaders
 * @name: header name
 * @token: token to look for
 *
 * Checks whether the list-valued header @name is present in @hdrs,
 * and contains a case-insensitive match for @token.
 *
 * (If @name is present in @hdrs, then this is equivalent to calling
 * [func@header_contains] on its value.)
 *
 * Returns: %TRUE if the header is present and contains @token,
 *   %FALSE otherwise.
 **/
gboolean
soup_message_headers_header_contains (SoupMessageHeaders *hdrs, const char *name, const char *token)
{
	const char *value;

	g_return_val_if_fail (hdrs, FALSE);

	value = soup_message_headers_get_list (hdrs, name);
	if (!value)
		return FALSE;
	return soup_header_contains (value, token);
}

gboolean
soup_message_headers_header_equals_common (SoupMessageHeaders *hdrs,
                                           SoupHeaderName      name,
                                           const char         *value)
{
        const char *internal_value;

        internal_value = soup_message_headers_get_list_common (hdrs, name);
        return internal_value ? g_ascii_strcasecmp (internal_value, value) == 0 : FALSE;
}

/**
 * soup_message_headers_header_equals:
 * @hdrs: a #SoupMessageHeaders
 * @name: header name
 * @value: expected value
 *
 * Checks whether the header @name is present in @hdrs and is
 * (case-insensitively) equal to @value.
 *
 * Returns: %TRUE if the header is present and its value is
 *   @value, %FALSE otherwise.
 **/
gboolean
soup_message_headers_header_equals (SoupMessageHeaders *hdrs, const char *name, const char *value)
{
        const char *internal_value;

	g_return_val_if_fail (hdrs, FALSE);

        internal_value = soup_message_headers_get_list (hdrs, name);
	if (!internal_value)
		return FALSE;
        return !g_ascii_strcasecmp (internal_value, value);
}

const char *
soup_message_headers_get_list_common (SoupMessageHeaders *hdrs,
                                      SoupHeaderName      name)
{
        SoupCommonHeader *hdr_array;
        GString *concat;
        char *value;
        int index, i;

	g_return_val_if_fail (hdrs, NULL);

        if (!hdrs->common_headers)
                return NULL;

        if (hdrs->common_concat) {
                value = g_hash_table_lookup (hdrs->common_concat, GUINT_TO_POINTER (name));
                if (value)
                        return value;
        }

        hdr_array = (SoupCommonHeader *)hdrs->common_headers->data;
        index = find_common_header (hdrs->common_headers, name, 0);
        if (index == -1)
                return NULL;

        if (find_common_header (hdrs->common_headers, name, 1) == -1)
                return hdr_array[index].value;

        concat = g_string_new (NULL);
        for (i = 0; (index = find_common_header (hdrs->common_headers, name, i)) != -1; i++) {
                if (i != 0)
                        g_string_append (concat, ", ");
                g_string_append (concat, hdr_array[index].value);
        }
        value = g_string_free (concat, FALSE);

        if (!hdrs->common_concat)
                hdrs->common_concat = g_hash_table_new_full (NULL, NULL, NULL, g_free);
        g_hash_table_insert (hdrs->common_concat, GUINT_TO_POINTER (name), value);
        return value;
}

/**
 * soup_message_headers_get_list:
 * @hdrs: a #SoupMessageHeaders
 * @name: header name
 * 
 * Gets the value of header @name in @hdrs.
 *
 * Use this for headers whose values are comma-delimited lists, and which are
 * therefore allowed to appear multiple times in the headers. For
 * non-list-valued headers, use [method@MessageHeaders.get_one].
 *
 * If @name appears multiple times in @hdrs,
 * [method@MessageHeaders.get_list] will concatenate all of the values
 * together, separated by commas. This is sometimes awkward to parse
 * (eg, WWW-Authenticate, Set-Cookie), but you have to be able to deal
 * with it anyway, because the HTTP spec explicitly states that this
 * transformation is allowed, and so an upstream proxy could do the
 * same thing.
 * 
 * Returns: (nullable) (transfer none): the header's value or %NULL if not found.
 **/
const char *
soup_message_headers_get_list (SoupMessageHeaders *hdrs, const char *name)
{
        SoupUncommonHeader *hdr_array;
	GString *concat;
	char *value;
	int index, i;
        SoupHeaderName header_name;

	g_return_val_if_fail (hdrs, NULL);
	g_return_val_if_fail (name != NULL, NULL);

        header_name = soup_header_name_from_string (name);
        if (header_name != SOUP_HEADER_UNKNOWN)
                return soup_message_headers_get_list_common (hdrs, header_name);

        if (!hdrs->uncommon_headers)
                return NULL;

	if (hdrs->uncommon_concat) {
		value = g_hash_table_lookup (hdrs->uncommon_concat, name);
		if (value)
			return value;
	}

	index = find_uncommon_header (hdrs->uncommon_headers, name, 0);
	if (index == -1)
		return NULL;

        hdr_array = (SoupUncommonHeader *)hdrs->uncommon_headers->data;
        if (find_uncommon_header (hdrs->uncommon_headers, name, 1) == -1)
		return hdr_array[index].value;

	concat = g_string_new (NULL);
	for (i = 0; (index = find_uncommon_header (hdrs->uncommon_headers, name, i)) != -1; i++) {
		if (i != 0)
			g_string_append (concat, ", ");
		g_string_append (concat, hdr_array[index].value);
	}
	value = g_string_free (concat, FALSE);

	if (!hdrs->uncommon_concat)
		hdrs->uncommon_concat = g_hash_table_new_full (soup_str_case_hash,
                                                               soup_str_case_equal,
                                                               g_free, g_free);
	g_hash_table_insert (hdrs->uncommon_concat, g_strdup (name), value);
	return value;
}

/**
 * SoupMessageHeadersIter:
 *
 * An opaque type used to iterate over a [struct@MessageHeaders] structure
 *
 * After intializing the iterator with [func@MessageHeadersIter.init], call
 * [method@MessageHeadersIter.next] to fetch data from it.
 *
 * You may not modify the headers while iterating over them.
 **/

typedef struct {
	SoupMessageHeaders *hdrs;
        int index_common;
	int index_uncommon;
} SoupMessageHeadersIterReal;

/**
 * soup_message_headers_iter_init:
 * @iter: (out) (transfer none): a pointer to a #SoupMessageHeadersIter structure
 * @hdrs: a #SoupMessageHeaders
 *
 * Initializes @iter for iterating @hdrs.
 **/
void
soup_message_headers_iter_init (SoupMessageHeadersIter *iter,
				SoupMessageHeaders *hdrs)
{
	SoupMessageHeadersIterReal *real = (SoupMessageHeadersIterReal *)iter;

	real->hdrs = hdrs;
        real->index_common = 0;
	real->index_uncommon = 0;
}

/**
 * soup_message_headers_iter_next:
 * @iter: (inout) (transfer none): a #SoupMessageHeadersIter
 * @name: (out) (transfer none): pointer to a variable to return
 *   the header name in
 * @value: (out) (transfer none): pointer to a variable to return
 *   the header value in
 *
 * Yields the next name/value pair in the [struct@MessageHeaders] being
 * iterated by @iter.
 *
 * If @iter has already yielded the last header, then
 * [method@MessageHeadersIter.next] will return %FALSE and @name and @value
 * will be unchanged.
 *
 * Returns: %TRUE if another name and value were returned, %FALSE
 *   if the end of the headers has been reached.
 **/
gboolean
soup_message_headers_iter_next (SoupMessageHeadersIter *iter,
				const char **name, const char **value)
{
	SoupMessageHeadersIterReal *real = (SoupMessageHeadersIterReal *)iter;

	g_return_val_if_fail (iter, FALSE);

        if (real->hdrs->common_headers &&
            real->index_common < real->hdrs->common_headers->len) {
                SoupCommonHeader *hdr_array = (SoupCommonHeader *)real->hdrs->common_headers->data;

                *name = soup_header_name_to_string (hdr_array[real->index_common].name);
                *value = hdr_array[real->index_common].value;
                real->index_common++;
                return TRUE;
        }

        if (real->hdrs->uncommon_headers &&
            real->index_uncommon < real->hdrs->uncommon_headers->len) {
                SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)real->hdrs->uncommon_headers->data;

                *name = hdr_array[real->index_uncommon].name;
                *value = hdr_array[real->index_uncommon].value;
                real->index_uncommon++;
                return TRUE;
        }

        return FALSE;
}

/**
 * SoupMessageHeadersForeachFunc:
 * @name: the header name
 * @value: the header value
 * @user_data: the data passed to [method@MessageHeaders.foreach]
 *
 * The callback passed to [method@MessageHeaders.foreach].
 **/

/**
 * soup_message_headers_foreach:
 * @hdrs: a #SoupMessageHeaders
 * @func: (scope call): callback function to run for each header
 * @user_data: data to pass to @func
 * 
 * Calls @func once for each header value in @hdrs.
 *
 * Beware that unlike [method@MessageHeaders.get_list], this processes the
 * headers in exactly the way they were added, rather than
 * concatenating multiple same-named headers into a single value.
 * (This is intentional; it ensures that if you call
 * [method@MessageHeaders.append] multiple times with the same name,
 * then the I/O code will output multiple copies of the header when
 * sending the message to the remote implementation, which may be
 * required for interoperability in some cases.)
 *
 * You may not modify the headers from @func.
 **/
void
soup_message_headers_foreach (SoupMessageHeaders           *hdrs,
			      SoupMessageHeadersForeachFunc func,
			      gpointer                      user_data)
{
	guint i;

	g_return_if_fail (hdrs);

        if (hdrs->common_headers) {
                SoupCommonHeader *hdr_array = (SoupCommonHeader *)hdrs->common_headers->data;

                for (i = 0; i < hdrs->common_headers->len; i++)
                        func (soup_header_name_to_string (hdr_array[i].name), hdr_array[i].value, user_data);
        }

        if (hdrs->uncommon_headers) {
                SoupUncommonHeader *hdr_array = (SoupUncommonHeader *)hdrs->uncommon_headers->data;

                for (i = 0; i < hdrs->uncommon_headers->len; i++)
                        func (hdr_array[i].name, hdr_array[i].value, user_data);
        }
}

/* Specific headers */

/**
 * SoupEncoding:
 * @SOUP_ENCODING_UNRECOGNIZED: unknown / error
 * @SOUP_ENCODING_NONE: no body is present (which is not the same as a
 *   0-length body, and only occurs in certain places)
 * @SOUP_ENCODING_CONTENT_LENGTH: Content-Length encoding
 * @SOUP_ENCODING_EOF: Response body ends when the connection is closed
 * @SOUP_ENCODING_CHUNKED: chunked encoding (currently only supported
 *   for response)
 * @SOUP_ENCODING_BYTERANGES: multipart/byteranges (Reserved for future
 *   use: NOT CURRENTLY IMPLEMENTED)
 *
 * How a message body is encoded for transport
 **/

/**
 * soup_message_headers_get_encoding:
 * @hdrs: a #SoupMessageHeaders
 *
 * Gets the message body encoding that @hdrs declare.
 *
 * This may not always correspond to the encoding used on the wire; eg, a HEAD
 * response may declare a Content-Length or Transfer-Encoding, but it will never
 * actually include a body.
 *
 * Returns: the encoding declared by @hdrs.
 **/
SoupEncoding
soup_message_headers_get_encoding (SoupMessageHeaders *hdrs)
{
	const char *header;

	g_return_val_if_fail (hdrs, SOUP_ENCODING_UNRECOGNIZED);

	if (hdrs->encoding != -1)
		return hdrs->encoding;

	/* If Transfer-Encoding was set, hdrs->encoding would already
	 * be set. So we don't need to check that possibility.
	 */
	header = soup_message_headers_get_one_common (hdrs, SOUP_HEADER_CONTENT_LENGTH);
	if (header) {
                soup_message_headers_set (hdrs, SOUP_HEADER_CONTENT_LENGTH, header);
		if (hdrs->encoding != -1)
			return hdrs->encoding;
	}

	/* Per RFC 2616 4.4, a response body that doesn't indicate its
	 * encoding otherwise is terminated by connection close, and a
	 * request that doesn't indicate otherwise has no body. Note
	 * that SoupMessage calls soup_message_headers_set_encoding()
	 * to override the response body default for our own
	 * server-side messages.
	 */
	hdrs->encoding = (hdrs->type == SOUP_MESSAGE_HEADERS_RESPONSE) ?
		SOUP_ENCODING_EOF : SOUP_ENCODING_NONE;
	return hdrs->encoding;
}

/**
 * soup_message_headers_set_encoding:
 * @hdrs: a #SoupMessageHeaders
 * @encoding: a #SoupEncoding
 *
 * Sets the message body encoding that @hdrs will declare.
 *
 * In particular, you should use this if you are going to send a request or
 * response in chunked encoding.
 **/
void
soup_message_headers_set_encoding (SoupMessageHeaders *hdrs,
				   SoupEncoding        encoding)
{
	g_return_if_fail (hdrs);

	if (encoding == hdrs->encoding)
		return;

	switch (encoding) {
	case SOUP_ENCODING_NONE:
	case SOUP_ENCODING_EOF:
		soup_message_headers_remove_common (hdrs, SOUP_HEADER_TRANSFER_ENCODING);
		soup_message_headers_remove_common (hdrs, SOUP_HEADER_CONTENT_LENGTH);
		break;

	case SOUP_ENCODING_CONTENT_LENGTH:
		soup_message_headers_remove_common (hdrs, SOUP_HEADER_TRANSFER_ENCODING);
		break;

	case SOUP_ENCODING_CHUNKED:
		soup_message_headers_remove_common (hdrs, SOUP_HEADER_CONTENT_LENGTH);
		soup_message_headers_replace_common (hdrs, SOUP_HEADER_TRANSFER_ENCODING, "chunked");
		break;

	default:
		g_return_if_reached ();
	}

	hdrs->encoding = encoding;
}

/**
 * soup_message_headers_get_content_length:
 * @hdrs: a #SoupMessageHeaders
 *
 * Gets the message body length that @hdrs declare.
 *
 * This will only be non-0 if [method@MessageHeaders.get_encoding] returns
 * %SOUP_ENCODING_CONTENT_LENGTH.
 *
 * Returns: the message body length declared by @hdrs.
 **/
goffset
soup_message_headers_get_content_length (SoupMessageHeaders *hdrs)
{
	SoupEncoding encoding;

	g_return_val_if_fail (hdrs, 0);

	encoding = soup_message_headers_get_encoding (hdrs);
	if (encoding == SOUP_ENCODING_CONTENT_LENGTH)
		return hdrs->content_length;
	else
		return 0;
}

/**
 * soup_message_headers_set_content_length:
 * @hdrs: a #SoupMessageHeaders
 * @content_length: the message body length
 *
 * Sets the message body length that @hdrs will declare, and sets
 * @hdrs's encoding to %SOUP_ENCODING_CONTENT_LENGTH.
 *
 * You do not normally need to call this; if @hdrs is set to use
 * Content-Length encoding, libsoup will automatically set its
 * Content-Length header for you immediately before sending the
 * headers. One situation in which this method is useful is when
 * generating the response to a HEAD request; Calling
 * [method@MessageHeaders.set_content_length] allows you to put the
 * correct content length into the response without needing to waste
 * memory by filling in a response body which won't actually be sent.
 **/
void
soup_message_headers_set_content_length (SoupMessageHeaders *hdrs,
					 goffset             content_length)
{
	char length[128];

	g_return_if_fail (hdrs);

	g_snprintf (length, sizeof (length), "%" G_GUINT64_FORMAT,
		    content_length);
	soup_message_headers_remove_common (hdrs, SOUP_HEADER_TRANSFER_ENCODING);
	soup_message_headers_replace_common (hdrs, SOUP_HEADER_CONTENT_LENGTH, length);
}

/**
 * SoupExpectation:
 * @SOUP_EXPECTATION_CONTINUE: "100-continue"
 * @SOUP_EXPECTATION_UNRECOGNIZED: any unrecognized expectation
 *
 * Represents the parsed value of the "Expect" header.
 **/

/**
 * soup_message_headers_get_expectations:
 * @hdrs: a #SoupMessageHeaders
 *
 * Gets the expectations declared by @hdrs's "Expect" header.
 *
 * Currently this will either be %SOUP_EXPECTATION_CONTINUE or
 * %SOUP_EXPECTATION_UNRECOGNIZED.
 *
 * Returns: the contents of @hdrs's "Expect" header
 **/
SoupExpectation
soup_message_headers_get_expectations (SoupMessageHeaders *hdrs)
{
	g_return_val_if_fail (hdrs, SOUP_EXPECTATION_UNRECOGNIZED);

	return hdrs->expectations;
}

/**
 * soup_message_headers_set_expectations:
 * @hdrs: a #SoupMessageHeaders
 * @expectations: the expectations to set
 *
 * Sets @hdrs's "Expect" header according to @expectations.
 *
 * Currently %SOUP_EXPECTATION_CONTINUE is the only known expectation
 * value. You should set this value on a request if you are sending a
 * large message body (eg, via POST or PUT), and want to give the
 * server a chance to reject the request after seeing just the headers
 * (eg, because it will require authentication before allowing you to
 * post, or because you're POSTing to a URL that doesn't exist). This
 * saves you from having to transmit the large request body when the
 * server is just going to ignore it anyway.
 **/
void
soup_message_headers_set_expectations (SoupMessageHeaders *hdrs,
				       SoupExpectation     expectations)
{
	g_return_if_fail ((expectations & ~SOUP_EXPECTATION_CONTINUE) == 0);

	if (expectations & SOUP_EXPECTATION_CONTINUE)
		soup_message_headers_replace_common (hdrs, SOUP_HEADER_EXPECT, "100-continue");
	else
		soup_message_headers_remove_common (hdrs, SOUP_HEADER_EXPECT);
}

/**
 * SoupRange:
 * @start: the start of the range
 * @end: the end of the range
 *
 * Represents a byte range as used in the Range header.
 *
 * If @end is non-negative, then @start and @end represent the bounds
 * of of the range, counting from 0. (Eg, the first 500 bytes would be
 * represented as @start = 0 and @end = 499.)
 *
 * If @end is -1 and @start is non-negative, then this represents a
 * range starting at @start and ending with the last byte of the
 * requested resource body. (Eg, all but the first 500 bytes would be
 * @start = 500, and @end = -1.)
 *
 * If @end is -1 and @start is negative, then it represents a "suffix
 * range", referring to the last -@start bytes of the resource body.
 * (Eg, the last 500 bytes would be @start = -500 and @end = -1.)
 **/

static int
sort_ranges (gconstpointer a, gconstpointer b)
{
	SoupRange *ra = (SoupRange *)a;
	SoupRange *rb = (SoupRange *)b;

	return ra->start - rb->start;
}

/* like soup_message_headers_get_ranges(), except it returns:
 *   SOUP_STATUS_OK if there is no Range or it should be ignored.
 *   SOUP_STATUS_PARTIAL_CONTENT if there is at least one satisfiable range.
 *   SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE if @check_satisfiable
 *     is %TRUE and the request is not satisfiable given @total_length.
 */
guint
soup_message_headers_get_ranges_internal (SoupMessageHeaders  *hdrs,
					  goffset              total_length,
					  gboolean             check_satisfiable,
					  SoupRange          **ranges,
					  int                 *length)
{
	const char *range = soup_message_headers_get_one_common (hdrs, SOUP_HEADER_RANGE);
	GSList *range_list, *r;
	GArray *array;
	char *spec, *end;
	guint status = SOUP_STATUS_OK;

	if (!range || strncmp (range, "bytes", 5) != 0)
		return status;

	range += 5;
	while (g_ascii_isspace (*range))
		range++;
	if (*range++ != '=')
		return status;
	while (g_ascii_isspace (*range))
		range++;

	range_list = soup_header_parse_list (range);
	if (!range_list)
		return status;

	array = g_array_new (FALSE, FALSE, sizeof (SoupRange));
	for (r = range_list; r; r = r->next) {
		SoupRange cur;

		spec = r->data;
		if (*spec == '-') {
			cur.start = g_ascii_strtoll (spec, &end, 10) + total_length;
			cur.end = total_length - 1;
		} else {
			cur.start = g_ascii_strtoull (spec, &end, 10);
			if (*end == '-')
				end++;
			if (*end) {
				cur.end = g_ascii_strtoull (end, &end, 10);
				if (cur.end < cur.start) {
					status = SOUP_STATUS_OK;
					break;
				}
			} else
				cur.end = total_length - 1;
		}
		if (*end) {
			status = SOUP_STATUS_OK;
			break;
		} else if (check_satisfiable && cur.start >= total_length) {
			if (status == SOUP_STATUS_OK)
				status = SOUP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE;
			continue;
		}

		g_array_append_val (array, cur);
		status = SOUP_STATUS_PARTIAL_CONTENT;
	}
	soup_header_free_list (range_list);

	if (status != SOUP_STATUS_PARTIAL_CONTENT) {
		g_array_free (array, TRUE);
		return status;
	}

	if (total_length) {
		guint i;

		g_array_sort (array, sort_ranges);
		for (i = 1; i < array->len; i++) {
			SoupRange *cur = &((SoupRange *)array->data)[i];
			SoupRange *prev = &((SoupRange *)array->data)[i - 1];

			if (cur->start <= prev->end) {
				prev->end = MAX (prev->end, cur->end);
				g_array_remove_index (array, i);
				i--;
			}
		}
	}

	*ranges = (SoupRange *)array->data;
	*length = array->len;

	g_array_free (array, FALSE);
	return SOUP_STATUS_PARTIAL_CONTENT;
}

/**
 * soup_message_headers_get_ranges:
 * @hdrs: a #SoupMessageHeaders
 * @total_length: the total_length of the response body
 * @ranges: (out) (array length=length): return location for an array
 *   of #SoupRange
 * @length: the length of the returned array
 *
 * Parses @hdrs's Range header and returns an array of the requested
 * byte ranges.
 *
 * The returned array must be freed with [method@MessageHeaders.free_ranges].
 *
 * If @total_length is non-0, its value will be used to adjust the
 * returned ranges to have explicit start and end values, and the
 * returned ranges will be sorted and non-overlapping. If
 * @total_length is 0, then some ranges may have an end value of -1,
 * as described under [struct@Range], and some of the ranges may be
 * redundant.
 *
 * Beware that even if given a @total_length, this function does not
 * check that the ranges are satisfiable.
 *
 * [class@Server] has built-in handling for range requests. If your
 * server handler returns a %SOUP_STATUS_OK response containing the
 * complete response body (rather than pausing the message and
 * returning some of the response body later), and there is a Range
 * header in the request, then libsoup will automatically convert the
 * response to a %SOUP_STATUS_PARTIAL_CONTENT response containing only
 * the range(s) requested by the client.
 *
 * The only time you need to process the Range header yourself is if
 * either you need to stream the response body rather than returning
 * it all at once, or you do not already have the complete response
 * body available, and only want to generate the parts that were
 * actually requested by the client.
 *
 * Returns: %TRUE if @hdrs contained a syntactically-valid
 *   "Range" header, %FALSE otherwise (in which case @range and @length
 *   will not be set).
 **/
gboolean
soup_message_headers_get_ranges (SoupMessageHeaders  *hdrs,
				 goffset              total_length,
				 SoupRange          **ranges,
				 int                 *length)
{
	guint status;

	g_return_val_if_fail (hdrs, FALSE);

	status = soup_message_headers_get_ranges_internal (hdrs, total_length, FALSE, ranges, length);
	return status == SOUP_STATUS_PARTIAL_CONTENT;
}

/**
 * soup_message_headers_free_ranges:
 * @hdrs: a #SoupMessageHeaders
 * @ranges: an array of #SoupRange
 *
 * Frees the array of ranges returned from [method@MessageHeaders.get_ranges].
 **/
void
soup_message_headers_free_ranges (SoupMessageHeaders  *hdrs,
				  SoupRange           *ranges)
{
	g_free (ranges);
}

/**
 * soup_message_headers_set_ranges:
 * @hdrs: a #SoupMessageHeaders
 * @ranges: an array of #SoupRange
 * @length: the length of @range
 *
 * Sets @hdrs's Range header to request the indicated ranges.
 *
 * If you only want to request a single range, you can use
 * [method@MessageHeaders.set_range].
 **/
void
soup_message_headers_set_ranges (SoupMessageHeaders  *hdrs,
				 SoupRange           *ranges,
				 int                  length)
{
	GString *header;
	int i;

	g_return_if_fail (hdrs);

	header = g_string_new ("bytes=");
	for (i = 0; i < length; i++) {
		if (i > 0)
			g_string_append_c (header, ',');
		if (ranges[i].end >= 0) {
			g_string_append_printf (header, "%" G_GINT64_FORMAT "-%" G_GINT64_FORMAT,
						ranges[i].start, ranges[i].end);
		} else if (ranges[i].start >= 0) {
			g_string_append_printf (header,"%" G_GINT64_FORMAT "-",
						ranges[i].start);
		} else {
			g_string_append_printf (header, "%" G_GINT64_FORMAT,
						ranges[i].start);
		}
	}

	soup_message_headers_replace_common (hdrs, SOUP_HEADER_RANGE, header->str);
	g_string_free (header, TRUE);
}

/**
 * soup_message_headers_set_range:
 * @hdrs: a #SoupMessageHeaders
 * @start: the start of the range to request
 * @end: the end of the range to request
 *
 * Sets @hdrs's Range header to request the indicated range.
 *
 * @start and @end are interpreted as in a [struct@Range].
 *
 * If you need to request multiple ranges, use
 * [method@MessageHeaders.set_ranges].
 **/
void
soup_message_headers_set_range (SoupMessageHeaders  *hdrs,
				goffset              start,
				goffset              end)
{
	SoupRange range;

	g_return_if_fail (hdrs);

	range.start = start;
	range.end = end;
	soup_message_headers_set_ranges (hdrs, &range, 1);
}

/**
 * soup_message_headers_get_content_range:
 * @hdrs: a #SoupMessageHeaders
 * @start: (out): return value for the start of the range
 * @end: (out): return value for the end of the range
 * @total_length: (out) (optional): return value for the total length of the
 *   resource, or %NULL if you don't care.
 *
 * Parses @hdrs's Content-Range header and returns it in @start,
 * @end, and @total_length. If the total length field in the header
 * was specified as "*", then @total_length will be set to -1.
 *
 * Returns: %TRUE if @hdrs contained a "Content-Range" header
 *   containing a byte range which could be parsed, %FALSE otherwise.
 **/
gboolean
soup_message_headers_get_content_range (SoupMessageHeaders  *hdrs,
					goffset             *start,
					goffset             *end,
					goffset             *total_length)
{
	const char *header;
	goffset length;
	char *p;

	g_return_val_if_fail (hdrs, FALSE);

        header = soup_message_headers_get_one_common (hdrs, SOUP_HEADER_CONTENT_RANGE);

	if (!header || strncmp (header, "bytes ", 6) != 0)
		return FALSE;

	header += 6;
	while (g_ascii_isspace (*header))
		header++;
	if (!g_ascii_isdigit (*header))
		return FALSE;

	*start = g_ascii_strtoull (header, &p, 10);
	if (*p != '-')
		return FALSE;
	*end = g_ascii_strtoull (p + 1, &p, 10);
	if (*p != '/')
		return FALSE;
	p++;
	if (*p == '*') {
		length = -1;
		p++;
	} else
		length = g_ascii_strtoull (p, &p, 10);

	if (total_length)
		*total_length = length;
	return *p == '\0';
}

/**
 * soup_message_headers_set_content_range:
 * @hdrs: a #SoupMessageHeaders
 * @start: the start of the range
 * @end: the end of the range
 * @total_length: the total length of the resource, or -1 if unknown
 *
 * Sets @hdrs's Content-Range header according to the given values.
 *
 * (Note that @total_length is the total length of the entire resource
 * that this is a range of, not simply @end - @start + 1.)
 *
 * [class@Server] has built-in handling for range requests, and you do
 * not normally need to call this function youself. See
 * [method@MessageHeaders.get_ranges] for more details.
 **/
void
soup_message_headers_set_content_range (SoupMessageHeaders  *hdrs,
					goffset              start,
					goffset              end,
					goffset              total_length)
{
	char *header;

	g_return_if_fail (hdrs);

	if (total_length >= 0) {
		header = g_strdup_printf ("bytes %" G_GINT64_FORMAT "-%"
					  G_GINT64_FORMAT "/%" G_GINT64_FORMAT,
					  start, end, total_length);
	} else {
		header = g_strdup_printf ("bytes %" G_GINT64_FORMAT "-%"
					  G_GINT64_FORMAT "/*", start, end);
	}
	soup_message_headers_replace_common (hdrs, SOUP_HEADER_CONTENT_RANGE, header);
	g_free (header);
}

static gboolean
parse_content_foo (SoupMessageHeaders *hdrs,
                   SoupHeaderName      header_name,
		   char              **foo,
                   GHashTable        **params)
{
	const char *header;
	char *semi;
        char *equal;

	header = soup_message_headers_get_one_common (hdrs, header_name);
	if (!header)
		return FALSE;

        /* Some websites send an invalid disposition that only contains parameters;
         * We can be flexible about handling these by detecting if the first word
         * is a parameter (foo=bar). */
        equal = strchr (header, '=');
        semi = strchr (header, ';');
        if (header_name == SOUP_HEADER_CONTENT_DISPOSITION &&
            (equal && (!semi || (equal < semi)))) {
                semi = (char *)header;
                if (foo)
                        *foo = NULL;
        } else if (foo) {
                *foo = g_strdup (header);
                semi = strchr (*foo, ';');
                if (semi) {
                        char *p = semi;

                        *semi++ = '\0';
                        while (p - 1 > *foo && g_ascii_isspace(p[-1]))
                                *(--p) = '\0';
                }
        } else {
                /* Skip type, we don't store it */
                if (semi)
                        semi++;
        }

	if (!params)
		return TRUE;

	if (!semi) {
		*params = soup_header_parse_semi_param_list ("");
		return TRUE;
	}

	*params = soup_header_parse_semi_param_list (semi);
	return TRUE;
}

static void
set_content_foo (SoupMessageHeaders *hdrs,
                 SoupHeaderName      header_name,
		 const char         *foo,
                 GHashTable         *params)
{
	GString *str;
	GHashTableIter iter;
	gpointer key, value;

	str = g_string_new (foo);
	if (params) {
		g_hash_table_iter_init (&iter, params);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			g_string_append (str, "; ");
			soup_header_g_string_append_param (str, key, value);
		}
	}

	soup_message_headers_replace_common (hdrs, header_name, str->str);
	g_string_free (str, TRUE);
}

/**
 * soup_message_headers_get_content_type:
 * @hdrs: a #SoupMessageHeaders
 * @params: (out) (element-type utf8 utf8) (optional) (transfer full):
 *   return location for the Content-Type parameters (eg, "charset"), or
 *   %NULL
 *
 * Looks up the "Content-Type" header in @hdrs, parses it, and returns
 * its value in *@content_type and *@params.
 *
 * @params can be %NULL if you are only interested in the content type itself.
 *
 * Returns: (nullable): a string with the value of the
 *   "Content-Type" header or %NULL if @hdrs does not contain that
 *   header or it cannot be parsed (in which case *@params will be
 *   unchanged).
 **/
const char *
soup_message_headers_get_content_type (SoupMessageHeaders  *hdrs,
				       GHashTable         **params)
{
	g_return_val_if_fail (hdrs, NULL);

	if (!hdrs->content_type)
		return NULL;

	if (params)
		parse_content_foo (hdrs, SOUP_HEADER_CONTENT_TYPE, NULL, params);
	return hdrs->content_type;
}

/**
 * soup_message_headers_set_content_type:
 * @hdrs: a #SoupMessageHeaders
 * @content_type: the MIME type
 * @params: (nullable) (element-type utf8 utf8): additional parameters
 *
 * Sets the "Content-Type" header in @hdrs to @content_type.
 *
 * Accepts additional parameters specified in @params.
 **/
void
soup_message_headers_set_content_type (SoupMessageHeaders  *hdrs,
				       const char          *content_type,
				       GHashTable          *params)
{
	g_return_if_fail (hdrs);

	set_content_foo (hdrs, SOUP_HEADER_CONTENT_TYPE, content_type, params);
}

/**
 * soup_message_headers_get_content_disposition:
 * @hdrs: a #SoupMessageHeaders
 * @disposition: (out) (transfer full): return location for the
 *   disposition-type, or %NULL
 * @params: (out) (transfer full) (element-type utf8 utf8): return
 *   location for the Content-Disposition parameters, or %NULL
 *
 * Looks up the "Content-Disposition" header in @hdrs, parses it, and
 * returns its value in *@disposition and *@params.
 *
 * @params can be %NULL if you are only interested in the disposition-type.
 *
 * In HTTP, the most common use of this header is to set a
 * disposition-type of "attachment", to suggest to the browser that a
 * response should be saved to disk rather than displayed in the
 * browser. If @params contains a "filename" parameter, this is a
 * suggestion of a filename to use. (If the parameter value in the
 * header contains an absolute or relative path, libsoup will truncate
 * it down to just the final path component, so you do not need to
 * test this yourself.)
 *
 * Content-Disposition is also used in "multipart/form-data", however
 * this is handled automatically by [struct@Multipart] and the associated
 * form methods.
 *
 * Returns: %TRUE if @hdrs contains a "Content-Disposition"
 *   header, %FALSE if not (in which case *@disposition and *@params
 *   will be unchanged).
 **/
gboolean
soup_message_headers_get_content_disposition (SoupMessageHeaders  *hdrs,
					      char               **disposition,
					      GHashTable         **params)
{
	gpointer orig_key, orig_value;

	g_return_val_if_fail (hdrs, FALSE);

	if (!parse_content_foo (hdrs, SOUP_HEADER_CONTENT_DISPOSITION,
				disposition, params))
		return FALSE;

	/* If there is a filename parameter, make sure it contains
	 * only a single path component
	 */
	if (params && g_hash_table_lookup_extended (*params, "filename",
						    &orig_key, &orig_value)) {
                if (orig_value) {
                        char *filename = strrchr (orig_value, '/');

                        if (filename)
                                g_hash_table_insert (*params, g_strdup (orig_key), g_strdup (filename + 1));
                } else {
                        /* filename with no value isn't valid. */
                        g_hash_table_remove (*params, "filename");
                }
	}
	return TRUE;
}

/**
 * soup_message_headers_set_content_disposition:
 * @hdrs: a #SoupMessageHeaders
 * @disposition: the disposition-type
 * @params: (nullable) (element-type utf8 utf8): additional parameters
 *
 * Sets the "Content-Disposition" header in @hdrs to @disposition,
 * optionally with additional parameters specified in @params.
 *
 * See [method@MessageHeaders.get_content_disposition] for a discussion
 * of how Content-Disposition is used in HTTP.
 **/
void
soup_message_headers_set_content_disposition (SoupMessageHeaders  *hdrs,
					      const char          *disposition,
					      GHashTable          *params)
{
	g_return_if_fail (hdrs && disposition);

	set_content_foo (hdrs, SOUP_HEADER_CONTENT_DISPOSITION, disposition, params);
}

