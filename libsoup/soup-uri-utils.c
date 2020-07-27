/* soup-uri-utils.c
 *
 * Copyright 2020 Igalia S.L.
 * Copyright 1999-2003 Ximian, Inc.
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>

#include <glib/gi18n-lib.h>

#include "soup-uri-utils.h"
#include "soup.h"
#include "soup-misc.h"

/**
 * SECTION:soup-uri-utils
 * @section_id: SoupURIUtils
 * @title: URI Utilities
 * @short_description: Functions to help working with #GUri and HTTP
 *
 * Utility functions and defines to help working with URIs.
 */

/**
 * SOUP_HTTP_URI_FLAGS:
 *
 * The set of #GUriFlags libsoup expects all #GUri to use.
 */

static inline int
soup_scheme_default_port (const char *scheme)
{
        if (!g_strcmp0 (scheme, "http") ||
            !g_strcmp0 (scheme, "ws"))
		return 80;
	else if (!g_strcmp0 (scheme, "https") ||
                 !g_strcmp0 (scheme, "wss"))
		return 443;
	else if (!g_strcmp0 (scheme, "ftp"))
		return 21;
	else
		return -1;
}

static inline gboolean
parts_equal (const char *one, const char *two, gboolean insensitive)
{
	if (!one && !two)
		return TRUE;
	if (!one || !two)
		return FALSE;
	return insensitive ? !g_ascii_strcasecmp (one, two) : !strcmp (one, two);
}

static inline gboolean
path_equal (const char *one, const char *two)
{
        if (one[0] == '\0')
                one = "/";
        if (two[0] == '\0')
                two = "/";

	return !strcmp (one, two);
}

/**
 * soup_uri_get_port_with_default:
 * @uri: A #GUri
 *
 * If @uri has a port of `-1` this will return the default
 * port for the sheme it uses if known.
 *
 * Returns: The port to use with the @uri or `-1` if unknown.
 */
int
soup_uri_get_port_with_default (GUri *uri)
{
        int port = g_uri_get_port (uri);
        if (port != -1)
                return port;

        return soup_scheme_default_port (g_uri_get_scheme (uri));
}

static gboolean
flags_equal (GUriFlags flags1, GUriFlags flags2)
{
        /* We only care about flags that affect the contents which these do */
        static const GUriFlags normalization_flags = (G_URI_FLAGS_ENCODED | G_URI_FLAGS_ENCODED_FRAGMENT |
                                                      G_URI_FLAGS_ENCODED_PATH | G_URI_FLAGS_ENCODED_QUERY |
                                                      G_URI_FLAGS_SCHEME_NORMALIZE);

        return (flags1 & normalization_flags) == (flags2 & normalization_flags);
}

/**
 * soup_uri_equal:
 * @uri1: a #GUri
 * @uri2: another #GUri
 *
 * Tests whether or not @uri1 and @uri2 are equal in all parts
 *
 * Returns: %TRUE if equal otherwise %FALSE
 **/
gboolean
soup_uri_equal (GUri *uri1, GUri *uri2)
{
     	g_return_val_if_fail (uri1 != NULL, FALSE);
	g_return_val_if_fail (uri2 != NULL, FALSE);

       	if (!flags_equal (g_uri_get_flags (uri1), g_uri_get_flags (uri2))                  ||
            g_strcmp0 (g_uri_get_scheme (uri1), g_uri_get_scheme (uri2))                   ||
	    soup_uri_get_port_with_default (uri1) != soup_uri_get_port_with_default (uri2) ||
	    !parts_equal (g_uri_get_user (uri1), g_uri_get_user (uri2), FALSE)             ||
	    !parts_equal (g_uri_get_password (uri1), g_uri_get_password (uri2), FALSE)     ||
	    !parts_equal (g_uri_get_host (uri1), g_uri_get_host (uri2), TRUE)              ||
	    !path_equal (g_uri_get_path (uri1), g_uri_get_path (uri2))                     ||
	    !parts_equal (g_uri_get_query (uri1), g_uri_get_query (uri2), FALSE)           ||
	    !parts_equal (g_uri_get_fragment (uri1), g_uri_get_fragment (uri2), FALSE)) {
                return FALSE;
            }

        return TRUE;
}

char *
soup_uri_get_path_and_query (GUri *uri)
{
	g_return_val_if_fail (uri != NULL, NULL);

	return g_uri_join_with_user (SOUP_HTTP_URI_FLAGS,
				     NULL, NULL, NULL, NULL, NULL, -1,
				     g_uri_get_path (uri),
				     g_uri_get_query (uri),
				     NULL);
}

/**
 * soup_uri_uses_default_port:
 * @uri: a #GUri
 *
 * Tests if @uri uses the default port for its scheme. (Eg, 80 for
 * http.) (This only works for http, https and ftp; libsoup does not know
 * the default ports of other protocols.)
 *
 * Returns: %TRUE or %FALSE
 **/
gboolean
soup_uri_uses_default_port (GUri *uri)
{
        g_return_val_if_fail (uri != NULL, FALSE);

        if (g_uri_get_port (uri) == -1)
                return TRUE;

        if (g_uri_get_scheme (uri))
                return g_uri_get_port (uri) == soup_scheme_default_port (g_uri_get_scheme (uri));

        return FALSE;
}

static GUri *
soup_uri_copy_with_query (GUri *uri, const char *query)
{
        return g_uri_build_with_user (
                g_uri_get_flags (uri) | G_URI_FLAGS_ENCODED_QUERY,
                g_uri_get_scheme (uri),
                g_uri_get_user (uri),
                g_uri_get_password (uri),
                g_uri_get_auth_params (uri),
                g_uri_get_host (uri),
                g_uri_get_port (uri),
                g_uri_get_path (uri),
                query,
                g_uri_get_fragment (uri)
        );
}

/**
 * soup_uri_copy_with_query_from_form:
 * @uri: a #GUri
 * @form: (element-type utf8 utf8): a #GHashTable containing HTML form
 * information
 *
 * Sets @uri's query to the result of encoding @form according to the
 * HTML form rules. See soup_form_encode_hash() for more information.
 *
 * Returns: (transfer full): A new #GUri
 **/
GUri *
soup_uri_copy_with_query_from_form (GUri *uri, GHashTable *form)
{
	g_return_val_if_fail (uri != NULL, NULL);

        char *query = soup_form_encode_hash (form);
	GUri *new_uri = soup_uri_copy_with_query (uri, query);
        g_free (query);
	return new_uri;
}

/**
 * soup_uri_copy_with_query_from_fields:
 * @uri: a #GUri
 * @first_field: name of the first form field to encode into query
 * @...: value of @first_field, followed by additional field names
 * and values, terminated by %NULL.
 *
 * Sets @uri's query to the result of encoding the given form fields
 * and values according to the * HTML form rules. See
 * soup_form_encode() for more information.
 *
 * Returns: (transfer full): A new #GUri
 **/
GUri *
soup_uri_copy_with_query_from_fields (GUri       *uri,
                                      const char *first_field,
                                      ...)
{
	va_list args;

	g_return_val_if_fail (uri != NULL, NULL);

	va_start (args, first_field);
	char *query = soup_form_encode_valist (first_field, args);
	va_end (args);

	GUri *new_uri = soup_uri_copy_with_query (uri, query);
        g_free (query);
	return new_uri;
}

GUri *
soup_uri_copy_host (GUri *uri)
{
        g_return_val_if_fail (uri != NULL, NULL);

        return g_uri_build (g_uri_get_flags (uri),
                            g_uri_get_scheme (uri), NULL,
                            g_uri_get_host (uri),
                            g_uri_get_port (uri),
                            "/", NULL, NULL);
}

/**
 * soup_uri_host_hash:
 * @key: (type GUri): a #GUri with a non-%NULL @host member
 *
 * Hashes @key, considering only the scheme, host, and port.
 *
 * Returns: A hash
 */
guint
soup_uri_host_hash (gconstpointer key)
{
	GUri *uri = (GUri*)key;
        const char *host;

	g_return_val_if_fail (uri != NULL, 0);

        host = g_uri_get_host (uri);

	g_return_val_if_fail (host != NULL, 0);

	return soup_str_case_hash (g_uri_get_scheme (uri)) +
               g_uri_get_port (uri) +
	       soup_str_case_hash (host);
}

/**
 * soup_uri_host_equal:
 * @v1: (type GUri): a #GUri with a non-%NULL @host member
 * @v2: (type GUri): a #GUri with a non-%NULL @host member
 *
 * Compares @v1 and @v2, considering only the scheme, host, and port.
 *
 * Returns: %TRUE if the URIs are equal in scheme, host, and port.
 */
gboolean
soup_uri_host_equal (gconstpointer v1, gconstpointer v2)
{
	GUri *one = (GUri*)v1;
	GUri *two = (GUri*)v2;
        const char *one_host, *two_host;
        int one_port, two_port;

	g_return_val_if_fail (one != NULL && two != NULL, one == two);

        one_host = g_uri_get_host (one);
        two_host = g_uri_get_host (two);

	g_return_val_if_fail (one_host != NULL && two_host != NULL, one_host == two_host);

        if (one == two)
                return TRUE;
	if (g_strcmp0 (g_uri_get_scheme (one), g_uri_get_scheme (two)) != 0)
		return FALSE;

        one_port = g_uri_get_port (one);
        two_port = g_uri_get_port (two);

        if (one_port == -1 && g_uri_get_scheme (one))
                one_port = soup_scheme_default_port (g_uri_get_scheme (one));
        if (two_port == -1 && g_uri_get_scheme (two))
                two_port = soup_scheme_default_port (g_uri_get_scheme (two));

	if (one_port != two_port)
		return FALSE;

	return g_ascii_strcasecmp (one_host, two_host) == 0;
}

gboolean
soup_uri_is_https (GUri *uri, char **aliases)
{
	g_return_val_if_fail (uri != NULL, FALSE);

        const char *scheme = g_uri_get_scheme (uri);

        if (G_UNLIKELY (scheme == NULL))
                return FALSE;

        if (strcmp (scheme, "https") == 0 ||
            strcmp (scheme, "wss") == 0)
            return TRUE;
	else if (!aliases)
		return FALSE;

	for (int i = 0; aliases[i]; i++) {
		if (strcmp (scheme, aliases[i]) == 0)
			return TRUE;
	}

	return FALSE;
}

gboolean
soup_uri_is_http (GUri *uri, char **aliases)
{
	g_return_val_if_fail (uri != NULL, FALSE);

        const char *scheme = g_uri_get_scheme (uri);

        if (G_UNLIKELY (scheme == NULL))
                return FALSE;

        if (strcmp (scheme, "http") == 0 ||
            strcmp (scheme, "ws") == 0)
            return TRUE;
	else if (!aliases)
		return FALSE;

	for (int i = 0; aliases[i]; i++) {
		if (strcmp (scheme, aliases[i]) == 0)
			return TRUE;
	}

	return FALSE;
}

#define BASE64_INDICATOR     ";base64"
#define BASE64_INDICATOR_LEN (sizeof (";base64") - 1)

/**
 * soup_uri_decode_data_uri:
 * @uri: a data URI, in string form
 * @content_type: (out) (nullable) (transfer full): location to store content type, or %NULL
 *
 * Decodes the given data URI and returns its contents and @content_type.
 *
 * Returns: (transfer full): a #GBytes with the contents of @uri,
 *    or %NULL if @uri is not a valid data URI
 */
GBytes *
soup_uri_decode_data_uri (const char *uri,
                          char      **content_type)
{
        GUri *soup_uri;
        const char *comma, *start, *end;
        gboolean base64 = FALSE;
        char *uri_string;
        GBytes *bytes;

        g_return_val_if_fail (uri != NULL, NULL);

        soup_uri = g_uri_parse (uri, SOUP_HTTP_URI_FLAGS, NULL);
        if (!soup_uri)
                return NULL;

        if (g_strcmp0 (g_uri_get_scheme (soup_uri), "data") || g_uri_get_host (soup_uri) != NULL)
                return NULL;

        if (content_type)
                *content_type = NULL;

        uri_string = g_uri_to_string (soup_uri);
        g_uri_unref (soup_uri);

        start = uri_string + 5;
        comma = strchr (start, ',');
        if (comma && comma != start) {
                /* Deal with MIME type / params */
                if (comma >= start + BASE64_INDICATOR_LEN && !g_ascii_strncasecmp (comma - BASE64_INDICATOR_LEN, BASE64_INDICATOR, BASE64_INDICATOR_LEN)) {
                        end = comma - BASE64_INDICATOR_LEN;
                        base64 = TRUE;
                } else
                        end = comma;

                if (end != start && content_type)
                        *content_type = g_uri_unescape_segment (start, end, NULL);
        }

        if (content_type && !*content_type)
                *content_type = g_strdup ("text/plain;charset=US-ASCII");

        if (comma)
                start = comma + 1;

        if (*start) {
                bytes = g_uri_unescape_bytes (start, -1, NULL, NULL);

                if (base64 && bytes) {
                        gsize content_length;
                        GByteArray *unescaped_array = g_bytes_unref_to_array (bytes);
                        g_base64_decode_inplace ((gchar*)unescaped_array->data, &content_length);
                        unescaped_array->len = content_length;
                        bytes = g_byte_array_free_to_bytes (unescaped_array);
                }
        } else {
                bytes = g_bytes_new_static (NULL, 0);
        }
        g_free (uri_string);

        return bytes;
}

GUri *
soup_uri_copy_with_credentials (GUri *uri, const char *username, const char *password)
{
        g_return_val_if_fail (uri != NULL, NULL);

        return g_uri_build_with_user (
                g_uri_get_flags (uri) | G_URI_FLAGS_HAS_PASSWORD,
                g_uri_get_scheme (uri),
                username, password,
                g_uri_get_auth_params (uri),
                g_uri_get_host (uri),
                g_uri_get_port (uri),
                g_uri_get_path (uri),
                g_uri_get_query (uri),
                g_uri_get_fragment (uri)
        );
}

GUri *
soup_uri_copy_with_normalized_flags (GUri *uri)
{
        GUriFlags flags = g_uri_get_flags (uri);

        /* We require its encoded (hostname encoding optional) */
        if (((flags & (G_URI_FLAGS_ENCODED_PATH | G_URI_FLAGS_ENCODED_QUERY | G_URI_FLAGS_ENCODED_FRAGMENT)) ||
             (flags & G_URI_FLAGS_ENCODED)) &&
            /* And has scheme-based normalization */
            (flags & G_URI_FLAGS_SCHEME_NORMALIZE))
                return g_uri_ref (uri);

        return g_uri_build_with_user (
                g_uri_get_flags (uri) | SOUP_HTTP_URI_FLAGS,
                g_uri_get_scheme (uri),
                g_uri_get_user (uri),
                g_uri_get_password (uri),
                g_uri_get_auth_params (uri),
                g_uri_get_host (uri),
                g_uri_get_port (uri),
                g_uri_get_path (uri),
                g_uri_get_query (uri),
                g_uri_get_fragment (uri)
        );
}
