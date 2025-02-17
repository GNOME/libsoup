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

#include "soup-uri-utils-private.h"
#include "soup.h"
#include "soup-misc.h"

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
 * Tests whether or not @uri1 and @uri2 are equal in all parts.
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
	    g_uri_get_port (uri1) != g_uri_get_port (uri2)                                 ||
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

/**
 * soup_uri_get_path_and_query:
 * @uri: a #GUri
 *
 * Extracts the `path` and `query` parts from @uri.
 *
 * Returns: string of combined path and query
 **/
char *
soup_uri_get_path_and_query (GUri *uri)
{
        const char *query;

	g_return_val_if_fail (uri != NULL, NULL);

        query = g_uri_get_query (uri);

        return g_strdup_printf ("%s%c%s", g_uri_get_path (uri),
                                query ? '?' : '\0',
                                query ? query : "");
}

/**
 * soup_uri_uses_default_port:
 * @uri: a #GUri
 *
 * Tests if @uri uses the default port for its scheme.
 *
 * (Eg, 80 for http.) (This only works for http, https and ftp; libsoup does not
 * know the default ports of other protocols.)
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

GUri *
soup_uri_copy_host (GUri *uri)
{
        g_return_val_if_fail (uri != NULL, NULL);

        return soup_uri_copy (uri,
                              SOUP_URI_USER, NULL,
                              SOUP_URI_PASSWORD, NULL,
                              SOUP_URI_AUTH_PARAMS, NULL,
                              SOUP_URI_PATH, "/",
                              SOUP_URI_QUERY, NULL,
                              SOUP_URI_FRAGMENT, NULL,
                              SOUP_URI_NONE);
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

	g_return_val_if_fail (one != NULL && two != NULL, one == two);

        one_host = g_uri_get_host (one);
        two_host = g_uri_get_host (two);

	g_return_val_if_fail (one_host != NULL && two_host != NULL, one_host == two_host);

        if (one == two)
                return TRUE;
	if (g_strcmp0 (g_uri_get_scheme (one), g_uri_get_scheme (two)) != 0)
		return FALSE;

	if (g_uri_get_port (one) != g_uri_get_port (two))
		return FALSE;

	return g_ascii_strcasecmp (one_host, two_host) == 0;
}

gboolean
soup_uri_is_https (GUri *uri)
{
        const char *scheme;

        g_assert (uri != NULL);

        scheme = g_uri_get_scheme (uri);
        if (G_UNLIKELY (scheme == NULL))
                return FALSE;

        return strcmp (scheme, "https") == 0 || strcmp (scheme, "wss") == 0;
}

gboolean
soup_uri_is_http (GUri *uri)
{
        const char *scheme;

        g_assert (uri != NULL);

        scheme = g_uri_get_scheme (uri);
        if (G_UNLIKELY (scheme == NULL))
                return FALSE;

        return strcmp (scheme, "http") == 0 || strcmp (scheme, "ws") == 0;
}

#define BASE64_INDICATOR     ";base64"
#define BASE64_INDICATOR_LEN (sizeof (";base64") - 1)

/**
 * soup_uri_decode_data_uri:
 * @uri: a data URI, in string form
 * @content_type: (out) (nullable) (transfer full): location to store content type
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

        if (g_strcmp0 (g_uri_get_scheme (soup_uri), "data") || g_uri_get_host (soup_uri) != NULL) {
                g_uri_unref (soup_uri);
                return NULL;
        }

        if (content_type)
                *content_type = NULL;

#if !GLIB_CHECK_VERSION (2, 83, 1)
        /* g_uri_to_string() is picky about paths that start with `//` and will assert, clean them up.
         * https://gitlab.gnome.org/GNOME/glib/-/merge_requests/4407 */
        const char *path = g_uri_get_path (soup_uri);
        if (path[0] == '/' && path[1] == '/') {
                char *new_path = g_strconcat ("/.", path, NULL);
                GUri *new_uri = soup_uri_copy (soup_uri, SOUP_URI_PATH, new_path, SOUP_URI_NONE);

                g_uri_unref (soup_uri);
                g_free (new_path);

                soup_uri = new_uri;
        }
#endif

        uri_string = g_uri_to_string (soup_uri);
        g_uri_unref (soup_uri);
        if (!uri_string)
                return NULL;

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
                        if (g_bytes_get_size (bytes) <= 1)
                                g_clear_pointer (&bytes, g_bytes_unref);
                        else {
                                gsize content_length;
                                GByteArray *unescaped_array = g_bytes_unref_to_array (bytes);
                                g_base64_decode_inplace ((gchar*)unescaped_array->data, &content_length);
                                unescaped_array->len = content_length;
                                bytes = g_byte_array_free_to_bytes (unescaped_array);
                        }
                }
        } else {
                bytes = g_bytes_new_static (NULL, 0);
        }
        g_free (uri_string);

        return bytes;
}

/**
 * SoupURIComponent:
 * @SOUP_URI_NONE: no component
 * @SOUP_URI_SCHEME: the URI scheme component
 * @SOUP_URI_USER: the URI user component
 * @SOUP_URI_PASSWORD: the URI password component
 * @SOUP_URI_AUTH_PARAMS: the URI authentication parameters component
 * @SOUP_URI_HOST: the URI host component
 * @SOUP_URI_PORT: the URI port component
 * @SOUP_URI_PATH: the URI path component
 * @SOUP_URI_QUERY: the URI query component
 * @SOUP_URI_FRAGMENT: the URI fragment component
 *
 * Enum values passed to [func@uri_copy] to indicate the components of
 * the URI that should be updated with the given values.
 */

static int
get_maybe_default_port (GUri *uri)
{
        const char *scheme = g_uri_get_scheme (uri);
        int port = g_uri_get_port (uri);

        switch (port) {
        case 80:
                if (!strcmp (scheme, "http") || !strcmp (scheme, "ws"))
                        return -1;
                break;
        case 443:
                if (!strcmp (scheme, "https") || !strcmp (scheme, "wss"))
                        return -1;
                break;
        default:
                break;
        }

        return port;
}

/**
 * soup_uri_copy: (skip)
 * @uri: the #GUri to copy
 * @first_component: first #SoupURIComponent to update
 * @...: value of @first_component  followed by additional
 *    components and values, terminated by %SOUP_URI_NONE
 *
 * As of 3.4.0 this will detect the default ports of HTTP(s) and WS(S)
 * URIs when copying and set it to the default port of the new scheme.
 * So for example copying `http://localhost:80` while changing the scheme to https
 * will result in `https://localhost:443`.
 * 
 * Return a copy of @uri with the given components updated.
 *
 * Returns: (transfer full): a new #GUri
 */
GUri *
soup_uri_copy (GUri            *uri,
               SoupURIComponent first_component,
               ...)
{
        va_list args;
        SoupURIComponent component = first_component;
        gpointer values[SOUP_URI_FRAGMENT + 1];
        gboolean values_to_set[SOUP_URI_FRAGMENT + 1];
        GUriFlags flags = g_uri_get_flags (uri);

        g_return_val_if_fail (uri != NULL, NULL);

        memset (&values_to_set, 0, sizeof (values_to_set));

        va_start (args, first_component);
        while (component != SOUP_URI_NONE) {
                if (component == SOUP_URI_PORT)
                        values[component] = GINT_TO_POINTER (va_arg (args, gint));
                else
                        values[component] = va_arg (args, gpointer);
                values_to_set[component] = TRUE;
                component = va_arg (args, SoupURIComponent);
        }
        va_end (args);

        if (values_to_set[SOUP_URI_PASSWORD])
                flags |= G_URI_FLAGS_HAS_PASSWORD;
        if (values_to_set[SOUP_URI_AUTH_PARAMS])
                flags |= G_URI_FLAGS_HAS_AUTH_PARAMS;
        if (values_to_set[SOUP_URI_PATH])
                flags |= G_URI_FLAGS_ENCODED_PATH;
        if (values_to_set[SOUP_URI_QUERY])
                flags |= G_URI_FLAGS_ENCODED_QUERY;
        if (values_to_set[SOUP_URI_FRAGMENT])
                flags |= G_URI_FLAGS_ENCODED_FRAGMENT;
        return g_uri_build_with_user (
                flags,
                values_to_set[SOUP_URI_SCHEME] ? values[SOUP_URI_SCHEME] : g_uri_get_scheme (uri),
                values_to_set[SOUP_URI_USER] ? values[SOUP_URI_USER] : g_uri_get_user (uri),
                values_to_set[SOUP_URI_PASSWORD] ? values[SOUP_URI_PASSWORD] : g_uri_get_password (uri),
                values_to_set[SOUP_URI_AUTH_PARAMS] ? values[SOUP_URI_AUTH_PARAMS] : g_uri_get_auth_params (uri),
                values_to_set[SOUP_URI_HOST] ? values[SOUP_URI_HOST] : g_uri_get_host (uri),
                values_to_set[SOUP_URI_PORT] ? GPOINTER_TO_INT (values[SOUP_URI_PORT]) : get_maybe_default_port (uri),
                values_to_set[SOUP_URI_PATH] ? values[SOUP_URI_PATH] : g_uri_get_path (uri),
                values_to_set[SOUP_URI_QUERY] ? values[SOUP_URI_QUERY] : g_uri_get_query (uri),
                values_to_set[SOUP_URI_FRAGMENT] ? values[SOUP_URI_FRAGMENT] : g_uri_get_fragment (uri)
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

char *
soup_uri_get_host_for_headers (GUri *uri)
{
        const char *host = g_uri_get_host (uri);

        if (strchr (host, ':'))
                return g_strdup_printf ("[%.*s]", (int)strcspn (host, "%"), host);
        if (g_hostname_is_non_ascii (host))
                return g_hostname_to_ascii (host);

        return g_strdup (host);
}
