/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-misc.c: Miscellaneous functions

 * Copyright (C) 2000-2003, Ximian, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "soup-misc.h"

/**
 * soup_str_case_hash:
 * @key: ASCII string to hash
 *
 * Hashes @key in a case-insensitive manner.
 *
 * Returns: the hash code.
 **/
guint
soup_str_case_hash (gconstpointer key)
{
	const char *p = key;
	guint h = g_ascii_toupper(*p);

	if (h)
		for (p += 1; *p != '\0'; p++)
			h = (h << 5) - h + g_ascii_toupper(*p);

	return h;
}

/**
 * soup_str_case_equal:
 * @v1: an ASCII string
 * @v2: another ASCII string
 *
 * Compares @v1 and @v2 in a case-insensitive manner
 *
 * Returns: %TRUE if they are equal (modulo case)
 **/
gboolean
soup_str_case_equal (gconstpointer v1,
		     gconstpointer v2)
{
	const char *string1 = v1;
	const char *string2 = v2;

	return g_ascii_strcasecmp (string1, string2) == 0;
}

GSource *
soup_add_completion_reffed (GMainContext   *async_context,
			    GSourceFunc     function,
			    gpointer        data,
			    GDestroyNotify  dnotify)
{
	GSource *source = g_idle_source_new ();

	g_source_set_static_name (source, "SoupCompletion");
	g_source_set_priority (source, G_PRIORITY_DEFAULT);
	g_source_set_callback (source, function, data, dnotify);
	g_source_attach (source, async_context);
	return source;
}

/*
 * soup_add_completion: (skip)
 * @async_context: (nullable): the #GMainContext to dispatch the I/O
 * watch in, or %NULL for the default context
 * @function: the callback to invoke
 * @data: user data to pass to @function
 *
 * Adds @function to be executed from inside @async_context with the
 * default priority. Use this when you want to complete an action in
 * @async_context's main loop, as soon as possible.
 *
 */
void
soup_add_completion (GMainContext *async_context,
	             GSourceFunc function, gpointer data)
{
	GSource *source;

	source = soup_add_completion_reffed (async_context, function, data, NULL);
	g_source_unref (source);
}

/**
 * soup_add_timeout: (skip)
 * @async_context: (nullable): the #GMainContext to dispatch the I/O
 *   watch in, or %NULL for the default context
 * @interval: the timeout interval, in milliseconds
 * @function: the callback to invoke at timeout time
 * @data: user data to pass to @function
 *
 * Adds a timeout as with [func@GLib.timeout_add], but using the given
 * @async_context.
 *
 * Returns: (transfer full): a #GSource, which can be removed from @async_context
 *   with [method@GLib.Source.destroy].
 **/
GSource *
soup_add_timeout (GMainContext *async_context,
		  guint interval,
		  GSourceFunc function, gpointer data)
{
	GSource *source = g_timeout_source_new (interval);
	g_source_set_static_name (source, "SoupTimeout");
	g_source_set_callback (source, function, data, NULL);
	g_source_attach (source, async_context);
	return source;
}

GMainContext *
soup_thread_default_context (void)
{
        GMainContext *context;

        context = g_main_context_get_thread_default ();
        if (!context)
                context = g_main_context_default ();

        return context;
}

/* 00 URI_UNRESERVED
 * 01 URI_PCT_ENCODED
 * 02 URI_GEN_DELIMS
 * 04 URI_SUB_DELIMS
 * 08 HTTP_SEPARATOR
 * 10 HTTP_CTL
 */
const char soup_char_attributes[] = {
	/* 0x00 - 0x07 */
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/* 0x08 - 0x0f */
	0x11, 0x19, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/* 0x10 - 0x17 */
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/* 0x18 - 0x1f */
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/*  !"#$%&' */
	0x09, 0x04, 0x09, 0x02, 0x04, 0x01, 0x04, 0x04,
	/* ()*+,-./ */
	0x0c, 0x0c, 0x04, 0x04, 0x0c, 0x00, 0x00, 0x0a,
	/* 01234567 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 89:;<=>? */
	0x00, 0x00, 0x0a, 0x0c, 0x09, 0x0a, 0x09, 0x0a,
	/* @ABCDEFG */
	0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* HIJKLMNO */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* PQRSTUVW */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* XYZ[\]^_ */
	0x00, 0x00, 0x00, 0x0a, 0x09, 0x0a, 0x01, 0x00,
	/* `abcdefg */
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* hijklmno */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* pqrstuvw */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* xyz{|}~  */
	0x00, 0x00, 0x00, 0x09, 0x01, 0x09, 0x00, 0x11,
	/* 0x80 - 0xFF */
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

/**
 * soup_host_matches_host
 * @host: a URI
 * @compare_with: a URI
 *
 * Checks if the @host and @compare_with exactly match or prefixed with a dot.
 *
 * Returns: %TRUE if the hosts match, %FALSE otherwise
 *
 **/
gboolean
soup_host_matches_host (const gchar *host, const gchar *compare_with)
{
	g_return_val_if_fail (host != NULL, FALSE);
	g_return_val_if_fail (compare_with != NULL, FALSE);

	if (!g_ascii_strcasecmp (host, compare_with))
		return TRUE;
	if (*host != '.')
		return FALSE;
	if (!g_ascii_strcasecmp (host + 1, compare_with))
		return TRUE;
	return g_str_has_suffix (compare_with, host);
}

/* Converts a language in POSIX format and to be RFC2616 compliant    */
/* Based on code from epiphany-webkit (ephy_langs_append_languages()) */
static gchar *
posix_lang_to_rfc2616 (const gchar *language)
{
	/* Don't include charset variants, etc */
	if (strchr (language, '.') || strchr (language, '@'))
		return NULL;

	/* Ignore "C" locale, which g_get_language_names() always
	 * includes as a fallback.
	 */
	if (!strcmp (language, "C"))
		return NULL;

	return g_strdelimit (g_ascii_strdown (language, -1), "_", '-');
}

/* Converts @quality from 0-100 to 0.0-1.0 and appends to @str */
static gchar *
add_quality_value (const gchar *str, int quality)
{
	g_return_val_if_fail (str != NULL, NULL);

	if (quality >= 0 && quality < 100) {
		/* We don't use %.02g because of "." vs "," locale issues */
		if (quality % 10)
			return g_strdup_printf ("%s;q=0.%02d", str, quality);
		else
			return g_strdup_printf ("%s;q=0.%d", str, quality / 10);
	} else
		return g_strdup (str);
}

/* Returns a RFC2616 compliant languages list from system locales */
gchar *
soup_get_accept_languages_from_system (void)
{
	const char * const * lang_names;
	GPtrArray *langs = NULL;
	char *lang, *langs_str;
	int delta;
	guint i;

	lang_names = g_get_language_names ();
	g_return_val_if_fail (lang_names != NULL, NULL);

	/* Build the array of languages */
	langs = g_ptr_array_new_with_free_func (g_free);
	for (i = 0; lang_names[i] != NULL; i++) {
		lang = posix_lang_to_rfc2616 (lang_names[i]);
		if (lang)
			g_ptr_array_add (langs, lang);
	}

	/* Add quality values */
	if (langs->len < 10)
		delta = 10;
	else if (langs->len < 20)
		delta = 5;
	else
		delta = 1;

	for (i = 0; i < langs->len; i++) {
		lang = langs->pdata[i];
		langs->pdata[i] = add_quality_value (lang, 100 - i * delta);
		g_free (lang);
	}

	/* Fallback: add "en" if list is empty */
	if (langs->len == 0)
		g_ptr_array_add (langs, g_strdup ("en"));

	g_ptr_array_add (langs, NULL);
	langs_str = g_strjoinv (", ", (char **)langs->pdata);
	g_ptr_array_free (langs, TRUE);

	return langs_str;
}

const char *
soup_http_version_to_string (SoupHTTPVersion version)
{
        switch (version) {
        case SOUP_HTTP_1_0:
                return "1.0";
        case SOUP_HTTP_1_1:
                return "1.1";
        case SOUP_HTTP_2_0:
                return "2";
        }

        g_assert_not_reached ();
        return NULL;
}
