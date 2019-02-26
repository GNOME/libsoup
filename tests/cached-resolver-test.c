/*
 * Copyright (C) 2019 Igalia S.L.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "test-utils.h"

static void
test_cached_resolver (void)
{
        GResolver *default_resolver = g_resolver_get_default ();
        GResolver *cached_resolver;
        GList *results;
        double default_time, cached_time;
        guint i;

        /* Just verify caching works at a basic level by being faster */

        g_assert_false (SOUP_IS_CACHED_RESOLVER (default_resolver));

        /* Warm any DNS cache */
        results = g_resolver_lookup_by_name (default_resolver, "gnome.org", NULL, NULL);
        g_assert_nonnull (results);
        g_resolver_free_addresses (results);

        g_test_timer_start ();

        for (i = 0; i < 100; ++i) {
                results = g_resolver_lookup_by_name (default_resolver, "gnome.org", NULL, NULL);
                g_assert_nonnull (results);
                g_resolver_free_addresses (results);
        }
        default_time = g_test_timer_elapsed ();

        soup_cached_resolver_ensure_default ();
        /* Test that its safe to call multiple times */
        soup_cached_resolver_ensure_default ();

        cached_resolver = g_resolver_get_default ();
        g_assert_true (SOUP_IS_CACHED_RESOLVER (cached_resolver));


        /* Warm the DNS cache */
        results = g_resolver_lookup_by_name (cached_resolver, "gnome.org", NULL, NULL);
        g_assert_nonnull (results);
        g_resolver_free_addresses (results);

        g_test_timer_start ();

        for (i = 0; i < 100; ++i) {
                results = g_resolver_lookup_by_name (cached_resolver, "gnome.org", NULL, NULL);
                g_assert_nonnull (results);
                g_resolver_free_addresses (results);
        }
        cached_time = g_test_timer_elapsed ();

        /* Cached will always be faster or else whats the point */
        g_assert_cmpfloat (default_time, >, cached_time);
        g_info ("%f > %f", default_time, cached_time);

        g_resolver_set_default (default_resolver);
        g_object_unref (default_resolver);
        g_object_unref (cached_resolver);
}

static void
on_lookup_by_name_finish (GResolver	*resolver,
                          GAsyncResult  *result,
                          gboolean      *done)
{
	GError *error = NULL;
	GList *addresses;

	addresses = g_resolver_lookup_by_name_finish (resolver, result, &error);
        g_assert_no_error (error);
        g_assert_nonnull (addresses);
        g_resolver_free_addresses (addresses);
        *done = TRUE;
}

static void
test_cached_resolver_async (void)
{
        GResolver *default_resolver = g_resolver_get_default ();
        GResolver *cached_resolver;
        gboolean done = FALSE;

        soup_cached_resolver_ensure_default ();
        cached_resolver = g_resolver_get_default ();

        /* Just sanity check it works */
        g_resolver_lookup_by_name_async (cached_resolver, "gnome.org", NULL, (GAsyncReadyCallback) on_lookup_by_name_finish, &done);

        while (done != TRUE)
                g_main_context_iteration (NULL, TRUE);

        /* And again cached */
        done = FALSE;
        g_resolver_lookup_by_name_async (cached_resolver, "gnome.org", NULL, (GAsyncReadyCallback)  on_lookup_by_name_finish, &done);

        while (done != TRUE)
                g_main_context_iteration (NULL, TRUE);

        g_resolver_set_default (default_resolver);
        g_object_unref (default_resolver);
        g_object_unref (cached_resolver);
}

int
main (int argc, char **argv)
{
	int ret;

	test_init (argc, argv, NULL);

	g_test_add_func ("/cached-resolver", test_cached_resolver);
        g_test_add_func ("/cached-resolver/async", test_cached_resolver_async);

	ret = g_test_run ();

	test_cleanup ();
	return ret;
}
