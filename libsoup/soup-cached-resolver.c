/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cached-resolver.c
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "soup-cached-resolver.h"

/**
 * SECTION:soup-cached-resolver
 * @short_description: Cached DNS Resolver
 *
 * #SoupCachedResolver wraps any existing #GResolver to allow
 * basic caching of DNS responses.
 *
 * The cache is designed to be short lived and small and not intended
 * to fully replace system resolver. It currently only caches resolving
 * names and does not cache any other record lookups.
 *
 * For best performance use in combination with soup_session_prefetch_dns().
 *
 * Note that the #GResolver that Gio uses is a global setting so
 * you will generally opt into it via soup_cached_resolver_ensure_default().
 * See also g_resolver_set_default() and g_resolver_get_default().
 */

/* This version introduces querying names for ipv4/ipv6
 * separately which we cache separately */
#if GLIB_CHECK_VERSION (2, 59, 0)
#define N_CACHES 3
#else
#define N_CACHES 1
#endif

struct _SoupCachedResolver
{
	GResolver parent_instance;
	GResolver *wrapped_resolver;
	GHashTable *dns_caches[N_CACHES];
	GMutex dns_cache_lock;
	guint64 max_size;
};

SOUP_AVAILABLE_IN_2_66
GType soup_cached_resolver_get_type (void) G_GNUC_CONST;

G_DEFINE_TYPE (SoupCachedResolver, soup_cached_resolver, G_TYPE_RESOLVER)

#define DNS_CACHE_EXPIRE_SECONDS 60

enum {
	PROP_0,
	PROP_WRAPPED_RESOLVER,
	PROP_MAX_SIZE,
	N_PROPS
};

/**
 * soup_cached_resolver_ensure_default:
 * 
 * Ensures that the global default #GResolver is a #SoupCachedResolver
 * or creates a new one wrapping the current default and sets that as
 * default.
 *
 * Since: 2.66
 */
void
soup_cached_resolver_ensure_default (void)
{
	GResolver *default_resolver = g_resolver_get_default ();
	if (!SOUP_IS_CACHED_RESOLVER (default_resolver)) {
		SoupCachedResolver *resolver = soup_cached_resolver_new (default_resolver);
		g_resolver_set_default (G_RESOLVER (resolver));
		g_object_unref (resolver);
	}
	g_object_unref (default_resolver);
}

/**
 * soup_cached_resolver_new:
 * @wrapped_resolver: Underlying #GResolver to be cached
 * 
 * Note that @wrapped_resolver must not be a #SoupCachedResolver.
 *
 * You should generally use soup_cached_resolver_ensure_default()
 * rather than this API directly.
 *
 * Returns: (transfer full): A new #SoupCachedResolver
 * Since: 2.66
 */
SoupCachedResolver *
soup_cached_resolver_new (GResolver *wrapped_resolver)
{
	g_return_val_if_fail (wrapped_resolver != NULL, NULL);
	g_return_val_if_fail (!SOUP_IS_CACHED_RESOLVER (wrapped_resolver), NULL);

	return g_object_new (SOUP_TYPE_CACHED_RESOVLER,
                             "wrapped-resolver", wrapped_resolver,
                             NULL);
}

typedef struct {
	GList *addresses; /* owned */
	gint64 expiration;
} CachedResponse;

static void
cached_response_free (CachedResponse *cache)
{
	g_resolver_free_addresses (cache->addresses);
	g_free (cache);
}

#if GLIB_CHECK_VERSION (2, 59, 0)

static GHashTable *
get_dns_cache_for_flags (SoupCachedResolver       *self,
			 GResolverNameLookupFlags  flags)
{
	/* A cache is kept for each type of response to avoid
	 * the overcomplication of combining or filtering results.
	 */
	if (flags & G_RESOLVER_NAME_LOOKUP_FLAGS_IPV4_ONLY)
		return self->dns_caches[0];
	else if (flags & G_RESOLVER_NAME_LOOKUP_FLAGS_IPV6_ONLY)
		return self->dns_caches[1];
	else
		return self->dns_caches[2];
}

#else

#define G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT 0
typedef int GResolverNameLookupFlags;

static GHashTable *
get_dns_cache_for_flags (SoupCachedResolver *self,
			 int                 ignored)
{
	return self->dns_caches[0];
}

#endif

static gpointer
copy_object (gconstpointer obj, gpointer user_data)
{
	return g_object_ref (G_OBJECT (obj));
}

static GList *
copy_addresses (GList *addresses)
{
	return g_list_copy_deep (addresses, copy_object, NULL);
}

static void
cleanup_dns_cache (SoupCachedResolver *self,
                   GHashTable         *cache)
{
	GHashTableIter iter;
	CachedResponse *cached;
	gint64 now = g_get_monotonic_time ();
	guint64 size = 0;

	g_mutex_lock (&self->dns_cache_lock);

	g_hash_table_iter_init (&iter, cache);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer*) &cached)) {
		if (cached->expiration <= now || size > self->max_size)
			g_hash_table_iter_remove (&iter);
		else
			++size;
	}

	g_mutex_unlock (&self->dns_cache_lock);
}

static void
cleanup_all_dns_caches (SoupCachedResolver *self)
{
	guint i;
	for (i = 0; i < G_N_ELEMENTS (self->dns_caches); ++i)
		cleanup_dns_cache (self, self->dns_caches[i]);
}

static void
update_dns_cache (SoupCachedResolver       *self,
		  const char               *hostname,
		  GList                    *addresses,
		  GResolverNameLookupFlags  flags)
{
	CachedResponse *cached;
	GHashTable *cache;

	if (addresses == NULL)
		return;

	cache = get_dns_cache_for_flags (self, flags);
	cached = g_new (CachedResponse, 1);
	cached->addresses = copy_addresses (addresses);
	cached->expiration = g_get_monotonic_time () + (DNS_CACHE_EXPIRE_SECONDS * 1000);

	/* Cleanup while we are at it. */
	cleanup_dns_cache (self, cache);

	g_mutex_lock (&self->dns_cache_lock);

	g_hash_table_insert (cache, g_strdup (hostname), cached);

	g_mutex_unlock (&self->dns_cache_lock);
}

/*
 * Returns: (transfer full): List of addresses
 */
static GList *
query_dns_cache (SoupCachedResolver       *self,
		 const char               *hostname,
		 GResolverNameLookupFlags  flags)
{
	CachedResponse *cached;
	GHashTable *cache;
	GList *addresses = NULL;
	gint64 now = g_get_monotonic_time ();

	cache = get_dns_cache_for_flags (self, flags);

	g_mutex_lock (&self->dns_cache_lock);

	cached = g_hash_table_lookup (cache, hostname);
	if (cached && cached->expiration > now)
		addresses = copy_addresses (cached->addresses);

	g_mutex_unlock (&self->dns_cache_lock);

	return addresses;
}

static void
reload (GResolver *resolver)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (resolver);
	guint i;

	g_info ("Flushing DNS Cache");

	/* Empty caches on system DNS changes */
	for (i = 0; i < G_N_ELEMENTS (self->dns_caches); ++i)
		g_hash_table_remove_all (self->dns_caches[i]);
}

#if GLIB_CHECK_VERSION (2, 59, 0)

typedef struct {
	char *hostname;
	GResolverNameLookupFlags flags;
} LookupData;

static LookupData *
lookup_data_new (const char *hostname, GResolverNameLookupFlags flags)
{
	LookupData *lookup_data = g_new (LookupData, 1);
	lookup_data->hostname = g_strdup (hostname);
	lookup_data->flags = flags;
	return lookup_data;
}

static void
lookup_data_free (LookupData *lookup_data)
{
	g_free (lookup_data->hostname);
	g_free (lookup_data);
}

static GList *
lookup_by_name_with_flags (GResolver                *resolver,
			   const gchar              *hostname,
			   GResolverNameLookupFlags  flags,
			   GCancellable             *cancellable,
			   GError                  **error)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (resolver);
	GList *addresses = query_dns_cache (self, hostname, flags);

	if (addresses)
		return addresses;

	addresses = g_resolver_lookup_by_name_with_flags (self->wrapped_resolver,
                                                          hostname,
							  flags,
                                                          cancellable,
                                                          error);
	update_dns_cache (self, hostname, addresses, flags);
	return addresses;
}

static GList *
lookup_by_name_with_flags_finish (GResolver	*resolver,
				  GAsyncResult  *result,
				  GError       **error)
{
	g_return_val_if_fail (g_task_is_valid (result, resolver), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static void
on_lookup_by_name_with_flags_finish (GObject	*resolver,
		                     GAsyncResult  *result,
                                     gpointer      user_data)
{
	GTask *task = G_TASK (user_data);
	SoupCachedResolver *self = g_task_get_source_object (task);
	LookupData *data = g_task_get_task_data (task);
	GError *error = NULL;
	GList *addresses;

	addresses = g_resolver_lookup_by_name_with_flags_finish (G_RESOLVER (resolver), result, &error);
	if (addresses) {
		update_dns_cache (self, data->hostname, addresses, data->flags);
		g_task_return_pointer (task, addresses, (GDestroyNotify) g_resolver_free_addresses);
	} else
		g_task_return_error (task, error);

	g_object_unref (task);
}

static void
lookup_by_name_with_flags_async (GResolver                *resolver,
				 const gchar              *hostname,
				 GResolverNameLookupFlags  flags,
				 GCancellable             *cancellable,
				 GAsyncReadyCallback	   callback,
				 gpointer                  user_data)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (resolver);
	GTask *task = g_task_new (self, cancellable, callback, user_data);
	GList *cached = query_dns_cache (self, hostname, flags);

	if (cached)
		g_task_return_pointer (task, cached, (GDestroyNotify) g_resolver_free_addresses);
	else {
		g_task_set_task_data (task, lookup_data_new (hostname, flags), (GDestroyNotify) lookup_data_free);
		g_resolver_lookup_by_name_with_flags_async (self->wrapped_resolver,
                                                            hostname,
                                                            flags,
                                                            cancellable,
                                                            on_lookup_by_name_with_flags_finish,
                                                            g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

#endif

static void
on_lookup_by_name_finish (GObject	*resolver,
                          GAsyncResult  *result,
                          gpointer      user_data)
{
	GTask *task = G_TASK (user_data);
	SoupCachedResolver *self = g_task_get_source_object (task);
	char *hostname = g_task_get_task_data (task);
	GError *error = NULL;
	GList *addresses;

	addresses = g_resolver_lookup_by_name_finish (G_RESOLVER (resolver), result, &error);
	if (addresses) {
		update_dns_cache (self, hostname, addresses, G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT);
		g_task_return_pointer (task, addresses, (GDestroyNotify) g_resolver_free_addresses);
	} else
		g_task_return_error (task, error);

	g_object_unref (task);
}

static void
lookup_by_name_async (GResolver		  *resolver,
                      const gchar         *hostname,
                      GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (resolver);
	GTask *task = g_task_new (self, cancellable, callback, user_data);
	GList *cached = query_dns_cache (self, hostname, G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT);

	if (cached)
		g_task_return_pointer (task, cached, (GDestroyNotify) g_resolver_free_addresses);
	else {
		g_task_set_task_data (task, g_strdup (hostname), g_free);
		g_resolver_lookup_by_name_async (self->wrapped_resolver,
                                                 hostname,
                                                 cancellable,
                                                 on_lookup_by_name_finish,
                                                 g_steal_pointer (&task));
	}

	g_clear_object (&task);
}

static GList *
lookup_by_name_finish (GResolver    *resolver,
                       GAsyncResult *result,
		       GError	    **error)
{
	g_return_val_if_fail (g_task_is_valid (result, resolver), NULL);

	return g_task_propagate_pointer (G_TASK (result), error);
}

static GList *
lookup_by_name (GResolver     *resolver,
		const gchar   *hostname,
		GCancellable  *cancellable,
		GError       **error)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (resolver);
	GList *addresses = query_dns_cache (self, hostname, G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT);

	if (addresses)
		return addresses;

	addresses = g_resolver_lookup_by_name (self->wrapped_resolver,
                                               hostname,
                                               cancellable,
                                               error);
	update_dns_cache (self, hostname, addresses, G_RESOLVER_NAME_LOOKUP_FLAGS_DEFAULT);
	return addresses;
}


static gchar *
lookup_by_address (GResolver	 *resolver,
		   GInetAddress	 *address,
		   GCancellable	 *cancellable,
		   GError       **error)
{
	return g_resolver_lookup_by_address (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, address, cancellable, error);
}

static void
lookup_by_address_async (GResolver           *resolver,
			 GInetAddress        *address,
			 GCancellable        *cancellable,
			 GAsyncReadyCallback  callback,
			 gpointer             user_data)
{
	g_resolver_lookup_by_address_async (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, address, cancellable, callback, user_data);
}

static gchar *
lookup_by_address_finish (GResolver	 *resolver,
			  GAsyncResult  *result,
			  GError	   **error)
{
	return g_resolver_lookup_by_address_finish (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, result, error);
}

static GList *
lookup_records (GResolver            *resolver,
		const gchar          *rrname,
		GResolverRecordType   record_type,
		GCancellable         *cancellable,
		GError              **error)
{
	return g_resolver_lookup_records (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, rrname, record_type, cancellable, error);
}

static void
lookup_records_async (GResolver		  *resolver,
                      const char          *rrname,
                      GResolverRecordType  record_type,
                      GCancellable        *cancellable,
                      GAsyncReadyCallback  callback,
                      gpointer             user_data)
{
	g_resolver_lookup_records_async (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, rrname, record_type, cancellable, callback, user_data);
}

static GList *
lookup_records_finish (GResolver     *resolver,
                       GAsyncResult  *result,
                       GError       **error)
{
	return g_resolver_lookup_records_finish (SOUP_CACHED_RESOLVER (resolver)->wrapped_resolver, result, error);
}

static void
soup_cached_resolver_get_property (GObject    *object,
                                   guint       prop_id,
                                   GValue     *value,
                                   GParamSpec *pspec)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (object);

	switch (prop_id)
	{
	case PROP_WRAPPED_RESOLVER:
		g_value_set_object (value, self->wrapped_resolver);
		break;
	case PROP_MAX_SIZE:
		g_value_set_uint64 (value, self->max_size);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
soup_cached_resolver_set_property (GObject      *object,
                                   guint         prop_id,
                                   const GValue *value,
                                   GParamSpec   *pspec)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (object);

	switch (prop_id)
	{
	case PROP_WRAPPED_RESOLVER:
		g_assert (self->wrapped_resolver == NULL);
		self->wrapped_resolver = g_value_dup_object (value);
		g_assert (self->wrapped_resolver != NULL);
		break;
	case PROP_MAX_SIZE:
		self->max_size = g_value_get_uint64 (value);
		cleanup_all_dns_caches (self);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
	}
}

static void
soup_cached_resolver_finalize (GObject *object)
{
	SoupCachedResolver *self = SOUP_CACHED_RESOLVER (object);
	g_clear_object (&self->wrapped_resolver);
	G_OBJECT_CLASS (soup_cached_resolver_parent_class)->finalize (object);
}

static void
soup_cached_resolver_class_init (SoupCachedResolverClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	GResolverClass *resolver_class = G_RESOLVER_CLASS (klass);

	object_class->finalize = soup_cached_resolver_finalize;
	object_class->get_property = soup_cached_resolver_get_property;
	object_class->set_property = soup_cached_resolver_set_property;

	resolver_class->lookup_by_name = lookup_by_name;
	resolver_class->lookup_by_name_async = lookup_by_name_async;
	resolver_class->lookup_by_name_finish = lookup_by_name_finish;
#if GLIB_CHECK_VERSION (2, 59, 0)
	resolver_class->lookup_by_name_with_flags = lookup_by_name_with_flags;
	resolver_class->lookup_by_name_with_flags_async = lookup_by_name_with_flags_async;
	resolver_class->lookup_by_name_with_flags_finish = lookup_by_name_with_flags_finish;
#endif
	resolver_class->lookup_by_address = lookup_by_address;
	resolver_class->lookup_by_address_async = lookup_by_address_async;
	resolver_class->lookup_by_address_finish = lookup_by_address_finish;
	resolver_class->lookup_records = lookup_records;
	resolver_class->lookup_records_async = lookup_records_async;
	resolver_class->lookup_records_finish = lookup_records_finish;

	resolver_class->reload = reload;

	/**
	 * SoupCachedResolver:wrapped-resolver:
	 *
	 * The #GResolver that is cached.
	 *
	 * Since: 2.66
	 */
	g_object_class_install_property (object_class, PROP_WRAPPED_RESOLVER,
					 g_param_spec_object ("wrapped-resolver", "wrapped-resolver",
					                      "DNS Resolver that is wrapped",
							      G_TYPE_RESOLVER,
							      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

	/**
	 * SoupCachedResolver:max-size:
	 *
	 * The maximum size of the DNS cache.
	 *
	 * Since: 2.66
	 */
	g_object_class_install_property (object_class, PROP_MAX_SIZE,
					 g_param_spec_uint64 ("max-size", "max-size",
					                      "Max size of DNS cache",
							      0, G_MAXUINT64, 400,
							      G_PARAM_READWRITE | G_PARAM_CONSTRUCT | G_PARAM_STATIC_STRINGS));
}

static void
soup_cached_resolver_init (SoupCachedResolver *self)
{
	guint i;  
	for (i = 0; i < G_N_ELEMENTS (self->dns_caches); ++i)
		self->dns_caches[i] = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) cached_response_free);
}
