/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * soup-cache.c
 *
 * Copyright (C) 2009, 2010 Igalia S.L.
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

/* TODO:
 * - Need to hook the feature in the sync SoupSession.
 * - Need more tests.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <glib/gstdio.h>

#include "soup-cache.h"
#include "soup-body-input-stream.h"
#include "soup-cache-client-input-stream.h"
#include "soup-cache-input-stream.h"
#include "soup-cache-private.h"
#include "soup-content-processor.h"
#include "soup-message-private.h"
#include "soup.h"
#include "soup-message-private.h"

/**
 * SECTION:soup-cache
 * @short_description: Caching support
 *
 * #SoupCache implements a file-based cache for HTTP resources.
 */

static SoupSessionFeatureInterface *soup_cache_default_feature_interface;
static void soup_cache_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static SoupContentProcessorInterface *soup_cache_default_content_processor_interface;
static void soup_cache_content_processor_init (SoupContentProcessorInterface *interface, gpointer interface_data);

#define DEFAULT_MAX_SIZE 50 * 1024 * 1024
#define MAX_ENTRY_DATA_PERCENTAGE 10 /* Percentage of the total size
	                                of the cache that can be
	                                filled by a single entry */

/*
 * Version 2: cache is now saved in soup.cache2. Added the version
 * number to the beginning of the file.
 *
 * Version 3: added HTTP status code to the cache entries.
 *
 * Version 4: replaced several types.
 *   - freshness_lifetime,corrected_initial_age,response_time: time_t -> guint32
 *   - status_code: guint -> guint16
 *   - hits: guint -> guint32
 *
 * Version 5: key is no longer stored on disk as it can be easily
 * built from the URI. Apart from that some fields in the
 * SoupCacheEntry have changed:
 *   - entry key is now a uint32 instead of a (char *).
 *   - added uri, used to check for collisions
 *   - removed filename, it's built from the entry key.
 */
#define SOUP_CACHE_CURRENT_VERSION 5

#define OLD_SOUP_CACHE_FILE "soup.cache"
#define SOUP_CACHE_FILE "soup.cache2"

#define SOUP_CACHE_HEADERS_FORMAT "{ss}"
#define SOUP_CACHE_PHEADERS_FORMAT "(sbuuuuuqa" SOUP_CACHE_HEADERS_FORMAT ")"
#define SOUP_CACHE_ENTRIES_FORMAT "(qa" SOUP_CACHE_PHEADERS_FORMAT ")"

/* Basically the same format than above except that some strings are
   prepended with &. This way the GVariant returns a pointer to the
   data instead of duplicating the string */
#define SOUP_CACHE_DECODE_HEADERS_FORMAT "{&s&s}"


typedef struct _SoupCacheEntry {
	guint32 key;
	char *uri;
	guint32 freshness_lifetime;
	gboolean must_revalidate;
	gsize length;
	guint32 corrected_initial_age;
	guint32 response_time;
	gboolean dirty;
	gboolean being_validated;
	SoupMessageHeaders *headers;
	guint32 hits;
	GCancellable *cancellable;
	guint16 status_code;
} SoupCacheEntry;

struct _SoupCachePrivate {
	char *cache_dir;
	GHashTable *cache;
	guint n_pending;
	SoupSession *session;
	SoupCacheType cache_type;
	guint size;
	guint max_size;
	guint max_entry_data_size; /* Computed value. Here for performance reasons */
	GList *lru_start;
};

enum {
	PROP_0,
	PROP_CACHE_DIR,
	PROP_CACHE_TYPE
};

G_DEFINE_TYPE_WITH_CODE (SoupCache, soup_cache, G_TYPE_OBJECT,
                         G_ADD_PRIVATE (SoupCache)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
						soup_cache_session_feature_init)
			 G_IMPLEMENT_INTERFACE (SOUP_TYPE_CONTENT_PROCESSOR,
						soup_cache_content_processor_init))

static gboolean soup_cache_entry_remove (SoupCache *cache, SoupCacheEntry *entry, gboolean purge);
static void make_room_for_new_entry (SoupCache *cache, guint length_to_add);
static gboolean cache_accepts_entries_of_size (SoupCache *cache, guint length_to_add);

static GFile *
get_file_from_entry (SoupCache *cache, SoupCacheEntry *entry)
{
	char *filename = g_strdup_printf ("%s%s%u", cache->priv->cache_dir,
					  G_DIR_SEPARATOR_S, (guint) entry->key);
	GFile *file = g_file_new_for_path (filename);
	g_free (filename);

	return file;
}

static SoupCacheability
get_cacheability (SoupCache *cache, SoupMessage *msg)
{
	SoupCacheability cacheability;
	const char *cache_control, *content_type;
	gboolean has_max_age = FALSE;

	/* 1. The request method must be cacheable */
	if (msg->method == SOUP_METHOD_GET)
		cacheability = SOUP_CACHE_CACHEABLE;
	else if (msg->method == SOUP_METHOD_HEAD ||
		 msg->method == SOUP_METHOD_TRACE ||
		 msg->method == SOUP_METHOD_CONNECT)
		return SOUP_CACHE_UNCACHEABLE;
	else
		return (SOUP_CACHE_UNCACHEABLE | SOUP_CACHE_INVALIDATES);

	content_type = soup_message_headers_get_content_type (msg->response_headers, NULL);
	if (content_type && !g_ascii_strcasecmp (content_type, "multipart/x-mixed-replace"))
		return SOUP_CACHE_UNCACHEABLE;

	cache_control = soup_message_headers_get_list (msg->response_headers, "Cache-Control");
	if (cache_control && *cache_control) {
		GHashTable *hash;
		SoupCachePrivate *priv = soup_cache_get_instance_private (cache);

		hash = soup_header_parse_param_list (cache_control);

		/* Shared caches MUST NOT store private resources */
		if (priv->cache_type == SOUP_CACHE_SHARED) {
			if (g_hash_table_lookup_extended (hash, "private", NULL, NULL)) {
				soup_header_free_param_list (hash);
				return SOUP_CACHE_UNCACHEABLE;
			}
		}

		/* 2. The 'no-store' cache directive does not appear in the
		 * headers
		 */
		if (g_hash_table_lookup_extended (hash, "no-store", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return SOUP_CACHE_UNCACHEABLE;
		}

		if (g_hash_table_lookup_extended (hash, "max-age", NULL, NULL))
			has_max_age = TRUE;

		/* This does not appear in section 2.1, but I think it makes
		 * sense to check it too?
		 */
		if (g_hash_table_lookup_extended (hash, "no-cache", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return SOUP_CACHE_UNCACHEABLE;
		}

		soup_header_free_param_list (hash);
	}

	/* Section 13.9 */
	if ((soup_message_get_uri (msg))->query &&
	    !soup_message_headers_get_one (msg->response_headers, "Expires") &&
	    !has_max_age)
		return SOUP_CACHE_UNCACHEABLE;

	switch (msg->status_code) {
	case SOUP_STATUS_PARTIAL_CONTENT:
		/* We don't cache partial responses, but they only
		 * invalidate cached full responses if the headers
		 * don't match.
		 */
		cacheability = SOUP_CACHE_UNCACHEABLE;
		break;

	case SOUP_STATUS_NOT_MODIFIED:
		/* A 304 response validates an existing cache entry */
		cacheability = SOUP_CACHE_VALIDATES;
		break;

	case SOUP_STATUS_MULTIPLE_CHOICES:
	case SOUP_STATUS_MOVED_PERMANENTLY:
	case SOUP_STATUS_GONE:
		/* FIXME: cacheable unless indicated otherwise */
		cacheability = SOUP_CACHE_UNCACHEABLE;
		break;

	case SOUP_STATUS_FOUND:
	case SOUP_STATUS_TEMPORARY_REDIRECT:
		/* FIXME: cacheable if explicitly indicated */
		cacheability = SOUP_CACHE_UNCACHEABLE;
		break;

	case SOUP_STATUS_SEE_OTHER:
	case SOUP_STATUS_FORBIDDEN:
	case SOUP_STATUS_NOT_FOUND:
	case SOUP_STATUS_METHOD_NOT_ALLOWED:
		return (SOUP_CACHE_UNCACHEABLE | SOUP_CACHE_INVALIDATES);

	default:
		/* Any 5xx status or any 4xx status not handled above
		 * is uncacheable but doesn't break the cache.
		 */
		if ((msg->status_code >= SOUP_STATUS_BAD_REQUEST &&
		     msg->status_code <= SOUP_STATUS_FAILED_DEPENDENCY) ||
		    msg->status_code >= SOUP_STATUS_INTERNAL_SERVER_ERROR)
			return SOUP_CACHE_UNCACHEABLE;

		/* An unrecognized 2xx, 3xx, or 4xx response breaks
		 * the cache.
		 */
		if ((msg->status_code > SOUP_STATUS_PARTIAL_CONTENT &&
		     msg->status_code < SOUP_STATUS_MULTIPLE_CHOICES) ||
		    (msg->status_code > SOUP_STATUS_TEMPORARY_REDIRECT &&
		     msg->status_code < SOUP_STATUS_INTERNAL_SERVER_ERROR))
			return (SOUP_CACHE_UNCACHEABLE | SOUP_CACHE_INVALIDATES);
		break;
	}

	return cacheability;
}

/* NOTE: this function deletes the file pointed by the file argument
 * and also unref's the GFile object representing it.
 */
static void
soup_cache_entry_free (SoupCacheEntry *entry)
{
	g_free (entry->uri);
	g_clear_pointer (&entry->headers, soup_message_headers_free);
	g_clear_object (&entry->cancellable);

	g_slice_free (SoupCacheEntry, entry);
}

static void
copy_headers (const char *name, const char *value, SoupMessageHeaders *headers)
{
	soup_message_headers_append (headers, name, value);
}

static void
remove_headers (const char *name, const char *value, SoupMessageHeaders *headers)
{
	soup_message_headers_remove (headers, name);
}

static char *hop_by_hop_headers[] = {"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"};

static void
copy_end_to_end_headers (SoupMessageHeaders *source, SoupMessageHeaders *destination)
{
	int i;

	soup_message_headers_foreach (source, (SoupMessageHeadersForeachFunc) copy_headers, destination);
	for (i = 0; i < G_N_ELEMENTS (hop_by_hop_headers); i++)
		soup_message_headers_remove (destination, hop_by_hop_headers[i]);
	soup_message_headers_clean_connection_headers (destination);
}

static guint
soup_cache_entry_get_current_age (SoupCacheEntry *entry)
{
	time_t now = time (NULL);
	time_t resident_time;

	resident_time = now - entry->response_time;
	return entry->corrected_initial_age + resident_time;
}

static gboolean
soup_cache_entry_is_fresh_enough (SoupCacheEntry *entry, gint min_fresh)
{
	guint limit = (min_fresh == -1) ? soup_cache_entry_get_current_age (entry) : (guint) min_fresh;
	return entry->freshness_lifetime > limit;
}

static inline guint32
get_cache_key_from_uri (const char *uri)
{
	return (guint32) g_str_hash (uri);
}

static void
soup_cache_entry_set_freshness (SoupCacheEntry *entry, SoupMessage *msg, SoupCache *cache)
{
	const char *cache_control;
	const char *expires, *date, *last_modified;

	/* Reset these values. We have to do this to ensure that
	 * revalidations overwrite previous values for the headers.
	 */
	entry->must_revalidate = FALSE;
	entry->freshness_lifetime = 0;

	cache_control = soup_message_headers_get_list (entry->headers, "Cache-Control");
	if (cache_control && *cache_control) {
		const char *max_age, *s_maxage;
		gint64 freshness_lifetime = 0;
		GHashTable *hash;
		SoupCachePrivate *priv = soup_cache_get_instance_private (cache);

		hash = soup_header_parse_param_list (cache_control);

		/* Should we re-validate the entry when it goes stale */
		entry->must_revalidate = g_hash_table_lookup_extended (hash, "must-revalidate", NULL, NULL);

		/* Section 2.3.1 */
		if (priv->cache_type == SOUP_CACHE_SHARED) {
			s_maxage = g_hash_table_lookup (hash, "s-maxage");
			if (s_maxage) {
				freshness_lifetime = g_ascii_strtoll (s_maxage, NULL, 10);
				if (freshness_lifetime) {
					/* Implies proxy-revalidate. TODO: is it true? */
					entry->must_revalidate = TRUE;
					soup_header_free_param_list (hash);
					return;
				}
			}
		}

		/* If 'max-age' cache directive is present, use that */
		max_age = g_hash_table_lookup (hash, "max-age");
		if (max_age)
			freshness_lifetime = g_ascii_strtoll (max_age, NULL, 10);

		if (freshness_lifetime) {
			entry->freshness_lifetime = (guint32) MIN (freshness_lifetime, G_MAXUINT32);
			soup_header_free_param_list (hash);
			return;
		}

		soup_header_free_param_list (hash);
	}

	/* If the 'Expires' response header is present, use its value
	 * minus the value of the 'Date' response header
	 */
	expires = soup_message_headers_get_one (entry->headers, "Expires");
	date = soup_message_headers_get_one (entry->headers, "Date");
	if (expires && date) {
		SoupDate *expires_d, *date_d;
		time_t expires_t, date_t;

		expires_d = soup_date_new_from_string (expires);
		if (expires_d) {
			date_d = soup_date_new_from_string (date);

			expires_t = soup_date_to_time_t (expires_d);
			date_t = soup_date_to_time_t (date_d);

			soup_date_free (expires_d);
			soup_date_free (date_d);

			if (expires_t && date_t) {
				entry->freshness_lifetime = (guint32) MAX (expires_t - date_t, 0);
				return;
			}
		} else {
			/* If Expires is not a valid date we should
			   treat it as already expired, see section
			   3.3 */
			entry->freshness_lifetime = 0;
			return;
		}
	}

	/* Otherwise an heuristic may be used */

	/* Heuristics MUST NOT be used with stored responses with
	   these status codes (section 2.3.1.1) */
	if (entry->status_code != SOUP_STATUS_OK &&
	    entry->status_code != SOUP_STATUS_NON_AUTHORITATIVE &&
	    entry->status_code != SOUP_STATUS_PARTIAL_CONTENT &&
	    entry->status_code != SOUP_STATUS_MULTIPLE_CHOICES &&
	    entry->status_code != SOUP_STATUS_MOVED_PERMANENTLY &&
	    entry->status_code != SOUP_STATUS_GONE)
		goto expire;

	/* TODO: attach warning 113 if response's current_age is more
	   than 24h (section 2.3.1.1) when using heuristics */

	/* Last-Modified based heuristic */
	last_modified = soup_message_headers_get_one (entry->headers, "Last-Modified");
	if (last_modified) {
		SoupDate *soup_date;
		time_t now, last_modified_t;

		soup_date = soup_date_new_from_string (last_modified);
		last_modified_t = soup_date_to_time_t (soup_date);
		now = time (NULL);

#define HEURISTIC_FACTOR 0.1 /* From Section 2.3.1.1 */

		entry->freshness_lifetime = MAX (0, (now - last_modified_t) * HEURISTIC_FACTOR);
		soup_date_free (soup_date);
	}

	return;

 expire:
	/* If all else fails, make the entry expire immediately */
	entry->freshness_lifetime = 0;
}

static SoupCacheEntry *
soup_cache_entry_new (SoupCache *cache, SoupMessage *msg, time_t request_time, time_t response_time)
{
	SoupCacheEntry *entry;
	const char *date;

	entry = g_slice_new0 (SoupCacheEntry);
	entry->dirty = FALSE;
	entry->being_validated = FALSE;
	entry->status_code = msg->status_code;
	entry->response_time = response_time;
	entry->uri = soup_uri_to_string (soup_message_get_uri (msg), FALSE);

	/* Headers */
	entry->headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
	copy_end_to_end_headers (msg->response_headers, entry->headers);

	/* LRU list */
	entry->hits = 0;

	/* Section 2.3.1, Freshness Lifetime */
	soup_cache_entry_set_freshness (entry, msg, cache);

	/* Section 2.3.2, Calculating Age */
	date = soup_message_headers_get_one (entry->headers, "Date");

	if (date) {
		SoupDate *soup_date;
		const char *age;
		time_t date_value, apparent_age, corrected_received_age, response_delay, age_value = 0;

		soup_date = soup_date_new_from_string (date);
		date_value = soup_date_to_time_t (soup_date);
		soup_date_free (soup_date);

		age = soup_message_headers_get_one (entry->headers, "Age");
		if (age)
			age_value = g_ascii_strtoll (age, NULL, 10);

		apparent_age = MAX (0, entry->response_time - date_value);
		corrected_received_age = MAX (apparent_age, age_value);
		response_delay = entry->response_time - request_time;
		entry->corrected_initial_age = corrected_received_age + response_delay;
	} else {
		/* Is this correct ? */
		entry->corrected_initial_age = time (NULL);
	}

	return entry;
}

static gboolean
soup_cache_entry_remove (SoupCache *cache, SoupCacheEntry *entry, gboolean purge)
{
	GList *lru_item;

	if (entry->dirty) {
		g_cancellable_cancel (entry->cancellable);
		return FALSE;
	}

	g_assert (!entry->dirty);
	g_assert (g_list_length (cache->priv->lru_start) == g_hash_table_size (cache->priv->cache));

	if (!g_hash_table_remove (cache->priv->cache, GUINT_TO_POINTER (entry->key)))
		return FALSE;

	/* Remove from LRU */
	lru_item = g_list_find (cache->priv->lru_start, entry);
	cache->priv->lru_start = g_list_delete_link (cache->priv->lru_start, lru_item);

	/* Adjust cache size */
	cache->priv->size -= entry->length;

	g_assert (g_list_length (cache->priv->lru_start) == g_hash_table_size (cache->priv->cache));

	/* Free resources */
	if (purge) {
		GFile *file = get_file_from_entry (cache, entry);
		g_file_delete (file, NULL, NULL);
		g_object_unref (file);
	}
	soup_cache_entry_free (entry);

	return TRUE;
}

static gint
lru_compare_func (gconstpointer a, gconstpointer b)
{
	SoupCacheEntry *entry_a = (SoupCacheEntry *)a;
	SoupCacheEntry *entry_b = (SoupCacheEntry *)b;

	/* The rationale of this sorting func is
	 *
	 * 1. sort by hits -> LRU algorithm, then
	 *
	 * 2. sort by freshness lifetime, we better discard first
	 * entries that are close to expire
	 *
	 * 3. sort by size, replace first small size resources as they
	 * are cheaper to download
	 */

	/* Sort by hits */
	if (entry_a->hits != entry_b->hits)
		return entry_a->hits - entry_b->hits;

	/* Sort by freshness_lifetime */
	if (entry_a->freshness_lifetime != entry_b->freshness_lifetime)
		return entry_a->freshness_lifetime - entry_b->freshness_lifetime;

	/* Sort by size */
	return entry_a->length - entry_b->length;
}

static gboolean
cache_accepts_entries_of_size (SoupCache *cache, guint length_to_add)
{
	/* We could add here some more heuristics. TODO: review how
	   this is done by other HTTP caches */

	return length_to_add <= cache->priv->max_entry_data_size;
}

static void
make_room_for_new_entry (SoupCache *cache, guint length_to_add)
{
	GList *lru_entry = cache->priv->lru_start;

	/* Check that there is enough room for the new entry. This is
	   an approximation as we're not working out the size of the
	   cache file or the size of the headers for performance
	   reasons. TODO: check if that would be really that expensive */

	while (lru_entry &&
	       (length_to_add + cache->priv->size > cache->priv->max_size)) {
		SoupCacheEntry *old_entry = (SoupCacheEntry *)lru_entry->data;

		/* Discard entries. Once cancelled resources will be
		 * freed in close_ready_cb
		 */
		if (soup_cache_entry_remove (cache, old_entry, TRUE))
			lru_entry = cache->priv->lru_start;
		else
			lru_entry = g_list_next (lru_entry);
	}
}

static gboolean
soup_cache_entry_insert (SoupCache *cache,
			 SoupCacheEntry *entry,
			 gboolean sort)
{
	guint length_to_add = 0;
	SoupCacheEntry *old_entry;

	/* Fill the key */
	entry->key = get_cache_key_from_uri ((const char *) entry->uri);

	if (soup_message_headers_get_encoding (entry->headers) == SOUP_ENCODING_CONTENT_LENGTH)
		length_to_add = soup_message_headers_get_content_length (entry->headers);

	/* Check if we are going to store the resource depending on its size */
	if (length_to_add) {
		if (!cache_accepts_entries_of_size (cache, length_to_add))
			return FALSE;

		/* Make room for new entry if needed */
		make_room_for_new_entry (cache, length_to_add);
	}

	/* Remove any previous entry */
	if ((old_entry = g_hash_table_lookup (cache->priv->cache, GUINT_TO_POINTER (entry->key))) != NULL) {
		if (!soup_cache_entry_remove (cache, old_entry, TRUE))
			return FALSE;
	}

	/* Add to hash table */
	g_hash_table_insert (cache->priv->cache, GUINT_TO_POINTER (entry->key), entry);

	/* Compute new cache size */
	cache->priv->size += length_to_add;

	/* Update LRU */
	if (sort)
		cache->priv->lru_start = g_list_insert_sorted (cache->priv->lru_start, entry, lru_compare_func);
	else
		cache->priv->lru_start = g_list_prepend (cache->priv->lru_start, entry);

	g_assert (g_list_length (cache->priv->lru_start) == g_hash_table_size (cache->priv->cache));

	return TRUE;
}

static SoupCacheEntry*
soup_cache_entry_lookup (SoupCache *cache,
			 SoupMessage *msg)
{
	SoupCacheEntry *entry;
	guint32 key;
	char *uri = NULL;

	uri = soup_uri_to_string (soup_message_get_uri (msg), FALSE);
	key = get_cache_key_from_uri ((const char *) uri);

	entry = g_hash_table_lookup (cache->priv->cache, GUINT_TO_POINTER (key));

	if (entry != NULL && (strcmp (entry->uri, uri) != 0))
		entry = NULL;

	g_free (uri);
	return entry;
}

GInputStream *
soup_cache_send_response (SoupCache *cache, SoupMessage *msg)
{
	SoupCacheEntry *entry;
	GInputStream *file_stream, *body_stream, *cache_stream, *client_stream;
	GFile *file;

	g_return_val_if_fail (SOUP_IS_CACHE (cache), NULL);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), NULL);

	entry = soup_cache_entry_lookup (cache, msg);
	g_return_val_if_fail (entry, NULL);

	file = get_file_from_entry (cache, entry);
	file_stream = G_INPUT_STREAM (g_file_read (file, NULL, NULL));
	g_object_unref (file);

	/* Do not change the original message if there is no resource */
	if (!file_stream)
		return NULL;

	body_stream = soup_body_input_stream_new (file_stream, SOUP_ENCODING_CONTENT_LENGTH, entry->length);
	g_object_unref (file_stream);

	if (!body_stream)
		return NULL;

	/* If we are told to send a response from cache any validation
	   in course is over by now */
	entry->being_validated = FALSE;

	/* Message starting */
	soup_message_starting (msg);

	/* Status */
	soup_message_set_status (msg, entry->status_code);

	/* Headers */
	copy_end_to_end_headers (entry->headers, msg->response_headers);

	/* Create the cache stream. */
	soup_message_disable_feature (msg, SOUP_TYPE_CACHE);
	cache_stream = soup_message_setup_body_istream (body_stream, msg,
							cache->priv->session,
							SOUP_STAGE_ENTITY_BODY);
	g_object_unref (body_stream);

	client_stream = soup_cache_client_input_stream_new (cache_stream);
	g_object_unref (cache_stream);

	return client_stream;
}

static void
msg_got_headers_cb (SoupMessage *msg, gpointer user_data)
{
	g_object_set_data (G_OBJECT (msg), "response-time", GINT_TO_POINTER (time (NULL)));
	g_signal_handlers_disconnect_by_func (msg, msg_got_headers_cb, user_data);
}

static void
msg_starting_cb (SoupMessage *msg, gpointer user_data)
{
	g_object_set_data (G_OBJECT (msg), "request-time", GINT_TO_POINTER (time (NULL)));
	g_signal_connect (msg, "got-headers", G_CALLBACK (msg_got_headers_cb), user_data);
	g_signal_handlers_disconnect_by_func (msg, msg_starting_cb, user_data);
}

static void
request_queued (SoupSessionFeature *feature, SoupSession *session, SoupMessage *msg)
{
	g_signal_connect (msg, "starting", G_CALLBACK (msg_starting_cb), feature);
}

static void
attach (SoupSessionFeature *feature, SoupSession *session)
{
	SoupCache *cache = SOUP_CACHE (feature);
	cache->priv->session = session;

	soup_cache_default_feature_interface->attach (feature, session);
}

static void
soup_cache_session_feature_init (SoupSessionFeatureInterface *feature_interface,
					gpointer interface_data)
{
	soup_cache_default_feature_interface =
		g_type_default_interface_peek (SOUP_TYPE_SESSION_FEATURE);

	feature_interface->attach = attach;
	feature_interface->request_queued = request_queued;
}

typedef struct {
	SoupCache *cache;
	SoupCacheEntry *entry;
} StreamHelper;

static void
istream_caching_finished (SoupCacheInputStream *istream,
			  gsize                 bytes_written,
			  GError               *error,
			  gpointer              user_data)
{
	StreamHelper *helper = (StreamHelper *) user_data;
	SoupCache *cache = helper->cache;
	SoupCacheEntry *entry = helper->entry;

	--cache->priv->n_pending;

	entry->dirty = FALSE;
	entry->length = bytes_written;
	g_clear_object (&entry->cancellable);

	if (error) {
		/* Update cache size */
		if (soup_message_headers_get_encoding (entry->headers) == SOUP_ENCODING_CONTENT_LENGTH)
			cache->priv->size -= soup_message_headers_get_content_length (entry->headers);

		soup_cache_entry_remove (cache, entry, TRUE);
		helper->entry = entry = NULL;
		goto cleanup;
	}

	if (soup_message_headers_get_encoding (entry->headers) != SOUP_ENCODING_CONTENT_LENGTH) {

		if (cache_accepts_entries_of_size (cache, entry->length)) {
			make_room_for_new_entry (cache, entry->length);
			cache->priv->size += entry->length;
		} else {
			soup_cache_entry_remove (cache, entry, TRUE);
			helper->entry = entry = NULL;
		}
	}

 cleanup:
	g_object_unref (helper->cache);
	g_slice_free (StreamHelper, helper);
}

static GInputStream*
soup_cache_content_processor_wrap_input (SoupContentProcessor *processor,
					 GInputStream *base_stream,
					 SoupMessage *msg,
					 GError **error)
{
	SoupCache *cache = (SoupCache*) processor;
	SoupCacheEntry *entry;
	SoupCacheability cacheability;
	GInputStream *istream;
	GFile *file;
	StreamHelper *helper;
	time_t request_time, response_time;

	/* First of all, check if we should cache the resource. */
	cacheability = soup_cache_get_cacheability (cache, msg);
	entry = soup_cache_entry_lookup (cache, msg);

	if (cacheability & SOUP_CACHE_INVALIDATES) {
		if (entry)
			soup_cache_entry_remove (cache, entry, TRUE);
		return NULL;
	}

	if (cacheability & SOUP_CACHE_VALIDATES) {
		/* It's possible to get a CACHE_VALIDATES with no
		 * entry in the hash table. This could happen if for
		 * example the soup client is the one creating the
		 * conditional request.
		 */
		if (entry)
			soup_cache_update_from_conditional_request (cache, msg);
		return NULL;
	}

	if (!(cacheability & SOUP_CACHE_CACHEABLE))
		return NULL;

	/* Check if we are already caching this resource */
	if (entry && (entry->dirty || entry->being_validated))
		return NULL;

	/* Create a new entry, deleting any old one if present */
	if (entry)
		soup_cache_entry_remove (cache, entry, TRUE);

	request_time = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (msg), "request-time"));
	response_time = GPOINTER_TO_INT (g_object_get_data (G_OBJECT (msg), "response-time"));
	entry = soup_cache_entry_new (cache, msg, request_time, response_time);
	entry->hits = 1;
	entry->dirty = TRUE;

	/* Do not continue if it can not be stored */
	if (!soup_cache_entry_insert (cache, entry, TRUE)) {
		soup_cache_entry_free (entry);
		return NULL;
	}

	entry->cancellable = g_cancellable_new ();
	++cache->priv->n_pending;

	helper = g_slice_new (StreamHelper);
	helper->cache = g_object_ref (cache);
	helper->entry = entry;

	file = get_file_from_entry (cache, entry);
	istream = soup_cache_input_stream_new (base_stream, file);
	g_object_unref (file);

	g_signal_connect (istream, "caching-finished", G_CALLBACK (istream_caching_finished), helper);

	return istream;
}

static void
soup_cache_content_processor_init (SoupContentProcessorInterface *processor_interface,
				   gpointer interface_data)
{
	soup_cache_default_content_processor_interface =
		g_type_default_interface_peek (SOUP_TYPE_CONTENT_PROCESSOR);

	processor_interface->processing_stage = SOUP_STAGE_ENTITY_BODY;
	processor_interface->wrap_input = soup_cache_content_processor_wrap_input;
}

static void
soup_cache_init (SoupCache *cache)
{
	SoupCachePrivate *priv;

	priv = cache->priv = soup_cache_get_instance_private (cache);

	priv->cache = g_hash_table_new (g_direct_hash, g_direct_equal);
	/* LRU */
	priv->lru_start = NULL;

	/* */
	priv->n_pending = 0;

	/* Cache size */
	priv->max_size = DEFAULT_MAX_SIZE;
	priv->max_entry_data_size = priv->max_size / MAX_ENTRY_DATA_PERCENTAGE;
	priv->size = 0;
}

static void
remove_cache_item (gpointer data,
		   gpointer user_data)
{
	soup_cache_entry_remove ((SoupCache *) user_data, (SoupCacheEntry *) data, FALSE);
}

static void
soup_cache_finalize (GObject *object)
{
	SoupCachePrivate *priv;
	GList *entries;

	priv = SOUP_CACHE (object)->priv;

	/* Cannot use g_hash_table_foreach as callbacks must not modify the hash table */
	entries = g_hash_table_get_values (priv->cache);
	g_list_foreach (entries, remove_cache_item, object);
	g_list_free (entries);

	g_hash_table_destroy (priv->cache);
	g_free (priv->cache_dir);

	g_list_free (priv->lru_start);

	G_OBJECT_CLASS (soup_cache_parent_class)->finalize (object);
}

static void
soup_cache_set_property (GObject *object, guint prop_id,
				const GValue *value, GParamSpec *pspec)
{
	SoupCachePrivate *priv = SOUP_CACHE (object)->priv;

	switch (prop_id) {
	case PROP_CACHE_DIR:
		g_assert (!priv->cache_dir);

		priv->cache_dir = g_value_dup_string (value);

		if (!priv->cache_dir)
			/* Set a default cache dir, different for each user */
			priv->cache_dir = g_build_filename (g_get_user_cache_dir (),
							    "httpcache",
							    NULL);

		/* Create directory if it does not exist */
		if (!g_file_test (priv->cache_dir, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR))
			g_mkdir_with_parents (priv->cache_dir, 0700);
		break;
	case PROP_CACHE_TYPE:
		priv->cache_type = g_value_get_enum (value);
		/* TODO: clear private entries and issue a warning if moving to shared? */
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_cache_get_property (GObject *object, guint prop_id,
			 GValue *value, GParamSpec *pspec)
{
	SoupCachePrivate *priv = SOUP_CACHE (object)->priv;

	switch (prop_id) {
	case PROP_CACHE_DIR:
		g_value_set_string (value, priv->cache_dir);
		break;
	case PROP_CACHE_TYPE:
		g_value_set_enum (value, priv->cache_type);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_cache_class_init (SoupCacheClass *cache_class)
{
	GObjectClass *gobject_class = (GObjectClass *)cache_class;

	gobject_class->finalize = soup_cache_finalize;
	gobject_class->set_property = soup_cache_set_property;
	gobject_class->get_property = soup_cache_get_property;

	cache_class->get_cacheability = get_cacheability;

	g_object_class_install_property (gobject_class, PROP_CACHE_DIR,
					 g_param_spec_string ("cache-dir",
							      "Cache directory",
							      "The directory to store the cache files",
							      NULL,
							      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
							      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property (gobject_class, PROP_CACHE_TYPE,
					 g_param_spec_enum ("cache-type",
							    "Cache type",
							    "Whether the cache is private or shared",
							    SOUP_TYPE_CACHE_TYPE,
							    SOUP_CACHE_SINGLE_USER,
							    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
							    G_PARAM_STATIC_STRINGS));
}

/**
 * SoupCacheType:
 * @SOUP_CACHE_SINGLE_USER: a single-user cache
 * @SOUP_CACHE_SHARED: a shared cache
 *
 * The type of cache; this affects what kinds of responses will be
 * saved.
 *
 * Since: 2.34
 */

/**
 * soup_cache_new:
 * @cache_dir: (allow-none): the directory to store the cached data, or %NULL
 *   to use the default one. Note that since the cache isn't safe to access for
 *   multiple processes at once, and the default directory isn't namespaced by
 *   process, clients are strongly discouraged from passing %NULL.
 * @cache_type: the #SoupCacheType of the cache
 *
 * Creates a new #SoupCache.
 *
 * Returns: a new #SoupCache
 *
 * Since: 2.34
 */
SoupCache *
soup_cache_new (const char *cache_dir, SoupCacheType cache_type)
{
	return g_object_new (SOUP_TYPE_CACHE,
			     "cache-dir", cache_dir,
			     "cache-type", cache_type,
			     NULL);
}

/**
 * soup_cache_has_response:
 * @cache: a #SoupCache
 * @msg: a #SoupMessage
 *
 * This function calculates whether the @cache object has a proper
 * response for the request @msg given the flags both in the request
 * and the cached reply and the time ellapsed since it was cached.
 *
 * Returns: whether or not the @cache has a valid response for @msg
 *
 * Since: 2.34
 */
SoupCacheResponse
soup_cache_has_response (SoupCache *cache, SoupMessage *msg)
{
	SoupCacheEntry *entry;
	const char *cache_control;
	gpointer value;
	int max_age, max_stale, min_fresh;
	GList *lru_item, *item;

	entry = soup_cache_entry_lookup (cache, msg);

	/* 1. The presented Request-URI and that of stored response
	 * match
	 */
	if (!entry)
		return SOUP_CACHE_RESPONSE_STALE;

	/* Increase hit count. Take sorting into account */
	entry->hits++;
	lru_item = g_list_find (cache->priv->lru_start, entry);
	item = lru_item;
	while (item->next && lru_compare_func (item->data, item->next->data) > 0)
		item = g_list_next (item);

	if (item != lru_item) {
		cache->priv->lru_start = g_list_remove_link (cache->priv->lru_start, lru_item);
		item = g_list_insert_sorted (item, lru_item->data, lru_compare_func);
		g_list_free (lru_item);
	}

	if (entry->dirty || entry->being_validated)
		return SOUP_CACHE_RESPONSE_STALE;

	/* 2. The request method associated with the stored response
	 *  allows it to be used for the presented request
	 */

	/* In practice this means we only return our resource for GET,
	 * cacheability for other methods is a TODO in the RFC
	 * (TODO: although we could return the headers for HEAD
	 * probably).
	 */
	if (msg->method != SOUP_METHOD_GET)
		return SOUP_CACHE_RESPONSE_STALE;

	/* 3. Selecting request-headers nominated by the stored
	 * response (if any) match those presented.
	 */

	/* TODO */

	/* 4. The request is a conditional request issued by the client.
	 */
	if (soup_message_headers_get_one (msg->request_headers, "If-Modified-Since") ||
	    soup_message_headers_get_list (msg->request_headers, "If-None-Match"))
		return SOUP_CACHE_RESPONSE_STALE;

	/* 5. The presented request and stored response are free from
	 * directives that would prevent its use.
	 */

	max_age = max_stale = min_fresh = -1;

	/* For HTTP 1.0 compatibility. RFC2616 section 14.9.4
	 */
	if (soup_message_headers_header_contains (msg->request_headers, "Pragma", "no-cache"))
		return SOUP_CACHE_RESPONSE_STALE;

	cache_control = soup_message_headers_get_list (msg->request_headers, "Cache-Control");
	if (cache_control && *cache_control) {
		GHashTable *hash = soup_header_parse_param_list (cache_control);

		if (g_hash_table_lookup_extended (hash, "no-store", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return SOUP_CACHE_RESPONSE_STALE;
		}

		if (g_hash_table_lookup_extended (hash, "no-cache", NULL, NULL)) {
			soup_header_free_param_list (hash);
			return SOUP_CACHE_RESPONSE_STALE;
		}

		if (g_hash_table_lookup_extended (hash, "max-age", NULL, &value) && value) {
			max_age = (int)MIN (g_ascii_strtoll (value, NULL, 10), G_MAXINT32);
			/* Forcing cache revalidaton
			 */
			if (!max_age) {
				soup_header_free_param_list (hash);
				return SOUP_CACHE_RESPONSE_NEEDS_VALIDATION;
			}
		}

		/* max-stale can have no value set, we need to use _extended */
		if (g_hash_table_lookup_extended (hash, "max-stale", NULL, &value)) {
			if (value)
				max_stale = (int)MIN (g_ascii_strtoll (value, NULL, 10), G_MAXINT32);
			else
				max_stale = G_MAXINT32;
		}

		value = g_hash_table_lookup (hash, "min-fresh");
		if (value)
			min_fresh = (int)MIN (g_ascii_strtoll (value, NULL, 10), G_MAXINT32);

		soup_header_free_param_list (hash);

		if (max_age > 0) {
			guint current_age = soup_cache_entry_get_current_age (entry);

			/* If we are over max-age and max-stale is not
			   set, do not use the value from the cache
			   without validation */
			if ((guint) max_age <= current_age && max_stale == -1)
				return SOUP_CACHE_RESPONSE_NEEDS_VALIDATION;
		}
	}

	/* 6. The stored response is either: fresh, allowed to be
	 * served stale or succesfully validated
	 */
	if (!soup_cache_entry_is_fresh_enough (entry, min_fresh)) {
		/* Not fresh, can it be served stale? */

		/* When the must-revalidate directive is present in a
		 * response received by a cache, that cache MUST NOT
		 * use the entry after it becomes stale
		 */
		/* TODO consider also proxy-revalidate & s-maxage */
		if (entry->must_revalidate)
			return SOUP_CACHE_RESPONSE_NEEDS_VALIDATION;

		if (max_stale != -1) {
			/* G_MAXINT32 means we accept any staleness */
			if (max_stale == G_MAXINT32)
				return SOUP_CACHE_RESPONSE_FRESH;

			if ((soup_cache_entry_get_current_age (entry) - entry->freshness_lifetime) <= (guint) max_stale)
				return SOUP_CACHE_RESPONSE_FRESH;
		}

		return SOUP_CACHE_RESPONSE_NEEDS_VALIDATION;
	}

	return SOUP_CACHE_RESPONSE_FRESH;
}

/**
 * soup_cache_get_cacheability:
 * @cache: a #SoupCache
 * @msg: a #SoupMessage
 *
 * Calculates whether the @msg can be cached or not.
 *
 * Returns: a #SoupCacheability value indicating whether the @msg can be cached or not.
 *
 * Since: 2.34
 */
SoupCacheability
soup_cache_get_cacheability (SoupCache *cache, SoupMessage *msg)
{
	g_return_val_if_fail (SOUP_IS_CACHE (cache), SOUP_CACHE_UNCACHEABLE);
	g_return_val_if_fail (SOUP_IS_MESSAGE (msg), SOUP_CACHE_UNCACHEABLE);

	return SOUP_CACHE_GET_CLASS (cache)->get_cacheability (cache, msg);
}

static gboolean
force_flush_timeout (gpointer data)
{
	gboolean *forced = (gboolean *)data;
	*forced = TRUE;

	return FALSE;
}

/**
 * soup_cache_flush:
 * @cache: a #SoupCache
 *
 * This function will force all pending writes in the @cache to be
 * committed to disk. For doing so it will iterate the #GMainContext
 * associated with @cache's session as long as needed.
 *
 * Contrast with soup_cache_dump(), which writes out the cache index
 * file.
 *
 * Since: 2.34
 */
void
soup_cache_flush (SoupCache *cache)
{
	GMainContext *async_context;
	SoupSession *session;
	GSource *timeout;
	gboolean forced = FALSE;

	g_return_if_fail (SOUP_IS_CACHE (cache));

	session = cache->priv->session;
	g_return_if_fail (SOUP_IS_SESSION (session));
	async_context = soup_session_get_async_context (session);

	/* We give cache 10 secs to finish */
	timeout = soup_add_timeout (async_context, 10000, force_flush_timeout, &forced);

	while (!forced && cache->priv->n_pending > 0)
		g_main_context_iteration (async_context, FALSE);

	if (!forced)
		g_source_destroy (timeout);
	else
		g_warning ("Cache flush finished despite %d pending requests", cache->priv->n_pending);
}

typedef void (* SoupCacheForeachFileFunc) (SoupCache *cache, const char *name, gpointer user_data);

static void
soup_cache_foreach_file (SoupCache *cache, SoupCacheForeachFileFunc func, gpointer user_data)
{
	GDir *dir;
	const char *name;
	SoupCachePrivate *priv = cache->priv;

	dir = g_dir_open (priv->cache_dir, 0, NULL);
	while ((name = g_dir_read_name (dir))) {
		if (g_str_has_prefix (name, "soup."))
		    continue;

		func (cache, name, user_data);
	}
	g_dir_close (dir);
}

static void
clear_cache_item (gpointer data,
		  gpointer user_data)
{
	soup_cache_entry_remove ((SoupCache *) user_data, (SoupCacheEntry *) data, TRUE);
}

static void
delete_cache_file (SoupCache *cache, const char *name, gpointer user_data)
{
	gchar *path;

	path = g_build_filename (cache->priv->cache_dir, name, NULL);
	g_unlink (path);
	g_free (path);
}

static void
clear_cache_files (SoupCache *cache)
{
	soup_cache_foreach_file (cache, delete_cache_file, NULL);
}

/**
 * soup_cache_clear:
 * @cache: a #SoupCache
 *
 * Will remove all entries in the @cache plus all the cache files.
 *
 * Since: 2.34
 */
void
soup_cache_clear (SoupCache *cache)
{
	GList *entries;

	g_return_if_fail (SOUP_IS_CACHE (cache));
	g_return_if_fail (cache->priv->cache);

	/* Cannot use g_hash_table_foreach as callbacks must not modify the hash table */
	entries = g_hash_table_get_values (cache->priv->cache);
	g_list_foreach (entries, clear_cache_item, cache);
	g_list_free (entries);

	/* Remove also any file not associated with a cache entry. */
	clear_cache_files (cache);
}

SoupMessage *
soup_cache_generate_conditional_request (SoupCache *cache, SoupMessage *original)
{
	SoupMessage *msg;
	SoupURI *uri;
	SoupCacheEntry *entry;
	const char *last_modified, *etag;
	GList *disabled_features, *f;

	g_return_val_if_fail (SOUP_IS_CACHE (cache), NULL);
	g_return_val_if_fail (SOUP_IS_MESSAGE (original), NULL);

	/* Add the validator entries in the header from the cached data */
	entry = soup_cache_entry_lookup (cache, original);
	g_return_val_if_fail (entry, NULL);

	last_modified = soup_message_headers_get_one (entry->headers, "Last-Modified");
	etag = soup_message_headers_get_one (entry->headers, "ETag");

	if (!last_modified && !etag)
		return NULL;

	entry->being_validated = TRUE;

	/* Copy the data we need from the original message */
	uri = soup_message_get_uri (original);
	msg = soup_message_new_from_uri (original->method, uri);
	soup_message_set_flags (msg, soup_message_get_flags (original));
	soup_message_disable_feature (msg, SOUP_TYPE_CACHE);

	soup_message_headers_foreach (original->request_headers,
				      (SoupMessageHeadersForeachFunc)copy_headers,
				      msg->request_headers);

	disabled_features = soup_message_get_disabled_features (original);
	for (f = disabled_features; f; f = f->next)
		soup_message_disable_feature (msg, (GType) GPOINTER_TO_SIZE (f->data));
	g_list_free (disabled_features);

	if (last_modified)
		soup_message_headers_append (msg->request_headers,
					     "If-Modified-Since",
					     last_modified);
	if (etag)
		soup_message_headers_append (msg->request_headers,
					     "If-None-Match",
					     etag);

	return msg;
}

void
soup_cache_cancel_conditional_request (SoupCache   *cache,
				       SoupMessage *msg)
{
	SoupCacheEntry *entry;

	entry = soup_cache_entry_lookup (cache, msg);
	if (entry)
		entry->being_validated = FALSE;

	soup_session_cancel_message (cache->priv->session, msg, SOUP_STATUS_CANCELLED);
}

void
soup_cache_update_from_conditional_request (SoupCache   *cache,
					    SoupMessage *msg)
{
	SoupCacheEntry *entry = soup_cache_entry_lookup (cache, msg);
	if (!entry)
		return;

	entry->being_validated = FALSE;

	if (msg->status_code == SOUP_STATUS_NOT_MODIFIED) {
		soup_message_headers_foreach (msg->response_headers,
					      (SoupMessageHeadersForeachFunc) remove_headers,
					      entry->headers);
		copy_end_to_end_headers (msg->response_headers, entry->headers);

		soup_cache_entry_set_freshness (entry, msg, cache);
	}
}

static void
pack_entry (gpointer data,
	    gpointer user_data)
{
	SoupCacheEntry *entry = (SoupCacheEntry *) data;
	SoupMessageHeadersIter iter;
	const char *header_key, *header_value;
	GVariantBuilder *entries_builder = (GVariantBuilder *)user_data;

	/* Do not store non-consolidated entries */
	if (entry->dirty || !entry->key)
		return;

	g_variant_builder_open (entries_builder, G_VARIANT_TYPE (SOUP_CACHE_PHEADERS_FORMAT));
	g_variant_builder_add (entries_builder, "s", entry->uri);
	g_variant_builder_add (entries_builder, "b", entry->must_revalidate);
	g_variant_builder_add (entries_builder, "u", entry->freshness_lifetime);
	g_variant_builder_add (entries_builder, "u", entry->corrected_initial_age);
	g_variant_builder_add (entries_builder, "u", entry->response_time);
	g_variant_builder_add (entries_builder, "u", entry->hits);
	g_variant_builder_add (entries_builder, "u", entry->length);
	g_variant_builder_add (entries_builder, "q", entry->status_code);

	/* Pack headers */
	g_variant_builder_open (entries_builder, G_VARIANT_TYPE ("a" SOUP_CACHE_HEADERS_FORMAT));
	soup_message_headers_iter_init (&iter, entry->headers);
	while (soup_message_headers_iter_next (&iter, &header_key, &header_value)) {
		if (g_utf8_validate (header_value, -1, NULL))
			g_variant_builder_add (entries_builder, SOUP_CACHE_HEADERS_FORMAT,
					       header_key, header_value);
	}
	g_variant_builder_close (entries_builder); /* "a" SOUP_CACHE_HEADERS_FORMAT */
	g_variant_builder_close (entries_builder); /* SOUP_CACHE_PHEADERS_FORMAT */
}

/**
 * soup_cache_dump:
 * @cache: a #SoupCache
 *
 * Synchronously writes the cache index out to disk. Contrast with
 * soup_cache_flush(), which writes pending cache
 * <emphasis>entries</emphasis> to disk.
 *
 * You must call this before exiting if you want your cache data to
 * persist between sessions.
 *
 * Since: 2.34.
 */
void
soup_cache_dump (SoupCache *cache)
{
	SoupCachePrivate *priv = soup_cache_get_instance_private (cache);
	char *filename;
	GVariantBuilder entries_builder;
	GVariant *cache_variant;

	if (!g_list_length (cache->priv->lru_start))
		return;

	/* Create the builder and iterate over all entries */
	g_variant_builder_init (&entries_builder, G_VARIANT_TYPE (SOUP_CACHE_ENTRIES_FORMAT));
	g_variant_builder_add (&entries_builder, "q", SOUP_CACHE_CURRENT_VERSION);
	g_variant_builder_open (&entries_builder, G_VARIANT_TYPE ("a" SOUP_CACHE_PHEADERS_FORMAT));
	g_list_foreach (cache->priv->lru_start, pack_entry, &entries_builder);
	g_variant_builder_close (&entries_builder);

	/* Serialize and dump */
	cache_variant = g_variant_builder_end (&entries_builder);
	g_variant_ref_sink (cache_variant);
	filename = g_build_filename (priv->cache_dir, SOUP_CACHE_FILE, NULL);
	g_file_set_contents (filename, (const char *) g_variant_get_data (cache_variant),
			     g_variant_get_size (cache_variant), NULL);
	g_free (filename);
	g_variant_unref (cache_variant);
}

static inline guint32
get_key_from_cache_filename (const char *name)
{
	guint64 key;

	key = g_ascii_strtoull (name, NULL, 10);
	return key ? (guint32)key : 0;
}

static void
insert_cache_file (SoupCache *cache, const char *name, GHashTable *leaked_entries)
{
	gchar *path;

	path = g_build_filename (cache->priv->cache_dir, name, NULL);
	if (g_file_test (path, G_FILE_TEST_IS_REGULAR)) {
		guint32 key = get_key_from_cache_filename (name);

		if (key) {
			g_hash_table_insert (leaked_entries, GUINT_TO_POINTER (key), path);
			return;
		}
	}
	g_free (path);
}

/**
 * soup_cache_load:
 * @cache: a #SoupCache
 *
 * Loads the contents of @cache's index into memory.
 *
 * Since: 2.34
 */
void
soup_cache_load (SoupCache *cache)
{
	gboolean must_revalidate;
	guint32 freshness_lifetime, hits;
	guint32 corrected_initial_age, response_time;
	char *url, *filename = NULL, *contents = NULL;
	GVariant *cache_variant;
	GVariantIter *entries_iter = NULL, *headers_iter = NULL;
	gsize length;
	SoupCacheEntry *entry;
	SoupCachePrivate *priv = cache->priv;
	guint16 version, status_code;
	GHashTable *leaked_entries = NULL;
	GHashTableIter iter;
	gpointer value;

	filename = g_build_filename (priv->cache_dir, SOUP_CACHE_FILE, NULL);
	if (!g_file_get_contents (filename, &contents, &length, NULL)) {
		g_free (filename);
		g_free (contents);
		clear_cache_files (cache);
		return;
	}
	g_free (filename);

	cache_variant = g_variant_new_from_data (G_VARIANT_TYPE (SOUP_CACHE_ENTRIES_FORMAT),
						 (const char *) contents, length, FALSE, g_free, contents);
	g_variant_get (cache_variant, SOUP_CACHE_ENTRIES_FORMAT, &version, &entries_iter);
	if (version != SOUP_CACHE_CURRENT_VERSION) {
		g_variant_iter_free (entries_iter);
		g_variant_unref (cache_variant);
		clear_cache_files (cache);
		return;
	}

	leaked_entries = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, g_free);
	soup_cache_foreach_file (cache, (SoupCacheForeachFileFunc)insert_cache_file, leaked_entries);

	while (g_variant_iter_loop (entries_iter, SOUP_CACHE_PHEADERS_FORMAT,
				    &url, &must_revalidate, &freshness_lifetime, &corrected_initial_age,
				    &response_time, &hits, &length, &status_code,
				    &headers_iter)) {
		const char *header_key, *header_value;
		SoupMessageHeaders *headers;
		SoupMessageHeadersIter soup_headers_iter;

		/* SoupMessage Headers */
		headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
		while (g_variant_iter_loop (headers_iter, SOUP_CACHE_HEADERS_FORMAT, &header_key, &header_value))
			if (*header_key && *header_value)
				soup_message_headers_append (headers, header_key, header_value);

		/* Check that we have headers */
		soup_message_headers_iter_init (&soup_headers_iter, headers);
		if (!soup_message_headers_iter_next (&soup_headers_iter, &header_key, &header_value)) {
			soup_message_headers_free (headers);
			continue;
		}

		/* Insert in cache */
		entry = g_slice_new0 (SoupCacheEntry);
		entry->uri = g_strdup (url);
		entry->must_revalidate = must_revalidate;
		entry->freshness_lifetime = freshness_lifetime;
		entry->corrected_initial_age = corrected_initial_age;
		entry->response_time = response_time;
		entry->hits = hits;
		entry->length = length;
		entry->headers = headers;
		entry->status_code = status_code;

		if (!soup_cache_entry_insert (cache, entry, FALSE))
			soup_cache_entry_free (entry);
		else
			g_hash_table_remove (leaked_entries, GUINT_TO_POINTER (entry->key));
	}

	/* Remove the leaked files */
	g_hash_table_iter_init (&iter, leaked_entries);
	while (g_hash_table_iter_next (&iter, NULL, &value))
		g_unlink ((char *)value);
	g_hash_table_destroy (leaked_entries);

	cache->priv->lru_start = g_list_reverse (cache->priv->lru_start);

	/* frees */
	g_variant_iter_free (entries_iter);
	g_variant_unref (cache_variant);
}

/**
 * soup_cache_set_max_size:
 * @cache: a #SoupCache
 * @max_size: the maximum size of the cache, in bytes
 *
 * Sets the maximum size of the cache.
 *
 * Since: 2.34
 */
void
soup_cache_set_max_size (SoupCache *cache,
			 guint      max_size)
{
	cache->priv->max_size = max_size;
	cache->priv->max_entry_data_size = cache->priv->max_size / MAX_ENTRY_DATA_PERCENTAGE;
}

/**
 * soup_cache_get_max_size:
 * @cache: a #SoupCache
 *
 * Gets the maximum size of the cache.
 *
 * Return value: the maximum size of the cache, in bytes.
 *
 * Since: 2.34
 */
guint
soup_cache_get_max_size (SoupCache *cache)
{
	return cache->priv->max_size;
}
