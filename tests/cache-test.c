/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright 2012 Red Hat, Inc.
 */

#include "test-utils.h"
#include <glib/gstdio.h>

static void
server_callback (SoupServer        *server,
		 SoupServerMessage *msg,
		 const char        *path,
		 GHashTable        *query,
		 gpointer           data)
{
	const char *last_modified, *etag;
	const char *header;
	const char *method;
	SoupMessageHeaders *request_headers;
	SoupMessageHeaders *response_headers;
	guint status = SOUP_STATUS_OK;

	method = soup_server_message_get_method (msg);

	if (method != SOUP_METHOD_GET && method != SOUP_METHOD_POST) {
		soup_server_message_set_status (msg, SOUP_STATUS_NOT_IMPLEMENTED, NULL);
		return;
	}

	request_headers = soup_server_message_get_request_headers (msg);
	response_headers = soup_server_message_get_response_headers (msg);
	header = soup_message_headers_get_one (request_headers,
					       "Test-Set-Expires");
	if (header) {
		soup_message_headers_append (response_headers,
					     "Expires",
					     header);
	}

	header = soup_message_headers_get_one (request_headers,
					       "Test-Set-Cache-Control");
	if (header) {
		soup_message_headers_append (response_headers,
					     "Cache-Control",
					     header);
	}

	last_modified = soup_message_headers_get_one (request_headers,
						      "Test-Set-Last-Modified");
	if (last_modified) {
		soup_message_headers_append (response_headers,
					     "Last-Modified",
					     last_modified);
	}

	etag = soup_message_headers_get_one (request_headers,
					     "Test-Set-ETag");
	if (etag) {
		soup_message_headers_append (response_headers,
					     "ETag",
					     etag);
	}


	header = soup_message_headers_get_one (request_headers,
					       "If-Modified-Since");
	if (header && last_modified) {
		GDateTime *modified_date, *header_date;

		modified_date = soup_date_time_new_from_http_string (last_modified);
		header_date = soup_date_time_new_from_http_string (header);

		if (g_date_time_compare (modified_date, header_date) <= 0)
			status = SOUP_STATUS_NOT_MODIFIED;

                g_date_time_unref (modified_date);
                g_date_time_unref (header_date);
	}

	header = soup_message_headers_get_one (request_headers,
					       "If-None-Match");
	if (header && etag) {
		if (!strcmp (header, etag))
			status = SOUP_STATUS_NOT_MODIFIED;
	}

	header = soup_message_headers_get_one (request_headers,
					       "Test-Set-My-Header");
	if (header) {
		soup_message_headers_append (response_headers,
					     "My-Header",
					     header);
	}

	if (status == SOUP_STATUS_OK) {
		GChecksum *sum;
		const char *body;

		sum = g_checksum_new (G_CHECKSUM_SHA256);
		g_checksum_update (sum, (guchar *)path, strlen (path));
		if (last_modified)
			g_checksum_update (sum, (guchar *)last_modified, strlen (last_modified));
		if (etag)
			g_checksum_update (sum, (guchar *)etag, strlen (etag));
		body = g_checksum_get_string (sum);
		soup_server_message_set_response (msg, "text/plain",
						  SOUP_MEMORY_COPY,
						  body, strlen (body) + 1);
		g_checksum_free (sum);
	}
	soup_server_message_set_status (msg, status, NULL);
}

static gboolean
is_network_stream (GInputStream *stream)
{
	while (G_IS_FILTER_INPUT_STREAM (stream))
		stream = G_FILTER_INPUT_STREAM (stream)->base_stream;

	return !G_IS_FILE_INPUT_STREAM (stream);
}

static char *do_request (SoupSession        *session,
			 GUri               *base_uri,
			 const char         *method,
			 const char         *path,
			 SoupMessageHeaders *response_headers,
			 ...) G_GNUC_NULL_TERMINATED;

static gboolean last_request_hit_network;
static gboolean last_request_validated;
static gboolean last_request_unqueued;

static void
copy_headers (const char         *name,
	      const char         *value,
	      gpointer            user_data)
{
	SoupMessageHeaders *headers = (SoupMessageHeaders *) user_data;
	soup_message_headers_append (headers, name, value);
}

static char *
do_request (SoupSession        *session,
	    GUri               *base_uri,
	    const char         *method,
	    const char         *path,
	    SoupMessageHeaders *response_headers,
	    ...)
{
	SoupMessage *msg;
	GInputStream *stream;
	GUri *uri;
	va_list ap;
	const char *header, *value;
	char buf[256];
	gsize nread;
	GError *error = NULL;

	last_request_validated = last_request_hit_network = FALSE;
	last_request_unqueued = FALSE;

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri (method, uri);
	g_uri_unref (uri);

	va_start (ap, response_headers);
	while ((header = va_arg (ap, const char *))) {
		value = va_arg (ap, const char *);
		soup_message_headers_append (soup_message_get_request_headers (msg),
					     header, value);
	}
	va_end (ap);

	stream = soup_test_request_send (session, msg, NULL, 0, &error);
	if (!stream) {
		debug_printf (1, "    could not send request: %s\n",
			      error->message);
		g_error_free (error);
		g_object_unref (msg);
		return NULL;
	}

	if (response_headers)
		soup_message_headers_foreach (soup_message_get_response_headers (msg), copy_headers, response_headers);

	g_object_unref (msg);

	if (last_request_validated)
		last_request_unqueued = FALSE;
	else
		soup_test_assert (!last_request_unqueued,
				  "Request unqueued before finishing");

	last_request_hit_network = is_network_stream (stream);

	g_input_stream_read_all (stream, buf, sizeof (buf), &nread,
				 NULL, &error);
	if (error) {
		debug_printf (1, "    could not read response: %s\n",
			      error->message);
		g_clear_error (&error);
	}
	soup_test_request_close_stream (stream, NULL, &error);
	if (error) {
		debug_printf (1, "    could not close stream: %s\n",
			      error->message);
		g_clear_error (&error);
	}
	g_object_unref (stream);

	/* Cache writes are G_PRIORITY_LOW, so they won't have happened yet... */
	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));

	return nread ? g_memdup2 (buf, nread) : g_strdup ("");
}

static void
do_request_with_cancel (SoupSession          *session,
			GUri                 *base_uri,
			const char           *method,
			const char           *path,
			SoupTestRequestFlags  flags)
{
	SoupMessage *msg;
	GInputStream *stream;
	GUri *uri;
	GError *error = NULL;
	GCancellable *cancellable;

	last_request_validated = last_request_hit_network = last_request_unqueued = FALSE;

	uri = g_uri_parse_relative (base_uri, path, SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri (method, uri);
	g_uri_unref (uri);
	cancellable = g_cancellable_new ();
	stream = soup_test_request_send (session, msg, cancellable, flags, &error);
	if (stream) {
		debug_printf (1, "    could not cancel the request\n");
		g_object_unref (stream);
		g_object_unref (msg);
		return;
	} else {
		g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
		g_clear_error (&error);
	}

	g_clear_object (&cancellable);
	g_clear_object (&stream);
	g_clear_object (&msg);

	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));
}

static void
message_starting (SoupMessage *msg, gpointer data)
{
	if (soup_message_headers_get_one (soup_message_get_request_headers (msg),
					  "If-Modified-Since") ||
	    soup_message_headers_get_one (soup_message_get_request_headers (msg),
					  "If-None-Match")) {
		debug_printf (2, "    Conditional request for %s\n",
			      g_uri_get_path (soup_message_get_uri (msg)));
		last_request_validated = TRUE;
	}
}

static void
request_queued (SoupSession *session, SoupMessage *msg,
		gpointer data)
{
	g_signal_connect (msg, "starting",
			  G_CALLBACK (message_starting),
			  data);
}

static void
request_unqueued (SoupSession *session, SoupMessage *msg,
		  gpointer data)
{
	last_request_unqueued = TRUE;
}

static void
do_basics_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *body2, *body3, *body4, *body5, *cmp;

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (request_queued), NULL);
	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (request_unqueued), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			    NULL);
	body2 = do_request (session, base_uri, "GET", "/2", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);
	body3 = do_request (session, base_uri, "GET", "/3", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);
	body4 = do_request (session, base_uri, "GET", "/4", NULL,
			    "Test-Set-ETag", "\"abcdefg\"",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);
	body5 = do_request (session, base_uri, "GET", "/5", NULL,
			    "Test-Set-Cache-Control", "no-cache",
			    NULL);


	/* Resource with future Expires should have been cached */
	debug_printf (1, "  Fresh cached resource\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	soup_test_assert (!last_request_hit_network,
			  "Request for /1 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /1 not unqueued");
	g_assert_cmpstr (body1, ==, cmp);
	g_free (cmp);


	/* Resource with long-ago Last-Modified should have been cached */
	debug_printf (1, "  Heuristically-fresh cached resource\n");
	cmp = do_request (session, base_uri, "GET", "/2", NULL,
			  NULL);
	/* Not validated even if it has must-revalidate, because it hasn't expired */
	soup_test_assert (!last_request_validated,
			  "Request for /2 was validated");
	soup_test_assert (!last_request_hit_network,
			  "Request for /2 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /2 not unqueued");
	g_assert_cmpstr (body2, ==, cmp);
	g_free (cmp);


	/* Adding a query string should bypass the cache but not invalidate it */
	debug_printf (1, "  Fresh cached resource with a query\n");
	cmp = do_request (session, base_uri, "GET", "/1?attr=value", NULL,
			  NULL);
	soup_test_assert (last_request_hit_network,
			  "Request for /1?attr=value filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /1?attr=value not unqueued");
	g_free (cmp);
	debug_printf (2, "  Second request\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	soup_test_assert (!last_request_hit_network,
			  "Second request for /1 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Request for /1 not unqueued");
	g_assert_cmpstr (body1, ==, cmp);
	g_free (cmp);


	/* Expired + must-revalidate causes a conditional request */
	debug_printf (1, "  Unchanged must-revalidate resource w/ Last-Modified\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	soup_test_assert (last_request_validated,
			  "Request for /3 not validated");
	soup_test_assert (!last_request_hit_network,
			  "Request for /3 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /3 not unqueued");
	g_assert_cmpstr (body3, ==, cmp);
	g_free (cmp);


	/* Validation failure should update cache */
	debug_printf (1, "  Changed must-revalidate resource w/ Last-Modified\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Sat, 02 Jan 2010 00:00:00 GMT",
			  "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	soup_test_assert (last_request_validated,
			  "Request for /3 not validated");
	soup_test_assert (last_request_hit_network,
			  "Request for /3 filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Request for /3 not unqueued");
	g_assert_cmpstr (body3, !=, cmp);
	g_free (cmp);

	debug_printf (2, "  Second request\n");
	cmp = do_request (session, base_uri, "GET", "/3", NULL,
			  "Test-Set-Last-Modified", "Sat, 02 Jan 2010 00:00:00 GMT",
			  "Test-Set-Cache-Control", "must-revalidate",
			  NULL);
	soup_test_assert (last_request_validated,
			  "Second request for /3 not validated");
	soup_test_assert (!last_request_hit_network,
			  "Second request for /3 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /3 not unqueued");
	g_assert_cmpstr (body3, !=, cmp);
	g_free (cmp);

	/* ETag + must-revalidate causes a conditional request */
	debug_printf (1, "  Unchanged must-revalidate resource w/ ETag\n");
	cmp = do_request (session, base_uri, "GET", "/4", NULL,
			  "Test-Set-ETag", "\"abcdefg\"",
			  NULL);
	soup_test_assert (last_request_validated,
			  "Request for /4 not validated");
	soup_test_assert (!last_request_hit_network,
			  "Request for /4 not filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Cached resource /4 not unqueued");
	g_assert_cmpstr (body4, ==, cmp);
	g_free (cmp);


	/* Cache-Control: no-cache prevents caching */
	debug_printf (1, "  Uncacheable resource\n");
	cmp = do_request (session, base_uri, "GET", "/5", NULL,
			  "Test-Set-Cache-Control", "no-cache",
			  NULL);
	soup_test_assert (last_request_hit_network,
			  "Request for /5 filled from cache");
	soup_test_assert (last_request_unqueued,
			  "Request for /5 not unqueued");
	g_assert_cmpstr (body5, ==, cmp);
	g_free (cmp);


	/* PUT to a URI invalidates the cache entry */
	debug_printf (1, "  Invalidating and re-requesting a cached resource\n");
	cmp = do_request (session, base_uri, "PUT", "/1", NULL,
			  NULL);
	soup_test_assert (last_request_hit_network,
			  "PUT filled from cache");
	g_free (cmp);
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  NULL);
	soup_test_assert (last_request_hit_network,
			  "PUT failed to invalidate cache entry");
	g_assert_true (last_request_hit_network);
	g_free (cmp);


	soup_test_session_abort_unref (session);
	g_object_unref (cache);

	g_free (cache_dir);
	g_free (body1);
	g_free (body2);
	g_free (body3);
	g_free (body4);
	g_free (body5);
}

static void
do_cancel_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *body2;
	guint flags;

	g_test_bug ("692310");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (request_unqueued), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			    NULL);
	body2 = do_request (session, base_uri, "GET", "/2", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			    "Test-Set-Expires", "Fri, 01 Jan 2011 00:00:00 GMT",
			    "Test-Set-Cache-Control", "must-revalidate",
			    NULL);

	/* Check that messages are correctly processed on cancellations. */
	debug_printf (1, "  Cancel fresh resource with g_cancellable_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/1", flags);
	soup_test_assert (last_request_unqueued,
			  "Cancelled request /1 not unqueued");

	soup_test_session_abort_unref (session);

	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	g_signal_connect (session, "request-unqueued",
			  G_CALLBACK (request_unqueued), NULL);

	/* Check that messages are correctly processed on cancellations. */
	debug_printf (1, "  Cancel a revalidating resource with g_cancellable_cancel()\n");
	flags = SOUP_TEST_REQUEST_CANCEL_IMMEDIATE;
	do_request_with_cancel (session, base_uri, "GET", "/2", flags);
	soup_test_assert (last_request_unqueued,
			  "Cancelled request /2 not unqueued");

	soup_test_session_abort_unref (session);

	g_object_unref (cache);
	g_free (cache_dir);
	g_free (body1);
	g_free (body2);
}

static gboolean
unref_stream (gpointer stream)
{
	g_object_unref (stream);
	return FALSE;
}

static void
base_stream_unreffed (gpointer loop, GObject *ex_base_stream)
{
	g_main_loop_quit (loop);
}

static void
do_refcounting_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	SoupMessage *msg;
	GInputStream *stream, *base_stream;
	GUri *uri;
	GError *error = NULL;
	guint flags;
	GMainLoop *loop;

	g_test_bug ("682527");

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	last_request_validated = last_request_hit_network = FALSE;

	uri = g_uri_parse_relative (base_uri, "/1", SOUP_HTTP_URI_FLAGS, NULL);
	msg = soup_message_new_from_uri ("GET", uri);
	g_uri_unref (uri);

	flags = SOUP_TEST_REQUEST_CANCEL_AFTER_SEND_FINISH;
	stream = soup_test_request_send (session, msg, NULL, flags, &error);
	if (!stream) {
		debug_printf (1, "    could not send request: %s\n",
			      error->message);
		g_error_free (error);
		g_object_unref (msg);
		return;
	}
	g_object_unref (msg);

	base_stream = g_filter_input_stream_get_base_stream (G_FILTER_INPUT_STREAM (stream));

	debug_printf (1, " Checking that the base stream is properly unref'ed\n");
	loop = g_main_loop_new (NULL, FALSE);
	g_object_weak_ref (G_OBJECT (base_stream), base_stream_unreffed, loop);
	g_idle_add (unref_stream, stream);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);

	soup_cache_flush ((SoupCache *)soup_session_get_feature (session, SOUP_TYPE_CACHE));

	g_object_unref (cache);
	g_free (cache_dir);
	soup_test_session_abort_unref (session);
}

static void
do_headers_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	SoupMessageHeaders *headers;
	SoupCache *cache;
	char *cache_dir;
	char *body1, *cmp;
	const char *header_value;

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	g_signal_connect (session, "request-queued",
			  G_CALLBACK (request_queued), NULL);

	debug_printf (2, "  Initial requests\n");
	body1 = do_request (session, base_uri, "GET", "/1", NULL,
			    "Test-Set-Last-Modified", "Fri, 01 Jan 2100 00:00:00 GMT",
			    "Test-Set-My-Header", "My header value",
			    NULL);

	/* My-Header new value should be updated in cache */
	debug_printf (2, "  Fresh cached resource which updates My-Header\n");
	cmp = do_request (session, base_uri, "GET", "/1", NULL,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  "Test-Set-My-Header", "My header NEW value",
			  NULL);
	soup_test_assert (last_request_validated,
			  "Request for /1 not validated");
	soup_test_assert (!last_request_hit_network,
			  "Request for /1 not filled from cache");
	g_free (cmp);

	/* Check that cache returns the updated header */
	debug_printf (2, "  Fresh cached resource with new value for My-Header\n");
	headers = soup_message_headers_new (SOUP_MESSAGE_HEADERS_RESPONSE);
	cmp = do_request (session, base_uri, "GET", "/1", headers,
			  "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
			  NULL);
	soup_test_assert (!last_request_hit_network,
			  "Request for /1 not filled from cache");
	g_free (cmp);

	header_value = soup_message_headers_get_list (headers, "My-Header");
	g_assert_cmpstr (header_value, ==, "My header NEW value");
	soup_message_headers_unref (headers);

	soup_test_session_abort_unref (session);
	g_object_unref (cache);

	g_free (cache_dir);
	g_free (body1);
}

static guint
count_cached_resources_in_dir (const char *cache_dir)
{
	GDir *dir;
	const char *name;
	guint retval = 0;

	dir = g_dir_open (cache_dir, 0, NULL);
	while ((name = g_dir_read_name (dir))) {
		if (g_str_has_prefix (name, "soup."))
			continue;

		retval++;
	}
	g_dir_close (dir);

	return retval;
}

static void
do_leaks_test (gconstpointer data)
{
	GUri *base_uri = (GUri *)data;
	SoupSession *session;
	SoupCache *cache;
	char *cache_dir;
	char *body;

	cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
	debug_printf (2, "  Caching to %s\n", cache_dir);
	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
	session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

	debug_printf (2, "  Initial requests\n");
	body = do_request (session, base_uri, "GET", "/1", NULL,
			   "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			   NULL);
	g_free (body);
	body = do_request (session, base_uri, "GET", "/2", NULL,
			   "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			   NULL);
	g_free (body);
	body = do_request (session, base_uri, "GET", "/3", NULL,
			   "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			   NULL);
	g_free (body);

	debug_printf (2, "  Dumping the cache\n");
	soup_cache_dump (cache);

	g_assert_cmpuint (count_cached_resources_in_dir (cache_dir), ==, 3);

	body = do_request (session, base_uri, "GET", "/4", NULL,
			   "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			   NULL);
	g_free (body);
	body = do_request (session, base_uri, "GET", "/5", NULL,
			   "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
			   NULL);
	g_free (body);

	/* Destroy the cache without dumping the last two resources */
	soup_test_session_abort_unref (session);
	g_object_unref (cache);

	cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);

	debug_printf (2, "  Loading the cache\n");
	g_assert_cmpuint (count_cached_resources_in_dir (cache_dir), ==, 5);
	soup_cache_load (cache);
	g_assert_cmpuint (count_cached_resources_in_dir (cache_dir), ==, 3);

	g_object_unref (cache);
	g_free (cache_dir);
}

static void
do_metrics_test (gconstpointer data)
{
        GUri *base_uri = (GUri *)data;
        SoupSession *session;
        SoupCache *cache;
        char *cache_dir;
        char *body;
        GUri *uri;
        SoupMessage *msg;
        SoupMessageHeaders *request_headers;
        GInputStream *stream;
        char buffer[256];
        gsize nread;
        SoupMessageMetrics *metrics;

        cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
        debug_printf (2, "  Caching to %s\n", cache_dir);
        cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
        session = soup_test_session_new (NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

        g_signal_connect (session, "request-queued",
                          G_CALLBACK (request_queued), NULL);
        g_signal_connect (session, "request-unqueued",
                          G_CALLBACK (request_unqueued), NULL);

        body = do_request (session, base_uri, "GET", "/1", NULL,
                           "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT",
                           NULL);
        g_free (body);

        last_request_validated = last_request_hit_network = last_request_unqueued = FALSE;
        uri = g_uri_parse_relative (base_uri, "/1", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        metrics = soup_message_get_metrics (msg);
        g_assert_nonnull (metrics);
        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), ==, 0);

        stream = soup_test_request_send (session, msg, NULL, 0, NULL);
        g_assert_true (G_IS_INPUT_STREAM (stream));
        g_assert_false (is_network_stream (stream));
        g_assert_null (soup_message_get_remote_address (msg));

        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >=, soup_message_metrics_get_fetch_start (metrics));
        g_input_stream_read_all (stream, buffer, sizeof (buffer), &nread, NULL, NULL);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >=, soup_message_metrics_get_request_start (metrics));
        soup_test_request_close_stream (stream, NULL, NULL);
        g_object_unref (stream);
        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >=, soup_message_metrics_get_response_start (metrics));
        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), >, 0);
        g_object_unref (msg);

        body = do_request (session, base_uri, "GET", "/2", NULL,
                           "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT",
                           "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT",
                           "Test-Set-Cache-Control", "must-revalidate",
                           NULL);
        g_free (body);

        last_request_validated = last_request_hit_network = last_request_unqueued = FALSE;
        uri = g_uri_parse_relative (base_uri, "/2", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        g_uri_unref (uri);

        request_headers = soup_message_get_request_headers (msg);
        soup_message_headers_append (request_headers,
                                     "Test-Set-Last-Modified", "Fri, 01 Jan 2010 00:00:00 GMT");
        soup_message_headers_append (request_headers,
                                     "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT");
        soup_message_headers_append (request_headers,
                                     "Test-Set-Cache-Control", "must-revalidate");

        soup_message_add_flags (msg, SOUP_MESSAGE_COLLECT_METRICS);
        metrics = soup_message_get_metrics (msg);
        g_assert_nonnull (metrics);
        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), ==, 0);

        stream = soup_test_request_send (session, msg, NULL, 0, NULL);
        g_assert_true (G_IS_INPUT_STREAM (stream));
        g_assert_false (is_network_stream (stream));
        g_assert_null (soup_message_get_remote_address (msg));
        g_assert_true (last_request_validated);

        g_assert_cmpuint (soup_message_metrics_get_fetch_start (metrics), >, 0);
        g_assert_cmpuint (soup_message_metrics_get_dns_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_dns_end (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_connect_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_tls_start (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_connect_end (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_start (metrics), >=, soup_message_metrics_get_fetch_start (metrics));
        g_input_stream_read_all (stream, buffer, sizeof (buffer), &nread, NULL, NULL);
        g_assert_cmpuint (soup_message_metrics_get_response_start (metrics), >=, soup_message_metrics_get_request_start (metrics));
        soup_test_request_close_stream (stream, NULL, NULL);
        g_object_unref (stream);
        g_assert_cmpuint (soup_message_metrics_get_response_end (metrics), >=, soup_message_metrics_get_response_start (metrics));
        g_assert_cmpuint (soup_message_metrics_get_request_header_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_bytes_sent (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_request_body_size (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_header_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_bytes_received (metrics), ==, 0);
        g_assert_cmpuint (soup_message_metrics_get_response_body_size (metrics), >, 0);
        g_object_unref (msg);

        soup_test_session_abort_unref (session);
        g_object_unref (cache);
        g_free (cache_dir);
}

typedef struct {
        SoupSession *session;
        GUri *uri;
        gboolean must_revalidate;
        gboolean is_expired;
        gboolean hit_network;
        gboolean validated;
        GError *error;
} ThreadTestRequest;

static void
threads_message_starting (SoupMessage       *msg,
                          ThreadTestRequest *request)
{
        SoupMessageHeaders *request_headers;

        if (request->validated)
                return;

        request_headers = soup_message_get_request_headers (msg);
        request->validated = !!soup_message_headers_get_one (request_headers, "If-Modified-Since");
}

static void
threads_request_queued (SoupSession       *session,
                        SoupMessage       *msg,
                        ThreadTestRequest *request)
{
        if (soup_message_get_uri (msg) != request->uri)
                return;

        g_signal_connect (msg, "starting",
                          G_CALLBACK (threads_message_starting),
                          request);
}

static void
task_async_function (GTask        *task,
                     GObject      *source,
                     gpointer      task_data,
                     GCancellable *cancellable)
{
        GMainContext *context;
        SoupMessage *msg;
        SoupMessageHeaders *request_headers;
        GInputStream *stream;
        ThreadTestRequest *request = (ThreadTestRequest *)task_data;

        context = g_main_context_new ();
        g_main_context_push_thread_default (context);

        msg = soup_message_new_from_uri ("GET", request->uri);
        g_signal_connect (request->session, "request-queued",
                          G_CALLBACK (threads_request_queued),
                          request);
        request_headers = soup_message_get_request_headers (msg);
        if (request->must_revalidate) {
                soup_message_headers_append (request_headers,
                                             "Test-Set-Last-Modified",
                                             request->is_expired ? "Sat, 02 Jan 2010 00:00:00 GMT" : "Fri, 01 Jan 2010 00:00:00 GMT");
                soup_message_headers_append (request_headers,
                                             "Test-Set-Expires", "Sat, 02 Jan 2011 00:00:00 GMT");
                soup_message_headers_append (request_headers,
                                             "Test-Set-Cache-Control", "must-revalidate");
        } else {
                soup_message_headers_append (request_headers,
                                             "Test-Set-Expires", "Fri, 01 Jan 2100 00:00:00 GMT");
        }

        stream = soup_test_request_send (request->session, msg, NULL, 0, &request->error);
        if (stream) {
                request->hit_network = is_network_stream (stream);
                soup_test_request_read_all (stream, NULL, &request->error);
                g_object_unref (stream);
        }

        g_signal_handlers_disconnect_by_data (request->session, request);

        g_object_unref (msg);

        /* Cache writes are G_PRIORITY_LOW, so they won't have happened yet */
        soup_cache_flush ((SoupCache *)soup_session_get_feature (request->session, SOUP_TYPE_CACHE));

        g_task_return_boolean (task, TRUE);

        g_main_context_pop_thread_default (context);
        g_main_context_unref (context);
}

static void
task_finished_cb (SoupSession  *session,
                  GAsyncResult *result,
                  guint        *finished_count)
{
        g_assert_true (g_task_propagate_boolean (G_TASK (result), NULL));
        g_atomic_int_inc (finished_count);
}

static void
do_threads_test (gconstpointer data)
{
        GUri *base_uri = (GUri *)data;
        SoupSession *session;
        SoupCache *cache;
        char *cache_dir;
        ThreadTestRequest requests[4];
        guint i;
        guint finished_count = 0;

        session = soup_test_session_new (NULL);

        cache_dir = g_dir_make_tmp ("cache-test-XXXXXX", NULL);
        cache = soup_cache_new (cache_dir, SOUP_CACHE_SINGLE_USER);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (cache));

        requests[0].session = session;
        requests[0].uri = g_uri_parse_relative (base_uri, "/1", SOUP_HTTP_URI_FLAGS, NULL);
        requests[0].must_revalidate = FALSE;
        requests[0].is_expired = FALSE;
        requests[1].session = session;
        requests[1].uri = g_uri_parse_relative (base_uri, "/2", SOUP_HTTP_URI_FLAGS, NULL);
        requests[1].must_revalidate = TRUE;
        requests[1].is_expired = FALSE;
        requests[2].session = session;
        requests[2].uri = g_uri_parse_relative (base_uri, "/3", SOUP_HTTP_URI_FLAGS, NULL);
        requests[2].must_revalidate = FALSE;
        requests[2].is_expired = FALSE;
        requests[3].session = session;
        requests[3].uri = g_uri_parse_relative (base_uri, "/4", SOUP_HTTP_URI_FLAGS, NULL);
        requests[3].must_revalidate = TRUE;
        requests[3].is_expired = FALSE;

        for (i = 0; i < 4; i++) {
                GTask *task;

                requests[i].hit_network = FALSE;
                requests[i].validated = FALSE;
                requests[i].error = NULL;

                task = g_task_new (NULL, NULL, (GAsyncReadyCallback)task_finished_cb, &finished_count);
                g_task_set_task_data (task, &requests[i], NULL);
                g_task_run_in_thread (task, (GTaskThreadFunc)task_async_function);
                g_object_unref (task);
        }

        while (g_atomic_int_get (&finished_count) != 4)
                g_main_context_iteration (NULL, TRUE);

        /* Initial requests hit the network */
        for (i = 0; i < 4; i++) {
                g_assert_true (requests[i].hit_network);
                g_assert_false (requests[i].validated);
                g_assert_no_error (requests[i].error);
        }

        finished_count = 0;
        for (i = 0; i < 4; i++) {
                GTask *task;

                requests[i].hit_network = FALSE;
                requests[i].validated = FALSE;
                requests[i].error = NULL;

                task = g_task_new (NULL, NULL, (GAsyncReadyCallback)task_finished_cb, &finished_count);
                g_task_set_task_data (task, &requests[i], NULL);
                g_task_run_in_thread (task, (GTaskThreadFunc)task_async_function);
                g_object_unref (task);
        }

        while (g_atomic_int_get (&finished_count) != 4)
                g_main_context_iteration (NULL, TRUE);

        /* None of the requests hit the ntwork */
        for (i = 0; i < 4; i++) {
                g_assert_false (requests[i].hit_network);
                g_assert_no_error (requests[i].error);
        }

        /* The ones including must-revalidate are validated */
        g_assert_false (requests[0].validated);
        g_assert_true (requests[1].validated);
        g_assert_false (requests[2].validated);
        g_assert_true (requests[3].validated);

        /* Try again making the validations fail */
        requests[1].is_expired = TRUE;
        requests[3].is_expired = TRUE;

        finished_count = 0;
        for (i = 0; i < 4; i++) {
                GTask *task;

                requests[i].hit_network = FALSE;
                requests[i].validated = FALSE;
                requests[i].error = NULL;

                task = g_task_new (NULL, NULL, (GAsyncReadyCallback)task_finished_cb, &finished_count);
                g_task_set_task_data (task, &requests[i], NULL);
                g_task_run_in_thread (task, (GTaskThreadFunc)task_async_function);
                g_object_unref (task);
        }

        while (g_atomic_int_get (&finished_count) != 4)
                g_main_context_iteration (NULL, TRUE);

        /* None of the requests failed */
        for (i = 0; i < 4; i++)
                g_assert_no_error (requests[i].error);

        /* The ones including must-revalidate are validated and hit the network this time */
        g_assert_false (requests[0].validated);
        g_assert_false (requests[0].hit_network);
        g_assert_true (requests[1].validated);
        g_assert_true (requests[1].hit_network);
        g_assert_false (requests[2].validated);
        g_assert_false (requests[2].hit_network);
        g_assert_true (requests[3].validated);
        g_assert_true (requests[3].hit_network);

        for (i = 0; i < 4; i++)
                g_uri_unref (requests[i].uri);

        soup_test_session_abort_unref (session);
        soup_cache_clear (cache);
        g_rmdir (cache_dir);
        g_object_unref (cache);
        g_free (cache_dir);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	GUri *base_uri;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
	soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);

	g_test_add_data_func ("/cache/basics", base_uri, do_basics_test);
	g_test_add_data_func ("/cache/cancellation", base_uri, do_cancel_test);
	g_test_add_data_func ("/cache/refcounting", base_uri, do_refcounting_test);
	g_test_add_data_func ("/cache/headers", base_uri, do_headers_test);
	g_test_add_data_func ("/cache/leaks", base_uri, do_leaks_test);
        g_test_add_data_func ("/cache/metrics", base_uri, do_metrics_test);
        g_test_add_data_func ("/cache/threads", base_uri, do_threads_test);

	ret = g_test_run ();

	g_uri_unref (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
