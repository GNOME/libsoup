/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */

#include "test-utils.h"

static SoupURI *base_uri;
static gboolean server_processed_message;
static gboolean timeout;
static GMainLoop *loop;
static SoupMessagePriority expected_priorities[3];
static GBytes *index_bytes;

static gboolean
timeout_cb (gpointer user_data)
{
	gboolean *timeout = user_data;

	*timeout = TRUE;
	return FALSE;
}

static void
server_handler (SoupServer        *server,
		SoupServerMessage *msg,
		const char        *path,
		GHashTable        *query,
		gpointer           user_data)
{
	if (!strcmp (path, "/request-timeout")) {
		GMainContext *context = g_main_context_get_thread_default ();
		GSource *timer;

		timer = g_timeout_source_new (100);
		g_source_set_callback (timer, timeout_cb, &timeout, NULL);
		g_source_attach (timer, context);
		g_source_unref (timer);
	} else if (!strcmp (path, "/index.txt")) {
		soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
		soup_server_message_set_response (msg, "text/plain",
						  SOUP_MEMORY_STATIC,
						  g_bytes_get_data (index_bytes, NULL),
						  g_bytes_get_size (index_bytes));
		return;
	} else
		server_processed_message = TRUE;

	soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
	soup_server_message_set_response (msg, "text/plain",
					  SOUP_MEMORY_STATIC,
					  "ok\r\n", 4);
}

static void
finished_cb (SoupMessage *msg,
	     gboolean    *finished)
{
	*finished = TRUE;
}

static void
cancel_message_cb (SoupMessage *msg, gpointer session)
{
	soup_session_cancel_message (session, msg, SOUP_STATUS_CANCELLED);
	g_main_loop_quit (loop);
}

static void
do_test_for_session (SoupSession *session,
		     gboolean queue_is_async,
		     gboolean send_is_blocking,
		     gboolean cancel_is_immediate)
{
	SoupMessage *msg;
	gboolean finished, local_timeout;
	guint timeout_id;
	SoupURI *timeout_uri;
	GBytes *body;

	debug_printf (1, "  queue_message\n");
	debug_printf (2, "    requesting timeout\n");
	timeout_uri = soup_uri_new_with_base (base_uri, "/request-timeout");
	msg = soup_message_new_from_uri ("GET", timeout_uri);
	soup_uri_free (timeout_uri);
	body = soup_test_session_send (session, msg, NULL, NULL);
	g_bytes_unref (body);
	g_object_unref (msg);

	msg = soup_message_new_from_uri ("GET", base_uri);
	server_processed_message = timeout = finished = FALSE;
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished_cb), &finished);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
	g_object_unref (msg);
	while (!timeout)
		g_usleep (100);
	debug_printf (2, "    got timeout\n");

	if (queue_is_async) {
		g_assert_false (server_processed_message);
		debug_printf (2, "    waiting for finished\n");
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
		g_assert_true (server_processed_message);
	} else {
		g_assert_true (server_processed_message);
		g_assert_false (finished);
		debug_printf (2, "    waiting for finished\n");
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
	}

	debug_printf (1, "  send_message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	server_processed_message = local_timeout = FALSE;
	timeout_id = g_idle_add_full (G_PRIORITY_HIGH, timeout_cb, &local_timeout, NULL);
	body = soup_test_session_send (session, msg, NULL, NULL);
        g_bytes_unref (body);
	g_object_unref (msg);

	g_assert_true (server_processed_message);

	if (send_is_blocking) {
		soup_test_assert (!local_timeout,
				  "send_message ran main loop");
	} else {
		soup_test_assert (local_timeout,
				  "send_message didn't run main loop");
	}

	if (!local_timeout)
		g_source_remove (timeout_id);

	if (!queue_is_async)
		return;

	debug_printf (1, "  cancel_message\n");
	msg = soup_message_new_from_uri ("GET", base_uri);
	finished = FALSE;
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished_cb), &finished);
	soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
	g_signal_connect (msg, "wrote-headers",
			  G_CALLBACK (cancel_message_cb), session);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);

	if (cancel_is_immediate)
		g_assert_true (finished);
	else
		g_assert_false (finished);

	if (!finished) {
		debug_printf (2, "    waiting for finished\n");
		while (!finished)
			g_main_context_iteration (NULL, TRUE);
		/* We need one iteration more because finished is emitted
		 * right before the item is unqueued.
		 */
		g_main_context_iteration (NULL, TRUE);
	}
	g_main_loop_unref (loop);

	soup_test_assert_message_status (msg, SOUP_STATUS_CANCELLED);
	g_object_unref (msg);
}

static void
do_plain_tests (void)
{
	SoupSession *session;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	do_test_for_session (session, TRUE, TRUE, FALSE);
	soup_test_session_abort_unref (session);
}

static void
priority_test_finished_cb (SoupMessage *msg,
			   guint       *finished_count)
{
	SoupMessagePriority priority = soup_message_get_priority (msg);

	debug_printf (1, "  received message %d with priority %d\n",
		      *finished_count, priority);

	soup_test_assert (priority == expected_priorities[*finished_count],
			  "message %d should have priority %d (%d found)",
			  *finished_count, expected_priorities[*finished_count], priority);

	(*finished_count)++;
}

static void
do_priority_tests (void)
{
	SoupSession *session;
	int i, finished_count = 0;
	SoupMessagePriority priorities[] =
		{ SOUP_MESSAGE_PRIORITY_LOW,
		  SOUP_MESSAGE_PRIORITY_HIGH,
		  SOUP_MESSAGE_PRIORITY_NORMAL };

	g_test_bug ("696277");

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);
	g_object_set (session, "max-conns", 1, NULL);

	expected_priorities[0] = SOUP_MESSAGE_PRIORITY_HIGH;
	expected_priorities[1] = SOUP_MESSAGE_PRIORITY_NORMAL;
	expected_priorities[2] = SOUP_MESSAGE_PRIORITY_LOW;

	for (i = 0; i < 3; i++) {
		SoupURI *msg_uri;
		SoupMessage *msg;
		char buf[5];

		g_snprintf (buf, sizeof (buf), "%d", i);
		msg_uri = soup_uri_new_with_base (base_uri, buf);
		msg = soup_message_new_from_uri ("GET", msg_uri);
		soup_uri_free (msg_uri);

		soup_message_set_priority (msg, priorities[i]);
		g_signal_connect (msg, "finished",
				  G_CALLBACK (priority_test_finished_cb), &finished_count);
		soup_session_send_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
		g_object_unref (msg);
	}

	debug_printf (2, "    waiting for finished\n");
	while (finished_count != 3)
		g_main_context_iteration (NULL, TRUE);

	soup_test_session_abort_unref (session);
}

static void
test_session_properties (const char *name,
			 SoupSession *session,
			 GProxyResolver *expected_proxy_resolver,
			 GTlsDatabase *expected_tls_database)
{
	GProxyResolver *proxy_resolver = NULL;
	GTlsDatabase *tlsdb = NULL;

	g_object_get (G_OBJECT (session),
		      SOUP_SESSION_PROXY_RESOLVER, &proxy_resolver,
		      SOUP_SESSION_TLS_DATABASE, &tlsdb,
		      NULL);

	soup_test_assert (proxy_resolver == expected_proxy_resolver,
			  "%s has %s proxy resolver",
			  name, proxy_resolver ? (expected_proxy_resolver ? "wrong" : "a") : "no");
	soup_test_assert (tlsdb == expected_tls_database,
			  "%s has %s TLS database",
			  name, tlsdb ? (expected_tls_database ? "wrong" : "a") : "no");

	g_clear_object (&proxy_resolver);
	g_clear_object (&tlsdb);
}

static void
do_property_tests (void)
{
	SoupSession *session;
	GProxyResolver *proxy_resolver, *default_proxy_resolver;
	GTlsDatabase *tlsdb, *default_tlsdb;

	g_test_bug ("708696");

	default_proxy_resolver = g_proxy_resolver_get_default ();
	default_tlsdb = g_tls_backend_get_default_database (g_tls_backend_get_default ());

	/* NOTE: We intentionally do not use soup_test_session_new() here */

	session = g_object_new (SOUP_TYPE_SESSION,
				NULL);
	test_session_properties ("Base plain session", session,
				 default_proxy_resolver, default_tlsdb);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_RESOLVER, NULL,
				NULL);
	test_session_properties ("Session with NULL :proxy-resolver", session,
				 NULL, default_tlsdb);
	g_object_unref (session);

	proxy_resolver = g_simple_proxy_resolver_new (NULL, NULL);
	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_PROXY_RESOLVER, proxy_resolver,
				NULL);
	test_session_properties ("Session with non-NULL :proxy-resolver", session,
				 proxy_resolver, default_tlsdb);
	g_object_unref (proxy_resolver);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_TLS_DATABASE, NULL,
				NULL);
	test_session_properties ("Session with NULL :tls-database", session,
				 default_proxy_resolver, NULL);
	g_object_unref (session);

	/* g_tls_file_database_new() will fail with the dummy backend,
	 * so we can only do this test if we have a real TLS backend.
	 */
	if (tls_available) {
		GError *error = NULL;

		tlsdb = g_tls_file_database_new (g_test_get_filename (G_TEST_DIST,
								      "test-cert.pem",
								      NULL), &error);
		g_assert_no_error (error);

		session = g_object_new (SOUP_TYPE_SESSION,
					SOUP_SESSION_TLS_DATABASE, tlsdb,
					NULL);
		test_session_properties ("Session with non-NULL :tls-database", session,
					 default_proxy_resolver, tlsdb);
		g_object_unref (tlsdb);
		g_object_unref (session);
	}

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, FALSE,
				NULL);
	test_session_properties ("Session with :ssl-use-system-ca-file FALSE", session,
				 default_proxy_resolver, NULL);
	g_object_unref (session);

	session = g_object_new (SOUP_TYPE_SESSION,
				SOUP_SESSION_SSL_USE_SYSTEM_CA_FILE, TRUE,
				NULL);
	test_session_properties ("Session with :ssl-use-system-ca-file TRUE", session,
				 default_proxy_resolver, default_tlsdb);
	g_object_unref (session);
}

static gint
compare_by_gtype (gconstpointer a,
		  gconstpointer b)
{
	return G_TYPE_CHECK_INSTANCE_TYPE (a, GPOINTER_TO_SIZE (b)) ? 0 : 1;
}

static void
do_features_test (void)
{
	SoupSession *session;
	GSList *features;
	SoupSessionFeature *feature;

	session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);

	features = soup_session_get_features (session, SOUP_TYPE_SESSION_FEATURE);
	/* SoupAuthManager is always added */
	g_assert_cmpuint (g_slist_length (features), >=, 1);
	g_assert_nonnull (g_slist_find_custom (features, GSIZE_TO_POINTER (SOUP_TYPE_AUTH_MANAGER), compare_by_gtype));
	g_assert_true (soup_session_has_feature (session, SOUP_TYPE_AUTH_MANAGER));
	feature = soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER);
	g_assert_true (SOUP_IS_AUTH_MANAGER (feature));
	soup_session_remove_feature (session, feature);
	g_assert_false (soup_session_has_feature (session, SOUP_TYPE_AUTH_MANAGER));
	g_assert_null (soup_session_get_feature (session, SOUP_TYPE_AUTH_MANAGER));
	g_slist_free (features);

	soup_test_session_abort_unref (session);
}

typedef enum {
        SYNC = 1 << 0,
        STREAM = 1 << 1
} GetTestFlags;

typedef struct {
        GMainLoop *loop;
        GBytes *body;
        char *content_type;
        GError *error;
} GetAsyncData;

static GBytes *
stream_to_bytes (GInputStream *stream)
{
        GOutputStream *ostream;
        GBytes *bytes;

        ostream = g_memory_output_stream_new (NULL, 0, g_realloc, g_free);
        g_output_stream_splice (ostream,
                                stream,
                                G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
                                G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET,
                                NULL, NULL);
        bytes = g_memory_output_stream_steal_as_bytes (G_MEMORY_OUTPUT_STREAM (ostream));
        g_object_unref (ostream);

        return bytes;
}

static void
read_uri_async_ready_cb (SoupSession  *session,
                         GAsyncResult *result,
                         GetAsyncData *data)
{
        GInputStream *stream;
        goffset content_length;

        stream = soup_session_read_uri_finish (session, result,
                                               &content_length,
                                               &data->content_type,
                                               &data->error);
        if (stream) {
                data->body = stream_to_bytes (stream);
                if (content_length != -1)
                        g_assert_cmpint (g_bytes_get_size (data->body), ==, content_length);
                g_object_unref (stream);
        }

        g_main_loop_quit (data->loop);
}

static void
load_uri_bytes_async_ready_cb (SoupSession  *session,
                               GAsyncResult *result,
                               GetAsyncData *data)
{
        data->body = soup_session_load_uri_bytes_finish (session, result,
                                                         &data->content_type,
                                                         &data->error);
        g_main_loop_quit (data->loop);
}

static void
do_read_uri_test (gconstpointer data)
{
        SoupURI *uri;
        char *uri_string;
        SoupSession *session;
        GBytes *body = NULL;
        char *content_type = NULL;
        GError *error = NULL;
        GetTestFlags flags = GPOINTER_TO_UINT (data);

        session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);

        uri = soup_uri_new_with_base (base_uri, "/index.txt");
        uri_string = soup_uri_to_string (uri, FALSE);

        if (flags & SYNC) {
                if (flags & STREAM) {
                        GInputStream *stream;
                        goffset content_length = 0;

                        stream = soup_session_read_uri (session, uri_string, NULL,
                                                        &content_length,
                                                        &content_type,
                                                        &error);
                        body = stream_to_bytes (stream);
                        if (content_length != -1)
                                g_assert_cmpint (g_bytes_get_size (body), ==, content_length);
                        g_object_unref (stream);
                } else {
                        body = soup_session_load_uri_bytes (session, uri_string, NULL,
                                                            &content_type, &error);
                }
        } else {
                GetAsyncData data;
                GMainContext *context;

                memset (&data, 0, sizeof (GetAsyncData));

                context = g_main_context_get_thread_default ();
                data.loop = g_main_loop_new (context, TRUE);
                if (flags & STREAM) {
                        soup_session_read_uri_async (session, uri_string, G_PRIORITY_DEFAULT, NULL,
                                                     (GAsyncReadyCallback)read_uri_async_ready_cb,
                                                     &data);
                } else {
                        soup_session_load_uri_bytes_async (session, uri_string, G_PRIORITY_DEFAULT, NULL,
                                                           (GAsyncReadyCallback)load_uri_bytes_async_ready_cb,
                                                           &data);
                }
                g_main_loop_run (data.loop);
                while (g_main_context_pending (context))
                        g_main_context_iteration (context, FALSE);
                g_main_loop_unref (data.loop);

                body = data.body;
                content_type = data.content_type;
                if (data.error)
                        g_propagate_error (&error, data.error);
        }

        g_assert_no_error (error);
        g_assert_nonnull (body);
        g_assert_cmpstr (content_type, ==, "text/plain");
        g_assert_cmpmem (g_bytes_get_data (body, NULL), g_bytes_get_size (body),
                         g_bytes_get_data (index_bytes, NULL), g_bytes_get_size (index_bytes));

        g_bytes_unref (body);
        g_free (content_type);
        g_free (uri_string);
        soup_uri_free (uri);

        soup_test_session_abort_unref (session);
}

static struct {
        const char *uri;
        int expected_error;
} get_error_tests[] = {
        { "./foo", SOUP_SESSION_ERROR_BAD_URI },
        { "http:/localhost/", SOUP_SESSION_ERROR_BAD_URI },
        { "foo://host/path", SOUP_SESSION_ERROR_UNSUPPORTED_URI_SCHEME }
};

static void
do_load_uri_error_tests (void)
{
        SoupSession *session;
        guint i;

        session = soup_test_session_new (SOUP_TYPE_SESSION, NULL);

        for (i = 0; i < G_N_ELEMENTS (get_error_tests); i++) {
                GError *error = NULL;

                g_assert_null (soup_session_load_uri_bytes (session, get_error_tests[i].uri, NULL, NULL, &error));
                g_assert_error (error, SOUP_SESSION_ERROR, get_error_tests[i].expected_error);
                g_error_free (error);
        }

        soup_test_session_abort_unref (session);
}

int
main (int argc, char **argv)
{
	SoupServer *server;
	int ret;

	test_init (argc, argv, NULL);

	server = soup_test_server_new (TRUE);
	soup_server_add_handler (server, NULL, server_handler, NULL, NULL);
	base_uri = soup_test_server_get_uri (server, "http", NULL);
	index_bytes = soup_test_get_index ();
 	soup_test_register_resources ();

	g_test_add_func ("/session/SoupSession", do_plain_tests);
	g_test_add_func ("/session/priority", do_priority_tests);
	g_test_add_func ("/session/property", do_property_tests);
	g_test_add_func ("/session/features", do_features_test);
	g_test_add_data_func ("/session/read-uri/async",
			      GINT_TO_POINTER (STREAM),
			      do_read_uri_test);
	g_test_add_data_func ("/session/read-uri/sync",
			      GINT_TO_POINTER (SYNC | STREAM),
			      do_read_uri_test);
	g_test_add_data_func ("/session/load-uri/async",
			      GINT_TO_POINTER (0),
			      do_read_uri_test);
	g_test_add_data_func ("/session/load-uri/sync",
			      GINT_TO_POINTER (SYNC),
			      do_read_uri_test);
	g_test_add_func ("/session/load-uri/errors", do_load_uri_error_tests);

	ret = g_test_run ();

	soup_uri_free (base_uri);
	soup_test_server_quit_unref (server);

	test_cleanup ();
	return ret;
}
