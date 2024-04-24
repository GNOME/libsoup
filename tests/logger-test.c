/*
 * Copyright (C) 2020 Igalia S.L.
 */

#include "test-utils.h"

static const char body_data[] =
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
        "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
        "im ad minim veniam, quis nostrud exercitation ullamco laboris "
        "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
        "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla "
        "pariatur. Excepteur sint occaecat cupidatat non proident, sunt in "
        "culpa qui officia deserunt mollit anim id est laborum.";

GUri *base_uri;

typedef struct {
        GHashTable *request;
        GHashTable *response;
        GByteArray *request_body;
        GByteArray *response_body;
} LogData;

static void
log_data_clear (LogData *data)
{
        g_clear_pointer (&data->request, g_hash_table_destroy);
        g_clear_pointer (&data->response, g_hash_table_destroy);
        g_clear_pointer (&data->request_body, g_byte_array_unref);
        g_clear_pointer (&data->response_body, g_byte_array_unref);
}

static void
printer (SoupLogger         *logger,
         SoupLoggerLogLevel  level,
         char                direction,
         const char         *data,
         LogData            *log)
{
        GHashTable **table;
        GByteArray **body;

        if (direction == '>') {
                table = &log->request;
                body = &log->request_body;
        } else if (direction == '<') {
                table = &log->response;
                body = &log->response_body;
        } else
                return;

        if (!*table) {
                /* first logger call; initialize headers */
                *table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
                g_hash_table_insert (*table, g_strdup ("status-line"), g_strdup (data));
        } else if (!*data) {
                /* empty line with direction delimits body */
                *body = g_byte_array_new ();
        } else if (*body) {
                /* we're only reading body now */
                if (!strcmp (data, "[...]"))
                        return;
                g_byte_array_append (*body, (const unsigned char *)data, strlen (data));
        } else {
                char *p;

                p = strstr (data, ":");
                g_hash_table_insert (*table, g_strndup (data, strlen (data) - strlen (p)), g_strdup (p + 2));
        }
}

static void
do_logger_minimal_test (void)
{
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        LogData log = { NULL, NULL, NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_MINIMAL);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
        g_object_unref (logger);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 3);
        g_assert_true (g_hash_table_contains (log.request, "status-line"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug"));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "status-line"), ==, "GET / HTTP/1.1");

        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 3);
        g_assert_true (g_hash_table_contains (log.response, "status-line"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug"));
        g_assert_cmpstr (g_hash_table_lookup (log.response, "status-line"), ==, "HTTP/1.1 200 OK");

        g_assert_null (log.request_body);
        g_assert_null (log.response_body);

        log_data_clear (&log);

        soup_test_session_abort_unref (session);
}

static void
do_logger_headers_test (void)
{
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        char *host;
        LogData log = { NULL, NULL, NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_HEADERS);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
        g_object_unref (logger);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 7);
        g_assert_true (g_hash_table_contains (log.request, "status-line"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Host"));
        g_assert_true (g_hash_table_contains (log.request, "Host"));
        g_assert_true (g_hash_table_contains (log.request, "Accept-Encoding"));
        g_assert_true (g_hash_table_contains (log.request, "Connection"));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "status-line"), ==, "GET / HTTP/1.1");
        host = g_strdup_printf ("127.0.0.1:%d", g_uri_get_port (base_uri));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Host"), ==, host);
        g_free (host);
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Accept-Encoding"), ==, "gzip, deflate");
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Connection"), ==, "Keep-Alive");

        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 6);
        g_assert_true (g_hash_table_contains (log.response, "status-line"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug"));
        g_assert_true (g_hash_table_contains (log.response, "Date"));
        g_assert_true (g_hash_table_contains (log.response, "Content-Type"));
        g_assert_true (g_hash_table_contains (log.response, "Content-Length"));
        g_assert_cmpstr (g_hash_table_lookup (log.response, "status-line"), ==, "HTTP/1.1 200 OK");
        g_assert_cmpstr (g_hash_table_lookup (log.response, "Content-Type"), ==, "text/plain");
        g_assert_cmpint (atoi (g_hash_table_lookup (log.response, "Content-Length")), ==, sizeof (body_data) - 1);

        g_assert_null (log.request_body);
        g_assert_null (log.response_body);

        log_data_clear (&log);

        soup_test_session_abort_unref (session);
}

static void
do_logger_body_test (void)
{
        GInputStream *body;
        GBytes *request;
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        char *host;
        LogData log = { NULL, NULL, NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_BODY);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));

        msg = soup_message_new_from_uri ("GET", base_uri);

        request = g_bytes_new_static (body_data, sizeof (body_data) - 1);
        soup_message_set_request_body_from_bytes (msg, NULL, request);
        g_bytes_unref (request);

        body = soup_session_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        for (;;) {
                gssize skip = g_input_stream_skip (body, 32, NULL, NULL);
                if (skip <= 0)
                            break;
        }

        g_object_unref (body);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 8);
        g_assert_true (g_hash_table_contains (log.request, "status-line"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Host"));
        g_assert_true (g_hash_table_contains (log.request, "Host"));
        g_assert_true (g_hash_table_contains (log.request, "Accept-Encoding"));
        g_assert_true (g_hash_table_contains (log.request, "Connection"));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "status-line"), ==, "GET / HTTP/1.1");
        host = g_strdup_printf ("127.0.0.1:%d", g_uri_get_port (base_uri));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Host"), ==, host);
        g_free (host);
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Accept-Encoding"), ==, "gzip, deflate");
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Connection"), ==, "Keep-Alive");
        g_assert_cmpint (atoi (g_hash_table_lookup (log.request, "Content-Length")), ==, sizeof (body_data) - 1);

        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 6);
        g_assert_true (g_hash_table_contains (log.response, "status-line"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.response, "Soup-Debug"));
        g_assert_true (g_hash_table_contains (log.response, "Date"));
        g_assert_true (g_hash_table_contains (log.response, "Content-Type"));
        g_assert_true (g_hash_table_contains (log.response, "Content-Length"));
        g_assert_cmpstr (g_hash_table_lookup (log.response, "status-line"), ==, "HTTP/1.1 200 OK");
        g_assert_cmpstr (g_hash_table_lookup (log.response, "Content-Type"), ==, "text/plain");
        g_assert_cmpint (atoi (g_hash_table_lookup (log.response, "Content-Length")), ==, sizeof (body_data) - 1);

        g_assert_nonnull (log.request_body);
        g_assert_nonnull (log.response_body);

        g_assert_cmpmem (log.request_body->data,
                         log.request_body->len,
                         body_data, sizeof (body_data) - 1);

        g_assert_cmpmem (log.response_body->data,
                         log.response_body->len,
                         body_data, sizeof (body_data) - 1);

        log_data_clear (&log);

        /* restrict maximum body size */
        soup_logger_set_max_body_size (logger, 64);

        msg = soup_message_new_from_uri ("GET", base_uri);
        body = soup_session_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        for (;;) {
                gssize skip = g_input_stream_skip (body, 32, NULL, NULL);
                if (skip <= 0)
                            break;
        }

        g_object_unref (body);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_null (log.request_body);
        g_assert_nonnull (log.response);
        g_assert_nonnull (log.response_body);

        g_assert_cmpmem (log.response_body->data,
                         log.response_body->len,
                         body_data, 64);

        log_data_clear (&log);

        g_object_unref (logger);
        soup_test_session_abort_unref (session);
}

static SoupLoggerLogLevel
filter (SoupLogger  *logger,
        SoupMessage *msg,
        gpointer     user_data)
{
        return GPOINTER_TO_UINT (user_data);
}

static void
do_logger_filters_test (void)
{
        GInputStream *body;
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        LogData log = { NULL, NULL, NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_BODY);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));

        /* Only log request with minimal level */
        soup_logger_set_request_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_MINIMAL), NULL);
        soup_logger_set_response_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_NONE), NULL);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 3);
        g_assert_null (log.response);
        g_assert_null (log.request_body);
        g_assert_null (log.response_body);

        log_data_clear (&log);

        /* Log request with headers level and response with minimal */
        soup_logger_set_request_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_HEADERS), NULL);
        soup_logger_set_response_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_MINIMAL), NULL);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 7);
        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 3);
        g_assert_null (log.request_body);
        g_assert_null (log.response_body);

        log_data_clear (&log);

        /* Only log response with headers level */
        soup_logger_set_request_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_NONE), NULL);
        soup_logger_set_response_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_HEADERS), NULL);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_null (log.request);
        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 6);
        g_assert_null (log.request_body);
        g_assert_null (log.response_body);

        log_data_clear (&log);

        /* Log request with minimal and response with body */
        soup_logger_set_request_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_MINIMAL), NULL);
        soup_logger_set_response_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_BODY), NULL);

        msg = soup_message_new_from_uri ("GET", base_uri);
        body = soup_session_send (session, msg, NULL, NULL);
        g_assert_nonnull (body);

        for (;;) {
                gssize skip = g_input_stream_skip (body, 32, NULL, NULL);
                if (skip <= 0)
                            break;
        }

        g_object_unref (body);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_null (log.request_body);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 3);
        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 6);
        g_assert_nonnull (log.response_body);

        g_assert_cmpmem (log.response_body->data,
                         log.response_body->len,
                         body_data, sizeof (body_data) - 1);

        log_data_clear (&log);

        g_object_unref (logger);
        soup_test_session_abort_unref (session);
}

static void
do_logger_cookies_test (void)
{
        SoupSession *session;
        SoupLogger *logger;
        GUri *uri;
        SoupMessage *msg;
        LogData log = { NULL, NULL, NULL, NULL };

        session = soup_test_session_new (NULL);
        soup_session_add_feature_by_type (session, SOUP_TYPE_COOKIE_JAR);

        logger = soup_logger_new (SOUP_LOGGER_LOG_HEADERS);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
        g_object_unref (logger);

        uri = g_uri_parse_relative (base_uri, "/cookies", SOUP_HTTP_URI_FLAGS, NULL);
        msg = soup_message_new_from_uri ("GET", uri);
        soup_test_session_send_message (session, msg);
        g_uri_unref (uri);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_false (g_hash_table_contains (log.request, "Cookie"));

        g_assert_nonnull (log.response);
        g_assert_true (g_hash_table_contains (log.response, "Set-Cookie"));
        g_assert_cmpstr (g_hash_table_lookup (log.response, "Set-Cookie"), ==, "foo=bar");
        log_data_clear (&log);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_true (g_hash_table_contains (log.request, "Cookie"));
        g_assert_cmpstr (g_hash_table_lookup (log.request, "Cookie"), ==, "foo=bar");

        g_assert_nonnull (log.response);
        g_assert_false (g_hash_table_contains (log.response, "Set-Cookie"));
        log_data_clear (&log);

        soup_test_session_abort_unref (session);
}

static void
preconnect_message_finsihed_cb (SoupMessage *msg,
                                gboolean    *finished)
{
        *finished = TRUE;
}

static void
do_logger_preconnect_test (void)
{
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        gboolean finished = FALSE;
        LogData log = { NULL, NULL, NULL, NULL };

        /* Preconnect messages should not be logged */
        session = soup_test_session_new (NULL);
        logger = soup_logger_new (SOUP_LOGGER_LOG_MINIMAL);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
        g_object_unref (logger);

        msg = soup_message_new_from_uri ("HEAD", base_uri);
        g_signal_connect_after (msg, "finished",
                                G_CALLBACK (preconnect_message_finsihed_cb),
                                &finished);
        soup_session_preconnect_async (session, msg, G_PRIORITY_DEFAULT, NULL, NULL, NULL);
        while (!finished)
                g_main_context_iteration (NULL, TRUE);
        g_object_unref (msg);

        g_assert_null (log.request);
        g_assert_null (log.response);

        soup_test_session_abort_unref (session);
}

static void
server_callback (SoupServer        *server,
                 SoupServerMessage *msg,
                 const char        *path,
                 GHashTable        *query,
                 gpointer           data)
{
        if (g_str_equal (path, "/cookies")) {
                soup_message_headers_replace (soup_server_message_get_response_headers (msg),
                                              "Set-Cookie", "foo=bar");
        }
        soup_server_message_set_status (msg, SOUP_STATUS_OK, NULL);
        soup_server_message_set_response (msg, "text/plain",
                                          SOUP_MEMORY_STATIC,
                                          body_data,
                                          sizeof (body_data) - 1);
}

int
main (int argc, char **argv)
{
        SoupServer *server;
        int ret;

        test_init (argc, argv, NULL);

        server = soup_test_server_new (SOUP_TEST_SERVER_IN_THREAD);
        soup_server_add_handler (server, NULL, server_callback, NULL, NULL);
        base_uri = soup_test_server_get_uri (server, "http", NULL);

        g_test_add_func ("/logger/minimal", do_logger_minimal_test);
        g_test_add_func ("/logger/headers", do_logger_headers_test);
        g_test_add_func ("/logger/body",    do_logger_body_test);
        g_test_add_func ("/logger/filters", do_logger_filters_test);
        g_test_add_func ("/logger/cookies", do_logger_cookies_test);
        g_test_add_func ("/logger/preconnect", do_logger_preconnect_test);

        ret = g_test_run ();

        soup_test_server_quit_unref (server);

        test_cleanup ();
        return ret;
}
