/*
 * Copyright (C) 2020 Igalia S.L.
 */

#include "test-utils.h"

GUri *base_uri;

typedef struct {
        GHashTable *request;
        GHashTable *response;
} LogData;

static void
log_data_clear (LogData *data)
{
        g_clear_pointer (&data->request, g_hash_table_destroy);
        g_clear_pointer (&data->response, g_hash_table_destroy);
}

static void
printer (SoupLogger         *logger,
         SoupLoggerLogLevel  level,
         char                direction,
         const char         *data,
         LogData            *log)
{
        GHashTable **table;

        if (direction == '>')
                table = &log->request;
        else if (direction == '<')
                table = &log->response;
        else
                return;

        if (!*table) {
                *table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
                g_hash_table_insert (*table, g_strdup ("status-line"), g_strdup (data));
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
        LogData log = { NULL, NULL };

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
        LogData log = { NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_HEADERS);
        soup_logger_set_printer (logger, (SoupLoggerPrinter)printer, &log, NULL);
        soup_session_add_feature (session, SOUP_SESSION_FEATURE (logger));
        g_object_unref (logger);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 6);
        g_assert_true (g_hash_table_contains (log.request, "status-line"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug-Timestamp"));
        g_assert_true (g_hash_table_contains (log.request, "Soup-Debug"));
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
        g_assert_cmpstr (g_hash_table_lookup (log.response, "Content-Length"), ==, "5");

        log_data_clear (&log);

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
        SoupSession *session;
        SoupLogger *logger;
        SoupMessage *msg;
        LogData log = { NULL, NULL };

        session = soup_test_session_new (NULL);

        logger = soup_logger_new (SOUP_LOGGER_LOG_HEADERS);
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
        log_data_clear (&log);

        /* Log request with headers level and response with minimal */
        soup_logger_set_request_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_HEADERS), NULL);
        soup_logger_set_response_filter (logger, filter, GUINT_TO_POINTER (SOUP_LOGGER_LOG_MINIMAL), NULL);

        msg = soup_message_new_from_uri ("GET", base_uri);
        soup_test_session_send_message (session, msg);
        g_object_unref (msg);

        g_assert_nonnull (log.request);
        g_assert_cmpuint (g_hash_table_size (log.request), ==, 6);
        g_assert_nonnull (log.response);
        g_assert_cmpuint (g_hash_table_size (log.response), ==, 3);
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
        LogData log = { NULL, NULL };

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
                                          SOUP_MEMORY_STATIC, "index", 5);
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
        g_test_add_func ("/logger/filters", do_logger_filters_test);
        g_test_add_func ("/logger/cookies", do_logger_cookies_test);

        ret = g_test_run ();

        soup_test_server_quit_unref (server);

        test_cleanup ();
        return ret;
}
