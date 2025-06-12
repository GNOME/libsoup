/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * soup-logger.c
 *
 * Copyright (C) 2001-2004 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 * Copyright (C) 2013 Igalia, S.L.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "soup-logger-private.h"
#include "soup-logger-input-stream.h"
#include "soup-connection.h"
#include "soup-message-private.h"
#include "soup-misc.h"
#include "soup.h"
#include "soup-session-feature-private.h"

/**
 * SoupLogger:
 *
 * Debug logging support
 *
 * [class@Logger] watches a [class@Session] and logs the HTTP traffic that
 * it generates, for debugging purposes. Many applications use an
 * environment variable to determine whether or not to use
 * [class@Logger], and to determine the amount of debugging output.
 *
 * To use [class@Logger], first create a logger with [ctor@Logger.new], optionally
 * configure it with [method@Logger.set_request_filter],
 * [method@Logger.set_response_filter], and [method@Logger.set_printer], and
 * then attach it to a session (or multiple sessions) with
 * [method@Session.add_feature].
 *
 * By default, the debugging output is sent to `stdout`, and looks something
 * like:
 *
 * ```
 * > POST /unauth HTTP/1.1
 * > Soup-Debug-Timestamp: 1200171744
 * > Soup-Debug: SoupSession 1 (0x612190), SoupMessage 1 (0x617000), GSocket 1 (0x612220)
 * > Host: localhost
 * > Content-Type: text/plain
 * > Connection: close
 *
 * < HTTP/1.1 201 Created
 * < Soup-Debug-Timestamp: 1200171744
 * < Soup-Debug: SoupMessage 1 (0x617000)
 * < Date: Sun, 12 Jan 2008 21:02:24 GMT
 * < Content-Length: 0
 * ```
 *
 * The `Soup-Debug-Timestamp` line gives the time (as a `time_t`) when the
 * request was sent, or the response fully received.
 *
 * The `Soup-Debug` line gives further debugging information about the
 * [class@Session], [class@Message], and [class@Gio.Socket] involved; the hex
 * numbers are the addresses of the objects in question (which may be useful if
 * you are running in a debugger). The decimal IDs are simply counters that
 * uniquely identify objects across the lifetime of the [class@Logger]. In
 * particular, this can be used to identify when multiple messages are sent
 * across the same connection.
 *
 * Currently, the request half of the message is logged just before
 * the first byte of the request gets written to the network (from the
 * [signal@Message::starting] signal).
 *
 * The response is logged just after the last byte of the response body is read
 * from the network (from the [signal@Message::got-body] or
 * [signal@Message::got-informational] signal), which means that the
 * [signal@Message::got-headers] signal, and anything triggered off it (such as
 * [signal@Message::authenticate]) will be emitted *before* the response headers are
 * actually logged.
 *
 * If the response doesn't happen to trigger the [signal@Message::got-body] nor
 * [signal@Message::got-informational] signals due to, for example, a
 * cancellation before receiving the last byte of the response body, the
 * response will still be logged on the event of the [signal@Message::finished]
 * signal.
 **/

struct _SoupLogger {
	GObject parent;
};

typedef struct {
	GQuark              tag;
        GMutex              mutex;
	GHashTable         *ids;
	GHashTable         *request_bodies;
	GHashTable         *response_bodies;

	SoupSession        *session;
	SoupLoggerLogLevel  level;
	int                 max_body_size;

	SoupLoggerFilter    request_filter;
	gpointer            request_filter_data;
	GDestroyNotify      request_filter_dnotify;

	SoupLoggerFilter    response_filter;
	gpointer            response_filter_data;
	GDestroyNotify      response_filter_dnotify;

	SoupLoggerPrinter   printer;
	gpointer            printer_data;
	GDestroyNotify      printer_dnotify;
} SoupLoggerPrivate;

enum {
	PROP_0,

	PROP_LEVEL,
	PROP_MAX_BODY_SIZE,

	LAST_PROPERTY
};

static GParamSpec *properties[LAST_PROPERTY] = { NULL, };

static void soup_logger_session_feature_init (SoupSessionFeatureInterface *feature_interface, gpointer interface_data);

static SoupContentProcessorInterface *soup_logger_default_content_processor_interface;
static void soup_logger_content_processor_init (SoupContentProcessorInterface *interface, gpointer interface_data);

G_DEFINE_FINAL_TYPE_WITH_CODE (SoupLogger, soup_logger, G_TYPE_OBJECT,
                               G_ADD_PRIVATE (SoupLogger)
                               G_IMPLEMENT_INTERFACE (SOUP_TYPE_SESSION_FEATURE,
                                                      soup_logger_session_feature_init)
                               G_IMPLEMENT_INTERFACE (SOUP_TYPE_CONTENT_PROCESSOR,
                                                      soup_logger_content_processor_init))

static void
write_body (SoupLogger *logger, const char *buffer, gsize nread,
            gpointer key, GHashTable *bodies)
{
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
        GString *body;

        if (!nread)
                return;

        g_mutex_lock (&priv->mutex);
        body = g_hash_table_lookup (bodies, key);

        if (!body) {
            body = g_string_new (NULL);
            g_hash_table_insert (bodies, key, body);
        }
        g_mutex_unlock (&priv->mutex);

        if (priv->max_body_size >= 0) {
                /* longer than max => we've written the extra [...] */
                if (body->len > priv->max_body_size)
                        return;
                int cap = priv->max_body_size - body->len;
                if (cap > 0)
                        g_string_append_len (body, buffer, MIN (nread, cap));
                if (nread > cap)
                        g_string_append (body, "\n[...]");
        } else {
                g_string_append_len (body, buffer, nread);
        }
}

void
soup_logger_log_request_data (SoupLogger *logger, SoupMessage *msg, const char *buffer, gsize len)
{
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        write_body (logger, buffer, len, msg, priv->request_bodies);
}

static void
write_response_body (SoupLoggerInputStream *stream, char *buffer, gsize nread,
                     gpointer user_data)
{
        SoupLogger *logger = soup_logger_input_stream_get_logger (stream);
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        write_body (logger, buffer, nread, user_data, priv->response_bodies);
}

static GInputStream *
soup_logger_content_processor_wrap_input (SoupContentProcessor *processor,
                            GInputStream *base_stream,
                            SoupMessage *msg,
                            GError **error)
{
        SoupLogger *logger = SOUP_LOGGER (processor);
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
        SoupLoggerInputStream *stream;
        SoupLoggerLogLevel log_level = SOUP_LOGGER_LOG_NONE;

        if (priv->request_filter || priv->response_filter) {
                if (priv->request_filter)
                        log_level = priv->request_filter (logger, msg, priv->request_filter_data);
                if (priv->response_filter)
                        log_level = MAX(log_level, priv->response_filter (logger, msg, priv->response_filter_data));
        }
        else
                log_level = priv->level;

        if (log_level < SOUP_LOGGER_LOG_BODY)
                return NULL;

        stream = g_object_new (SOUP_TYPE_LOGGER_INPUT_STREAM,
                               "base-stream", base_stream,
                               "logger", logger,
                               NULL);

        g_signal_connect_object (stream, "read-data",
                                 G_CALLBACK (write_response_body), msg, 0);

        return G_INPUT_STREAM (stream);
}

static void
soup_logger_content_processor_init (SoupContentProcessorInterface *interface,
                                    gpointer interface_data)
{
        soup_logger_default_content_processor_interface =
                g_type_default_interface_peek (SOUP_TYPE_CONTENT_PROCESSOR);

        interface->processing_stage = SOUP_STAGE_BODY_DATA;
        interface->wrap_input = soup_logger_content_processor_wrap_input;
}

static void
body_free (gpointer str)
{
        g_string_free (str, TRUE);
}

static void
soup_logger_init (SoupLogger *logger)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	char *id;

	id = g_strdup_printf ("SoupLogger-%p", logger);
	priv->tag = g_quark_from_string (id);
	g_free (id);
	priv->ids = g_hash_table_new (NULL, NULL);
	priv->request_bodies = g_hash_table_new_full (NULL, NULL, NULL, body_free);
	priv->response_bodies = g_hash_table_new_full (NULL, NULL, NULL, body_free);
        g_mutex_init (&priv->mutex);
}

static void
soup_logger_finalize (GObject *object)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	g_hash_table_destroy (priv->ids);
	g_hash_table_destroy (priv->request_bodies);
	g_hash_table_destroy (priv->response_bodies);

	if (priv->request_filter_dnotify)
		priv->request_filter_dnotify (priv->request_filter_data);
	if (priv->response_filter_dnotify)
		priv->response_filter_dnotify (priv->response_filter_data);
	if (priv->printer_dnotify)
		priv->printer_dnotify (priv->printer_data);

        g_mutex_clear (&priv->mutex);

	G_OBJECT_CLASS (soup_logger_parent_class)->finalize (object);
}

static void
soup_logger_set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	switch (prop_id) {
	case PROP_LEVEL:
		priv->level = g_value_get_enum (value);
		break;
	case PROP_MAX_BODY_SIZE:
		priv->max_body_size = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_logger_get_property (GObject *object, guint prop_id,
			   GValue *value, GParamSpec *pspec)
{
	SoupLogger *logger = SOUP_LOGGER (object);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	switch (prop_id) {
	case PROP_LEVEL:
		g_value_set_enum (value, priv->level);
		break;
	case PROP_MAX_BODY_SIZE:
		g_value_set_int (value, priv->max_body_size);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
soup_logger_class_init (SoupLoggerClass *logger_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (logger_class);

	object_class->finalize = soup_logger_finalize;
	object_class->set_property = soup_logger_set_property;
	object_class->get_property = soup_logger_get_property;

	/* properties */
	/**
	 * SoupLogger:level:
	 *
	 * The level of logging output.
	 */
        properties[PROP_LEVEL] =
		g_param_spec_enum ("level",
				    "Level",
				    "The level of logging output",
				    SOUP_TYPE_LOGGER_LOG_LEVEL,
				    SOUP_LOGGER_LOG_MINIMAL,
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS);
	/**
	 * SoupLogger:max-body-size: (attributes org.gtk.Property.get=soup_logger_get_max_body_size org.gtk.Property.set=soup_logger_set_max_body_size)
	 *
	 * If [property@Logger:level] is %SOUP_LOGGER_LOG_BODY, this gives
	 * the maximum number of bytes of the body that will be logged.
	 * (-1 means "no limit".)
	 **/
        properties[PROP_MAX_BODY_SIZE] =
		g_param_spec_int ("max-body-size",
				    "Max Body Size",
				    "The maximum body size to output",
				    -1,
				    G_MAXINT,
				    -1,
				    G_PARAM_CONSTRUCT |
				    G_PARAM_READWRITE |
				    G_PARAM_STATIC_STRINGS);

        g_object_class_install_properties (object_class, LAST_PROPERTY, properties);
}

/**
 * SoupLoggerLogLevel:
 * @SOUP_LOGGER_LOG_NONE: No logging
 * @SOUP_LOGGER_LOG_MINIMAL: Log the Request-Line or Status-Line and
 *   the Soup-Debug pseudo-headers
 * @SOUP_LOGGER_LOG_HEADERS: Log the full request/response headers
 * @SOUP_LOGGER_LOG_BODY: Log the full headers and request/response bodies
 *
 * Describes the level of logging output to provide.
 **/

/**
 * soup_logger_new:
 * @level: the debug level
 *
 * Creates a new [class@Logger] with the given debug level.
 *
 * If you need finer control over what message parts are and aren't
 * logged, use [method@Logger.set_request_filter] and
 * [method@Logger.set_response_filter].
 *
 * Returns: a new #SoupLogger
 **/
SoupLogger *
soup_logger_new (SoupLoggerLogLevel level)
{
	return g_object_new (SOUP_TYPE_LOGGER, "level", level, NULL);
}

/**
 * SoupLoggerFilter:
 * @logger: the #SoupLogger
 * @msg: the message being logged
 * @user_data: the data passed to [method@Logger.set_request_filter]
 *   or [method@Logger.set_response_filter]
 *
 * The prototype for a logging filter.
 *
 * The filter callback will be invoked for each request or response, and should
 * analyze it and return a [enum@LoggerLogLevel] value indicating how much of
 * the message to log.
 *
 * Returns: a [enum@LoggerLogLevel] value indicating how much of the message to
 *   log
 **/

/**
 * soup_logger_set_request_filter:
 * @logger: a #SoupLogger
 * @request_filter: the callback for request debugging
 * @filter_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @filter_data
 *
 * Sets up a filter to determine the log level for a given request.
 *
 * For each HTTP request @logger will invoke @request_filter to
 * determine how much (if any) of that request to log. (If you do not
 * set a request filter, @logger will just always log requests at the
 * level passed to [ctor@Logger.new].)
 **/
void
soup_logger_set_request_filter (SoupLogger       *logger,
				SoupLoggerFilter  request_filter,
				gpointer          filter_data,
				GDestroyNotify    destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->request_filter         = request_filter;
	priv->request_filter_data    = filter_data;
	priv->request_filter_dnotify = destroy;
}

/**
 * soup_logger_set_response_filter:
 * @logger: a #SoupLogger
 * @response_filter: the callback for response debugging
 * @filter_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @filter_data
 *
 * Sets up a filter to determine the log level for a given response.
 *
 * For each HTTP response @logger will invoke @response_filter to
 * determine how much (if any) of that response to log. (If you do not
 * set a response filter, @logger will just always log responses at
 * the level passed to [ctor@Logger.new].)
 **/
void
soup_logger_set_response_filter (SoupLogger       *logger,
				 SoupLoggerFilter  response_filter,
				 gpointer          filter_data,
				 GDestroyNotify    destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->response_filter         = response_filter;
	priv->response_filter_data    = filter_data;
	priv->response_filter_dnotify = destroy;
}

/**
 * SoupLoggerPrinter:
 * @logger: the #SoupLogger
 * @level: the level of the information being printed.
 * @direction: a single-character prefix to @data
 * @data: data to print
 * @user_data: the data passed to [method@Logger.set_printer]
 *
 * The prototype for a custom printing callback.
 *
 * @level indicates what kind of information is being printed. Eg, it
 * will be %SOUP_LOGGER_LOG_HEADERS if @data is header data.
 *
 * @direction is either '<', '>', or ' ', and @data is the single line
 * to print; the printer is expected to add a terminating newline.
 *
 * To get the effect of the default printer, you would do:
 *
 * ```c
 * printf ("%c %s\n", direction, data);
 * ```
 **/

/**
 * soup_logger_set_printer:
 * @logger: a #SoupLogger
 * @printer: the callback for printing logging output
 * @printer_data: data to pass to the callback
 * @destroy: a #GDestroyNotify to free @printer_data
 *
 * Sets up an alternate log printing routine, if you don't want
 * the log to go to `stdout`.
 **/
void
soup_logger_set_printer (SoupLogger        *logger,
			 SoupLoggerPrinter  printer,
			 gpointer           printer_data,
			 GDestroyNotify     destroy)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	priv->printer         = printer;
	priv->printer_data    = printer_data;
	priv->printer_dnotify = destroy;
}

/**
 * soup_logger_set_max_body_size: (attributes org.gtk.Method.set_property=max-body-size)
 * @logger: a #SoupLogger
 * @max_body_size: the maximum body size to log
 *
 * Sets the maximum body size for @logger (-1 means no limit).
 **/
void
soup_logger_set_max_body_size (SoupLogger *logger, int max_body_size)
{
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        priv->max_body_size = max_body_size;
}

/**
 * soup_logger_get_max_body_size: (attributes org.gtk.Method.get_property=max-body-size)
 * @logger: a #SoupLogger
 *
 * Get the maximum body size for @logger.
 *
 * Returns: the maximum body size, or -1 if unlimited
 **/
int
soup_logger_get_max_body_size (SoupLogger *logger)
{
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        return priv->max_body_size;
}

static guint
soup_logger_get_id (SoupLogger *logger, gpointer object)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

	return GPOINTER_TO_UINT (g_object_get_qdata (object, priv->tag));
}

static guint
soup_logger_set_id (SoupLogger *logger, gpointer object)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	gpointer klass = G_OBJECT_GET_CLASS (object);
	gpointer id;

        g_mutex_lock (&priv->mutex);
	id = g_hash_table_lookup (priv->ids, klass);
	id = (char *)id + 1;
	g_hash_table_insert (priv->ids, klass, id);
        g_mutex_unlock (&priv->mutex);

	g_object_set_qdata (object, priv->tag, id);
	return GPOINTER_TO_UINT (id);
}

static void soup_logger_print (SoupLogger *logger, SoupLoggerLogLevel level,
			       char direction, const char *format, ...) G_GNUC_PRINTF (4, 5);

static void
soup_logger_print (SoupLogger *logger, SoupLoggerLogLevel level,
		   char direction, const char *format, ...)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	va_list args;
	char *data, *line, *end;

	va_start (args, format);
	data = g_strdup_vprintf (format, args);
	va_end (args);

	line = data;
	do {
		end = strchr (line, '\n');
		if (end)
			*end = '\0';
		if (priv->printer) {
			priv->printer (logger, level, direction,
				       line, priv->printer_data);
		} else
			printf ("%c %s\n", direction, line);

		line = end + 1;
	} while (end && *line);

	g_free (data);
}

static void
soup_logger_print_basic_auth (SoupLogger *logger, const char *value)
{
	char *decoded, *decoded_utf8, *p;
	gsize len;

	decoded = (char *)g_base64_decode (value + 6, &len);
	if (decoded && !g_utf8_validate (decoded, -1, NULL)) {
		decoded_utf8 = g_convert_with_fallback (decoded, -1,
							"UTF-8", "ISO-8859-1",
							NULL, NULL, &len,
							NULL);
		if (decoded_utf8) {
			g_free (decoded);
			decoded = decoded_utf8;
		}
	}

	if (!decoded)
		decoded = g_strdup (value);
	p = strchr (decoded, ':');
	if (p) {
		while (++p < decoded + len)
			*p = '*';
	}
	soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>',
			   "Authorization: Basic [%.*s]", (int)len, decoded);
	g_free (decoded);
}

static void
print_request (SoupLogger *logger, SoupMessage *msg,
	       GSocket *socket, gboolean restarted)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	SoupLoggerLogLevel log_level;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	char *socket_dbg;
	GString *body;
	GUri *uri;

	if (priv->request_filter) {
		log_level = priv->request_filter (logger, msg,
						  priv->request_filter_data);
	} else
		log_level = priv->level;

	if (log_level == SOUP_LOGGER_LOG_NONE)
		return;

	uri = soup_message_get_uri (msg);
	if (soup_message_get_method (msg) == SOUP_METHOD_CONNECT) {
		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
				   "CONNECT %s:%u HTTP/%s",
				   g_uri_get_host (uri), g_uri_get_port (uri),
				   soup_http_version_to_string (soup_message_get_http_version (msg)));
	} else {
		soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
				   "%s %s%s%s HTTP/%s",
				   soup_message_get_method (msg),
                                   g_uri_get_path (uri),
				   g_uri_get_query (uri) ? "?" : "",
				   g_uri_get_query (uri) ? g_uri_get_query (uri) : "",
				   soup_http_version_to_string (soup_message_get_http_version (msg)));
	}

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
			   "Soup-Debug-Timestamp: %lu",
			   (unsigned long)time (0));

	socket_dbg = socket ?
		g_strdup_printf ("%s %u (%p)",
				 g_type_name_from_instance ((GTypeInstance *)socket),
				 soup_logger_get_id (logger, socket), socket)
		: NULL;

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
			   "Soup-Debug: %s %u (%p), %s %u (%p), %s%s",
			   g_type_name_from_instance ((GTypeInstance *)priv->session),
			   soup_logger_get_id (logger, priv->session), priv->session,
			   g_type_name_from_instance ((GTypeInstance *)msg),
			   soup_logger_get_id (logger, msg), msg,
			   socket_dbg ? socket_dbg : "cached",
			   restarted ? ", restarted" : "");
	g_free (socket_dbg);

	if (log_level == SOUP_LOGGER_LOG_MINIMAL)
		return;

	soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>', "Soup-Host: %s", g_uri_get_host (uri));

	soup_message_headers_iter_init (&iter, soup_message_get_request_headers (msg));
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		if (!g_ascii_strcasecmp (name, "Authorization") &&
		    !g_ascii_strncasecmp (value, "Basic ", 6))
			soup_logger_print_basic_auth (logger, value);
		else {
			soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '>',
					   "%s: %s", name, value);
		}
	}

	if (log_level == SOUP_LOGGER_LOG_HEADERS)
		return;

	/* will be logged in get_informational */
	if (soup_message_headers_get_expectations (soup_message_get_request_headers (msg)) == SOUP_EXPECTATION_CONTINUE)
		return;

	if (!g_hash_table_steal_extended (priv->request_bodies, msg, NULL, (gpointer *)&body))
		return;

	soup_logger_print (logger, SOUP_LOGGER_LOG_BODY, '>', "\n%s", body->str);
	g_string_free (body, TRUE);
}

static void
print_response (SoupLogger *logger, SoupMessage *msg)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	SoupLoggerLogLevel log_level;
	SoupMessageHeadersIter iter;
	const char *name, *value;
	GString *body;

	if (priv->response_filter) {
		log_level = priv->response_filter (logger, msg,
						   priv->response_filter_data);
	} else
		log_level = priv->level;

	if (log_level == SOUP_LOGGER_LOG_NONE)
		return;

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "HTTP/%s %u %s\n",
			   soup_http_version_to_string (soup_message_get_http_version (msg)),
			   soup_message_get_status (msg), soup_message_get_reason_phrase (msg));

	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "Soup-Debug-Timestamp: %lu",
			   (unsigned long)time (0));
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '<',
			   "Soup-Debug: %s %u (%p)",
			   g_type_name_from_instance ((GTypeInstance *)msg),
			   soup_logger_get_id (logger, msg), msg);

	if (log_level == SOUP_LOGGER_LOG_MINIMAL)
		return;

	soup_message_headers_iter_init (&iter, soup_message_get_response_headers (msg));
	while (soup_message_headers_iter_next (&iter, &name, &value)) {
		soup_logger_print (logger, SOUP_LOGGER_LOG_HEADERS, '<',
				   "%s: %s", name, value);
	}

	if (log_level == SOUP_LOGGER_LOG_HEADERS)
		return;

	if (!g_hash_table_steal_extended (priv->response_bodies, msg, NULL, (gpointer *)&body))
		return;

	soup_logger_print (logger, SOUP_LOGGER_LOG_BODY, '<', "\n%s", body->str);
	g_string_free (body, TRUE);
}

static void
finished (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = user_data;
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        /* Do not print the response if we didn't print a request. This can happen if
         * msg is a preconnect request, for example.
         */
        if (!soup_logger_get_id (logger, msg))
                return;

        g_mutex_lock (&priv->mutex);
	print_response (logger, msg);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");
        g_mutex_unlock (&priv->mutex);
}

static void
got_informational (SoupMessage *msg, gpointer user_data)
{
        SoupLogger *logger = user_data;
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
        SoupLoggerLogLevel log_level;
        GString *body = NULL;

        g_mutex_lock (&priv->mutex);

        if (priv->response_filter)
                log_level = priv->response_filter (logger, msg,
                                                   priv->response_filter_data);
        else
                log_level = priv->level;

        g_signal_handlers_disconnect_by_func (msg, finished, logger);
        print_response (logger, msg);
        soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");

        if (!g_hash_table_steal_extended (priv->response_bodies, msg, NULL, (gpointer *)&body)) {
                g_mutex_unlock (&priv->mutex);
                return;
        }

        if (soup_message_get_status (msg) == SOUP_STATUS_CONTINUE) {
                soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, '>',
                                   "[Now sending request body...]");

                if (log_level == SOUP_LOGGER_LOG_BODY) {
                        soup_logger_print (logger, SOUP_LOGGER_LOG_BODY,
                                           '>', "%s", body->str);
                }

                soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");
        }

        g_string_free (body, TRUE);

        g_mutex_unlock (&priv->mutex);
}

static void
got_body (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = user_data;
        SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);

        g_mutex_lock (&priv->mutex);

	g_signal_handlers_disconnect_by_func (msg, finished, logger);

	print_response (logger, msg);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");

        g_mutex_unlock (&priv->mutex);
}

static void
wrote_body (SoupMessage *msg, gpointer user_data)
{
	SoupLogger *logger = SOUP_LOGGER (user_data);
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (logger);
	gboolean restarted;
	guint msg_id;
	SoupConnection *conn;
	GSocket *socket = NULL;

	msg_id = soup_logger_get_id (logger, msg);
	if (msg_id)
		restarted = TRUE;
	else {
		soup_logger_set_id (logger, msg);
		restarted = FALSE;
	}

	if (!soup_logger_get_id (logger, priv->session))
		soup_logger_set_id (logger, priv->session);

	conn = soup_message_get_connection (msg);
        if (conn) {
                socket = soup_connection_get_socket (conn);
                g_object_unref (conn);
        }
	if (socket && !soup_logger_get_id (logger, socket))
		soup_logger_set_id (logger, socket);

        g_mutex_lock (&priv->mutex);
	print_request (logger, msg, socket, restarted);
	soup_logger_print (logger, SOUP_LOGGER_LOG_MINIMAL, ' ', "\n");
        g_mutex_unlock (&priv->mutex);
}

static void
soup_logger_request_queued (SoupSessionFeature *logger,
			    SoupMessage        *msg)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	g_signal_connect (msg, "wrote-body",
				G_CALLBACK (wrote_body),
				logger);
	g_signal_connect (msg, "got-informational",
			  G_CALLBACK (got_informational),
			  logger);
	g_signal_connect (msg, "got-body",
			  G_CALLBACK (got_body),
			  logger);
	g_signal_connect (msg, "finished",
			  G_CALLBACK (finished),
			  logger);
}

static void
soup_logger_request_unqueued (SoupSessionFeature *logger,
			      SoupMessage        *msg)
{
	g_return_if_fail (SOUP_IS_MESSAGE (msg));

	g_signal_handlers_disconnect_by_data (msg, logger);
}

static void
soup_logger_feature_attach (SoupSessionFeature *feature,
			    SoupSession *session)
{
	SoupLoggerPrivate *priv = soup_logger_get_instance_private (SOUP_LOGGER (feature));

	priv->session = session;
}

static void
soup_logger_session_feature_init (SoupSessionFeatureInterface *feature_interface,
				  gpointer interface_data)
{
	feature_interface->attach = soup_logger_feature_attach;
	feature_interface->request_queued = soup_logger_request_queued;
	feature_interface->request_unqueued = soup_logger_request_unqueued;
}
